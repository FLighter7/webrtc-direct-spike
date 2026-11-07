// Command server is a throwaway spike: an ICE-lite WebRTC server that a browser
// reaches with no signaling exchange. The browser learns the server's fixed
// parameters (ICE password, certificate fingerprint, port, addresses) once from
// a pairing code and builds the server's answer itself on every connection.
//
// The client picks the server's ICE ufrag per connection. The server sees an
// unknown ufrag in the first STUN binding request, checks the request against
// its fixed password, and only then creates a peer connection for it.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	"github.com/pion/webrtc/v4"
	qrcode "github.com/skip2/go-qrcode"
)

const (
	chunkBytes      = 16 * 1024
	bufferHighBytes = 1024 * 1024
	bufferLowBytes  = 256 * 1024
	maxBlobBytes    = 8 * 1024 * 1024
	connectDeadline = 20 * time.Second
)

// The server never sees the client's real offer, so it builds a stand-in. The
// client's ufrag comes from the first STUN request; the password and the
// fingerprint are placeholders, since the server never checks the client's
// side of ICE (it is ICE-lite) nor its certificate (verification is off and
// the client proves itself with a token inside the channel instead).
const (
	placeholderPwd         = "placeholderplaceholder00"
	placeholderFingerprint = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
)

type identity struct {
	ServerID string `json:"serverId"`
	Name     string `json:"name"`
	Port     int    `json:"port"`
	ICEPwd   string `json:"icePwd"`
	Token    string `json:"token"`
	CertPEM  string `json:"certPem"`
}

// pairingCode is what the QR carries, as base64url JSON.
type pairingCode struct {
	V int      `json:"v"`
	N string   `json:"n"`
	P string   `json:"p"`
	F string   `json:"f"`
	O int      `json:"o"`
	H []string `json:"h"`
	K string   `json:"k"`
}

type server struct {
	id      *identity
	cert    webrtc.Certificate
	fpHex   string
	hosts   []string
	ips     []net.IP
	pageURL string
	mux     ice.UDPMux

	mu       sync.Mutex
	pending  map[string]bool
	sessions map[*session]struct{}
	version  int
}

type session struct {
	srv    *server
	ufrag  string
	remote string
	since  time.Time
	pc     *webrtc.PeerConnection
	dc     *webrtc.DataChannel
	lowCh  chan struct{}

	mu     sync.Mutex
	label  string
	authed bool

	sendMu    sync.Mutex
	closeOnce sync.Once
}

type frame struct {
	T     string  `json:"t"`
	Token string  `json:"token,omitempty"`
	Label string  `json:"label,omitempty"`
	N     int     `json:"n,omitempty"`
	TS    float64 `json:"ts,omitempty"`
	Bytes int     `json:"bytes,omitempty"`
}

func main() {
	idPath := flag.String("identity", "identity.json", "file holding the server's fixed identity")
	port := flag.Int("port", 47800, "UDP port, used only when a new identity is created")
	httpAddr := flag.String("http", "127.0.0.1:47801", "address of the pairing page")
	page := flag.String("page", "https://flighter7.github.io/webrtc-direct-spike/", "client page the QR points at")
	clientDir := flag.String("client", "..", "folder with the client page, served at /client/")
	mdnsName := flag.String("mdns", "", ".local name to advertise (default: this machine's own)")
	expired := flag.Bool("expired-cert", false, "when creating a new identity, give it an already expired certificate")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	id, cert, err := loadOrCreateIdentity(*idPath, *port, *expired)
	if err != nil {
		log.Fatal(err)
	}

	fpHex, err := sha256Fingerprint(cert)
	if err != nil {
		log.Fatal(err)
	}

	s := &server{
		id:       id,
		cert:     cert,
		fpHex:    fpHex,
		ips:      lanIPv4(),
		pageURL:  *page,
		pending:  map[string]bool{},
		sessions: map[*session]struct{}{},
	}
	if len(s.ips) == 0 {
		log.Fatal("no LAN IPv4 address found")
	}

	name := *mdnsName
	if name == "" {
		name = localHostName()
	}
	if name != "" {
		s.hosts = append(s.hosts, name)
	}
	for _, ip := range s.ips {
		s.hosts = append(s.hosts, ip.String())
	}

	if err := s.listen(); err != nil {
		log.Fatal(err)
	}

	log.Printf("identity %s (%s), server id %s", *idPath, id.Name, id.ServerID)
	log.Printf("certificate expires %s", cert.Expires().Format("2006-01-02"))
	log.Printf("fingerprint sha-256 %s", fpHex)
	log.Printf("listening on UDP %d at %s", id.Port, strings.Join(s.hosts, ", "))

	go s.serveHTTP(*httpAddr, *clientDir)
	log.Printf("pairing page: http://%s/", *httpAddr)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Printf("stopping")
	_ = s.mux.Close()
}

func randomString(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}

	return string(b)
}

func loadOrCreateIdentity(path string, port int, expired bool) (*identity, webrtc.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		var id identity
		if err := json.Unmarshal(raw, &id); err != nil {
			return nil, webrtc.Certificate{}, fmt.Errorf("parse %s: %w", path, err)
		}
		cert, err := webrtc.CertificateFromPEM(id.CertPEM)
		if err != nil {
			return nil, webrtc.Certificate{}, fmt.Errorf("certificate in %s: %w", path, err)
		}

		return &id, *cert, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, webrtc.Certificate{}, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, webrtc.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return nil, webrtc.Certificate{}, err
	}

	notBefore := time.Now().AddDate(0, 0, -1)
	notAfter := notBefore.AddDate(20, 0, 0)
	if expired {
		notBefore = time.Now().AddDate(0, 0, -30)
		notAfter = time.Now().AddDate(0, 0, -1)
	}

	cert, err := webrtc.NewCertificate(key, x509.Certificate{
		SerialNumber: serial,
		Version:      2,
		Issuer:       pkix.Name{CommonName: "webrtc-direct-spike"},
		Subject:      pkix.Name{CommonName: "webrtc-direct-spike"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	})
	if err != nil {
		return nil, webrtc.Certificate{}, err
	}
	pemText, err := cert.PEM()
	if err != nil {
		return nil, webrtc.Certificate{}, err
	}

	host, _ := os.Hostname()
	id := &identity{
		ServerID: randomString(12),
		Name:     host,
		Port:     port,
		ICEPwd:   randomString(24),
		Token:    randomString(22),
		CertPEM:  pemText,
	}
	out, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return nil, webrtc.Certificate{}, err
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return nil, webrtc.Certificate{}, err
	}
	log.Printf("created a new identity in %s", path)

	return id, *cert, nil
}

func sha256Fingerprint(cert webrtc.Certificate) (string, error) {
	fps, err := cert.GetFingerprints()
	if err != nil {
		return "", err
	}
	for _, fp := range fps {
		if fp.Algorithm == "sha-256" {
			return fp.Value, nil
		}
	}

	return "", errors.New("no sha-256 fingerprint")
}

// localHostName is the name this machine already answers to over mDNS.
func localHostName() string {
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("scutil", "--get", "LocalHostName").Output(); err == nil {
			if name := strings.TrimSpace(string(out)); name != "" {
				return name + ".local"
			}
		}
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		return ""
	}
	if !strings.Contains(host, ".") {
		host += ".local"
	}

	return host
}

// lanIPv4 lists the addresses a phone on the same network could reach:
// interfaces that are up, not loopback, not point-to-point (VPN tunnels).
func lanIPv4() []net.IP {
	var ips []net.IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLinkLocalUnicast() {
				continue
			}
			ips = append(ips, ip4)
		}
	}

	return ips
}

// listen also binds loopback, unadvertised: a browser on this same machine
// resolves this machine's .local name to 127.0.0.1 first.
func (s *server) listen() error {
	var muxes []ice.UDPMux
	for _, ip := range append([]net.IP{net.IPv4(127, 0, 0, 1)}, s.ips...) {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: s.id.Port})
		if err != nil {
			return fmt.Errorf("listen %s:%d: %w", ip, s.id.Port, err)
		}
		muxes = append(muxes, ice.NewUDPMuxDefault(ice.UDPMuxParams{
			UDPConn:           conn,
			OnUnhandledPacket: s.onUnhandled,
		}))
	}
	s.mux = ice.NewMultiUDPMuxDefault(muxes...)

	return nil
}

// onUnhandled sees every packet no peer connection claims yet. It must not
// block: a valid binding request for an unknown ufrag starts a peer connection
// in the background, and the browser's retransmitted check reaches it.
func (s *server) onUnhandled(data []byte, addr netip.AddrPort) {
	if !stun.IsMessage(data) {
		return
	}
	msg := &stun.Message{Raw: append([]byte(nil), data...)}
	if err := msg.Decode(); err != nil || msg.Type != stun.BindingRequest {
		return
	}
	var user stun.Username
	if err := user.GetFrom(msg); err != nil {
		return
	}
	local, remote, ok := strings.Cut(string(user), ":")
	if !ok || local == "" || remote == "" {
		return
	}
	if err := stun.NewShortTermIntegrity(s.id.ICEPwd).Check(msg); err != nil {
		log.Printf("binding request from %s with a wrong password, ignored", addr)

		return
	}

	s.mu.Lock()
	if s.pending[local] {
		s.mu.Unlock()

		return
	}
	s.pending[local] = true
	s.mu.Unlock()

	go s.accept(local, remote, addr.String())
}

func (s *server) accept(ufrag, remoteUfrag, remote string) {
	sess := &session{srv: s, ufrag: ufrag, remote: remote, since: time.Now(), lowCh: make(chan struct{}, 1)}
	logf := func(format string, args ...any) {
		log.Printf("[%s] "+format, append([]any{ufrag}, args...)...)
	}
	elapsed := func() int64 { return time.Since(sess.since).Milliseconds() }

	settings := webrtc.SettingEngine{}
	settings.SetLite(true)
	settings.SetICECredentials(ufrag, s.id.ICEPwd)
	settings.DisableCertificateFingerprintVerification(true)
	if err := settings.SetAnsweringDTLSRole(webrtc.DTLSRoleServer); err != nil {
		logf("dtls role: %v", err)
		s.forget(sess)

		return
	}
	settings.SetICEUDPMux(s.mux)
	settings.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	settings.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)

	api := webrtc.NewAPI(webrtc.WithSettingEngine(settings))
	pc, err := api.NewPeerConnection(webrtc.Configuration{Certificates: []webrtc.Certificate{s.cert}})
	if err != nil {
		logf("peer connection: %v", err)
		s.forget(sess)

		return
	}
	sess.pc = pc
	logf("new client from %s (client ufrag %s)", remote, remoteUfrag)

	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		logf("ice %s (+%d ms)", state, elapsed())
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		logf("connection %s (+%d ms)", state, elapsed())
		switch state {
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed, webrtc.PeerConnectionStateDisconnected:
			sess.close("connection " + state.String())
		default:
		}
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		sess.dc = dc
		dc.SetBufferedAmountLowThreshold(bufferLowBytes)
		dc.OnBufferedAmountLow(func() {
			select {
			case sess.lowCh <- struct{}{}:
			default:
			}
		})
		dc.OnOpen(func() { logf("channel %q open (+%d ms)", dc.Label(), elapsed()) })
		dc.OnMessage(sess.handle)
		dc.OnClose(func() { sess.close("channel closed") })
	})

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: standInOffer(remoteUfrag)}); err != nil {
		logf("remote description: %v", err)
		sess.close("bad remote description")

		return
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		logf("answer: %v", err)
		sess.close("no answer")

		return
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		logf("local description: %v", err)
		sess.close("bad local description")

		return
	}

	time.AfterFunc(connectDeadline, func() {
		if pc.ConnectionState() != webrtc.PeerConnectionStateConnected {
			sess.close(fmt.Sprintf("not connected within %s", connectDeadline))
		}
	})
}

func standInOffer(clientUfrag string) string {
	return strings.Join([]string{
		"v=0",
		"o=- 0 2 IN IP4 127.0.0.1",
		"s=-",
		"t=0 0",
		"a=group:BUNDLE 0",
		"a=msid-semantic: WMS",
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
		"c=IN IP4 0.0.0.0",
		"a=ice-ufrag:" + clientUfrag,
		"a=ice-pwd:" + placeholderPwd,
		"a=fingerprint:sha-256 " + placeholderFingerprint,
		"a=setup:actpass",
		"a=mid:0",
		"a=sctp-port:5000",
		"a=max-message-size:262144",
	}, "\r\n") + "\r\n"
}

func (s *server) forget(sess *session) {
	s.mu.Lock()
	delete(s.pending, sess.ufrag)
	delete(s.sessions, sess)
	s.mu.Unlock()
}

func (c *session) close(why string) {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		label := c.label
		c.mu.Unlock()
		log.Printf("[%s] closed: %s (%s, %s)", c.ufrag, why, label, time.Since(c.since).Round(time.Millisecond))
		c.srv.forget(c)
		if c.pc != nil {
			// Closing from inside a Pion callback can deadlock.
			go func() { _ = c.pc.Close() }()
		}
	})
}

func (c *session) send(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.dc != nil {
		_ = c.dc.SendText(string(data))
	}
}

func (c *session) handle(msg webrtc.DataChannelMessage) {
	if !msg.IsString {
		return
	}
	var f frame
	if err := json.Unmarshal(msg.Data, &f); err != nil {
		return
	}

	c.mu.Lock()
	authed := c.authed
	c.mu.Unlock()
	if f.T != "hello" && !authed {
		c.send(map[string]any{"t": "denied", "reason": "say hello first"})

		return
	}

	switch f.T {
	case "hello":
		if f.Token != c.srv.id.Token {
			log.Printf("[%s] wrong token from %q", c.ufrag, f.Label)
			c.send(map[string]any{"t": "denied", "reason": "wrong token"})
			c.close("wrong token")

			return
		}
		c.mu.Lock()
		c.label = f.Label
		c.authed = true
		c.mu.Unlock()

		c.srv.mu.Lock()
		c.srv.sessions[c] = struct{}{}
		peers := len(c.srv.sessions)
		version := c.srv.version
		c.srv.mu.Unlock()

		log.Printf("[%s] hello from %q at %s (+%d ms), %d connected", c.ufrag, f.Label, c.remote, time.Since(c.since).Milliseconds(), peers)
		c.send(map[string]any{
			"t":        "welcome",
			"serverId": c.srv.id.ServerID,
			"name":     c.srv.id.Name,
			"hosts":    c.srv.hosts,
			"version":  version,
			"peers":    peers,
			"remote":   c.remote,
		})
	case "echo":
		c.send(map[string]any{"t": "echo", "n": f.N, "ts": f.TS})
	case "blob":
		go c.sendBlob(f.Bytes)
	case "touch":
		version := c.srv.touch(c)
		c.send(map[string]any{"t": "touched", "version": version})
	default:
		c.send(map[string]any{"t": "unknown", "what": f.T})
	}
}

func (c *session) sendBlob(size int) {
	if size <= 0 || size > maxBlobBytes {
		c.send(map[string]any{"t": "denied", "reason": "blob size out of range"})

		return
	}
	payload := make([]byte, size)
	_, _ = rand.Read(payload)

	started := time.Now()
	c.send(map[string]any{"t": "blob", "bytes": size})
	for offset := 0; offset < size; offset += chunkBytes {
		end := min(offset+chunkBytes, size)
		if c.dc.BufferedAmount() > bufferHighBytes {
			select {
			case <-c.lowCh:
			case <-time.After(5 * time.Second):
				log.Printf("[%s] blob stalled at %d bytes", c.ufrag, offset)

				return
			}
		}
		c.sendMu.Lock()
		err := c.dc.Send(payload[offset:end])
		c.sendMu.Unlock()
		if err != nil {
			log.Printf("[%s] blob send: %v", c.ufrag, err)

			return
		}
	}
	log.Printf("[%s] blob of %d bytes queued in %s", c.ufrag, size, time.Since(started).Round(time.Millisecond))
}

// touch stands in for "a file changed": it bumps a counter and tells every
// other connected device.
func (s *server) touch(from *session) int {
	from.mu.Lock()
	label := from.label
	from.mu.Unlock()

	s.mu.Lock()
	s.version++
	version := s.version
	var others []*session
	for sess := range s.sessions {
		if sess != from {
			others = append(others, sess)
		}
	}
	s.mu.Unlock()

	log.Printf("[%s] touch from %q -> version %d, telling %d other device(s)", from.ufrag, label, version, len(others))
	for _, other := range others {
		other.send(map[string]any{"t": "changed", "version": version, "from": label})
	}

	return version
}

func (s *server) code() string {
	raw, err := hex.DecodeString(strings.ReplaceAll(s.fpHex, ":", ""))
	if err != nil {
		panic(err)
	}
	data, err := json.Marshal(pairingCode{
		V: 1,
		N: s.id.Name,
		P: s.id.ICEPwd,
		F: base64.RawURLEncoding.EncodeToString(raw),
		O: s.id.Port,
		H: s.hosts,
		K: s.id.Token,
	})
	if err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(data)
}

func (s *server) serveHTTP(addr, clientDir string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/qr.png", func(w http.ResponseWriter, _ *http.Request) {
		png, err := qrcode.Encode(s.pageURL+"#"+s.code(), qrcode.Low, 640)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, _ *http.Request) {
		type row struct {
			Label  string `json:"label"`
			Remote string `json:"remote"`
			Since  string `json:"since"`
		}
		s.mu.Lock()
		rows := make([]row, 0, len(s.sessions))
		for sess := range s.sessions {
			sess.mu.Lock()
			rows = append(rows, row{Label: sess.label, Remote: sess.remote, Since: sess.since.Format("15:04:05")})
			sess.mu.Unlock()
		}
		version := s.version
		s.mu.Unlock()
		sort.Slice(rows, func(i, j int) bool { return rows[i].Since < rows[j].Since })
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"version": version, "sessions": rows})
	})
	mux.Handle("/client/", http.StripPrefix("/client/", http.FileServer(http.Dir(clientDir))))

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)

		return
	}
	code := s.code()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, indexHTML,
		html.EscapeString(s.id.Name),
		html.EscapeString(strings.Join(s.hosts, ", ")),
		s.id.Port,
		html.EscapeString(s.pageURL+"#"+code),
		html.EscapeString(code),
		html.EscapeString("/client/#"+code),
	)
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Spike server</title>
<style>
:root { color-scheme: light dark; --bg: #ffffff; --fg: #1a1a1a; --muted: #5f5f5f; --line: #d0d0d0; }
@media (prefers-color-scheme: dark) { :root { --bg: #161616; --fg: #ececec; --muted: #a8a8a8; --line: #3a3a3a; } }
body { margin: 0; padding: 16px; background: var(--bg); color: var(--fg); font: 16px/1.5 system-ui, sans-serif; }
main { max-width: 720px; margin: 0 auto; }
img { width: min(100%%, 360px); background: #ffffff; padding: 12px; border-radius: 8px; }
textarea { width: 100%%; box-sizing: border-box; font: 13px/1.4 ui-monospace, monospace; }
.muted { color: var(--muted); }
table { border-collapse: collapse; width: 100%%; }
td, th { border-bottom: 1px solid var(--line); padding: 4px 8px; text-align: left; }
</style>
</head>
<body>
<main>
<h1>Spike server: %s</h1>
<p class="muted">Advertised: %s, UDP %d</p>
<h2>Pair a device</h2>
<p>Scan with the phone camera. It opens the client page with the code.</p>
<p><img src="/qr.png" alt="Pairing QR code"></p>
<p><a href="%s">Client page with this code</a></p>
<p>Or paste this code into the client page:</p>
<textarea id="code" rows="4" readonly>%s</textarea>
<p><button id="copy" type="button">Copy code</button></p>
<p><a href="%s">Local client page on this computer</a></p>
<h2>Connected devices</h2>
<p class="muted">Touch counter: <span id="version">0</span></p>
<table><thead><tr><th>Device</th><th>From</th><th>Since</th></tr></thead><tbody id="rows"></tbody></table>
</main>
<script>
document.getElementById('copy').addEventListener('click', async () => {
	const area = document.getElementById('code');
	try { await navigator.clipboard.writeText(area.value); } catch { area.select(); document.execCommand('copy'); }
});
async function refresh() {
	try {
		const status = await (await fetch('/api/status')).json();
		document.getElementById('version').textContent = status.version;
		const rows = document.getElementById('rows');
		rows.replaceChildren(...status.sessions.map((s) => {
			const tr = document.createElement('tr');
			for (const value of [s.label, s.remote, s.since]) {
				const td = document.createElement('td');
				td.textContent = value;
				tr.append(td);
			}
			return tr;
		}));
	} catch {}
}
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
`

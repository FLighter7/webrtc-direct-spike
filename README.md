# WebRTC Direct Spike

Throwaway experiment: can a browser (an installed PWA included) connect to a server on the local network over WebRTC with **no signaling exchange**, using only parameters it learned once from a pairing code?

- `server/` — Go + Pion. An ICE-lite server on one UDP port with a fixed ICE password and certificate. The client picks the server's ICE ufrag per connection; the server sees the unknown ufrag in the first STUN request, checks it against its password, and creates a peer connection for it.
- `index.html` — the client page, served by GitHub Pages. It builds the server's SDP answer itself from the pairing code.

## Run

```bash
cd server
go build -o spike-server . && ./spike-server
```

Open `http://127.0.0.1:47801/` for the pairing QR. The identity (`server/identity.json`, git-ignored) is created on first start and reused afterwards, so a restart needs no new pairing.

Flags: `-port` (UDP, default 47800, only for a new identity), `-identity <file>`, `-expired-cert` (a new identity with an already expired certificate), `-mdns <name.local>`.

# Remote Device Control relay

This service forwards **ciphertext only**. The Windows clients establish their
own pinned TLS session inside the two WebSocket channels. The relay never has
the host's private certificate key or the end-to-end pairing secret, and does
not record screens, keyboard input, capabilities or IP addresses persistently.

Run with a dedicated unprivileged account, a private loopback listener and the
project's HTTPS reverse-proxy configuration:

```sh
python -m uvicorn relay:app --host 127.0.0.1 --port 18768 --workers 1 \
  --ws-max-size 65536 --ws-max-queue 1 --no-access-log --no-proxy-headers
```

One worker is deliberate: room ownership and bounded admission live in memory.
Restarting the relay disconnects sessions; clients reconnect. Do not expose the
loopback port directly or add multiple independent workers behind a load balancer.

The reverse proxy must replace `X-Forwarded-For` with the actual peer address,
disable request/access logging for this route, allow WebSocket upgrades, enforce
handshake connection/rate limits and retain normal HTTPS certificate validation.
Only a loopback TCP peer can supply the forwarded address to this service.

Routes:

- `GET /remote-device-control/health`: protocol and bounded-payload status only.
- `GET /remote-device-control/hosts`: public metadata for explicitly opted-in, live hosts; protected hosts never appear. Records expire after twelve seconds and responses are not cached.
- `POST /remote-device-control/hosts` and `DELETE /remote-device-control/hosts?room=...`: publication/removal requires the private `x-remote-owner` credential. It must match the live relay host's self-certifying room. This credential is distinct from the public viewer relay capability and end-to-end private connection secret.
- `WS /remote-device-control/relay`: exactly four capability headers:
  `x-remote-room` (32 lowercase hex characters), `x-remote-token` (64 lowercase
  hex characters), `x-remote-role` (`host` or `viewer`) and `x-remote-channel`
  (`video` or `input`). No URL query strings or browser `Origin` are accepted.

New hosts additionally use `x-remote-host-key` for the private host-owner proof. A public room is the first 32 lowercase hex characters of SHA-256 over that 64-character owner credential. Only a proven owner can register its host role or replace an unowned legacy reservation. The viewer's public capability cannot publish another fingerprint or become the host owner. Legacy protected hosts retain their existing four-header registration.

The relay capability is **separate from the end-to-end pairing secret**. Protected hosts share it only in their private pairing code. Explicitly public hosts publish their viewer capability so code-free clients can connect; their private owner proof stays on the host.
A host must register a channel before a viewer joins it. A matching pair receives
the binary bootstrap marker `RDC-READY-1`, then exchanges opaque binary data.
Duplicate roles are refused instead of evicting an established peer. Disconnect
removes the pair; the counterpart is closed and must reconnect.

Default bounds are eight rooms, four active rooms, eight connections per IP,
20 handshakes per minute per IP, 1,024 transient IP rate buckets, 65,536 bytes per
WebSocket message, 20 seconds to pair and one hour maximum room lifetime. Video
has a 6 Mbit/s allowance and input a reserved 2 Mbit/s allowance, shared by both
directions of each room/channel. There are no application data queues: a slow
recipient backpressures its sender. Encoders should keep only the latest frame.
These are engineering/fair-use limits, not a bandwidth or latency guarantee.

Tests use disposable rooms and fake capabilities only:

```sh
python -m unittest discover -s tests -v
```

The two-client pairing token alone is not a customer billing/authorization
system. A public deployment remains subject to bounded service exhaustion;
apply upstream IP admission, monitoring and a private host allow-list or an
authenticated enrollment gateway if stronger public-service access control is
required. Do not embed a universal private relay key in a downloadable EXE.

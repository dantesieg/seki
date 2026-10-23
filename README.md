# Seki

UDP 443 router for QUIC that keeps connection migration working.

- New connections (client Initial): decrypts the Initial (QUIC v1/v2), reads the SNI, routes by `sni` map.
- Packets from an unknown client address with a routable DCID (`seki-cid`): routed to the backend
  by server id, so Wi-Fi to mobile switches and NAT rebinding reach the same backend. Each client
  address gets its own upstream socket, so the backend sees the migration and validates the path itself.
- Everything else: IP+port flow table to `default`.

Packets are forwarded unchanged. Connections and migrations are logged (client IP, backend, SNI/server id).

Build: `cargo zigbuild --release -p seki --target x86_64-unknown-linux-musl` (also `aarch64-unknown-linux-musl`).
Run: `seki /etc/seki/seki.yaml`, log level via `SEKI_LOG` (default `info`). Config: `seki.example.yaml`.

## seki-cid

CID = `[config_id:3 | len-1:5] || AES-128(server_id || nonce)` (single block if 16 bytes, else
QUIC-LB four-pass Feistel). Stateless; reset token = `HMAC-SHA256(reset_secret, cid)[..16]`.
See `seki-cid/src/lib.rs`.

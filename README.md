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

## Fast path (nftables DNAT)

With `fastpath.enabled: true`, Seki installs table `ip seki` at start (replacing any old one) and
deletes it on SIGTERM/SIGINT. Packets from undecided client tuples are `notrack`ed and reach Seki.
Once Seki routes a tuple (SNI, CID label, or fallback), it adds `client ip.port : backend ip.port`
to map `flowmap` and the key to set `flowkeys` (timeout = max(connection_timeout, flow_timeout),
refreshed by every packet). It then re-injects the packets it used to decide, with the client's source
address (IP_TRANSPARENT) towards the public IP, so they get the same conntrack entry as the rest
of the flow. From then on the kernel forwards both directions.

- Migration: a new client tuple reaches Seki, gets routed by CID and added. The old tuple expires.
- If a key expires while the conntrack entry lives, the next packet reaches Seki again and is re-added
  to the same backend.
- If the nft add fails, that flow falls back to the userspace relay (`seki_fastpath_fallbacks`).
- Backends see real client IPs (not Seki's).
- IPv4 only. IPv6 clients use the userspace relay.
- If Seki stops, existing conntrack entries keep forwarding until they expire.

Host prerequisites:

- Root or `CAP_NET_ADMIN` (nft, IP_TRANSPARENT, SO_MARK). A process manager running Seki as root is enough.
- `nft` binary (nftables ≥ 1.0), kernel with nf_tables, nf_conntrack, nft_fib, nft_nat (any modern distro).
- Loopback backends (127.0.0.1) need `sysctl -w net.ipv4.conf.all.route_localnet=1` (persist in
  /etc/sysctl.d/). The Seki table drops non-lo packets to 127.0.0.0/8 unless they are DNATed, so this
  doesn't expose loopback services. The alternative is backends listening on a non-loopback address.
- A host firewall must accept DNATed traffic: `ct status dnat accept` in the input chain (ufw: allow the
  backend ports, or add that rule).
- conntrack: defaults work (UDP 30 s unreplied, 120 s stream). If a conntrack entry expires mid-flow,
  the next packet re-matches `flowmap`. Raise `net.netfilter.nf_conntrack_max` if you expect more than
  about 200k flows. Map and set size is 262144.

Metrics: `seki_fastpath_flows` (total added), `seki_fastpath_active`, `seki_fastpath_injected`,
`seki_fastpath_inject_errors`, `seki_fastpath_fallbacks`, plus per backend `seki_backend_fastpath_flows`
and `seki_backend_fastpath_{packets,bytes}_{in,out}` from nft counters (refreshed every 15 s). The plain
`seki_backend_packets_*` counters only cover what Seki itself relayed or injected.

//! Kernel fast path: once Seki has decided a client 4-tuple, it adds it to an
//! nftables map and the kernel DNATs the rest of the flow (conntrack handles
//! the return path). Packets of undecided tuples are `notrack`ed so they reach
//! Seki's socket without pinning a non-NAT conntrack entry. The packets Seki
//! used to decide are re-injected with the client's source address
//! (IP_TRANSPARENT) towards the public address, so they create exactly the
//! conntrack entry the following wire packets will match.
//!
//! IPv4 only. All nft calls run sequentially in one worker task.

use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::warn;

const TABLE: &str = "ip seki";
/// SO_MARK on injected packets, so the output notrack rule skips them.
pub const MARK: u32 = 0x5e4b;

pub enum Op {
    Add(Vec<(SocketAddrV4, SocketAddrV4)>),
    Gc(Vec<SocketAddrV4>),
}

pub enum Event {
    Added(Vec<(SocketAddrV4, bool)>),
    /// Tuples whose key expired (map entry removed), plus per-backend
    /// counters (packets_in, bytes_in, packets_out, bytes_out).
    Gc(Vec<SocketAddrV4>, Vec<[u64; 4]>),
}

pub struct Fastpath {
    pub public: SocketAddrV4,
    pub tx: mpsc::UnboundedSender<Op>,
    nft: String,
}

fn ruleset(port: u16, timeout: u64, backends: &[Option<SocketAddrV4>]) -> String {
    let mut s = format!(
        "table {TABLE} {{
  set flowkeys {{ type ipv4_addr . inet_service; flags dynamic, timeout; timeout {timeout}s; size 262144; }}
  map flowmap {{ type ipv4_addr . inet_service : ipv4_addr . inet_service; size 262144; }}
  chain raw_pre {{ type filter hook prerouting priority raw; policy accept;
    udp dport {port} fib daddr type local ip saddr . udp sport @flowkeys update @flowkeys {{ ip saddr . udp sport }} accept
    udp dport {port} fib daddr type local notrack
  }}
  chain raw_out {{ type filter hook output priority raw; policy accept;
    meta mark != {MARK} udp sport {port} notrack
  }}
  chain nat_pre {{ type nat hook prerouting priority dstnat; policy accept;
    udp dport {port} fib daddr type local dnat ip to ip saddr . udp sport map @flowmap
  }}
  chain nat_out {{ type nat hook output priority -100; policy accept;
    meta mark {MARK} udp dport {port} dnat ip to ip saddr . udp sport map @flowmap
  }}
"
    );
    let (mut cin, mut cout) = (String::new(), String::new());
    for (i, b) in backends.iter().enumerate() {
        let Some(b) = b else { continue };
        s += &format!("  counter in_{i} {{}}\n  counter out_{i} {{}}\n");
        cin += &format!("    ct status dnat ip daddr {} udp dport {} counter name in_{i}\n", b.ip(), b.port());
        cout += &format!("    ct status dnat ip saddr {} udp sport {} counter name out_{i}\n", b.ip(), b.port());
    }
    s += &format!("  chain cnt_in {{ type filter hook input priority filter; policy accept;\n    iifname != \"lo\" ip daddr 127.0.0.0/8 ct status & dnat == 0 drop\n{cin}  }}\n");
    s += &format!("  chain cnt_out {{ type filter hook output priority filter; policy accept;\n{cout}  }}\n}}\n");
    s
}

fn run_sync(nft: &str, args: &[&str], stdin: Option<&str>) -> Result<()> {
    use std::io::Write;
    let mut c = std::process::Command::new(nft);
    c.args(args).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::piped());
    let mut ch = c.spawn().with_context(|| format!("running {nft}"))?;
    if let Some(s) = stdin {
        ch.stdin.take().unwrap().write_all(s.as_bytes())?;
    }
    drop(ch.stdin.take());
    let out = ch.wait_with_output()?;
    if !out.status.success() {
        bail!("{nft} {args:?}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

async fn run(nft: &str, args: &[&str], stdin: Option<&str>) -> Result<String> {
    let mut c = tokio::process::Command::new(nft);
    c.args(args).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut ch = c.spawn().with_context(|| format!("running {nft}"))?;
    let mut si = ch.stdin.take().unwrap();
    if let Some(s) = stdin {
        si.write_all(s.as_bytes()).await?;
    }
    drop(si);
    let out = ch.wait_with_output().await?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn detect_public() -> Result<Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0")?;
    s.connect("192.0.2.1:9")?; // no packet is sent
    match s.local_addr()?.ip() {
        std::net::IpAddr::V4(ip) => Ok(ip),
        _ => bail!("no IPv4 default route"),
    }
}

impl Fastpath {
    /// Replace the nft table and start the worker.
    pub fn start(nft: String, public_ip: Option<Ipv4Addr>, listen: std::net::SocketAddr, timeout: u64, backends: &[Option<SocketAddrV4>]) -> Result<(Self, mpsc::UnboundedReceiver<Event>)> {
        let ip = match (public_ip, listen.ip()) {
            (Some(ip), _) => ip,
            (None, std::net::IpAddr::V4(ip)) if !ip.is_unspecified() => ip,
            _ => detect_public().context("fastpath: detecting public IPv4 (set fastpath.public_ip)")?,
        };
        let _ = run_sync(&nft, &["delete", "table", "ip", "seki"], None);
        run_sync(&nft, &["-f", "-"], Some(&ruleset(listen.port(), timeout, backends))).context("fastpath: loading nft table")?;
        let (tx, rx) = mpsc::unbounded_channel();
        let (etx, erx) = mpsc::unbounded_channel();
        tokio::spawn(worker(nft.clone(), rx, etx, backends.len()));
        Ok((Fastpath { public: SocketAddrV4::new(ip, listen.port()), tx, nft }, erx))
    }

    pub fn stop(&self) {
        if let Err(e) = run_sync(&self.nft, &["delete", "table", "ip", "seki"], None) {
            warn!("fastpath cleanup: {e:#}");
        }
    }

    /// Send `pkts` as if from `src` to the public address; the nat output
    /// chain DNATs them into the same conntrack entry the wire flow uses.
    #[cfg(target_os = "linux")]
    pub fn inject(&self, src: SocketAddrV4, pkts: &[Vec<u8>]) -> std::io::Result<()> {
        use std::os::fd::FromRawFd;
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let sock = std::net::UdpSocket::from_raw_fd(fd);
            let one: libc::c_int = 1;
            let set = |level, opt, v: &libc::c_int| libc::setsockopt(fd, level, opt, v as *const _ as *const libc::c_void, 4) == 0;
            if !set(libc::SOL_IP, libc::IP_TRANSPARENT, &one) || !set(libc::SOL_SOCKET, libc::SO_REUSEADDR, &one) || !set(libc::SOL_SOCKET, libc::SO_MARK, &(MARK as libc::c_int)) {
                return Err(std::io::Error::last_os_error());
            }
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: src.port().to_be(),
                sin_addr: libc::in_addr { s_addr: u32::from(*src.ip()).to_be() },
                sin_zero: [0; 8],
            };
            if libc::bind(fd, &sa as *const _ as *const libc::sockaddr, size_of::<libc::sockaddr_in>() as libc::socklen_t) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            for p in pkts {
                sock.send_to(p, self.public)?;
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn inject(&self, _: SocketAddrV4, _: &[Vec<u8>]) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

fn elem(k: &SocketAddrV4) -> String { format!("{} . {}", k.ip(), k.port()) }

async fn worker(nft: String, mut rx: mpsc::UnboundedReceiver<Op>, tx: mpsc::UnboundedSender<Event>, nback: usize) {
    let mut next: Option<Op> = None;
    loop {
        let op = match next.take() {
            Some(o) => o,
            None => match rx.recv().await {
                Some(o) => o,
                None => return,
            },
        };
        match op {
            Op::Add(mut adds) => {
                // batch queued adds into one nft call
                while let Ok(o) = rx.try_recv() {
                    match o {
                        Op::Add(a) => adds.extend(a),
                        g => { next = Some(g); break; }
                    }
                }
                let script = |a: &[(SocketAddrV4, SocketAddrV4)]| {
                    a.iter().map(|(k, v)| format!("add element {TABLE} flowmap {{ {} : {} }}\nadd element {TABLE} flowkeys {{ {} }}\n", elem(k), elem(v), elem(k))).collect::<String>()
                };
                let res = if run(&nft, &["-f", "-"], Some(&script(&adds))).await.is_ok() {
                    adds.iter().map(|(k, _)| (*k, true)).collect()
                } else {
                    let mut r = Vec::new();
                    for a in &adds {
                        let ok = match run(&nft, &["-f", "-"], Some(&script(std::slice::from_ref(a)))).await {
                            Ok(_) => true,
                            Err(e) => { warn!(client = %a.0, "fastpath add failed: {e:#}"); false }
                        };
                        r.push((a.0, ok));
                    }
                    r
                };
                let _ = tx.send(Event::Added(res));
            }
            Op::Gc(known) => {
                let out = match run(&nft, &["-j", "list", "table", "ip", "seki"], None).await {
                    Ok(o) => o,
                    Err(e) => { warn!("fastpath list: {e:#}"); continue }
                };
                let (live, counters) = parse_table(&out, nback);
                let gone: Vec<_> = known.into_iter().filter(|k| !live.contains(k)).collect();
                if !gone.is_empty() {
                    let s: String = gone.iter().map(|k| format!("delete element {TABLE} flowmap {{ {} }}\n", elem(k))).collect();
                    if run(&nft, &["-f", "-"], Some(&s)).await.is_err() {
                        for k in &gone {
                            let _ = run(&nft, &["delete", "element", "ip", "seki", "flowmap", &format!("{{ {} }}", elem(k))], None).await;
                        }
                    }
                }
                let _ = tx.send(Event::Gc(gone, counters));
            }
        }
    }
}

fn concat(v: &Value, out: &mut Vec<SocketAddrV4>) {
    match v {
        Value::Object(m) => {
            if let Some(Value::Array(c)) = m.get("concat")
                && let [Value::String(ip), Value::Number(p)] = &c[..]
                && let (Ok(ip), Some(p)) = (ip.parse(), p.as_u64())
            {
                out.push(SocketAddrV4::new(ip, p as u16));
                return;
            }
            m.values().for_each(|x| concat(x, out));
        }
        Value::Array(a) => a.iter().for_each(|x| concat(x, out)),
        _ => {}
    }
}

fn parse_table(json: &str, nback: usize) -> (HashSet<SocketAddrV4>, Vec<[u64; 4]>) {
    let mut live = HashSet::new();
    let mut counters = vec![[0u64; 4]; nback];
    let Ok(v) = serde_json::from_str::<Value>(json) else { return (live, counters) };
    for o in v["nftables"].as_array().into_iter().flatten() {
        if o["set"]["name"] == "flowkeys" {
            let mut ks = Vec::new();
            concat(&o["set"]["elem"], &mut ks);
            live.extend(ks);
        } else if let Some(name) = o["counter"]["name"].as_str() {
            let (dir, i) = match name.split_once('_') {
                Some(("in", i)) => (0, i),
                Some(("out", i)) => (2, i),
                _ => continue,
            };
            if let Ok(i) = i.parse::<usize>()
                && i < nback
            {
                counters[i][dir] = o["counter"]["packets"].as_u64().unwrap_or(0);
                counters[i][dir + 1] = o["counter"]["bytes"].as_u64().unwrap_or(0);
            }
        }
    }
    (live, counters)
}

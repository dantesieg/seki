mod config;
mod initial;

use anyhow::{Context, Result};
use initial::CryptoBuf;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, warn};

static START: LazyLock<Instant> = LazyLock::new(Instant::now);
fn now() -> u64 { START.elapsed().as_secs() }

macro_rules! metrics {
    ($($name:ident),*) => {
        $(static $name: AtomicU64 = AtomicU64::new(0);)*
        fn render_metrics(active: u64, backends: &[(String, Arc<Stats>)]) -> String {
            let mut s = String::new();
            $(s += &format!("seki_{} {}\n", stringify!($name).to_ascii_lowercase(), $name.load(Relaxed));)*
            s += &format!("seki_flows_active {active}\n");
            for (n, st) in backends {
                for (m, v) in [("packets_in", &st.packets_in), ("bytes_in", &st.bytes_in), ("packets_out", &st.packets_out), ("bytes_out", &st.bytes_out), ("migrations", &st.migrations), ("flows_active", &st.active)] {
                    s += &format!("seki_backend_{m}{{backend=\"{n}\"}} {}\n", v.load(Relaxed));
                }
            }
            s
        }
    };
}
metrics!(PACKETS_IN, BYTES_IN, PACKETS_OUT, BYTES_OUT, FLOWS_SNI, FLOWS_CID, FLOWS_FALLBACK, MIGRATIONS, SEND_ERRORS);
static ACTIVE: AtomicU64 = AtomicU64::new(0);

/// Per-backend counters; in = client→backend, out = backend→client.
#[derive(Default)]
struct Stats {
    packets_in: AtomicU64,
    bytes_in: AtomicU64,
    packets_out: AtomicU64,
    bytes_out: AtomicU64,
    migrations: AtomicU64,
    active: AtomicU64,
}

impl Stats {
    fn add_in(&self, n: usize) {
        self.packets_in.fetch_add(1, Relaxed);
        self.bytes_in.fetch_add(n as u64, Relaxed);
    }
}

struct Backend {
    name: String,
    addr: SocketAddr,
    routable: bool,
    stats: Arc<Stats>,
}

struct Flow {
    up: Arc<UdpSocket>,
    stats: Arc<Stats>,
    last: Arc<AtomicU64>,
    dead: Arc<AtomicBool>,
}

struct Pending {
    crypto: CryptoBuf,
    pkts: Vec<Vec<u8>>,
    since: Instant,
}

enum Reason {
    Sni(Option<String>),
    Cid(u64),
    Fallback,
}

struct Router {
    public: Arc<UdpSocket>,
    backends: Vec<Backend>,
    sni_exact: HashMap<String, usize>,
    sni_wild: Vec<(String, usize)>,
    default: usize,
    cid: Option<seki_cid::Config>,
    by_sid: HashMap<u64, usize>,
    flow_timeout: u64,
    conn_timeout: u64,
    flows: HashMap<SocketAddr, Flow>,
    pending: HashMap<SocketAddr, Pending>,
}

const MAX_PENDING_PKTS: usize = 6;
const PENDING_TIMEOUT: Duration = Duration::from_millis(1500);
const MAX_PENDING_ADDRS: usize = 4096;

impl Router {
    fn route_sni(&self, sni: Option<&str>) -> usize {
        let Some(s) = sni else { return self.default };
        if let Some(&i) = self.sni_exact.get(s) {
            return i;
        }
        self.sni_wild.iter().find(|(suf, _)| s.ends_with(suf.as_str())).map_or(self.default, |&(_, i)| i)
    }

    fn route_cid(&self, dcid: &[u8]) -> Option<(usize, u64)> {
        let sid = self.cid.as_ref()?.decode_u64(dcid).ok()?;
        self.by_sid.get(&sid).map(|&i| (i, sid))
    }

    async fn handle(&mut self, src: SocketAddr, pkt: &[u8]) {
        if let Some(f) = self.flows.get(&src) {
            if !f.dead.load(Relaxed) {
                f.last.store(now(), Relaxed);
                f.stats.add_in(pkt.len());
                if f.up.send(pkt).await.is_err() {
                    SEND_ERRORS.fetch_add(1, Relaxed);
                }
                return;
            }
            self.flows.remove(&src);
        }
        if let Some(p) = self.pending.get_mut(&src) {
            p.pkts.push(pkt.to_vec());
            initial::collect_crypto(pkt, &mut p.crypto);
            return self.try_decide(src, false).await;
        }
        let first = pkt[0];
        if first & 0x80 != 0 {
            if pkt.len() < 7 {
                return self.open(src, self.default, Reason::Fallback, vec![pkt.to_vec()]).await;
            }
            let version = u32::from_be_bytes(pkt[1..5].try_into().unwrap());
            if initial::is_initial(first, version) {
                if self.pending.len() >= MAX_PENDING_ADDRS {
                    return self.open(src, self.default, Reason::Fallback, vec![pkt.to_vec()]).await;
                }
                let mut crypto = CryptoBuf::default();
                let ok = initial::collect_crypto(pkt, &mut crypto);
                self.pending.insert(src, Pending { crypto, pkts: vec![pkt.to_vec()], since: Instant::now() });
                return self.try_decide(src, !ok).await;
            }
            let dl = pkt[5] as usize;
            if let Some((i, sid)) = pkt.get(6..6 + dl).and_then(|d| self.route_cid(d)) {
                return self.open(src, i, Reason::Cid(sid), vec![pkt.to_vec()]).await;
            }
        } else if let Some((i, sid)) = self.route_cid(&pkt[1..]) {
            MIGRATIONS.fetch_add(1, Relaxed);
            self.backends[i].stats.migrations.fetch_add(1, Relaxed);
            return self.open(src, i, Reason::Cid(sid), vec![pkt.to_vec()]).await;
        }
        self.open(src, self.default, Reason::Fallback, vec![pkt.to_vec()]).await
    }

    /// Route a pending Initial flow once the SNI is known (or give up).
    async fn try_decide(&mut self, src: SocketAddr, give_up: bool) {
        let Some(p) = self.pending.get(&src) else { return };
        let sni = match p.crypto.sni() {
            Ok(s) => s,
            Err(()) if give_up || p.pkts.len() >= MAX_PENDING_PKTS || p.since.elapsed() > PENDING_TIMEOUT => None,
            Err(()) => return,
        };
        let p = self.pending.remove(&src).unwrap();
        let i = self.route_sni(sni.as_deref());
        self.open(src, i, Reason::Sni(sni), p.pkts).await;
    }

    async fn open(&mut self, src: SocketAddr, bi: usize, reason: Reason, pkts: Vec<Vec<u8>>) {
        let b = &self.backends[bi];
        let bind: SocketAddr = if b.addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
        let up = match UdpSocket::bind(bind).await {
            Ok(s) if s.connect(b.addr).await.is_ok() => Arc::new(s),
            r => {
                warn!(backend = %b.name, error = ?r.err(), "upstream socket failed");
                return;
            }
        };
        let client = src.ip().to_string();
        match &reason {
            Reason::Sni(s) => { FLOWS_SNI.fetch_add(1, Relaxed); info!(%client, port = src.port(), backend = %b.name, sni = s.as_deref().unwrap_or("-"), "new connection") }
            Reason::Cid(sid) => { FLOWS_CID.fetch_add(1, Relaxed); info!(%client, port = src.port(), backend = %b.name, server_id = sid, "migrated connection (routed by cid)") }
            Reason::Fallback => { FLOWS_FALLBACK.fetch_add(1, Relaxed); debug!(%client, port = src.port(), backend = %b.name, "fallback flow") }
        }
        let idle = if b.routable { self.conn_timeout } else { self.flow_timeout };
        let stats = b.stats.clone();
        let flow = Flow { up: up.clone(), stats: stats.clone(), last: Arc::new(AtomicU64::new(now())), dead: Arc::new(AtomicBool::new(false)) };
        for p in &pkts {
            stats.add_in(p.len());
            if up.send(p).await.is_err() {
                SEND_ERRORS.fetch_add(1, Relaxed);
            }
        }
        ACTIVE.fetch_add(1, Relaxed);
        stats.active.fetch_add(1, Relaxed);
        tokio::spawn(reply_loop(up, stats, self.public.clone(), src, flow.last.clone(), flow.dead.clone(), idle, b.name.clone()));
        self.flows.insert(src, flow);
    }

    async fn tick(&mut self) {
        self.flows.retain(|_, f| !f.dead.load(Relaxed));
        let expired: Vec<_> = self.pending.iter().filter(|(_, p)| p.since.elapsed() > PENDING_TIMEOUT).map(|(a, _)| *a).collect();
        for a in expired {
            self.try_decide(a, true).await;
        }
    }
}

async fn reply_loop(up: Arc<UdpSocket>, stats: Arc<Stats>, public: Arc<UdpSocket>, client: SocketAddr, last: Arc<AtomicU64>, dead: Arc<AtomicBool>, idle: u64, backend: String) {
    let mut buf = vec![0u8; 65535];
    loop {
        match tokio::time::timeout(Duration::from_secs(5), up.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                last.store(now(), Relaxed);
                PACKETS_OUT.fetch_add(1, Relaxed);
                BYTES_OUT.fetch_add(n as u64, Relaxed);
                stats.packets_out.fetch_add(1, Relaxed);
                stats.bytes_out.fetch_add(n as u64, Relaxed);
                if public.send_to(&buf[..n], client).await.is_err() {
                    SEND_ERRORS.fetch_add(1, Relaxed);
                }
            }
            Ok(Err(_)) => {} // ICMP unreachable etc.; keep going until idle
            Err(_) => {
                if now().saturating_sub(last.load(Relaxed)) >= idle {
                    break;
                }
            }
        }
    }
    dead.store(true, Relaxed);
    ACTIVE.fetch_sub(1, Relaxed);
    stats.active.fetch_sub(1, Relaxed);
    debug!(client = %client, %backend, "flow closed (idle)");
}

/// Set DF and never fragment locally (IP_PMTUDISC_PROBE), so QUIC PMTUD
/// probes forwarded to clients are passed or dropped intact.
#[cfg(target_os = "linux")]
fn set_pmtudisc_probe(s: &UdpSocket, v6: bool) {
    use std::os::fd::AsRawFd;
    let set = |level, opt, val: libc::c_int| unsafe {
        libc::setsockopt(s.as_raw_fd(), level, opt, &val as *const _ as *const libc::c_void, size_of::<libc::c_int>() as libc::socklen_t) == 0
    };
    // On a dual-stack v6 socket, IP_MTU_DISCOVER covers v4-mapped traffic.
    let v4 = set(libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, libc::IP_PMTUDISC_PROBE);
    let v6ok = !v6 || set(libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER, libc::IPV6_PMTUDISC_PROBE);
    if !(v6ok && (v4 || v6)) {
        warn!("setting PMTUDISC_PROBE failed: {}", std::io::Error::last_os_error());
    }
}

#[cfg(not(target_os = "linux"))]
fn set_pmtudisc_probe(_: &UdpSocket, _: bool) {}

async fn serve_metrics(addr: SocketAddr, backends: Arc<Vec<(String, Arc<Stats>)>>) -> Result<()> {
    let l = TcpListener::bind(addr).await.with_context(|| format!("metrics bind {addr}"))?;
    info!(%addr, "metrics listening");
    loop {
        let Ok((mut s, _)) = l.accept().await else { continue };
        let backends = backends.clone();
        tokio::spawn(async move {
            let mut b = [0u8; 1024];
            let _ = tokio::time::timeout(Duration::from_secs(2), s.read(&mut b)).await;
            let body = render_metrics(ACTIVE.load(Relaxed), &backends);
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let _ = s.write_all(resp.as_bytes()).await;
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args().nth(1).unwrap_or_else(|| "seki.yaml".into());
    if path == "-h" || path == "--help" {
        println!("usage: seki [config.yaml]");
        return Ok(());
    }
    let cfg = config::Config::load(&path)?;
    let filter = tracing_subscriber::EnvFilter::try_from_env("SEKI_LOG").unwrap_or_else(|_| "info".into());
    if cfg.log_json {
        tracing_subscriber::fmt().json().with_env_filter(filter).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    LazyLock::force(&START);

    let cid = cfg.cid_config()?;
    let idx = |n: &str| cfg.backends.iter().position(|b| b.name == n).unwrap();
    let mut by_sid = HashMap::new();
    for (i, b) in cfg.backends.iter().enumerate() {
        if let Some(s) = b.server_id
            && by_sid.insert(s, i).is_some()
        {
            anyhow::bail!("duplicate server_id {s}");
        }
    }
    let (mut sni_exact, mut sni_wild) = (HashMap::new(), Vec::new());
    for (k, v) in &cfg.sni {
        let k = k.to_ascii_lowercase();
        match k.strip_prefix('*') {
            Some(suf) => sni_wild.push((suf.to_string(), idx(v))),
            None => { sni_exact.insert(k, idx(v)); }
        }
    }
    sni_wild.sort_by_key(|(s, _)| std::cmp::Reverse(s.len()));

    let public = Arc::new(UdpSocket::bind(cfg.listen).await.with_context(|| format!("bind {}", cfg.listen))?);
    set_pmtudisc_probe(&public, cfg.listen.is_ipv6());
    info!(listen = %cfg.listen, backends = cfg.backends.len(), "seki started");
    let backends: Vec<Backend> = cfg.backends.iter().map(|b| Backend { name: b.name.clone(), addr: b.address, routable: b.server_id.is_some(), stats: Arc::default() }).collect();
    if let Some(m) = cfg.metrics {
        let stats = Arc::new(backends.iter().map(|b| (b.name.clone(), b.stats.clone())).collect());
        tokio::spawn(async move {
            if let Err(e) = serve_metrics(m, stats).await {
                warn!("metrics: {e:#}");
            }
        });
    }
    let mut r = Router {
        public: public.clone(),
        backends,
        sni_exact,
        sni_wild,
        default: idx(&cfg.default),
        cid,
        by_sid,
        flow_timeout: cfg.flow_timeout,
        conn_timeout: cfg.connection_timeout,
        flows: HashMap::new(),
        pending: HashMap::new(),
    };
    let mut buf = vec![0u8; 65535];
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            res = public.recv_from(&mut buf) => match res {
                Ok((n, src)) if n > 0 => {
                    PACKETS_IN.fetch_add(1, Relaxed);
                    BYTES_IN.fetch_add(n as u64, Relaxed);
                    r.handle(src, &buf[..n]).await;
                }
                Ok(_) => {}
                Err(e) => debug!("recv: {e}"),
            },
            _ = tick.tick() => r.tick().await,
            _ = tokio::signal::ctrl_c() => break,
            _ = term.recv() => break,
        }
    }
    info!("seki stopping");
    Ok(())
}

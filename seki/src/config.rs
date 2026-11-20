use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    #[serde(default = "default_metrics")]
    pub metrics: Option<SocketAddr>,
    pub cid: Option<CidConfig>,
    pub backends: Vec<Backend>,
    /// SNI (exact or "*.suffix") -> backend name.
    #[serde(default)]
    pub sni: HashMap<String, String>,
    /// Backend for unmatched SNI, unknown labels and non-QUIC traffic.
    pub default: String,
    /// Idle timeout (s) for plain IP+port flows.
    #[serde(default = "d60")]
    pub flow_timeout: u64,
    /// Idle timeout (s) for flows to routable-ID backends.
    #[serde(default = "d300")]
    pub connection_timeout: u64,
    #[serde(default)]
    pub log_json: bool,
    /// Kernel fast path (nftables DNAT + conntrack) for decided flows.
    pub fastpath: Option<FastpathConfig>,
    /// Initials whose DCID carries a valid seki-cid mark go to `backend`;
    /// unmarked ones fall through to SNI routing (e.g. a real HTTP/3 site).
    pub mark: Option<MarkConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarkConfig {
    pub key: Option<String>,
    pub key_file: Option<PathBuf>,
    pub backend: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FastpathConfig {
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Public IPv4 that clients send to; autodetected from the default route if unset.
    pub public_ip: Option<std::net::Ipv4Addr>,
    #[serde(default = "nft_bin")]
    pub nft: String,
}

fn yes() -> bool { true }
fn nft_bin() -> String { "nft".into() }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CidConfig {
    #[serde(default)]
    pub config_id: u8,
    pub server_id_len: usize,
    pub nonce_len: usize,
    pub key: Option<String>,
    pub key_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    pub name: String,
    pub address: SocketAddr,
    /// QUIC-LB server id; set for backends that issue routable CIDs.
    pub server_id: Option<u64>,
}

fn default_metrics() -> Option<SocketAddr> { Some("127.0.0.1:9443".parse().unwrap()) }
fn d60() -> u64 { 60 }
fn d300() -> u64 { 300 }

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let s = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
        let c: Config = serde_yaml_ng::from_str(&s).context("parsing config")?;
        let names: Vec<&str> = c.backends.iter().map(|b| b.name.as_str()).collect();
        if !names.contains(&c.default.as_str()) {
            bail!("default backend {:?} not defined", c.default);
        }
        for (k, v) in &c.sni {
            if !names.contains(&v.as_str()) {
                bail!("sni {k:?} -> unknown backend {v:?}");
            }
        }
        if let Some(m) = &c.mark
            && !names.contains(&m.backend.as_str())
        {
            bail!("mark -> unknown backend {:?}", m.backend);
        }
        if c.backends.iter().any(|b| b.server_id.is_some()) && c.cid.is_none() {
            bail!("backends have server_id but no cid section");
        }
        Ok(c)
    }

    pub fn mark_key(&self) -> Result<Option<seki_cid::mark::MarkKey>> {
        let Some(m) = &self.mark else { return Ok(None) };
        let key = read_key("mark", &m.key, &m.key_file)?;
        if let Some(c) = &self.cid
            && read_key("cid", &c.key, &c.key_file)? == key
        {
            bail!("mark key must differ from the cid key");
        }
        Ok(Some(seki_cid::mark::MarkKey::new(&key)))
    }

    pub fn cid_config(&self) -> Result<Option<seki_cid::Config>> {
        let Some(c) = &self.cid else { return Ok(None) };
        let key = read_key("cid", &c.key, &c.key_file)?;
        Ok(Some(seki_cid::Config::new(c.config_id, c.server_id_len, c.nonce_len, &key).map_err(|e| anyhow::anyhow!("cid: {e}"))?))
    }
}

fn read_key(what: &str, key: &Option<String>, file: &Option<PathBuf>) -> Result<[u8; 16]> {
    let hex = match (key, file) {
        (Some(k), None) => k.clone(),
        (None, Some(f)) => std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?,
        _ => bail!("{what}: set exactly one of key / key_file"),
    };
    seki_cid::parse_key_hex(&hex).map_err(|e| anyhow::anyhow!("{what} key: {e} (need 32 hex chars)"))
}

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
}

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
        if c.backends.iter().any(|b| b.server_id.is_some()) && c.cid.is_none() {
            bail!("backends have server_id but no cid section");
        }
        Ok(c)
    }

    pub fn cid_config(&self) -> Result<Option<seki_cid::Config>> {
        let Some(c) = &self.cid else { return Ok(None) };
        let hex = match (&c.key, &c.key_file) {
            (Some(k), None) => k.clone(),
            (None, Some(f)) => std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?,
            _ => bail!("cid: set exactly one of key / key_file"),
        };
        let key = seki_cid::parse_key_hex(&hex).map_err(|e| anyhow::anyhow!("cid key: {e} (need 32 hex chars)"))?;
        Ok(Some(seki_cid::Config::new(c.config_id, c.server_id_len, c.nonce_len, &key).map_err(|e| anyhow::anyhow!("cid: {e}"))?))
    }
}

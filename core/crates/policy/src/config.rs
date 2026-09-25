//! `config.json`, written by the app and read by the tunnel.

use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

use crate::PolicyError;

/// A DNS-over-HTTPS server reached by IP address, with the TLS name set explicitly so the
/// resolver never needs DNS to find its upstream.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DohUpstream {
    pub ip: IpAddr,
    #[serde(default = "default_port")]
    pub port: u16,
    pub tls_name: String,
    #[serde(default = "default_path")]
    pub path: String,
}

fn default_port() -> u16 {
    443
}

fn default_path() -> String {
    "/dns-query".to_string()
}

impl DohUpstream {
    /// Cloudflare, `1.1.1.1` as `cloudflare-dns.com`.
    pub fn cloudflare() -> DohUpstream {
        DohUpstream {
            ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            port: 443,
            tls_name: "cloudflare-dns.com".to_string(),
            path: "/dns-query".to_string(),
        }
    }

    /// Quad9, `9.9.9.9` as `dns.quad9.net`.
    pub fn quad9() -> DohUpstream {
        DohUpstream {
            ip: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            port: 443,
            tls_name: "dns.quad9.net".to_string(),
            path: "/dns-query".to_string(),
        }
    }
}

/// Tunnel configuration. Missing fields take their defaults and unknown fields are
/// ignored, so an older tunnel can read a file written by a newer app.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Tried in order. Default: Cloudflare, then Quad9.
    pub doh_upstreams: Vec<DohUpstream>,
    /// User host patterns that are never intercepted, see [`crate::HostPattern`].
    pub passthrough: Vec<String>,
    /// User host patterns where nothing is blocked: DNS names matching one resolve normally,
    /// and a request is allowed when its own host or its page's host matches.
    pub allowlist: Vec<String>,
    /// When false every connection is passed through untouched. Default true.
    pub mitm_enabled: bool,
    /// Intercepted client connections allowed at once; above it new ones pass through.
    /// Default 32.
    pub max_intercepted_connections: u32,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            doh_upstreams: vec![DohUpstream::cloudflare(), DohUpstream::quad9()],
            passthrough: Vec::new(),
            allowlist: Vec::new(),
            mitm_enabled: true,
            max_intercepted_connections: 32,
        }
    }
}

impl Config {
    pub fn from_json(s: &str) -> Result<Config, PolicyError> {
        serde_json::from_str(s).map_err(|e| PolicyError::Config(e.to_string()))
    }

    /// Pretty-printed JSON; the app shows the file in its debug view.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("Config holds only strings, numbers and bools")
    }
}

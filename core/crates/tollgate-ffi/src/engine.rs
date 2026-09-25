//! The engine the tunnel runs: DNS answers on the packet path, and the proxy plus the DNS
//! forwarder on one runtime thread.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use tollgate_common::clock;
use tollgate_common::stats::{Stats as Counters, StatsSnapshot};
use tollgate_dns::{DnsHandler, DohError, Outcome};
use tollgate_filter::{DOMAINS_FILE, DomainSet, ENGINE_FILE, FilterEngine, FilterError};
use tollgate_mitm::{CertAuthority, ProxyContext};
use tollgate_policy::{Config, Policy};

use crate::ca::load_ca;
use crate::error::{TollgateError, catch_panic};

/// Learned certificate pins, read by `Engine::new`.
pub const LEARNED_PINS_FILE: &str = "learned-pins.json";

/// Counters since the engine was created. Mirrors `tollgate_common::stats::StatsSnapshot`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct Stats {
    pub dns_queries: u64,
    pub dns_blocked: u64,
    pub dns_cache_hits: u64,
    pub dns_forwarded: u64,
    pub dns_failed: u64,
    pub packets_dropped: u64,
    pub http_requests: u64,
    pub http_blocked: u64,
    pub connections_intercepted: u64,
    pub connections_passthrough: u64,
    pub tls_client_rejections: u64,
    pub tls_abandoned_after_handshake: u64,
}

impl From<StatsSnapshot> for Stats {
    fn from(s: StatsSnapshot) -> Stats {
        Stats {
            dns_queries: s.dns_queries,
            dns_blocked: s.dns_blocked,
            dns_cache_hits: s.dns_cache_hits,
            dns_forwarded: s.dns_forwarded,
            dns_failed: s.dns_failed,
            packets_dropped: s.packets_dropped,
            http_requests: s.http_requests,
            http_blocked: s.http_blocked,
            connections_intercepted: s.connections_intercepted,
            connections_passthrough: s.connections_passthrough,
            tls_client_rejections: s.tls_client_rejections,
            tls_abandoned_after_handshake: s.tls_abandoned_after_handshake,
        }
    }
}

/// The tunnel's Rust side: DNS answers, the DNS forwarder and the HTTPS proxy.
#[derive(uniffi::Object)]
pub struct Engine {
    data_dir: PathBuf,
    mitm_active: bool,
    stats: Arc<Counters>,
    dns: Arc<DnsHandler>,
    proxy: Arc<ProxyContext>,
}

#[uniffi::export]
impl Engine {
    /// Parses `config_json` and loads what `data_dir` holds: `engine.dat`, `domains.bin`,
    /// `ca.pem` with `ca.key`, and `learned-pins.json`. Each file is optional; a file that
    /// cannot be loaded is logged and skipped. HTTPS interception needs both the CA and
    /// `engine.dat`; without them every connection is passed through.
    #[uniffi::constructor]
    pub fn new(config_json: String, data_dir: String) -> Result<Arc<Engine>, TollgateError> {
        catch_panic(|| Engine::open(&config_json, Path::new(&data_dir)))
    }

    /// Handles raw IP packets from the tunnel without waiting on the network. Returns the
    /// replies it can give at once: blocked names, HTTPS and SVCB queries, cache hits and
    /// errors. Until the engine has a runtime, queries that need the upstream get SERVFAIL.
    pub fn handle_packets(&self, packets: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, TollgateError> {
        catch_panic(|| Ok(self.answer(&packets)))
    }

    /// Loads `engine.dat` and `domains.bin` again and swaps both in. A missing file clears
    /// that list; a file that fails to load is an error and nothing is swapped.
    pub fn reload_lists(&self) -> Result<(), TollgateError> {
        catch_panic(|| {
            let filter = load_filter(&self.data_dir)?;
            let domains = load_domains(&self.data_dir)?;
            log::info!(
                "reloaded lists: engine {}, DNS blocklist {} hashes",
                if filter.is_some() {
                    "loaded"
                } else {
                    "missing"
                },
                domains.as_ref().map_or(0, |set| set.len())
            );
            self.proxy.filter.store(filter);
            self.dns.set_blocklist(domains);
            Ok(())
        })
    }

    pub fn stats(&self) -> Stats {
        catch_panic(|| Ok(self.stats.snapshot().into())).unwrap_or_default()
    }

    /// The learned pins as JSON, the format of `learned-pins.json`.
    pub fn learned_pins_json(&self) -> String {
        catch_panic(|| Ok(self.proxy.policy.learned_pins_json())).unwrap_or_default()
    }

    /// Whether HTTPS connections can be intercepted: `mitm_enabled` in the config, a CA and
    /// `engine.dat` were all present when the engine was created.
    pub fn mitm_active(&self) -> bool {
        self.mitm_active
    }
}

impl Engine {
    fn open(config_json: &str, data_dir: &Path) -> Result<Arc<Engine>, TollgateError> {
        let config = Config::from_json(config_json).map_err(|e| TollgateError::Config {
            message: e.to_string(),
        })?;
        let filter = load_filter(data_dir).unwrap_or_else(|e| {
            log::warn!("running without the URL filter: {e}");
            None
        });
        let domains = load_domains(data_dir).unwrap_or_else(|e| {
            log::warn!("running without the DNS blocklist: {e}");
            None
        });
        let ca = load_ca(data_dir).unwrap_or_else(|e| {
            log::warn!("running without the CA: {e}");
            None
        });
        let mitm_active = config.mitm_enabled && ca.is_some() && filter.is_some();
        if config.mitm_enabled && !mitm_active {
            log::warn!(
                "HTTPS interception is off: {}",
                if ca.is_none() {
                    "no CA"
                } else {
                    "no engine.dat"
                }
            );
        }
        let policy_config = Config {
            mitm_enabled: mitm_active,
            ..config.clone()
        };
        let pins = read_pins(data_dir);
        let policy =
            Policy::new(&policy_config, pins.as_deref()).map_err(|e| TollgateError::Config {
                message: e.to_string(),
            })?;
        // The proxy needs a CA even when it only passes connections through; this one is
        // never used to issue a leaf because the policy intercepts nothing.
        let ca = match ca {
            Some(ca) => ca,
            None => CertAuthority::generate("Tollgate unused").map_err(|e| TollgateError::Ca {
                message: e.to_string(),
            })?,
        };
        let stats = Arc::new(Counters::default());
        let proxy = Arc::new(ProxyContext {
            policy: Arc::new(policy),
            filter: ArcSwapOption::new(filter),
            ca: Arc::new(ca),
            stats: stats.clone(),
            max_intercepted: config.max_intercepted_connections as usize,
            available_memory,
        });
        let dns = Arc::new(DnsHandler::new(domains, stats.clone()));
        Ok(Arc::new(Engine {
            data_dir: data_dir.to_path_buf(),
            mitm_active,
            stats,
            dns,
            proxy,
        }))
    }

    fn answer(&self, packets: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let now = clock::now_secs();
        let mut replies = Vec::new();
        for packet in packets {
            match self.dns.handle_packet(packet, now) {
                Outcome::Reply(reply) => replies.push(reply),
                Outcome::Drop => {}
                Outcome::Forward(job) => {
                    replies.push(self.dns.complete(job, Err(DohError::Stopped), now));
                }
            }
        }
        replies
    }
}

fn load_filter(dir: &Path) -> Result<Option<Arc<FilterEngine>>, TollgateError> {
    match FilterEngine::load(&dir.join(ENGINE_FILE)) {
        Ok(engine) => Ok(Some(Arc::new(engine))),
        Err(FilterError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TollgateError::Lists {
            message: e.to_string(),
        }),
    }
}

fn load_domains(dir: &Path) -> Result<Option<Arc<DomainSet>>, TollgateError> {
    match DomainSet::load(&dir.join(DOMAINS_FILE)) {
        Ok(set) => Ok(Some(Arc::new(set))),
        Err(FilterError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TollgateError::Lists {
            message: e.to_string(),
        }),
    }
}

fn read_pins(dir: &Path) -> Option<String> {
    let path = dir.join(LEARNED_PINS_FILE);
    match std::fs::read_to_string(&path) {
        Ok(json) => Some(json),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => {
            log::warn!("ignoring {}: {e}", path.display());
            None
        }
    }
}

/// Bytes the extension may still allocate before jetsam ends it. `None` outside iOS, and
/// when iOS reports 0, which it does for processes without a limit.
#[cfg(target_os = "ios")]
fn available_memory() -> Option<u64> {
    unsafe extern "C" {
        fn os_proc_available_memory() -> usize;
    }
    // SAFETY: os_proc_available_memory takes no arguments and has no preconditions; it is
    // part of libSystem since iOS 13.
    let bytes = unsafe { os_proc_available_memory() };
    (bytes > 0).then_some(bytes as u64)
}

#[cfg(not(target_os = "ios"))]
fn available_memory() -> Option<u64> {
    None
}

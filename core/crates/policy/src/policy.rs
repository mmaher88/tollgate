//! The interception decision and certificate pin learning.
//!
//! Every `now` argument is wall-clock Unix seconds (`tollgate_common::clock::unix_secs`),
//! because learned pins are saved and must survive a reboot.

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};

use crate::{Config, HostPattern, PolicyError, bundled_passthrough};

/// Two client rejections of the same host at most this many seconds apart make it a pin.
pub const REJECTION_WINDOW_SECS: u64 = 10 * 60;
/// A learned pin is kept for this long after it was learned.
pub const PIN_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;
/// Hosts with a single recent rejection that are remembered at once.
const MAX_RECENT_REJECTIONS: usize = 1024;
const PINS_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Intercept,
    Passthrough(PassthroughReason),
}

/// Why a connection is not intercepted. `NotTls`, `Capacity` and `LowMemory` are decided by
/// the proxy, never by [`Policy::classify`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassthroughReason {
    MitmDisabled,
    User,
    Bundled,
    LearnedPin,
    NotTls,
    Capacity,
    LowMemory,
}

/// The TLS alerts a client sends when it rejects our certificate. Each kind counts the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectionKind {
    UnknownCa,
    BadCertificate,
    CertificateUnknown,
    DecryptError,
}

/// Exact names and `*.` suffixes, matched with hash lookups on the host and its parents.
#[derive(Default)]
struct PatternSet {
    exact: HashSet<String>,
    suffix: HashSet<String>,
}

impl PatternSet {
    fn new<'a>(patterns: impl IntoIterator<Item = &'a HostPattern>) -> PatternSet {
        let mut set = PatternSet::default();
        for p in patterns {
            let target = if p.is_wildcard() {
                &mut set.suffix
            } else {
                &mut set.exact
            };
            target.insert(p.name().to_string());
        }
        set
    }

    /// `key` is a lookup key from [`lookup_key`].
    fn matches(&self, key: &str) -> bool {
        if self.exact.contains(key) {
            return true;
        }
        if self.suffix.is_empty() {
            return false;
        }
        let parents = key.match_indices('.').map(|(i, _)| &key[i + 1..]);
        std::iter::once(key)
            .chain(parents)
            .any(|s| self.suffix.contains(s))
    }
}

static BUNDLED_SET: LazyLock<PatternSet> = LazyLock::new(|| {
    let patterns: Vec<HostPattern> = bundled_passthrough()
        .iter()
        .map(|p| HostPattern::parse(p).expect("bundled patterns are valid"))
        .collect();
    PatternSet::new(&patterns)
});

/// Lowercase, one trailing dot removed, IPv6 brackets removed.
fn lookup_key(host: &str) -> String {
    let host = host.strip_suffix('.').unwrap_or(host);
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    host.to_ascii_lowercase()
}

fn pin_is_live(learned_at: u64, now: u64) -> bool {
    now.saturating_sub(learned_at) < PIN_LIFETIME_SECS
}

#[derive(Default)]
struct Learning {
    /// Host to the time it became a pin.
    pins: HashMap<String, u64>,
    /// Host to the time of its last rejection that did not make it a pin.
    recent: HashMap<String, u64>,
}

#[derive(Serialize, Deserialize)]
struct PinsFile {
    version: u32,
    pins: Vec<PinEntry>,
}

#[derive(Serialize, Deserialize)]
struct PinEntry {
    host: String,
    learned_at: u64,
}

/// Decides per host whether the proxy intercepts. `Send + Sync`; learning state sits behind
/// a mutex.
pub struct Policy {
    mitm_enabled: bool,
    user: PatternSet,
    allowlist: PatternSet,
    learning: Mutex<Learning>,
}

impl Policy {
    /// Fails if a user passthrough or allowlist pattern is invalid. A learned pins file that cannot be
    /// read is logged and ignored: it is a cache that rebuilds itself.
    pub fn new(config: &Config, learned_pins_json: Option<&str>) -> Result<Policy, PolicyError> {
        let user = parse_patterns(&config.passthrough)?;
        let allowlist = parse_patterns(&config.allowlist)?;
        let pins = learned_pins_json.map(parse_pins).unwrap_or_default();
        Ok(Policy {
            mitm_enabled: config.mitm_enabled,
            user: PatternSet::new(&user),
            allowlist: PatternSet::new(&allowlist),
            learning: Mutex::new(Learning {
                pins,
                recent: HashMap::new(),
            }),
        })
    }

    /// Order: MITM disabled, user passthrough, bundled passthrough, learned pins, intercept.
    pub fn classify(&self, host: &str, now: u64) -> Decision {
        if !self.mitm_enabled {
            return Decision::Passthrough(PassthroughReason::MitmDisabled);
        }
        let key = lookup_key(host);
        if self.user.matches(&key) {
            return Decision::Passthrough(PassthroughReason::User);
        }
        if BUNDLED_SET.matches(&key) {
            return Decision::Passthrough(PassthroughReason::Bundled);
        }
        let learned = self.lock().pins.get(&key).copied();
        if learned.is_some_and(|at| pin_is_live(at, now)) {
            return Decision::Passthrough(PassthroughReason::LearnedPin);
        }
        Decision::Intercept
    }

    /// Returns true when this rejection made the host a learned pin.
    pub fn record_client_rejection(&self, host: &str, kind: RejectionKind, now: u64) -> bool {
        let key = lookup_key(host);
        if key.is_empty() {
            return false;
        }
        let mut learning = self.lock();
        learning.pins.retain(|_, at| pin_is_live(*at, now));
        if learning.pins.contains_key(&key) {
            return false;
        }
        match learning.recent.get(&key) {
            Some(&previous) if now.saturating_sub(previous) <= REJECTION_WINDOW_SECS => {
                learning.recent.remove(&key);
                log::info!("learned certificate pin for {key} after {kind:?}");
                learning.pins.insert(key, now);
                true
            }
            _ => {
                log::debug!("client rejected our certificate for {key}: {kind:?}");
                if learning.recent.len() >= MAX_RECENT_REJECTIONS {
                    learning
                        .recent
                        .retain(|_, at| now.saturating_sub(*at) <= REJECTION_WINDOW_SECS);
                }
                if learning.recent.len() >= MAX_RECENT_REJECTIONS {
                    let oldest = learning
                        .recent
                        .iter()
                        .min_by_key(|(_, at)| **at)
                        .map(|(host, _)| host.clone());
                    if let Some(oldest) = oldest {
                        learning.recent.remove(&oldest);
                    }
                }
                learning.recent.insert(key, now);
                false
            }
        }
    }

    /// Makes `host` a learned pin at once because the proxy could not verify the upstream
    /// server's certificate (for example a missing intermediate, or a root that only the
    /// system trusts). Such a failure repeats on every connection, and the client, which
    /// can fetch intermediates and trusts the system roots, is the better judge once the
    /// connection is passed through. Returns true when the host became a pin; false when it
    /// already was one or `host` is empty. The pin expires like any other.
    pub fn learn_upstream_untrusted(&self, host: &str, now: u64) -> bool {
        let key = lookup_key(host);
        if key.is_empty() {
            return false;
        }
        let mut learning = self.lock();
        learning.pins.retain(|_, at| pin_is_live(*at, now));
        if learning.pins.contains_key(&key) {
            return false;
        }
        learning.recent.remove(&key);
        learning.pins.insert(key, now);
        true
    }

    /// True when `host` matches a user allowlist pattern, so nothing for it is blocked.
    pub fn is_allowlisted(&self, host: &str) -> bool {
        let key = lookup_key(host);
        !key.is_empty() && self.allowlist.matches(&key)
    }

    /// Forgets learned pins, and pending single rejections, for these hosts. Hosts are
    /// compared ignoring ASCII case and one trailing dot. Returns how many pins were removed.
    pub fn forget_pins(&self, hosts: &[String]) -> usize {
        let mut learning = self.lock();
        let mut removed = 0;
        for host in hosts {
            let key = lookup_key(host);
            if learning.pins.remove(&key).is_some() {
                log::info!("forgot learned certificate pin for {key}");
                removed += 1;
            }
            learning.recent.remove(&key);
        }
        removed
    }

    /// Every learned pin as (host, learned_at unix seconds), sorted by host. These are the
    /// pins [`Policy::learned_pins_json`] saves.
    pub fn learned_pins(&self) -> Vec<(String, u64)> {
        let mut pins: Vec<(String, u64)> = self
            .lock()
            .pins
            .iter()
            .map(|(host, at)| (host.clone(), *at))
            .collect();
        pins.sort();
        pins
    }

    /// `{"version":1,"pins":[{"host":"...","learned_at":...}]}`, sorted by host.
    pub fn learned_pins_json(&self) -> String {
        let pins = self
            .learned_pins()
            .into_iter()
            .map(|(host, learned_at)| PinEntry { host, learned_at })
            .collect();
        let file = PinsFile {
            version: PINS_FORMAT_VERSION,
            pins,
        };
        serde_json::to_string(&file).expect("pins hold only strings and numbers")
    }

    fn lock(&self) -> MutexGuard<'_, Learning> {
        self.learning.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn parse_patterns(patterns: &[String]) -> Result<Vec<HostPattern>, PolicyError> {
    patterns.iter().map(|p| HostPattern::parse(p)).collect()
}

fn parse_pins(json: &str) -> HashMap<String, u64> {
    match serde_json::from_str::<PinsFile>(json) {
        Ok(file) if file.version == PINS_FORMAT_VERSION => file
            .pins
            .into_iter()
            .map(|p| (lookup_key(&p.host), p.learned_at))
            .filter(|(host, _)| !host.is_empty())
            .collect(),
        Ok(file) => {
            log::warn!("ignoring learned pins with format version {}", file.version);
            HashMap::new()
        }
        Err(e) => {
            log::warn!("ignoring unreadable learned pins: {e}");
            HashMap::new()
        }
    }
}

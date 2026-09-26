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
/// Upstream TLS failures on this many different hosts within [`UPSTREAM_BURST_SECS`] come
/// from the network, not the servers: a captive portal, or a filter that intercepts HTTPS.
pub const UPSTREAM_BURST_HOSTS: usize = 3;
/// See [`UPSTREAM_BURST_HOSTS`].
pub const UPSTREAM_BURST_SECS: u64 = 60;
/// After a burst, upstream failures teach nothing for this long.
pub const UPSTREAM_SUPPRESS_SECS: u64 = 10 * 60;
/// Pins learned from upstream failures this recently are dropped on a network change.
pub const UPSTREAM_RECENT_SECS: u64 = 5 * 60;

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

/// A time recorded up to this far in the future still counts; one further ahead was taken
/// while the wall clock was wrong and is treated as expired, so a pin learned then does not
/// outlive its lifetime by the clock error.
const CLOCK_TOLERANCE_SECS: u64 = 60 * 60;

/// Whether `at` lies at most `max_age` seconds before `now` (and not far after it).
fn within(at: u64, now: u64, max_age: u64) -> bool {
    at <= now.saturating_add(CLOCK_TOLERANCE_SECS) && now.saturating_sub(at) <= max_age
}

fn pin_is_live(learned_at: u64, now: u64) -> bool {
    within(learned_at, now, PIN_LIFETIME_SECS - 1)
}

#[derive(Default)]
struct Learning {
    /// Host to the time it became a pin.
    pins: HashMap<String, u64>,
    /// Host to the time of its last rejection that did not make it a pin.
    recent: HashMap<String, u64>,
    /// Pins learned from upstream failures in the last [`UPSTREAM_RECENT_SECS`] of this
    /// session, oldest first, with the time each was learned, so a burst or a network
    /// change can take them back. Not saved: only fresh pins are taken back.
    upstream: Vec<(String, u64)>,
    /// Upstream failures teach nothing before this time (after a burst).
    upstream_suppressed_until: Option<u64>,
}

impl Learning {
    /// Removes `host`'s pin if it is the one learned from an upstream failure at `at`.
    fn take_back(&mut self, host: &str, at: u64) -> bool {
        if self.pins.get(host) == Some(&at) {
            self.pins.remove(host);
            return true;
        }
        false
    }

    /// Whether upstream failures are ignored at `now`. A suppression that lies further
    /// ahead than it can (the wall clock went back) is dropped.
    fn upstream_suppressed(&mut self, now: u64) -> bool {
        match self.upstream_suppressed_until {
            Some(until) if now < until && until - now <= UPSTREAM_SUPPRESS_SECS => true,
            _ => {
                self.upstream_suppressed_until = None;
                false
            }
        }
    }
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
                ..Learning::default()
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
            Some(&previous) if within(previous, now, REJECTION_WINDOW_SECS) => {
                learning.recent.remove(&key);
                learning.upstream.retain(|(host, _)| *host != key);
                log::info!("learned certificate pin for {key} after {kind:?}");
                learning.pins.insert(key, now);
                true
            }
            _ => {
                log::debug!("client rejected our certificate for {key}: {kind:?}");
                if learning.recent.len() >= MAX_RECENT_REJECTIONS {
                    learning
                        .recent
                        .retain(|_, at| within(*at, now, REJECTION_WINDOW_SECS));
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

    /// Makes `host` a learned pin at once because the proxy's TLS client cannot talk to the
    /// upstream server: its certificate could not be verified (for example a missing
    /// intermediate, or a root that only the system trusts), it shares no protocol version
    /// or cipher suite with the proxy, or it requires a client certificate. Such a failure
    /// repeats on every connection, and the client, which can fetch intermediates, trusts
    /// the system roots and may hold the certificate, is the better judge once the
    /// connection is passed through. The pin expires like any other.
    ///
    /// When the network rather than the server presents the certificate (a captive portal
    /// before login, a filter that intercepts HTTPS), every host fails. So the host that
    /// would make [`UPSTREAM_BURST_HOSTS`] different hosts learned this way within
    /// [`UPSTREAM_BURST_SECS`] is not learned, the others from that window are taken back
    /// (pins from client rejections are kept), and upstream failures teach nothing for
    /// [`UPSTREAM_SUPPRESS_SECS`].
    ///
    /// Returns true when the host became a pin; false when it already was one, `host` is
    /// empty, or the failure was part of a burst.
    pub fn learn_upstream_untrusted(&self, host: &str, now: u64) -> bool {
        let key = lookup_key(host);
        if key.is_empty() {
            return false;
        }
        let mut learning = self.lock();
        learning.pins.retain(|_, at| pin_is_live(*at, now));
        if learning.pins.contains_key(&key) || learning.upstream_suppressed(now) {
            return false;
        }
        learning
            .upstream
            .retain(|(_, at)| within(*at, now, UPSTREAM_RECENT_SECS));
        let burst: Vec<(String, u64)> = learning
            .upstream
            .iter()
            .filter(|(_, at)| within(*at, now, UPSTREAM_BURST_SECS))
            .cloned()
            .collect();
        let hosts: HashSet<&str> = burst.iter().map(|(host, _)| host.as_str()).collect();
        if hosts.len() + 1 >= UPSTREAM_BURST_HOSTS {
            let mut taken_back = 0;
            for (host, at) in &burst {
                if learning.take_back(host, *at) {
                    taken_back += 1;
                }
            }
            learning
                .upstream
                .retain(|(_, at)| !within(*at, now, UPSTREAM_BURST_SECS));
            learning.upstream_suppressed_until = Some(now + UPSTREAM_SUPPRESS_SECS);
            log::info!(
                "upstream TLS failed for {UPSTREAM_BURST_HOSTS} hosts within \
                 {UPSTREAM_BURST_SECS} s, so the network probably intercepts HTTPS: took back \
                 {taken_back} learned pins, learning nothing from upstream failures for \
                 {} minutes",
                UPSTREAM_SUPPRESS_SECS / 60
            );
            return false;
        }
        learning.recent.remove(&key);
        learning.pins.insert(key.clone(), now);
        learning.upstream.push((key, now));
        true
    }

    /// Drops the pins learned from upstream failures in the last [`UPSTREAM_RECENT_SECS`]:
    /// a captive portal or filtering network may have caused them without a burst. Call it
    /// when the device wakes or the network path changes (after a portal login, or on
    /// leaving the network). A host that really needs it is learned again on its next
    /// failure. Pins from client rejections are kept.
    pub fn on_network_change(&self, now: u64) {
        let mut learning = self.lock();
        let upstream = std::mem::take(&mut learning.upstream);
        let mut dropped = 0;
        for (host, at) in upstream {
            if within(at, now, UPSTREAM_RECENT_SECS) && learning.take_back(&host, at) {
                dropped += 1;
            }
        }
        if dropped > 0 {
            log::info!(
                "network changed: dropped {dropped} certificate pins learned from upstream \
                 failures in the last {} minutes",
                UPSTREAM_RECENT_SECS / 60
            );
        }
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
            learning.upstream.retain(|(host, _)| *host != key);
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

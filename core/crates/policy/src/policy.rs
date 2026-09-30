//! The interception decision and certificate pin learning.
//!
//! A host becomes a learned pin in three ways, each with its own rule: a client rejects our
//! certificate with a TLS alert ([`Policy::record_client_rejection`]), a client hangs up
//! without an alert after receiving our certificate ([`Policy::record_silent_refusal`]), or
//! the proxy itself cannot trust the upstream server ([`Policy::learn_upstream_untrusted`]).
//!
//! Every `now` argument is wall-clock Unix seconds (`tollgate_common::clock::unix_secs`),
//! because learned pins are saved and must survive a reboot.

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};

use crate::{Config, HostPattern, PolicyError, bundled_passthrough};

/// Two client rejections of the same host at most this many seconds apart make it a pin.
/// Silent refusals are counted over the same window (see [`SILENT_REFUSALS`]).
pub const REJECTION_WINDOW_SECS: u64 = 10 * 60;
/// A learned pin is kept for this long after it was learned.
pub const PIN_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;
/// Hosts with a single recent rejection that are remembered at once. Also the most hosts
/// remembered at once with pending silent refusals, with silent refusals counted for a
/// flood, with a recent successful handshake, and with a recent held-back log line.
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

/// Silent refusals of the same host in this many different seconds, all within
/// [`REJECTION_WINDOW_SECS`], make it a pin. Refusals within one second count once: a
/// client that loses a race or is suspended hangs up all its connections of that moment
/// together, while a pinning app keeps retrying and is refused again each time (the X app
/// for iOS hung up 13 times on one host within 5 seconds, Messenger 147 times within 45).
/// The window spans several uses of an app, as the alert rule's does: a pinning app may
/// reach a second host only once or twice each time it is used (the X app hung up on its
/// second pinned host in two seconds only, 4 seconds apart), so a window of a minute would
/// never learn that host, however often the app is opened.
///
/// A client's successful handshake with our certificate for the host keeps it from being
/// learned this way for the same [`REJECTION_WINDOW_SECS`]: that client trusts us, and its
/// hang-ups have other causes. A browser can keep using one connection for minutes without
/// a new handshake, so a shorter guard would let its rare hang-ups add up over the window.
/// Only a flood of refusals overrides this guard (see [`SILENT_FLOOD_SECS`]).
pub const SILENT_REFUSALS: usize = 3;
/// Silent refusals of a host in [`SILENT_FLOOD_SECONDS`] different seconds within the last
/// [`SILENT_FLOOD_SECS`], at least [`SILENT_FLOOD_RATIO`] times as many as the handshakes
/// clients completed with our certificate for it in the same time, are a flood: they make
/// the host a pin although a client trusted us for it within [`REJECTION_WINDOW_SECS`].
/// An app that pins a host other clients trust us for keeps retrying and is refused every
/// time: Messenger cancelled 286 connections to one host in 39 different seconds within a
/// minute, while the Facebook app and Messenger's own notification extension completed
/// handshakes for Meta hosts about once a minute, and the success guard kept the host from
/// being learned. A browser that trusts us hangs up only the connections of a moment (a
/// race lost, the device suspended) and completes more handshakes than it hangs up. The
/// window is short so that a flood is judged against the handshakes of the same minute,
/// not against older trust.
pub const SILENT_FLOOD_SECS: u64 = 60;
/// See [`SILENT_FLOOD_SECS`]. A browser's hang-ups of a moment fall within one or two
/// seconds (7 at most, within 2 seconds, in a device log), while Messenger reached 10
/// different seconds 19 seconds into its refusals.
pub const SILENT_FLOOD_SECONDS: usize = 10;
/// See [`SILENT_FLOOD_SECS`]. Refusals and handshakes are counted in connections. A
/// browser that mostly succeeds stays below 1, and the worst moment in the device log
/// stays below 4 even counted against the quieter host: 7 hang-ups on two hosts that
/// completed 18 and 2 handshakes. Messenger's 286 refusals met at most 2 handshakes for
/// Meta hosts within their minute, and 133 refusals by its tenth different second met 1.
pub const SILENT_FLOOD_RATIO: u32 = 5;
/// Silent refusals of a host that the success guard holds back (see [`SILENT_REFUSALS`])
/// are logged at info level, which the tunnel's log shows, once they fall in
/// [`SILENT_REFUSALS`] different seconds within [`SILENT_FLOOD_SECS`], naming the host and
/// the counts, so that the owner can find which host an app pins; at most once per host in
/// this interval.
pub const SILENT_HELD_BACK_LOG_SECS: u64 = 5 * 60;
/// Pins learned from silent refusals this recently are taken back when the device wakes or
/// the network path changes (see [`Policy::on_network_change`]), since clients hang up the
/// connections they were setting up then.
pub const SILENT_RECENT_SECS: u64 = 60;
/// Silent refusals on this many different hosts within [`SILENT_BURST_SECS`] have a common
/// cause rather than pinning apps: a network change, the device sleeping, a browser's
/// connections losing a race all at once, or the Tollgate certificate no longer being
/// trusted. A pinning app refuses on a few hosts (the X app on three within 10 seconds,
/// one of them after it had trusted our certificate for that host).
pub const SILENT_BURST_HOSTS: usize = 4;
/// See [`SILENT_BURST_HOSTS`].
pub const SILENT_BURST_SECS: u64 = 10;
/// After a burst of silent refusals, silent refusals teach nothing for this long; each
/// further burst starts it again.
pub const SILENT_SUPPRESS_SECS: u64 = 60;

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

/// Connections of one host counted per second over the last [`SILENT_FLOOD_SECS`]:
/// (second, count), one entry for each second with any.
#[derive(Default)]
struct PerSecond(Vec<(u64, u32)>);

impl PerSecond {
    /// Counts one connection at `now`, and forgets the seconds no longer within
    /// [`SILENT_FLOOD_SECS`] of it.
    fn add(&mut self, now: u64) {
        self.0.retain(|(at, _)| within(*at, now, SILENT_FLOOD_SECS));
        match self.0.iter_mut().find(|(at, _)| *at == now) {
            Some((_, count)) => *count = count.saturating_add(1),
            None => self.0.push((now, 1)),
        }
    }

    /// The connections, and the different seconds with any, within [`SILENT_FLOOD_SECS`]
    /// of `now`.
    fn count(&self, now: u64) -> (u32, usize) {
        self.0
            .iter()
            .filter(|(at, _)| within(*at, now, SILENT_FLOOD_SECS))
            .fold((0, 0), |(connections, seconds), (_, count)| {
                (connections.saturating_add(*count), seconds + 1)
            })
    }

    /// The last second counted.
    fn last(&self) -> u64 {
        self.0.iter().map(|(at, _)| *at).max().unwrap_or(0)
    }
}

/// The handshakes clients completed with our certificate for one host.
#[derive(Default)]
struct Trusted {
    /// The time of the last one, which guards the host from silent refusals for
    /// [`REJECTION_WINDOW_SECS`].
    last: u64,
    /// Those of the last [`SILENT_FLOOD_SECS`], which a flood of silent refusals must
    /// outnumber.
    recent: PerSecond,
}

/// A host's silent refusals and completed handshakes within the last [`SILENT_FLOOD_SECS`].
#[derive(Clone, Copy)]
struct FloodCounts {
    refusals: u32,
    /// The different seconds with refusals.
    seconds: usize,
    handshakes: u32,
}

impl FloodCounts {
    /// Whether the refusals are a flood (see [`SILENT_FLOOD_SECS`]).
    fn is_flood(self) -> bool {
        self.seconds >= SILENT_FLOOD_SECONDS
            && u64::from(self.refusals)
                >= u64::from(self.handshakes) * u64::from(SILENT_FLOOD_RATIO)
    }
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
    /// Host to the different seconds of its silent refusals in the last
    /// [`REJECTION_WINDOW_SECS`], while they have not made it a pin.
    silent_pending: HashMap<String, Vec<u64>>,
    /// Host to the time of its last silent refusal in the last [`SILENT_BURST_SECS`],
    /// whether it counted or not, to see a burst.
    silent_hosts: HashMap<String, u64>,
    /// Host to its silent refusals in the last [`SILENT_FLOOD_SECS`], whether the success
    /// guard held them back or not, while they have not made it a pin, to see a flood.
    silent_flood: HashMap<String, PerSecond>,
    /// Host to the handshakes clients completed with our certificate for it, kept for
    /// [`REJECTION_WINDOW_SECS`] after the last one.
    trusted: HashMap<String, Trusted>,
    /// Host to the time its held-back silent refusals were last logged, kept for
    /// [`SILENT_HELD_BACK_LOG_SECS`].
    held_back_logged: HashMap<String, u64>,
    /// Pins learned from silent refusals in the last [`SILENT_RECENT_SECS`] of this session,
    /// oldest first, with the time each was learned, so a burst or a network change can
    /// take them back. Not saved: only fresh pins are taken back.
    silent: Vec<(String, u64)>,
    /// Silent refusals teach nothing before this time (after a burst).
    silent_suppressed_until: Option<u64>,
}

impl Learning {
    /// Removes `host`'s pin if it is still the one learned at `at` (from an upstream failure
    /// or from silent refusals).
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

    /// Whether silent refusals are ignored at `now`, like [`Learning::upstream_suppressed`].
    fn silent_suppressed(&mut self, now: u64) -> bool {
        match self.silent_suppressed_until {
            Some(until) if now < until && until - now <= SILENT_SUPPRESS_SECS => true,
            _ => {
                self.silent_suppressed_until = None;
                false
            }
        }
    }

    /// Notes a silent refusal of `host` at `now` for burst detection. Returns how many
    /// different hosts were refused silently within [`SILENT_BURST_SECS`], this one included.
    fn note_silent_host(&mut self, host: &str, now: u64) -> usize {
        self.silent_hosts
            .retain(|_, at| within(*at, now, SILENT_BURST_SECS));
        if !self.silent_hosts.contains_key(host) {
            make_room(&mut self.silent_hosts, |_| true, |at| *at);
        }
        self.silent_hosts.insert(host.to_string(), now);
        self.silent_hosts.len()
    }

    /// Counts a silent refusal of `host` at `now` toward a flood. Returns the host's
    /// refusals, and the different seconds with any, within [`SILENT_FLOOD_SECS`], this
    /// one included.
    fn count_for_flood(&mut self, host: &str, now: u64) -> (u32, usize) {
        if !self.silent_flood.contains_key(host) {
            make_room(
                &mut self.silent_flood,
                |refusals| refusals.count(now).1 > 0,
                PerSecond::last,
            );
        }
        let refusals = self.silent_flood.entry(host.to_string()).or_default();
        refusals.add(now);
        refusals.count(now)
    }

    /// The handshakes clients completed with our certificate for `host` within
    /// [`SILENT_FLOOD_SECS`] of `now`.
    fn recent_handshakes(&self, host: &str, now: u64) -> u32 {
        self.trusted
            .get(host)
            .map_or(0, |trusted| trusted.recent.count(now).0)
    }

    /// Makes `host` a pin learned from silent refusals at `now`, which a burst or a network
    /// change can take back for [`SILENT_RECENT_SECS`], and forgets what was pending for it.
    fn learn_silent(&mut self, host: String, now: u64) {
        self.silent_pending.remove(&host);
        self.silent_flood.remove(&host);
        self.recent.remove(&host);
        self.upstream.retain(|(pending, _)| *pending != host);
        self.silent
            .retain(|(_, at)| within(*at, now, SILENT_RECENT_SECS));
        self.silent.push((host.clone(), now));
        self.pins.insert(host, now);
    }

    /// Logs at info level that the success guard held back the silent refusals of `host`,
    /// trusted at `trusted_at`: once they fall in [`SILENT_REFUSALS`] different seconds
    /// within [`SILENT_FLOOD_SECS`] (what would make a pin without the guard), and at most
    /// once in [`SILENT_HELD_BACK_LOG_SECS`], since a pinning app keeps being refused.
    fn log_held_back(&mut self, host: &str, counts: FloodCounts, trusted_at: u64, now: u64) {
        if counts.seconds < SILENT_REFUSALS {
            return;
        }
        let logged = self.held_back_logged.get(host).copied();
        if logged.is_some_and(|at| within(at, now, SILENT_HELD_BACK_LOG_SECS - 1)) {
            return;
        }
        if logged.is_none() {
            let fresh = |at: &u64| within(*at, now, SILENT_HELD_BACK_LOG_SECS - 1);
            make_room(&mut self.held_back_logged, fresh, |at| *at);
        }
        self.held_back_logged.insert(host.to_string(), now);
        log::info!(
            "not learning a certificate pin for {host} yet: {} silent refusals in {} different \
             seconds within {SILENT_FLOOD_SECS} s, but a client trusted our certificate for it \
             {} s ago, with {} handshakes within {SILENT_FLOOD_SECS} s (a flood of refusals in \
             {SILENT_FLOOD_SECONDS} different seconds, {SILENT_FLOOD_RATIO} times the \
             handshakes, would make it a pin)",
            counts.refusals,
            counts.seconds,
            now.saturating_sub(trusted_at),
            counts.handshakes
        );
    }

    /// A burst of silent refusals at `now` (see [`Policy::record_silent_refusal`]): forgets
    /// the pending silent refusals and those counted for a flood, takes back the pins
    /// learned from silent refusals within [`SILENT_BURST_SECS`], and ignores silent
    /// refusals for [`SILENT_SUPPRESS_SECS`].
    fn silent_burst(&mut self, now: u64) {
        let starting = !self.silent_suppressed(now);
        let mut taken_back = 0;
        for (host, at) in std::mem::take(&mut self.silent) {
            if !within(at, now, SILENT_BURST_SECS) {
                self.silent.push((host, at));
            } else if self.take_back(&host, at) {
                taken_back += 1;
            }
        }
        self.silent_pending.clear();
        self.silent_flood.clear();
        self.silent_suppressed_until = Some(now.saturating_add(SILENT_SUPPRESS_SECS));
        if starting || taken_back > 0 {
            log::info!(
                "silent refusals on {} hosts within {SILENT_BURST_SECS} s have a common \
                 cause: took back {taken_back} certificate pins learned from silent refusals, \
                 learning nothing from them for {SILENT_SUPPRESS_SECS} s",
                self.silent_hosts.len()
            );
        }
    }
}

/// Makes room for one more host in `map`, which holds at most [`MAX_RECENT_REJECTIONS`]
/// hosts: when it is full, keeps only the entries `fresh` accepts, then, if it is still
/// full, drops the entry whose time `last` gives is the earliest.
fn make_room<V>(
    map: &mut HashMap<String, V>,
    fresh: impl Fn(&V) -> bool,
    last: impl Fn(&V) -> u64,
) {
    if map.len() < MAX_RECENT_REJECTIONS {
        return;
    }
    map.retain(|_, value| fresh(value));
    if map.len() < MAX_RECENT_REJECTIONS {
        return;
    }
    let oldest = map
        .iter()
        .min_by_key(|(_, value)| last(value))
        .map(|(host, _)| host.clone());
    if let Some(oldest) = oldest {
        map.remove(&oldest);
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
                learning.silent_pending.remove(&key);
                learning.silent_flood.remove(&key);
                learning.upstream.retain(|(host, _)| *host != key);
                learning.silent.retain(|(host, _)| *host != key);
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
    /// (pins learned from clients are kept), and upstream failures teach nothing for
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
        learning.silent_pending.remove(&key);
        learning.silent_flood.remove(&key);
        learning.pins.insert(key.clone(), now);
        learning.upstream.push((key, now));
        true
    }

    /// Records that a client hung up during the TLS handshake for `host` after it was sent
    /// our certificate, without the alert [`Policy::record_client_rejection`] learns from:
    /// the connection ended, or the client sent close_notify. An app that pins certificates
    /// may do this when it cancels the connection inside its certificate check (the X app
    /// for iOS does), but so does any client that gives up on a connection it no longer
    /// needs: one that lost a race to another network, was suspended, or preconnected. So
    /// the rule is stricter than for alerts:
    ///
    /// - refusals in [`SILENT_REFUSALS`] different seconds within
    ///   [`REJECTION_WINDOW_SECS`] make the host a pin;
    /// - but none while a client has completed a handshake with our certificate for the
    ///   host in the last [`REJECTION_WINDOW_SECS`]
    ///   ([`Policy::record_intercepted_handshake`]): that client trusts us, as browsers do,
    ///   so the hang-ups have other causes;
    /// - unless the refusals flood the host: in [`SILENT_FLOOD_SECONDS`] different seconds
    ///   within the last [`SILENT_FLOOD_SECS`], and at least [`SILENT_FLOOD_RATIO`] times
    ///   the handshakes completed for it in that time, as a pinning app that shares its host
    ///   with clients that trust us refuses every retry. Refusals the guard holds back are
    ///   logged at info level with the host and the counts (see
    ///   [`SILENT_HELD_BACK_LOG_SECS`]);
    /// - and none from a burst: when refusals hit [`SILENT_BURST_HOSTS`] different hosts
    ///   within [`SILENT_BURST_SECS`], the pending refusals and those counted for a flood
    ///   are forgotten, the pins learned from silent refusals within that window are taken
    ///   back (other pins are kept), and silent refusals teach nothing for
    ///   [`SILENT_SUPPRESS_SECS`], counted again from every refusal while the burst lasts.
    ///   A flood on one host is not a burst.
    ///
    /// Pending refusals are not saved, and a wake or a network change forgets them (see
    /// [`Policy::on_network_change`]). Returns true when this refusal made the host a pin;
    /// false when it already was one, `host` is empty, or the refusal did not complete the
    /// rule.
    pub fn record_silent_refusal(&self, host: &str, now: u64) -> bool {
        let key = lookup_key(host);
        if key.is_empty() {
            return false;
        }
        let mut learning = self.lock();
        learning.pins.retain(|_, at| pin_is_live(*at, now));
        if learning.pins.contains_key(&key) {
            return false;
        }
        if learning.note_silent_host(&key, now) >= SILENT_BURST_HOSTS {
            learning.silent_burst(now);
            return false;
        }
        if learning.silent_suppressed(now) {
            return false;
        }
        let (refusals, seconds) = learning.count_for_flood(&key, now);
        let trusted = learning.trusted.get(&key).map(|trusted| trusted.last);
        if let Some(trusted_at) = trusted.filter(|at| within(*at, now, REJECTION_WINDOW_SECS)) {
            learning.silent_pending.remove(&key);
            let counts = FloodCounts {
                refusals,
                seconds,
                handshakes: learning.recent_handshakes(&key, now),
            };
            if !counts.is_flood() {
                log::debug!("{key} hung up during the handshake, but a client trusted us for it");
                learning.log_held_back(&key, counts, trusted_at, now);
                return false;
            }
            log::info!(
                "learned certificate pin for {key} after a flood of {refusals} silent refusals \
                 in {seconds} different seconds within {SILENT_FLOOD_SECS} s, against {} \
                 handshakes; a client trusted our certificate for it {} s ago",
                counts.handshakes,
                now.saturating_sub(trusted_at)
            );
            learning.learn_silent(key, now);
            return true;
        }
        if !learning.silent_pending.contains_key(&key) {
            let fresh = |seconds: &Vec<u64>| {
                seconds
                    .iter()
                    .any(|at| within(*at, now, REJECTION_WINDOW_SECS))
            };
            let last = |seconds: &Vec<u64>| seconds.iter().copied().max().unwrap_or(0);
            make_room(&mut learning.silent_pending, fresh, last);
        }
        let seconds = learning.silent_pending.entry(key.clone()).or_default();
        seconds.retain(|at| within(*at, now, REJECTION_WINDOW_SECS));
        if seconds.contains(&now) {
            return false;
        }
        seconds.push(now);
        if seconds.len() < SILENT_REFUSALS {
            log::debug!("{key} hung up during the handshake after our certificate");
            return false;
        }
        log::info!("learned certificate pin for {key} after {SILENT_REFUSALS} silent refusals");
        learning.learn_silent(key, now);
        true
    }

    /// Records that a client completed a TLS handshake with our certificate for `host`, so
    /// it trusts us: silent refusals of the host teach nothing for the next
    /// [`REJECTION_WINDOW_SECS`] unless they flood it, and those pending are forgotten (see
    /// [`Policy::record_silent_refusal`]). The handshake is also counted for
    /// [`SILENT_FLOOD_SECS`], against a flood; the refusals counted for a flood are kept.
    pub fn record_intercepted_handshake(&self, host: &str, now: u64) {
        let key = lookup_key(host);
        if key.is_empty() {
            return;
        }
        let mut learning = self.lock();
        learning.silent_pending.remove(&key);
        if !learning.trusted.contains_key(&key) {
            let fresh = |trusted: &Trusted| within(trusted.last, now, REJECTION_WINDOW_SECS);
            make_room(&mut learning.trusted, fresh, |trusted| trusted.last);
        }
        let trusted = learning.trusted.entry(key).or_default();
        trusted.last = now;
        trusted.recent.add(now);
    }

    /// Drops the pins learned from upstream failures in the last [`UPSTREAM_RECENT_SECS`]:
    /// a captive portal or filtering network may have caused them without a burst. Also
    /// drops the pins learned from silent refusals in the last [`SILENT_RECENT_SECS`], a
    /// flood's included, and forgets the pending silent refusals and those counted for a
    /// flood: while the network changes or the device goes to sleep, clients hang up the
    /// connections they were setting up. Call it when the device wakes or the network path
    /// changes (after a portal login, or on leaving the network). A host that really needs
    /// it is learned again on its next failures. Pins learned from alerts are kept.
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
        let silent = std::mem::take(&mut learning.silent);
        let mut dropped = 0;
        for (host, at) in silent {
            if within(at, now, SILENT_RECENT_SECS) && learning.take_back(&host, at) {
                dropped += 1;
            }
        }
        learning.silent_pending.clear();
        learning.silent_flood.clear();
        learning.silent_hosts.clear();
        if dropped > 0 {
            log::info!(
                "network changed: dropped {dropped} certificate pins learned from silent \
                 refusals in the last {SILENT_RECENT_SECS} s"
            );
        }
    }

    /// True when `host` matches a user allowlist pattern, so nothing for it is blocked.
    pub fn is_allowlisted(&self, host: &str) -> bool {
        let key = lookup_key(host);
        !key.is_empty() && self.allowlist.matches(&key)
    }

    /// Forgets learned pins, pending single rejections and pending silent refusals (those
    /// counted for a flood too) for these hosts. Hosts are compared ignoring ASCII case and
    /// one trailing dot. Returns how many pins were removed.
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
            learning.silent_pending.remove(&key);
            learning.silent_flood.remove(&key);
            learning.upstream.retain(|(host, _)| *host != key);
            learning.silent.retain(|(host, _)| *host != key);
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

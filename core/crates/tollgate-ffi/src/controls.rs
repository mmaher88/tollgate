//! M3 user controls: the blocked log, learned pin management and host pattern validation.
//! The engine methods live on [`crate::Engine`]; the free functions here work on the data
//! directory while the tunnel is off.

use std::io::ErrorKind;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use tollgate_common::events;
use tollgate_policy::{Config, HostPattern, Policy};

use crate::ca::write_private;
use crate::engine::LEARNED_PINS_FILE;
use crate::error::{TollgateError, catch_panic};

/// Serializes the read, change and rewrite of `learned-pins.json` in [`forget_stored_pins`],
/// so concurrent calls do not bring back each other's forgotten pins.
static STORED_PINS: Mutex<()> = Mutex::new(());

/// What was blocked. Mirrors `tollgate_common::events::EventKind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum EventKind {
    Dns,
    Request,
}

/// One entry of the blocked log. Mirrors `tollgate_common::events::BlockEvent`.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BlockEvent {
    /// Wall-clock time of the block, in seconds since the Unix epoch.
    pub unix_secs: u64,
    pub kind: EventKind,
    /// The queried name for DNS blocks, the request host for request blocks.
    pub host: String,
    /// The request URL, at most 512 bytes; `None` for DNS blocks.
    pub url: Option<String>,
    /// The host of the page that made the request, when known.
    pub source_host: Option<String>,
}

impl From<events::BlockEvent> for BlockEvent {
    fn from(e: events::BlockEvent) -> BlockEvent {
        BlockEvent {
            unix_secs: e.unix_secs,
            kind: match e.kind {
                events::EventKind::Dns => EventKind::Dns,
                events::EventKind::Request => EventKind::Request,
            },
            host: e.host,
            url: e.url,
            source_host: e.source_host,
        }
    }
}

/// A host whose clients reject our certificate, so its connections pass through.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct LearnedPin {
    pub host: String,
    /// When the pin was learned, in seconds since the Unix epoch.
    pub learned_at: u64,
}

pub(crate) fn learned_pins(policy: &Policy) -> Vec<LearnedPin> {
    policy
        .learned_pins()
        .into_iter()
        .map(|(host, learned_at)| LearnedPin { host, learned_at })
        .collect()
}

pub(crate) fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Checks a passthrough or allowlist entry with the core's own parser. The error is
/// `TollgateError::Config` with the parser's message.
#[uniffi::export]
pub fn validate_host_pattern(pattern: String) -> Result<(), TollgateError> {
    catch_panic(|| {
        HostPattern::parse(&pattern)
            .map(drop)
            .map_err(|e| TollgateError::Config {
                message: e.to_string(),
            })
    })
}

/// The learned pins in `data_dir/learned-pins.json`, sorted by host, for the app while the
/// tunnel is off. A missing file means no pins; an unreadable one is ignored like the
/// engine ignores it.
#[uniffi::export]
pub fn stored_learned_pins(data_dir: String) -> Result<Vec<LearnedPin>, TollgateError> {
    catch_panic(|| {
        let policy = stored_policy(Path::new(&data_dir))?;
        Ok(policy.as_ref().map(learned_pins).unwrap_or_default())
    })
}

/// Forgets these hosts' pins in `data_dir/learned-pins.json` and rewrites the file in the
/// engine's format with the engine's private atomic writer. Returns how many pins were
/// removed; the file is written only when that is more than zero, and a missing file
/// stays missing.
///
/// Calls in one process run one at a time. While the tunnel runs the engine owns the pins
/// and would write them back, so use [`crate::Engine::forget_pins`] then.
#[uniffi::export]
pub fn forget_stored_pins(data_dir: String, hosts: Vec<String>) -> Result<u32, TollgateError> {
    catch_panic(|| {
        let dir = Path::new(&data_dir);
        let _serial = STORED_PINS.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(policy) = stored_policy(dir)? else {
            return Ok(0);
        };
        let removed = policy.forget_pins(&hosts);
        if removed > 0 {
            write_private(&dir.join(LEARNED_PINS_FILE), &policy.learned_pins_json())?;
        }
        Ok(count(removed))
    })
}

/// A policy holding the stored pins, parsed exactly as the engine parses them; `None` when
/// there is no pins file.
fn stored_policy(dir: &Path) -> Result<Option<Policy>, TollgateError> {
    let path = dir.join(LEARNED_PINS_FILE);
    let json = match std::fs::read_to_string(&path) {
        Ok(json) => json,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(TollgateError::io(format!("{}: {e}", path.display()))),
    };
    let config = Config::default();
    Policy::new(&config, Some(&json))
        .map(Some)
        .map_err(|e| TollgateError::Internal {
            message: e.to_string(),
        })
}

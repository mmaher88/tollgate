//! The blocked log: the most recent block events, kept in memory only.
//!
//! DNS blocks record the queried name; request blocks record the request host, its URL
//! (truncated to [`EventLog::MAX_URL_BYTES`]) and the host of the page that made it.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

/// What was blocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// A DNS query answered with a blocked response.
    Dns,
    /// An intercepted HTTP request blocked by the request engine.
    Request,
}

/// One block, as shown in the app's log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockEvent {
    /// Wall-clock time of the block, in seconds since the Unix epoch.
    pub unix_secs: u64,
    pub kind: EventKind,
    /// The queried name for DNS blocks, the request host for request blocks.
    pub host: String,
    /// The request URL; `None` for DNS blocks.
    pub url: Option<String>,
    /// The host of the page that made the request, when known.
    pub source_host: Option<String>,
}

/// A bounded ring buffer of the newest [`EventLog::CAPACITY`] block events. Send + Sync.
#[derive(Debug, Default)]
pub struct EventLog {
    events: Mutex<VecDeque<BlockEvent>>,
}

impl EventLog {
    /// Number of events kept; recording one more drops the oldest.
    pub const CAPACITY: usize = 500;
    /// URLs longer than this many bytes are cut at the last character boundary before it,
    /// and their allocation is shrunk to match.
    pub const MAX_URL_BYTES: usize = 512;
    /// A DNS name is at most 253 bytes; anything longer came from a malformed request.
    pub const MAX_HOST_BYTES: usize = 253;

    pub fn new() -> EventLog {
        EventLog::default()
    }

    /// Stores `event`, truncating its URL and dropping the oldest event when full.
    pub fn record(&self, mut event: BlockEvent) {
        if let Some(url) = event.url.as_mut() {
            truncate_at_char_boundary(url, Self::MAX_URL_BYTES);
        }
        truncate_at_char_boundary(&mut event.host, Self::MAX_HOST_BYTES);
        if let Some(source) = event.source_host.as_mut() {
            truncate_at_char_boundary(source, Self::MAX_HOST_BYTES);
        }
        let mut events = self.lock();
        if events.len() >= Self::CAPACITY {
            events.pop_front();
        }
        events.push_back(event);
    }

    /// Up to `limit` events, newest first.
    pub fn recent(&self, limit: usize) -> Vec<BlockEvent> {
        self.lock().iter().rev().take(limit).cloned().collect()
    }

    /// Removes every event.
    pub fn clear(&self) {
        self.lock().clear();
    }

    /// A panic while holding the lock cannot leave the buffer inconsistent (every change is
    /// a single push, pop or clear), so a poisoned lock is recovered.
    fn lock(&self) -> MutexGuard<'_, VecDeque<BlockEvent>> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn truncate_at_char_boundary(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    // Truncating keeps the capacity: without this each event would hold the whole URL.
    s.shrink_to_fit();
}

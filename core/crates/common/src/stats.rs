//! Lock-free counters shared by dns, mitm and ffi.
//!
//! Counters are independent and only read for display, so every access is `Relaxed`.

use std::sync::atomic::{AtomicU64, Ordering};

/// Lock-free counters shared by dns, mitm and ffi.
#[derive(Default, Debug)]
pub struct Stats {
    pub dns_queries: AtomicU64,
    pub dns_blocked: AtomicU64,
    pub dns_cache_hits: AtomicU64,
    pub dns_forwarded: AtomicU64,
    pub dns_failed: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub http_requests: AtomicU64,
    pub http_blocked: AtomicU64,
    pub connections_intercepted: AtomicU64,
    pub connections_passthrough: AtomicU64,
    pub tls_client_rejections: AtomicU64,
    pub tls_abandoned_after_handshake: AtomicU64,
}

/// A copy of every counter at one moment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
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

impl Stats {
    /// Adds one to a counter, for example `Stats::inc(&stats.dns_queries)`.
    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Reads every counter. Counters are read one by one, so a snapshot taken while other
    /// threads are counting may mix values from slightly different moments.
    pub fn snapshot(&self) -> StatsSnapshot {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        StatsSnapshot {
            dns_queries: get(&self.dns_queries),
            dns_blocked: get(&self.dns_blocked),
            dns_cache_hits: get(&self.dns_cache_hits),
            dns_forwarded: get(&self.dns_forwarded),
            dns_failed: get(&self.dns_failed),
            packets_dropped: get(&self.packets_dropped),
            http_requests: get(&self.http_requests),
            http_blocked: get(&self.http_blocked),
            connections_intercepted: get(&self.connections_intercepted),
            connections_passthrough: get(&self.connections_passthrough),
            tls_client_rejections: get(&self.tls_client_rejections),
            tls_abandoned_after_handshake: get(&self.tls_abandoned_after_handshake),
        }
    }
}

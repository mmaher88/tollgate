use std::sync::Arc;
use std::sync::atomic::Ordering;

use tollgate_common::stats::{Stats, StatsSnapshot};

#[test]
fn new_stats_are_zero() {
    assert_eq!(Stats::default().snapshot(), StatsSnapshot::default());
}

#[test]
fn snapshot_copies_each_counter_into_its_own_field() {
    let stats = Stats::default();
    let counters = [
        &stats.dns_queries,
        &stats.dns_blocked,
        &stats.dns_cache_hits,
        &stats.dns_forwarded,
        &stats.dns_failed,
        &stats.packets_dropped,
        &stats.http_requests,
        &stats.http_blocked,
        &stats.connections_intercepted,
        &stats.connections_passthrough,
        &stats.tls_client_rejections,
        &stats.tls_abandoned_after_handshake,
    ];
    for (i, counter) in counters.iter().enumerate() {
        counter.fetch_add(i as u64 + 1, Ordering::Relaxed);
    }
    assert_eq!(
        stats.snapshot(),
        StatsSnapshot {
            dns_queries: 1,
            dns_blocked: 2,
            dns_cache_hits: 3,
            dns_forwarded: 4,
            dns_failed: 5,
            packets_dropped: 6,
            http_requests: 7,
            http_blocked: 8,
            connections_intercepted: 9,
            connections_passthrough: 10,
            tls_client_rejections: 11,
            tls_abandoned_after_handshake: 12,
        }
    );
}

#[test]
fn inc_counts_from_many_threads() {
    let stats = Arc::new(Stats::default());
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let stats = Arc::clone(&stats);
            std::thread::spawn(move || {
                for _ in 0..10_000 {
                    Stats::inc(&stats.http_requests);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let snapshot = stats.snapshot();
    assert_eq!(snapshot.http_requests, 80_000);
    assert_eq!(snapshot.http_blocked, 0);
}

#[test]
fn stats_can_be_shared_across_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Stats>();
}

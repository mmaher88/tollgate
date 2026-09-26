//! Host name lookups for the proxy over DNS over HTTPS.

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};

use support::doh_server::{TestServer, closed_upstream, trusting};
use tollgate_common::resolve::Resolve;
use tollgate_dns::HostResolver;

static CLOCK: AtomicU64 = AtomicU64::new(1_000);
fn clock() -> u64 {
    CLOCK.load(Ordering::SeqCst)
}

const ANSWER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

#[tokio::test]
async fn looks_names_up_over_doh_and_keeps_them_for_their_ttl() {
    let server = TestServer::start().await;
    let resolver = HostResolver::with_clock(trusting(vec![server.upstream()], &[&server]), clock);

    assert_eq!(resolver.lookup("WWW.Example.com.").await, [ANSWER]);
    // One A and one AAAA query.
    assert_eq!(server.requests(), 2);
    assert_eq!(resolver.lookup("www.example.com").await, [ANSWER]);
    assert_eq!(server.requests(), 2);

    // The test server's records have a TTL of 300 s.
    CLOCK.fetch_add(300, Ordering::SeqCst);
    assert_eq!(resolver.lookup("www.example.com").await, [ANSWER]);
    assert_eq!(server.requests(), 4);
}

#[tokio::test]
async fn addresses_are_returned_without_a_lookup() {
    let resolver = HostResolver::new(trusting(vec![closed_upstream().await], &[]));
    assert_eq!(
        resolver.lookup("192.0.2.9").await,
        [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))]
    );
    assert_eq!(
        resolver.lookup("2001:db8::1").await,
        ["2001:db8::1".parse::<IpAddr>().unwrap()]
    );
}

#[tokio::test]
async fn a_failed_lookup_is_empty_and_not_kept() {
    let resolver = HostResolver::new(trusting(vec![closed_upstream().await], &[]));
    assert!(resolver.lookup("www.example.com").await.is_empty());
    assert!(resolver.lookup("www.example.com").await.is_empty());
}

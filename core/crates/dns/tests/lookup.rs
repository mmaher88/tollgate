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

/// Local network names go to the system resolver (and from there to the network's own
/// resolver), never to the public DoH upstreams, which only know they do not exist.
#[tokio::test]
async fn local_names_are_not_looked_up_over_doh() {
    let server = TestServer::start().await;
    let resolver = HostResolver::new(trusting(vec![server.upstream()], &[&server]));
    for host in ["nas.lan", "homeassistant.home.arpa.", "nas", "fritz.box"] {
        assert!(resolver.lookup(host).await.is_empty(), "{host}");
    }
    assert_eq!(server.requests(), 0);
    assert_eq!(resolver.lookup("www.example.com").await, [ANSWER]);
}

/// Callers asking for a name that is being looked up share that lookup, and at most
/// `LOOKUP_PERMITS / 2` names are looked up at once, so the lookups never take more than
/// their share of the resolver's in-flight limit.
#[tokio::test]
async fn lookups_are_shared_and_take_turns() {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use support::doh_server::Mode;
    use tollgate_dns::LOOKUP_PERMITS;

    let server = TestServer::start().await;
    server.set_mode(Mode::Gated);
    let resolver = Arc::new(HostResolver::new(trusting(
        vec![server.upstream()],
        &[&server],
    )));
    let lookup = |host: String| {
        let resolver = resolver.clone();
        tokio::spawn(async move { resolver.lookup(&host).await })
    };
    let same: Vec<_> = (0..5)
        .map(|_| lookup("shared.example".to_string()))
        .collect();
    let others: Vec<_> = (0..LOOKUP_PERMITS)
        .map(|i| lookup(format!("host{i}.example")))
        .collect();

    let deadline = Instant::now() + Duration::from_secs(1);
    while server.requests() < LOOKUP_PERMITS {
        assert!(Instant::now() < deadline, "only {}", server.requests());
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    // One A and one AAAA query for each name with a turn; the shared name counts once.
    assert_eq!(server.requests(), LOOKUP_PERMITS);

    server.open_gate();
    for task in same.into_iter().chain(others) {
        assert_eq!(task.await.unwrap(), [ANSWER]);
    }
    // 1 shared name and LOOKUP_PERMITS others, two queries each.
    assert_eq!(server.requests(), 2 * (LOOKUP_PERMITS + 1));
}

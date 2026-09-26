mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::rr::RecordType;
use support::doh_server::{Mode, TestServer, silent_upstream, trusting};
use support::{decode, query};
use tollgate_common::resolve::Resolve;
use tollgate_dns::{
    COLD_DEADLINE, DOWN_FOR, DohError, DohResolver, HostResolver, MAX_IDLE, WARM_DEADLINE,
};

fn assert_between(elapsed: Duration, low: Duration, high: Duration) {
    assert!(
        elapsed >= low && elapsed < high,
        "took {elapsed:?}, expected {low:?} to {high:?}"
    );
}

#[test]
fn deadlines() {
    assert_eq!(COLD_DEADLINE, Duration::from_millis(2000));
    assert_eq!(WARM_DEADLINE, Duration::from_millis(1500));
    assert_eq!(MAX_IDLE, Duration::from_secs(30));
    assert_eq!(DOWN_FOR, Duration::from_secs(30));
}

/// A resolver whose clock the test moves by hand.
fn with_manual_clock(resolver: DohResolver) -> (DohResolver, Arc<AtomicU64>) {
    let now = Arc::new(AtomicU64::new(1_000));
    let clock = now.clone();
    (
        resolver.with_clock(move || clock.load(Ordering::SeqCst)),
        now,
    )
}

#[tokio::test]
async fn an_upstream_that_timed_out_is_tried_after_the_others() {
    let (_listener, silent) = silent_upstream().await;
    let server = TestServer::start().await;
    let resolver = trusting(vec![silent, server.upstream()], &[&server]);
    let query = query(1, "example.com.", RecordType::A, None);
    resolver.resolve(&query).await.unwrap();

    // The silent upstream is not waited on again while the other one answers.
    let start = Instant::now();
    resolver.resolve(&query).await.unwrap();
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(server.requests(), 2);

    // Nor by the proxy's lookups of new names, which share the resolver.
    let lookups = HostResolver::new(resolver.clone());
    let start = Instant::now();
    assert!(!lookups.lookup("new.example.com").await.is_empty());
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "{:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn a_hung_warm_connection_marks_its_upstream_down() {
    let first = TestServer::start().await;
    let second = TestServer::start().await;
    let resolver = trusting(
        vec![first.upstream(), second.upstream()],
        &[&first, &second],
    );
    let query = query(1, "example.com.", RecordType::A, None);
    resolver.resolve(&query).await.unwrap();
    first.set_mode(Mode::Hang);
    resolver.resolve(&query).await.unwrap();

    // Without a mark, this query would pay the cold deadline on the first upstream.
    let start = Instant::now();
    resolver.resolve(&query).await.unwrap();
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(first.requests(), 2);
    assert_eq!(second.requests(), 2);
}

#[tokio::test]
async fn a_down_upstream_is_probed_in_the_background_when_its_time_is_up() {
    let first = TestServer::start().await;
    let second = TestServer::start().await;
    let (resolver, now) = with_manual_clock(trusting(
        vec![first.upstream(), second.upstream()],
        &[&first, &second],
    ));
    let query = query(1, "example.com.", RecordType::A, None);
    first.set_mode(Mode::Hang);
    resolver.resolve(&query).await.unwrap();
    assert_eq!(second.requests(), 1);

    // Still down: the answer comes from the second upstream without touching the first.
    first.set_mode(Mode::Answer);
    now.fetch_add(DOWN_FOR.as_secs() - 1, Ordering::SeqCst);
    resolver.resolve(&query).await.unwrap();
    assert_eq!(first.requests(), 1);
    assert_eq!(second.requests(), 2);

    // The time is up: this query does not wait for the first upstream, which is probed
    // on the side.
    now.fetch_add(2, Ordering::SeqCst);
    let start = Instant::now();
    resolver.resolve(&query).await.unwrap();
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(second.requests(), 3);
    for _ in 0..100 {
        if first.requests() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(first.requests(), 2);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The probe answered, so the first upstream is preferred again.
    resolver.resolve(&query).await.unwrap();
    assert_eq!(first.requests(), 3);
    assert_eq!(second.requests(), 3);
}

#[tokio::test]
async fn a_failed_probe_keeps_the_upstream_down() {
    let (_listener, silent) = silent_upstream().await;
    let server = TestServer::start().await;
    let (resolver, now) = with_manual_clock(trusting(vec![silent, server.upstream()], &[&server]));
    let query = query(1, "example.com.", RecordType::A, None);
    resolver.resolve(&query).await.unwrap();

    now.fetch_add(DOWN_FOR.as_secs() + 1, Ordering::SeqCst);
    resolver.resolve(&query).await.unwrap();
    // Let the probe time out.
    tokio::time::sleep(COLD_DEADLINE + Duration::from_millis(300)).await;

    let start = Instant::now();
    resolver.resolve(&query).await.unwrap();
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(server.requests(), 3);
}

#[tokio::test]
async fn reset_connections_gives_a_down_upstream_another_chance() {
    let first = TestServer::start().await;
    let second = TestServer::start().await;
    let resolver = trusting(
        vec![first.upstream(), second.upstream()],
        &[&first, &second],
    );
    let query = query(1, "example.com.", RecordType::A, None);
    first.set_mode(Mode::Hang);
    resolver.resolve(&query).await.unwrap();
    first.set_mode(Mode::Answer);
    resolver.resolve(&query).await.unwrap();
    assert_eq!(first.requests(), 1);

    resolver.reset_connections();
    resolver.resolve(&query).await.unwrap();
    assert_eq!(first.requests(), 2);
    assert_eq!(second.requests(), 2);
}

#[tokio::test]
async fn upstreams_that_are_all_down_are_still_tried_in_order() {
    let (_first_listener, first) = silent_upstream().await;
    let (_second_listener, second) = silent_upstream().await;
    let resolver = DohResolver::new(vec![first, second]);
    let query = query(1, "example.com.", RecordType::A, None);
    assert_eq!(resolver.resolve(&query).await, Err(DohError::Timeout));

    let start = Instant::now();
    assert_eq!(resolver.resolve(&query).await, Err(DohError::Timeout));
    assert_between(
        start.elapsed(),
        COLD_DEADLINE * 2,
        COLD_DEADLINE * 2 + Duration::from_millis(700),
    );
}

#[tokio::test]
async fn a_silent_upstream_costs_the_cold_deadline_then_fails_over() {
    let (_listener, silent) = silent_upstream().await;
    let server = TestServer::start().await;
    let resolver = trusting(vec![silent, server.upstream()], &[&server]);
    let start = Instant::now();
    let answer = resolver
        .resolve(&query(1, "example.com.", RecordType::A, None))
        .await
        .unwrap();
    assert_between(
        start.elapsed(),
        COLD_DEADLINE,
        COLD_DEADLINE + Duration::from_millis(700),
    );
    assert_eq!(decode(&answer).metadata.id, 1);
}

#[tokio::test]
async fn a_silent_upstream_alone_times_out() {
    let (_listener, silent) = silent_upstream().await;
    let resolver = DohResolver::new(vec![silent]);
    let start = Instant::now();
    let result = resolver
        .resolve(&query(1, "example.com.", RecordType::A, None))
        .await;
    assert_eq!(result, Err(DohError::Timeout));
    assert_between(
        start.elapsed(),
        COLD_DEADLINE,
        COLD_DEADLINE + Duration::from_millis(700),
    );
}

#[tokio::test]
async fn a_hung_connection_costs_the_warm_deadline_and_is_replaced() {
    let first = TestServer::start().await;
    let second = TestServer::start().await;
    let resolver = trusting(
        vec![first.upstream(), second.upstream()],
        &[&first, &second],
    );
    let query = query(1, "example.com.", RecordType::A, None);
    resolver.resolve(&query).await.unwrap();

    first.set_mode(Mode::Hang);
    let start = Instant::now();
    resolver.resolve(&query).await.unwrap();
    assert_between(
        start.elapsed(),
        WARM_DEADLINE,
        WARM_DEADLINE + Duration::from_millis(600),
    );
    assert_eq!(second.requests(), 1);

    // The hung connection was dropped, so the next query to it opens a new one.
    first.set_mode(Mode::Answer);
    resolver.reset_connections();
    resolver.resolve(&query).await.unwrap();
    assert_eq!(first.connections(), 2);
    assert_eq!(first.requests(), 3);
    assert_eq!(second.requests(), 1);
}

#[tokio::test]
async fn a_closed_connection_is_retried_once_on_a_new_one() {
    let server = TestServer::start().await;
    let resolver = trusting(vec![server.upstream()], &[&server]);
    let query = query(1, "example.com.", RecordType::A, None);
    resolver.resolve(&query).await.unwrap();

    server.set_mode(Mode::DropOnce);
    let start = Instant::now();
    let answer = resolver.resolve(&query).await.unwrap();
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(decode(&answer).answers.len(), 1);
    assert_eq!(server.connections(), 2);
    assert_eq!(server.requests(), 3);
}

#[tokio::test]
async fn after_one_retry_the_next_upstream_is_tried() {
    let first = TestServer::start().await;
    let second = TestServer::start().await;
    let resolver = trusting(
        vec![first.upstream(), second.upstream()],
        &[&first, &second],
    );
    let query = query(1, "example.com.", RecordType::A, None);
    resolver.resolve(&query).await.unwrap();

    first.set_mode(Mode::DropAlways);
    resolver.resolve(&query).await.unwrap();
    // The warm attempt and exactly one retry on a new connection, then the next upstream.
    assert_eq!(first.connections(), 2);
    assert_eq!(first.requests(), 3);
    assert_eq!(second.requests(), 1);
}

#[tokio::test]
async fn reconnects_after_the_server_closes_an_idle_connection() {
    let server = TestServer::start().await;
    let resolver = trusting(vec![server.upstream()], &[&server]);
    let query = query(1, "example.com.", RecordType::A, None);
    server.set_mode(Mode::AnswerThenGoAway);
    resolver.resolve(&query).await.unwrap();
    // Let the client read the GOAWAY and the close.
    tokio::time::sleep(Duration::from_millis(100)).await;

    server.set_mode(Mode::Answer);
    resolver.resolve(&query).await.unwrap();
    assert_eq!(server.connections(), 2);
    assert_eq!(server.requests(), 2);
}

#[tokio::test]
async fn a_connection_idle_longer_than_max_idle_is_replaced_before_use() {
    let server = TestServer::start().await;
    let now = Arc::new(AtomicU64::new(1_000));
    let clock = now.clone();
    let resolver = trusting(vec![server.upstream()], &[&server])
        .with_clock(move || clock.load(Ordering::SeqCst));
    let query = query(1, "example.com.", RecordType::A, None);
    resolver.resolve(&query).await.unwrap();

    // Idle for less than MAX_IDLE: the connection is used again.
    now.fetch_add(MAX_IDLE.as_secs() - 1, Ordering::SeqCst);
    resolver.resolve(&query).await.unwrap();
    assert_eq!(server.connections(), 1);
    // Idle time counts from the last request, not from when the connection opened.
    now.fetch_add(MAX_IDLE.as_secs() - 1, Ordering::SeqCst);
    resolver.resolve(&query).await.unwrap();
    assert_eq!(server.connections(), 1);

    // The device slept: the first connection is dead, and has been idle too long.
    server.set_mode(Mode::HangConnection(1));
    now.fetch_add(MAX_IDLE.as_secs() + 1, Ordering::SeqCst);
    let start = Instant::now();
    let answer = resolver.resolve(&query).await.unwrap();
    assert!(start.elapsed() < COLD_DEADLINE, "{:?}", start.elapsed());
    assert_eq!(decode(&answer).answers.len(), 1);
    assert_eq!(server.connections(), 2);
    // The dead connection never saw the query.
    assert_eq!(server.requests(), 4);
}

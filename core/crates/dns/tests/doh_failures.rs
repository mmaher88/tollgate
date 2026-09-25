mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::rr::RecordType;
use support::doh_server::{Mode, TestServer, silent_upstream, trusting};
use support::{decode, query};
use tollgate_dns::{COLD_DEADLINE, DohError, DohResolver, MAX_IDLE, WARM_DEADLINE};

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

    // The hung connection was dropped, so the next query opens a new one.
    first.set_mode(Mode::Answer);
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

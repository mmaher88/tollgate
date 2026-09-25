mod support;

use std::time::{Duration, Instant};

use hickory_proto::rr::RecordType;
use support::doh_server::{Mode, TestServer, trusting};
use support::{decode, query};
use tollgate_dns::{DohError, MAX_IN_FLIGHT};

#[tokio::test]
async fn at_most_128_queries_are_in_flight_on_one_shared_connection() {
    assert_eq!(MAX_IN_FLIGHT, 128);
    let server = TestServer::start().await;
    server.set_mode(Mode::Gated);
    let resolver = trusting(vec![server.upstream()], &[&server]);

    let tasks: Vec<_> = (0..MAX_IN_FLIGHT as u16)
        .map(|id| {
            let resolver = resolver.clone();
            tokio::spawn(async move {
                resolver
                    .resolve(&query(id, "example.com.", RecordType::A, None))
                    .await
            })
        })
        .collect();

    // Every query reaches the server and waits there.
    let deadline = Instant::now() + Duration::from_secs(1);
    while server.requests() < MAX_IN_FLIGHT {
        assert!(
            Instant::now() < deadline,
            "only {} arrived",
            server.requests()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // One more is refused at once instead of queueing.
    let start = Instant::now();
    let refused = resolver
        .resolve(&query(999, "example.com.", RecordType::A, None))
        .await;
    assert_eq!(refused, Err(DohError::Busy));
    assert!(start.elapsed() < Duration::from_millis(50));

    server.open_gate();
    for (id, task) in tasks.into_iter().enumerate() {
        let answer = task.await.unwrap().unwrap();
        assert_eq!(usize::from(decode(&answer).metadata.id), id);
    }
    // All of them shared one connection, and the slots are free again.
    assert_eq!(server.connections(), 1);
    assert!(
        resolver
            .resolve(&query(1000, "example.com.", RecordType::A, None))
            .await
            .is_ok()
    );
}

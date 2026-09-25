mod support;

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, RecordType};
use rustls::pki_types::CertificateDer;
use support::doh_server::{Mode, TLS_NAME, TestServer, closed_upstream, trusting};
use support::{decode, query};
use tollgate_dns::{DohError, DohResolver};

#[test]
fn resolver_and_its_future_can_move_between_threads() {
    fn check<T: Send + Sync + Clone + 'static>(_: &T) {}
    fn check_send<T: Send>(_: &T) {}
    let resolver = DohResolver::new(Vec::new());
    check(&resolver);
    let query = [0u8; 12];
    let future = resolver.resolve(&query);
    check_send(&future);
}

#[tokio::test]
async fn resolves_with_rfc_8484_post_over_h2() {
    let server = TestServer::start().await;
    let resolver = trusting(vec![server.upstream()], &[&server]);
    let query = query(0x1234, "example.com.", RecordType::A, None);
    let answer = resolver.resolve(&query).await.unwrap();

    let message = decode(&answer);
    assert_eq!(message.metadata.id, 0x1234);
    assert_eq!(message.answers.len(), 1);
    assert_eq!(
        message.answers[0].data,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))
    );

    let seen = server.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "POST");
    assert_eq!(
        seen[0].uri,
        format!("https://{TLS_NAME}:{}/dns-query", server.addr.port())
    );
    assert_eq!(
        seen[0].content_type.as_deref(),
        Some("application/dns-message")
    );
    assert_eq!(seen[0].accept.as_deref(), Some("application/dns-message"));
    // The id is 0 on the wire; everything else is the query as given.
    assert_eq!(seen[0].body[..2], [0, 0]);
    assert_eq!(seen[0].body[2..], query[2..]);
}

#[tokio::test]
async fn uses_the_configured_path() {
    let server = TestServer::start().await;
    let mut upstream = server.upstream();
    upstream.path = "/custom/path".to_string();
    let resolver = trusting(vec![upstream], &[&server]);
    resolver
        .resolve(&query(1, "example.com.", RecordType::A, None))
        .await
        .unwrap();
    assert!(server.seen()[0].uri.ends_with("/custom/path"));
}

#[tokio::test]
async fn reuses_one_connection() {
    let server = TestServer::start().await;
    let resolver = trusting(vec![server.upstream()], &[&server]);
    for id in 0..5 {
        let answer = resolver
            .resolve(&query(id, "example.com.", RecordType::A, None))
            .await
            .unwrap();
        assert_eq!(decode(&answer).metadata.id, id);
    }
    // A clone shares the connection.
    resolver
        .clone()
        .resolve(&query(9, "example.com.", RecordType::A, None))
        .await
        .unwrap();
    assert_eq!(server.connections(), 1);
    assert_eq!(server.requests(), 6);
}

#[tokio::test]
async fn concurrent_queries_do_not_wait_for_each_other() {
    let server = TestServer::start().await;
    server.set_mode(Mode::Gated);
    let resolver = trusting(vec![server.upstream()], &[&server]);
    let tasks: Vec<_> = (0..20u16)
        .map(|id| {
            let resolver = resolver.clone();
            tokio::spawn(async move {
                resolver
                    .resolve(&query(id, "example.com.", RecordType::A, None))
                    .await
            })
        })
        .collect();
    // All 20 are at the server before any is answered: none waits for another's answer.
    let deadline = Instant::now() + Duration::from_secs(1);
    while server.requests() < 20 {
        assert!(
            Instant::now() < deadline,
            "only {} arrived",
            server.requests()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    server.open_gate();
    for task in tasks {
        assert!(task.await.unwrap().is_ok());
    }
    assert_eq!(server.connections(), 1);
}

#[tokio::test]
async fn rejects_a_certificate_from_an_unknown_authority() {
    let server = TestServer::start().await;
    let resolver = DohResolver::new(vec![server.upstream()]);
    let err = resolver
        .resolve(&query(1, "example.com.", RecordType::A, None))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, DohError::Tls(message) if message.contains("UnknownIssuer")),
        "{err:?}"
    );
}

#[tokio::test]
async fn rejects_a_certificate_for_another_name() {
    let server = TestServer::start().await;
    let resolver = trusting(vec![server.upstream_named("other.test")], &[&server]);
    let err = resolver
        .resolve(&query(1, "example.com.", RecordType::A, None))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, DohError::Tls(message) if message.contains("not valid for name")),
        "{err:?}"
    );
}

#[tokio::test]
async fn http_errors_and_short_answers_are_errors() {
    let server = TestServer::start().await;
    let resolver = trusting(vec![server.upstream()], &[&server]);
    let query = query(1, "example.com.", RecordType::A, None);
    server.set_mode(Mode::Status(503));
    assert_eq!(resolver.resolve(&query).await, Err(DohError::Status(503)));
    server.set_mode(Mode::Short);
    assert!(matches!(
        resolver.resolve(&query).await,
        Err(DohError::BadAnswer(_))
    ));
    server.set_mode(Mode::Answer);
    assert!(resolver.resolve(&query).await.is_ok());
    // None of these broke the connection.
    assert_eq!(server.connections(), 1);
}

#[tokio::test]
async fn fails_over_to_the_next_upstream() {
    let first = TestServer::start().await;
    let second = TestServer::start().await;
    let resolver = trusting(
        vec![closed_upstream().await, first.upstream(), second.upstream()],
        &[&first, &second],
    );
    let query = query(1, "example.com.", RecordType::A, None);
    assert!(resolver.resolve(&query).await.is_ok());
    assert_eq!((first.requests(), second.requests()), (1, 0));

    first.set_mode(Mode::Status(500));
    assert!(resolver.resolve(&query).await.is_ok());
    assert_eq!((first.requests(), second.requests()), (2, 1));
}

#[tokio::test]
async fn reports_the_last_upstream_error() {
    let server = TestServer::start().await;
    server.set_mode(Mode::Status(502));
    let resolver = trusting(vec![closed_upstream().await, server.upstream()], &[&server]);
    let query = query(1, "example.com.", RecordType::A, None);
    assert_eq!(resolver.resolve(&query).await, Err(DohError::Status(502)));

    let resolver = DohResolver::new(vec![closed_upstream().await]);
    assert!(matches!(
        resolver.resolve(&query).await,
        Err(DohError::Connect(_))
    ));
}

#[tokio::test]
async fn invalid_upstreams_are_skipped() {
    let server = TestServer::start().await;
    let mut no_slash = server.upstream();
    no_slash.path = "dns-query".to_string();
    let bad_name = server.upstream_named("not a name");
    let query = query(1, "example.com.", RecordType::A, None);

    let resolver = trusting(vec![no_slash.clone(), bad_name.clone()], &[&server]);
    assert_eq!(resolver.resolve(&query).await, Err(DohError::NoUpstream));

    let resolver = trusting(vec![no_slash, bad_name, server.upstream()], &[&server]);
    assert!(resolver.resolve(&query).await.is_ok());
    assert_eq!(server.requests(), 1);
}

#[tokio::test]
async fn rejects_short_queries_and_bad_roots() {
    let resolver = DohResolver::new(Vec::new());
    assert_eq!(resolver.resolve(&[0; 11]).await, Err(DohError::BadQuery));
    assert_eq!(resolver.resolve(&[0; 12]).await, Err(DohError::NoUpstream));
    let garbage = CertificateDer::from(vec![1, 2, 3]);
    assert!(matches!(
        DohResolver::with_extra_roots(Vec::new(), &[garbage]),
        Err(DohError::Config(_))
    ));
}

#[tokio::test]
async fn an_ipv6_literal_tls_name_is_usable() {
    let server = TestServer::start().await;
    let resolver = trusting(vec![server.upstream_named("::1")], &[&server]);
    let query = query(0x0606, "example.com.", RecordType::A, None);
    let answer = resolver.resolve(&query).await.unwrap();
    assert_eq!(decode(&answer).metadata.id, 0x0606);
    assert_eq!(
        server.seen()[0].uri,
        format!("https://[::1]:{}/dns-query", server.addr.port())
    );
}

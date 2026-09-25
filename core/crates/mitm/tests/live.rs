//! A live check through the real internet. Ignored by default because it needs the
//! network; run it with `cargo test -p tollgate-mitm --test live -- --ignored`.

mod support;

use std::sync::Arc;

use hyper::{StatusCode, Version};
use tollgate_mitm::{CertAuthority, ServeOptions};
use tollgate_policy::Config;

use support::client::{get, http1, send1};
use support::proxy;
use support::tunnel::{connect, http2, peer_issuer, send2, tls, tls_config};

#[tokio::test]
#[ignore = "needs the network: cargo test -p tollgate-mitm --test live -- --ignored"]
async fn example_com_through_the_proxy() {
    let ca = Arc::new(CertAuthority::generate("Tollgate Live CA").unwrap());
    let ctx = proxy::context(
        ca.clone(),
        &Config::default(),
        Some("||example.com/blocked\n"),
    );
    let proxy = proxy::start(ctx, ServeOptions::default()).await;

    let tcp = connect(proxy.addr, "example.com:443").await;
    let tls2 = tls(
        tcp,
        tls_config(&[&ca], &[b"h2", b"http/1.1"]),
        "example.com",
    )
    .await
    .unwrap();
    assert_eq!(peer_issuer(&tls2), "CN=Tollgate Live CA, O=Tollgate");
    let mut h2 = http2(tls2).await;
    let reply = send2(&mut h2, get("https://example.com/", &[])).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.version, Version::HTTP_2);
    assert!(reply.body.contains("Example Domain"), "{}", reply.body);
    let blocked = send2(&mut h2, get("https://example.com/blocked", &[])).await;
    assert_eq!(blocked.status, StatusCode::FORBIDDEN);

    let tcp = connect(proxy.addr, "example.com:443").await;
    let tls1 = tls(tcp, tls_config(&[&ca], &[b"http/1.1"]), "example.com")
        .await
        .unwrap();
    let mut h1 = http1(tls1).await;
    let reply = send1(&mut h1, get("/", &[("host", "example.com")])).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("Example Domain"));

    let stats = proxy.stats();
    assert_eq!(stats.connections_intercepted, 2);
    assert_eq!(stats.http_requests, 3);
    assert_eq!(stats.http_blocked, 1);
}

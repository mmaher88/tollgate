//! TLS upstreams: absolute-form `https://` requests sent to the proxy use the same pool
//! as intercepted requests.

mod support;

use std::sync::Arc;

use hyper::StatusCode;
use tollgate_mitm::{CertAuthority, ServeOptions};
use tollgate_policy::Config;

use support::client::{get, proxy_get};
use support::tunnel::{connect, http2, issuer_via, peer_issuer, send2, tls, tls_config};
use support::{proxy, tls_origin};

fn ca(name: &str) -> Arc<CertAuthority> {
    Arc::new(CertAuthority::generate(name).unwrap())
}

async fn start(options: ServeOptions) -> proxy::TestProxy {
    let ctx = proxy::context(ca("Tollgate Test CA"), &Config::default(), None);
    proxy::start(ctx, options).await
}

#[tokio::test]
async fn http2_origin_gets_one_shared_connection() {
    let origin_ca = ca("Origin CA");
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2", b"http/1.1"]).await;
    let proxy = start(tls_origin::trusting(&origin_ca)).await;
    let url = format!("https://localhost:{}/page?q=1", origin.port());

    for _ in 0..3 {
        let reply = proxy_get(proxy.addr, &url, &[("cookie", "a=1")]).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(
            reply.body,
            format!(
                "GET /page?q=1 authority=localhost:{} version=HTTP/2.0 conn=1 cookie=a=1",
                origin.port()
            )
        );
    }
    assert_eq!(origin.connections(), 1);
}

#[tokio::test]
async fn concurrent_requests_share_one_http2_connection() {
    let origin_ca = ca("Origin CA");
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2"]).await;
    let proxy = start(tls_origin::trusting(&origin_ca)).await;
    let url = format!("https://localhost:{}/?delay=100", origin.port());

    let requests: Vec<_> = (0..8)
        .map(|_| {
            let url = url.clone();
            let addr = proxy.addr;
            tokio::spawn(async move { proxy_get(addr, &url, &[]).await })
        })
        .collect();
    for request in requests {
        let reply = request.await.unwrap();
        assert_eq!(reply.status, StatusCode::OK);
        assert!(reply.body.contains(" conn=1 "), "{}", reply.body);
    }
    assert_eq!(origin.requests(), 8);
    assert_eq!(origin.connections(), 1);
}

#[tokio::test]
async fn http1_only_origin_gets_http1_with_one_cookie_header() {
    let origin_ca = ca("Origin CA");
    let origin = tls_origin::https(origin_ca.clone(), &[b"http/1.1"]).await;
    let proxy = start(tls_origin::trusting(&origin_ca)).await;
    let url = format!("https://localhost:{}/", origin.port());

    let cookies = [("cookie", "a=1"), ("cookie", "b=2")];
    let reply = proxy_get(proxy.addr, &url, &cookies).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.body,
        format!(
            "GET / authority=localhost:{} version=HTTP/1.1 conn=1 cookie=a=1; b=2",
            origin.port()
        )
    );
}

#[tokio::test]
async fn ip_address_origins_are_verified_by_ip() {
    let origin_ca = ca("Origin CA");
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2"]).await;
    let proxy = start(tls_origin::trusting(&origin_ca)).await;

    let reply = proxy_get(
        proxy.addr,
        &format!("https://127.0.0.1:{}/", origin.port()),
        &[],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("version=HTTP/2.0"), "{}", reply.body);
}

#[tokio::test]
async fn untrusted_origin_certificate_gets_502_and_the_host_is_passed_through_from_then_on() {
    let origin_ca = ca("Unknown CA");
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2", b"http/1.1"]).await;
    let proxy = start(tls_origin::trusting(&ca("Some Other CA"))).await;

    let reply = proxy_get(
        proxy.addr,
        &format!("https://localhost:{}/", origin.port()),
        &[],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert_eq!(origin.requests(), 0);
    let pins: Vec<String> = proxy
        .ctx
        .policy
        .learned_pins()
        .into_iter()
        .map(|(host, _)| host)
        .collect();
    assert_eq!(pins, ["localhost"]);

    // The client now judges the origin's certificate itself.
    let target = format!("localhost:{}", origin.port());
    let issuer = issuer_via(proxy.addr, &target, &[&origin_ca], "localhost").await;
    assert_eq!(issuer, "CN=Unknown CA, O=Tollgate");
}

#[tokio::test]
async fn an_intercepted_host_with_an_unverifiable_certificate_is_learned() {
    let tollgate_ca = ca("Tollgate Test CA");
    let origin_ca = ca("Unknown CA");
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2", b"http/1.1"]).await;
    let ctx = proxy::context(tollgate_ca.clone(), &Config::default(), None);
    let proxy = proxy::start(ctx, tls_origin::trusting(&ca("Some Other CA"))).await;
    let target = format!("localhost:{}", origin.port());

    let tcp = connect(proxy.addr, &target).await;
    let tls = tls(tcp, tls_config(&[&tollgate_ca], &[b"h2"]), "localhost")
        .await
        .unwrap();
    assert_eq!(peer_issuer(&tls), "CN=Tollgate Test CA, O=Tollgate");
    let mut sender = http2(tls).await;
    let reply = send2(
        &mut sender,
        get(&format!("https://localhost:{}/", origin.port()), &[]),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert_eq!(proxy.ctx.policy.learned_pins().len(), 1);

    let issuer = issuer_via(proxy.addr, &target, &[&origin_ca], "localhost").await;
    assert_eq!(issuer, "CN=Unknown CA, O=Tollgate");
}

#[tokio::test]
async fn an_unreachable_origin_is_not_learned() {
    let proxy = start(ServeOptions::default()).await;
    let port = support::origin::closed_port().await;
    let reply = proxy_get(proxy.addr, &format!("https://localhost:{port}/"), &[]).await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert!(proxy.ctx.policy.learned_pins().is_empty());
}

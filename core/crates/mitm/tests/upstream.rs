//! TLS upstreams: absolute-form `https://` requests sent to the proxy use the same pool
//! as intercepted requests.

mod support;

use std::sync::Arc;

use hyper::StatusCode;
use tollgate_mitm::{CertAuthority, ServeOptions};
use tollgate_policy::Config;

use support::client::proxy_get;
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
async fn untrusted_origin_certificate_gets_502() {
    let origin = tls_origin::https(ca("Unknown CA"), &[b"h2", b"http/1.1"]).await;
    let proxy = start(tls_origin::trusting(&ca("Some Other CA"))).await;

    let reply = proxy_get(
        proxy.addr,
        &format!("https://localhost:{}/", origin.port()),
        &[],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert_eq!(origin.requests(), 0);
}

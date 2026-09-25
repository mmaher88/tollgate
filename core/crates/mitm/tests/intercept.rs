//! `CONNECT` tunnels that the proxy intercepts: TLS with a Tollgate leaf, HTTP/2 or
//! HTTP/1.1 to the client, filtering, and forwarding through the shared pool.

mod support;

use std::sync::Arc;
use std::time::Duration;

use hyper::{StatusCode, Version};
use tokio::io::AsyncWriteExt;
use tollgate_mitm::CertAuthority;
use tollgate_policy::Config;

use support::client::{get, http1, read_to_close, send1, wait_for};
use support::tunnel::{alpn, connect, http2, peer_issuer, send2, tls, tls_config};
use support::{proxy, tls_origin};

const RULES: &str = "\
||ads.tollgate.test^
/pixel/*$image
||tracker.tollgate.test^$third-party
";

struct Setup {
    ca: Arc<CertAuthority>,
    origin: support::origin::Origin,
    proxy: proxy::TestProxy,
}

impl Setup {
    /// `CONNECT 127.0.0.1:<origin port>`.
    fn target(&self) -> String {
        format!("127.0.0.1:{}", self.origin.port())
    }

    /// `https://<name>:<origin port><path>`.
    fn url(&self, name: &str, path: &str) -> String {
        format!("https://{name}:{}{path}", self.origin.port())
    }
}

async fn setup_with(alpn: &[&[u8]], edit: impl FnOnce(&mut tollgate_mitm::ProxyContext)) -> Setup {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let origin = tls_origin::https(origin_ca.clone(), alpn).await;
    let mut ctx = proxy::context(ca.clone(), &Config::default(), Some(RULES));
    edit(&mut ctx);
    let proxy = proxy::start(ctx, tls_origin::trusting(&origin_ca)).await;
    Setup { ca, origin, proxy }
}

async fn setup() -> Setup {
    setup_with(&[b"h2", b"http/1.1"], |_| {}).await
}

#[tokio::test]
async fn http2_client_is_intercepted_and_forwarded() {
    let s = setup().await;
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let config = tls_config(&[&s.ca], &[b"h2", b"http/1.1"]);
    let tls = tls(tcp, config, "www.tollgate.test").await.unwrap();
    assert_eq!(peer_issuer(&tls), "CN=Tollgate Test CA, O=Tollgate");
    assert_eq!(alpn(&tls).as_deref(), Some(&b"h2"[..]));

    let mut h2 = http2(tls).await;
    let reply = send2(&mut h2, get(&s.url("www.tollgate.test", "/page?x=1"), &[])).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.version, Version::HTTP_2);
    assert_eq!(
        reply.body,
        format!(
            "GET /page?x=1 authority=www.tollgate.test:{} version=HTTP/2.0 conn=1 cookie=",
            s.origin.port()
        )
    );
    let stats = s.proxy.stats();
    assert_eq!(stats.connections_intercepted, 1);
    assert_eq!(stats.connections_passthrough, 0);
    assert_eq!(stats.http_requests, 1);
}

#[tokio::test]
async fn http1_client_is_intercepted_and_forwarded() {
    let s = setup().await;
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let config = tls_config(&[&s.ca], &[b"http/1.1"]);
    let tls = tls(tcp, config, "www.tollgate.test").await.unwrap();
    assert_eq!(alpn(&tls).as_deref(), Some(&b"http/1.1"[..]));

    let mut h1 = http1(tls).await;
    let request = get("/page", &[("host", "www.tollgate.test"), ("cookie", "a=1")]);
    let reply = send1(&mut h1, request).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.version, Version::HTTP_11);
    // The URL comes from the SNI and the CONNECT port, not from the Host header.
    assert_eq!(
        reply.body,
        format!(
            "GET /page authority=www.tollgate.test:{} version=HTTP/2.0 conn=1 cookie=a=1",
            s.origin.port()
        )
    );
}

#[tokio::test]
async fn blocked_requests_get_403_with_cors_header() {
    let s = setup().await;
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let tls = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), "ads.tollgate.test")
        .await
        .unwrap();
    let mut h2 = http2(tls).await;

    let reply = send2(&mut h2, get(&s.url("ads.tollgate.test", "/banner.js"), &[])).await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.headers["access-control-allow-origin"], "*");
    assert_eq!(reply.body, "");
    assert_eq!(s.origin.requests(), 0);
    assert_eq!(s.proxy.stats().http_blocked, 1);
}

/// Opens an intercepted HTTP/2 connection for `name` and checks each case.
/// A path, its request headers and the status the client should get.
type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], StatusCode);

async fn check_statuses(s: &Setup, name: &str, cases: &[Case<'_>]) {
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let tls = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), name)
        .await
        .unwrap();
    let mut h2 = http2(tls).await;
    for (path, headers, expected) in cases {
        let reply = send2(&mut h2, get(&s.url(name, path), headers)).await;
        assert_eq!(reply.status, *expected, "{name}{path} {headers:?}");
    }
}

#[tokio::test]
async fn request_type_comes_from_fetch_dest_then_accept_then_extension() {
    let s = setup().await;
    // `/pixel/*$image`
    let cases: &[Case] = &[
        (
            "/pixel/a",
            &[("sec-fetch-dest", "image")],
            StatusCode::FORBIDDEN,
        ),
        (
            "/pixel/a",
            &[("accept", "image/avif,*/*")],
            StatusCode::FORBIDDEN,
        ),
        ("/pixel/a.png", &[], StatusCode::FORBIDDEN),
        (
            "/pixel/a.png",
            &[("sec-fetch-dest", "script"), ("accept", "image/avif")],
            StatusCode::OK,
        ),
        ("/pixel/a", &[], StatusCode::OK),
    ];
    check_statuses(&s, "www.tollgate.test", cases).await;
}

#[tokio::test]
async fn documents_are_their_own_source() {
    let s = setup().await;
    // `||tracker.tollgate.test^$third-party`: a top-level document is first party; the
    // same URL embedded by another site, or with no source at all, is third party.
    let cases: &[Case] = &[
        ("/", &[("sec-fetch-dest", "document")], StatusCode::OK),
        (
            "/",
            &[
                ("sec-fetch-dest", "iframe"),
                ("referer", "https://news.test/"),
            ],
            StatusCode::FORBIDDEN,
        ),
        (
            "/app.js",
            &[("referer", "https://tracker.tollgate.test/")],
            StatusCode::OK,
        ),
        (
            "/app.js",
            &[("origin", "https://tracker.tollgate.test")],
            StatusCode::OK,
        ),
        ("/app.js", &[], StatusCode::FORBIDDEN),
    ];
    check_statuses(&s, "tracker.tollgate.test", cases).await;
}

#[tokio::test]
async fn http2_request_for_another_authority_gets_421() {
    let s = setup().await;
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let tls = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), "a.tollgate.test")
        .await
        .unwrap();
    let mut h2 = http2(tls).await;

    let other_host = send2(&mut h2, get(&s.url("b.tollgate.test", "/"), &[])).await;
    assert_eq!(other_host.status, StatusCode::MISDIRECTED_REQUEST);
    let other_port = send2(&mut h2, get("https://a.tollgate.test:1/", &[])).await;
    assert_eq!(other_port.status, StatusCode::MISDIRECTED_REQUEST);
    let same = send2(&mut h2, get(&s.url("A.Tollgate.Test", "/"), &[])).await;
    assert_eq!(same.status, StatusCode::OK);
    assert_eq!(s.origin.requests(), 1);
}

#[tokio::test]
async fn client_without_sni_gets_a_leaf_for_the_connect_ip() {
    let s = setup().await;
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let tls = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), "127.0.0.1")
        .await
        .unwrap();
    assert_eq!(peer_issuer(&tls), "CN=Tollgate Test CA, O=Tollgate");
    let mut h2 = http2(tls).await;

    let reply = send2(&mut h2, get(&s.url("127.0.0.1", "/ip"), &[])).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        reply.body.starts_with("GET /ip authority=127.0.0.1:"),
        "{}",
        reply.body
    );
}

#[tokio::test]
async fn upstream_is_shared_across_client_connections_and_converted_to_http1() {
    let s = setup_with(&[b"http/1.1"], |_| {}).await;
    for _ in 0..2 {
        let tcp = connect(s.proxy.addr, &s.target()).await;
        let tls = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), "www.tollgate.test")
            .await
            .unwrap();
        let mut h2 = http2(tls).await;
        let cookies = [("cookie", "a=1"), ("cookie", "b=2")];
        let reply = send2(&mut h2, get(&s.url("www.tollgate.test", "/"), &cookies)).await;
        assert_eq!(
            reply.body,
            format!(
                "GET / authority=www.tollgate.test:{} version=HTTP/1.1 conn=1 cookie=a=1; b=2",
                s.origin.port()
            )
        );
    }
    assert_eq!(s.origin.connections(), 1);
}

#[tokio::test]
async fn untrusted_upstream_certificate_gets_502() {
    let s = setup().await;
    // An origin whose certificate comes from a CA the proxy does not trust.
    let rogue = tls_origin::https(
        Arc::new(CertAuthority::generate("Rogue CA").unwrap()),
        &[b"h2"],
    )
    .await;
    let tcp = connect(s.proxy.addr, &format!("127.0.0.1:{}", rogue.port())).await;
    let tls = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), "www.tollgate.test")
        .await
        .unwrap();
    let mut h2 = http2(tls).await;
    let url = format!("https://www.tollgate.test:{}/", rogue.port());

    let reply = send2(&mut h2, get(&url, &[])).await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert_eq!(rogue.requests(), 0);
}

#[tokio::test]
async fn idle_intercepted_connections_give_back_their_slot() {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2"]).await;
    let mut ctx = proxy::context(ca.clone(), &Config::default(), None);
    ctx.max_intercepted = 1;
    let mut options = tls_origin::trusting(&origin_ca);
    options.idle_timeout = Duration::from_millis(300);
    let proxy = proxy::start(ctx, options).await;
    let target = format!("127.0.0.1:{}", origin.port());

    let tcp = connect(proxy.addr, &target).await;
    let mut idle = tls(tcp, tls_config(&[&ca], &[b"h2"]), "www.tollgate.test")
        .await
        .unwrap();
    let closed = read_to_close(&mut idle, Duration::from_secs(5)).await;
    assert!(closed.is_some(), "the idle connection was closed");

    wait_for("the slot to be free", || {
        proxy.stats().connections_intercepted == 1
    })
    .await;
    let tcp = connect(proxy.addr, &target).await;
    let tls = tls(tcp, tls_config(&[&ca], &[b"h2"]), "www.tollgate.test").await;
    assert_eq!(
        peer_issuer(&tls.unwrap()),
        "CN=Tollgate Test CA, O=Tollgate"
    );
    assert_eq!(proxy.stats().connections_intercepted, 2);
}

#[tokio::test]
async fn incomplete_client_hello_times_out() {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let ctx = proxy::context(ca, &Config::default(), None);
    let options = tollgate_mitm::ServeOptions {
        handshake_timeout: Duration::from_millis(300),
        ..tollgate_mitm::ServeOptions::default()
    };
    let proxy = proxy::start(ctx, options).await;
    let origin = support::origin::http().await;

    let mut tcp = connect(proxy.addr, &format!("127.0.0.1:{}", origin.port())).await;
    // A TLS record header announcing 512 bytes, then nothing.
    tcp.write_all(&[0x16, 0x03, 0x01, 0x02, 0x00])
        .await
        .unwrap();
    let closed = read_to_close(&mut tcp, Duration::from_secs(5)).await;
    assert_eq!(closed, Some(Vec::new()));
    assert_eq!(origin.connections(), 0);
}

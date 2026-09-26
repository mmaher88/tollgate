//! Responses still streaming on an upstream connection whose network is gone: after a
//! reset, a connection whose source address is no longer assigned is closed, so the
//! client sees its response fail (and an EventSource reconnects) instead of waiting on a
//! dead path forever.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::StatusCode;
use hyper::body::Incoming;
use tokio::net::TcpStream;
use tollgate_mitm::{CertAuthority, ServeOptions};
use tollgate_policy::Config;

use support::client::{Sender1, get, http1, proxy_get};
use support::{origin, proxy, tls_origin};

/// How long a stream may take to end after a reset whose address check fails: the
/// check runs at once, so this is only a margin.
const ENDS_WITHIN: Duration = Duration::from_secs(3);

fn ca(name: &str) -> Arc<CertAuthority> {
    Arc::new(CertAuthority::generate(name).unwrap())
}

async fn start(
    mut options: ServeOptions,
    present: fn(std::net::IpAddr) -> bool,
) -> proxy::TestProxy {
    options.local_address_present = present;
    let ctx = proxy::context(ca("Tollgate Test CA"), &Config::default(), None);
    proxy::start(ctx, options).await
}

/// Sends `GET url` in absolute form through the proxy and returns once the first body
/// frame is in. The client connection stays open while the returned values live.
async fn open_stream(proxy: std::net::SocketAddr, url: &str) -> (Sender1, Incoming) {
    let tcp = TcpStream::connect(proxy).await.unwrap();
    let mut sender = http1(tcp).await;
    let mut request = get(url, &[]);
    let host = request.uri().authority().unwrap().to_string();
    request.headers_mut().insert("host", host.parse().unwrap());
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let first = tokio::time::timeout(ENDS_WITHIN, body.frame())
        .await
        .expect("first event")
        .expect("body open")
        .expect("first frame");
    assert_eq!(first.into_data().unwrap(), "data: 1\n\n");
    (sender, body)
}

/// Waits for the body to end; panics if it is still open after [`ENDS_WITHIN`].
async fn ends(body: &mut Incoming) -> String {
    let deadline = tokio::time::Instant::now() + ENDS_WITHIN;
    loop {
        match tokio::time::timeout_at(deadline, body.frame()).await {
            Err(_) => panic!("the stream is still open"),
            Ok(None) => return "end".to_string(),
            Ok(Some(Err(e))) => return format!("error: {e}"),
            Ok(Some(Ok(_))) => {}
        }
    }
}

static H1_PRESENT: AtomicBool = AtomicBool::new(true);
fn h1_present(_: std::net::IpAddr) -> bool {
    H1_PRESENT.load(Ordering::SeqCst)
}

#[tokio::test]
async fn a_reset_ends_an_http1_stream_whose_address_is_gone() {
    let origin = origin::http().await;
    let proxy = start(ServeOptions::default(), h1_present).await;
    let url = format!("http://{}/drip", origin.addr);
    let (_sender, mut body) = open_stream(proxy.addr, &url).await;

    H1_PRESENT.store(false, Ordering::SeqCst);
    proxy.ctx.reset_upstream_connections();
    let ended = ends(&mut body).await;
    assert!(ended.starts_with("error"), "{ended}");

    // The origin sees the connection close, and the next request gets a new one.
    support::client::wait_for("the upstream connection to close", || origin.live() == 0).await;
    let reply = proxy_get(proxy.addr, &format!("http://{}/", origin.addr), &[]).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains(" conn=2 "), "{}", reply.body);
}

static H2_PRESENT: AtomicBool = AtomicBool::new(true);
fn h2_present(_: std::net::IpAddr) -> bool {
    H2_PRESENT.load(Ordering::SeqCst)
}

#[tokio::test]
async fn a_reset_ends_an_http2_stream_whose_address_is_gone() {
    let origin_ca = ca("Origin CA");
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2"]).await;
    let proxy = start(tls_origin::trusting(&origin_ca), h2_present).await;
    let base = format!("https://localhost:{}", origin.port());
    let reply = proxy_get(proxy.addr, &format!("{base}/"), &[]).await;
    assert!(
        reply.body.contains("version=HTTP/2.0 conn=1 "),
        "{}",
        reply.body
    );
    let (_sender, mut body) = open_stream(proxy.addr, &format!("{base}/drip")).await;
    assert_eq!(
        origin.connections(),
        1,
        "the stream shares the HTTP/2 connection"
    );

    H2_PRESENT.store(false, Ordering::SeqCst);
    proxy.ctx.reset_upstream_connections();
    let ended = ends(&mut body).await;
    assert!(ended.starts_with("error"), "{ended}");

    support::client::wait_for("the upstream connection to close", || origin.live() == 0).await;
    let reply = proxy_get(proxy.addr, &format!("{base}/"), &[]).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains(" conn=2 "), "{}", reply.body);
}

static KEPT_PRESENT: AtomicBool = AtomicBool::new(true);
fn kept_present(_: std::net::IpAddr) -> bool {
    KEPT_PRESENT.load(Ordering::SeqCst)
}

/// A reset alone (a wake, or a network change that kept the address) leaves streams alone.
#[tokio::test]
async fn a_reset_keeps_streams_whose_address_is_still_there() {
    let origin_ca = ca("Origin CA");
    let h2 = tls_origin::https(origin_ca.clone(), &[b"h2"]).await;
    let h1 = origin::http().await;
    let proxy = start(tls_origin::trusting(&origin_ca), kept_present).await;
    let (_s2, mut body2) = open_stream(
        proxy.addr,
        &format!("https://localhost:{}/drip?every=200", h2.port()),
    )
    .await;
    let (_s1, mut body1) =
        open_stream(proxy.addr, &format!("http://{}/drip?every=200", h1.addr)).await;

    proxy.ctx.reset_upstream_connections();
    // Past the second address check, 2 s after the reset.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    for body in [&mut body1, &mut body2] {
        for _ in 0..3 {
            let frame = tokio::time::timeout(ENDS_WITHIN, body.frame())
                .await
                .expect("the stream keeps going")
                .expect("body open")
                .expect("a frame");
            assert!(frame.into_data().unwrap().starts_with(b"data: "));
        }
    }
}

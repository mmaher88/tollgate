//! Plain HTTP requests sent to the proxy in absolute form.

mod support;

use std::sync::Arc;
use std::time::Duration;

use hyper::StatusCode;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tollgate_mitm::{CertAuthority, ServeOptions, accept_backoff};
use tollgate_policy::Config;

use support::client::{proxy_get, read_to_close, wait_for};
use support::{origin, proxy};

const RULES: &str = "\
/ads/*
/track/*$image
/banner/*$domain=news.test
";

fn ca() -> Arc<CertAuthority> {
    Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap())
}

async fn start(options: ServeOptions) -> proxy::TestProxy {
    proxy::start(
        proxy::context(ca(), &Config::default(), Some(RULES)),
        options,
    )
    .await
}

#[tokio::test]
async fn plain_request_is_forwarded_in_origin_form() {
    let origin = origin::http().await;
    let proxy = start(ServeOptions::default()).await;
    let url = format!("http://127.0.0.1:{}/hello?x=1", origin.port());

    let reply = proxy_get(proxy.addr, &url, &[("proxy-connection", "keep-alive")]).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.body,
        format!(
            "GET /hello?x=1 authority=127.0.0.1:{} version=HTTP/1.1 conn=1 cookie=",
            origin.port()
        )
    );
    assert_eq!(proxy.stats().http_requests, 1);
    assert_eq!(proxy.stats().http_blocked, 0);
}

#[tokio::test]
async fn blocked_request_gets_an_empty_403_readable_by_any_origin() {
    let origin = origin::http().await;
    let proxy = start(ServeOptions::default()).await;
    let url = format!("http://127.0.0.1:{}/ads/banner.js", origin.port());

    let reply = proxy_get(proxy.addr, &url, &[]).await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.headers["access-control-allow-origin"], "*");
    assert_eq!(reply.body, "");
    assert_eq!(
        origin.connections(),
        0,
        "blocked requests never reach the origin"
    );
    assert_eq!(proxy.stats().http_requests, 1);
    assert_eq!(proxy.stats().http_blocked, 1);
}

#[tokio::test]
async fn request_type_comes_from_fetch_dest_then_accept_then_extension() {
    let origin = origin::http().await;
    let proxy = start(ServeOptions::default()).await;
    let url = |path: &str| format!("http://127.0.0.1:{}{path}", origin.port());
    let status = async |path: &str, headers: &[(&str, &str)]| {
        proxy_get(proxy.addr, &url(path), headers).await.status
    };

    // `/track/*$image` blocks images only.
    let image = [("accept", "image/webp,*/*")];
    assert_eq!(status("/track/p", &image).await, StatusCode::FORBIDDEN);
    let html = [("accept", "text/html")];
    assert_eq!(status("/track/p", &html).await, StatusCode::OK);
    let dest_first = [("sec-fetch-dest", "image"), ("accept", "text/html")];
    assert_eq!(status("/track/p", &dest_first).await, StatusCode::FORBIDDEN);
    assert_eq!(status("/track/p.gif", &[]).await, StatusCode::FORBIDDEN);
    assert_eq!(status("/track/p", &[]).await, StatusCode::OK);
}

#[tokio::test]
async fn source_url_comes_from_referer_then_origin() {
    let origin = origin::http().await;
    let proxy = start(ServeOptions::default()).await;
    let url = format!("http://127.0.0.1:{}/banner/1.png", origin.port());
    let status = async |headers: &[(&str, &str)]| proxy_get(proxy.addr, &url, headers).await.status;

    // `/banner/*$domain=news.test` applies to requests made by news.test pages.
    let referer = [("referer", "http://news.test/article")];
    assert_eq!(status(&referer).await, StatusCode::FORBIDDEN);
    let origin_header = [("origin", "http://news.test")];
    assert_eq!(status(&origin_header).await, StatusCode::FORBIDDEN);
    let referer_first = [
        ("referer", "http://other.test/"),
        ("origin", "http://news.test"),
    ];
    assert_eq!(status(&referer_first).await, StatusCode::OK);
    assert_eq!(status(&[("origin", "null")]).await, StatusCode::OK);
    assert_eq!(status(&[]).await, StatusCode::OK);
}

#[tokio::test]
async fn upstream_connections_are_reused_across_clients() {
    let origin = origin::http().await;
    let proxy = start(ServeOptions::default()).await;
    let url = format!("http://127.0.0.1:{}/", origin.port());

    for _ in 0..3 {
        let reply = proxy_get(proxy.addr, &url, &[]).await;
        assert!(reply.body.contains(" conn=1 "), "{}", reply.body);
    }
    assert_eq!(origin.connections(), 1);
}

#[tokio::test]
async fn at_most_six_http1_connections_per_origin() {
    let origin = origin::http().await;
    let proxy = start(ServeOptions::default()).await;
    let url = format!("http://127.0.0.1:{}/?delay=300", origin.port());

    let requests: Vec<_> = (0..10)
        .map(|_| {
            let url = url.clone();
            let addr = proxy.addr;
            tokio::spawn(async move { proxy_get(addr, &url, &[]).await })
        })
        .collect();
    for request in requests {
        assert_eq!(request.await.unwrap().status, StatusCode::OK);
    }

    assert_eq!(origin.requests(), 10);
    assert_eq!(origin.max_live(), 6);
    assert_eq!(origin.connections(), 6);
}

#[tokio::test]
async fn idle_connections_make_room_under_the_global_limit() {
    let first = origin::http().await;
    let second = origin::http().await;
    let options = ServeOptions {
        max_upstream_connections: 1,
        ..ServeOptions::default()
    };
    let proxy = start(options).await;

    let first_url = format!("http://127.0.0.1:{}/", first.port());
    assert_eq!(
        proxy_get(proxy.addr, &first_url, &[]).await.status,
        StatusCode::OK
    );
    let second_url = format!("http://127.0.0.1:{}/", second.port());
    assert_eq!(
        proxy_get(proxy.addr, &second_url, &[]).await.status,
        StatusCode::OK
    );

    wait_for("the idle connection to the first origin to close", || {
        first.live() == 0
    })
    .await;
    assert_eq!(second.live(), 1);
}

#[tokio::test]
async fn unreachable_upstream_gets_502_and_bad_requests_400() {
    let proxy = start(ServeOptions::default()).await;
    let port = origin::closed_port().await;

    let reply = proxy_get(proxy.addr, &format!("http://127.0.0.1:{port}/"), &[]).await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);

    let mut tcp = TcpStream::connect(proxy.addr).await.unwrap();
    tcp.write_all(b"GET /relative HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_to_close(&mut tcp, Duration::from_secs(5))
        .await
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
}

#[tokio::test]
async fn idle_clients_are_disconnected() {
    let options = ServeOptions {
        idle_timeout: Duration::from_millis(300),
        ..ServeOptions::default()
    };
    let proxy = start(options).await;

    let mut silent = TcpStream::connect(proxy.addr).await.unwrap();
    let closed = read_to_close(&mut silent, Duration::from_secs(5)).await;
    assert_eq!(closed, Some(Vec::new()));
}

#[tokio::test]
async fn slow_request_headers_are_cut_off() {
    let options = ServeOptions {
        header_read_timeout: Duration::from_millis(300),
        ..ServeOptions::default()
    };
    let proxy = start(options).await;

    let mut slow = TcpStream::connect(proxy.addr).await.unwrap();
    slow.write_all(b"GET http://127.0.0.1/ HTTP/1.1\r\n")
        .await
        .unwrap();
    // hyper closes the connection without a response; the idle timeout is still 60 s.
    let closed = read_to_close(&mut slow, Duration::from_secs(5)).await;
    assert_eq!(closed, Some(Vec::new()));
}

#[tokio::test]
async fn shutdown_stops_the_listener() {
    let proxy = start(ServeOptions::default()).await;
    let addr = proxy.addr;
    let mut open = TcpStream::connect(addr).await.unwrap();

    proxy.stop().await;

    assert!(
        read_to_close(&mut open, Duration::from_secs(5))
            .await
            .is_some()
    );
    assert!(TcpStream::connect(addr).await.is_err());
}

#[test]
fn accept_backoff_doubles_from_10ms_to_1s() {
    let ms = |errors| accept_backoff(errors).as_millis();
    assert_eq!(ms(0), 0);
    assert_eq!(ms(1), 10);
    assert_eq!(ms(2), 20);
    assert_eq!(ms(7), 640);
    assert_eq!(ms(8), 1000);
    assert_eq!(ms(40), 1000);
    assert_eq!(ms(u32::MAX), 1000);
}

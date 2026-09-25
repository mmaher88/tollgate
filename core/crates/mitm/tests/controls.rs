//! The allowlist and the blocked log on the request path.

mod support;

use std::sync::Arc;

use hyper::StatusCode;
use tollgate_common::clock::unix_secs;
use tollgate_common::events::{BlockEvent, EventKind, EventLog};
use tollgate_mitm::{CertAuthority, ServeOptions};
use tollgate_policy::Config;

use support::client::proxy_get;
use support::tunnel::{connect, http2, send2, tls, tls_config};
use support::{client, origin, proxy, tls_origin};

const RULES: &str = "\
/ads/*
||ads.tollgate.test^
";

fn ca() -> Arc<CertAuthority> {
    Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap())
}

/// A plain-HTTP proxy with `RULES`, the given allowlist and a fresh event log.
async fn start(allowlist: &[&str]) -> (proxy::TestProxy, Arc<EventLog>) {
    let config = Config {
        allowlist: allowlist.iter().map(|s| s.to_string()).collect(),
        ..Config::default()
    };
    let events = Arc::new(EventLog::new());
    let mut ctx = proxy::context(ca(), &config, Some(RULES));
    ctx.events = Some(events.clone());
    (proxy::start(ctx, ServeOptions::default()).await, events)
}

#[tokio::test]
async fn blocked_request_is_recorded_with_its_page_host() {
    let origin = origin::http().await;
    let (proxy, events) = start(&[]).await;
    let url = format!("http://127.0.0.1:{}/ads/banner.js?id=7", origin.port());

    let before = unix_secs();
    let reply = proxy_get(
        proxy.addr,
        &url,
        &[("referer", "http://WWW.News.test:8080/article?x=1")],
    )
    .await;
    let after = unix_secs();

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let recorded = events.recent(10);
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    let event = &recorded[0];
    assert!((before..=after).contains(&event.unix_secs), "{event:?}");
    assert_eq!(
        *event,
        BlockEvent {
            unix_secs: event.unix_secs,
            kind: EventKind::Request,
            host: "127.0.0.1".into(),
            url: Some(url),
            source_host: Some("www.news.test".into()),
        }
    );
}

#[tokio::test]
async fn blocked_request_without_a_page_has_no_source_host() {
    let origin = origin::http().await;
    let (proxy, events) = start(&[]).await;
    let url = format!("http://127.0.0.1:{}/ads/1.js", origin.port());

    assert_eq!(
        proxy_get(proxy.addr, &url, &[]).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        proxy_get(proxy.addr, &url, &[("origin", "null")])
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let recorded = events.recent(10);
    assert_eq!(recorded.len(), 2);
    assert!(
        recorded.iter().all(|e| e.source_host.is_none()),
        "{recorded:?}"
    );
}

#[tokio::test]
async fn allowed_requests_are_not_recorded() {
    let origin = origin::http().await;
    let (proxy, events) = start(&[]).await;
    let url = format!("http://127.0.0.1:{}/page", origin.port());

    assert_eq!(
        proxy_get(proxy.addr, &url, &[]).await.status,
        StatusCode::OK
    );
    assert!(events.recent(10).is_empty());
}

#[tokio::test]
async fn allowlisted_page_host_allows_a_request_that_would_be_blocked() {
    let origin = origin::http().await;
    let (proxy, events) = start(&["*.news.test"]).await;
    let url = format!("http://127.0.0.1:{}/ads/banner.js", origin.port());

    let from_news = [("referer", "https://www.News.test/article")];
    assert_eq!(
        proxy_get(proxy.addr, &url, &from_news).await.status,
        StatusCode::OK
    );
    let from_origin_header = [("origin", "https://news.test")];
    assert_eq!(
        proxy_get(proxy.addr, &url, &from_origin_header)
            .await
            .status,
        StatusCode::OK
    );
    // Other pages, and no page at all, are still blocked.
    let from_other = [("referer", "https://fakenews.test/")];
    assert_eq!(
        proxy_get(proxy.addr, &url, &from_other).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        proxy_get(proxy.addr, &url, &[]).await.status,
        StatusCode::FORBIDDEN
    );

    let stats = proxy.stats();
    assert_eq!(stats.http_requests, 4);
    assert_eq!(stats.http_blocked, 2);
    assert_eq!(events.recent(10).len(), 2);
}

#[tokio::test]
async fn allowlisted_request_host_allows_a_request_that_would_be_blocked() {
    let origin = origin::http().await;
    let (proxy, events) = start(&["127.0.0.1"]).await;
    let url = format!("http://127.0.0.1:{}/ads/banner.js", origin.port());

    let reply = proxy_get(proxy.addr, &url, &[("referer", "https://news.test/")]).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(origin.requests(), 1);
    let stats = proxy.stats();
    assert_eq!(stats.http_requests, 1);
    assert_eq!(stats.http_blocked, 0);
    assert!(events.recent(10).is_empty());
}

/// Intercepted HTTPS: the host comes from the SNI, without the port.
#[tokio::test]
async fn intercepted_requests_are_recorded_and_allowlisted_by_host() {
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2", b"http/1.1"]).await;
    let target = format!("127.0.0.1:{}", origin.port());
    let url = |name: &str, path: &str| format!("https://{name}:{}{path}", origin.port());

    for (allowlist, expected) in [
        (&[][..], StatusCode::FORBIDDEN),
        (&["*.tollgate.test"][..], StatusCode::OK),
    ] {
        let ca = ca();
        let config = Config {
            allowlist: allowlist.iter().map(|s| s.to_string()).collect(),
            ..Config::default()
        };
        let events = Arc::new(EventLog::new());
        let mut ctx = proxy::context(ca.clone(), &config, Some(RULES));
        ctx.events = Some(events.clone());
        let proxy = proxy::start(ctx, tls_origin::trusting(&origin_ca)).await;

        let tcp = connect(proxy.addr, &target).await;
        let tls = tls(tcp, tls_config(&[&ca], &[b"h2"]), "ads.tollgate.test")
            .await
            .unwrap();
        let mut h2 = http2(tls).await;
        let request_url = url("ads.tollgate.test", "/banner.js");
        let request = client::get(&request_url, &[("referer", "https://news.test/a")]);
        let reply = send2(&mut h2, request).await;

        assert_eq!(reply.status, expected, "allowlist {allowlist:?}");
        let recorded = events.recent(10);
        if expected == StatusCode::OK {
            assert!(recorded.is_empty(), "{recorded:?}");
        } else {
            assert_eq!(recorded.len(), 1);
            assert_eq!(recorded[0].kind, EventKind::Request);
            assert_eq!(recorded[0].host, "ads.tollgate.test");
            assert_eq!(recorded[0].url.as_deref(), Some(request_url.as_str()));
            assert_eq!(recorded[0].source_host.as_deref(), Some("news.test"));
        }
        assert_eq!(proxy.stats().http_requests, 1);
        proxy.stop().await;
    }
}

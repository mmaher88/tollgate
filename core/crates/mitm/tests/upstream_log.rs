//! The info lines, which the tunnel's log shows, for failed upstream requests: a server
//! whose certificate the client would reject too, and an unreachable host, are named at
//! most once a minute each. One test function: the logger is process-wide, so the steps
//! must not run in parallel.

mod support;

use std::sync::{Arc, Mutex};

use hyper::StatusCode;
use log::{Level, LevelFilter, Log, Metadata, Record};
use tokio::net::TcpListener;
use tollgate_mitm::CertAuthority;
use tollgate_policy::Config;

use support::client::{get, proxy_try_get};
use support::tunnel::{connect, http2, send2, tls, tls_config};
use support::{proxy, tls_origin};

/// Keeps the messages this crate logs at info level or above.
struct Capture(Mutex<Vec<String>>);

impl Log for Capture {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info && metadata.target().starts_with("tollgate_mitm")
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            self.0.lock().unwrap().push(record.args().to_string());
        }
    }

    fn flush(&self) {}
}

static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));

/// The lines logged since the last call that start with `upstream `.
fn upstream_lines() -> Vec<String> {
    let lines = std::mem::take(&mut *CAPTURE.0.lock().unwrap());
    lines
        .into_iter()
        .filter(|line| line.starts_with("upstream "))
        .collect()
}

fn ca(name: &str) -> Arc<CertAuthority> {
    Arc::new(CertAuthority::generate(name).unwrap())
}

#[tokio::test]
async fn upstream_failures_that_name_a_host_are_logged_at_info() {
    log::set_logger(&CAPTURE).unwrap();
    log::set_max_level(LevelFilter::Debug);
    let origin_ca = ca("Origin CA");
    let tollgate_ca = ca("Tollgate Test CA");
    let ctx = proxy::context(tollgate_ca.clone(), &Config::default(), None);
    let proxy = proxy::start(ctx, tls_origin::trusting(&origin_ca)).await;

    // An app's requests on an intercepted connection to a server whose certificate is for
    // another name get the text 502, and the host is named once.
    let origin = tls_origin::for_name(origin_ca.clone(), "elsewhere.tollgate.test").await;
    let authority = format!("localhost:{}", origin.port());
    let tcp = connect(proxy.addr, &authority).await;
    let client = tls(tcp, tls_config(&[&tollgate_ca], &[b"h2"]), "localhost")
        .await
        .unwrap();
    let mut h2 = http2(client).await;
    let url = format!("https://{authority}/");
    for _ in 0..3 {
        let reply = send2(&mut h2, get(&url, &[])).await;
        assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    }
    let lines = upstream_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let expected = format!("upstream {authority}: certificate rejected (connecting: ");
    assert!(lines[0].starts_with(&expected), "{lines:?}");
    assert!(
        lines[0].contains(r#"certificate not valid for name "localhost""#),
        "{lines:?}"
    );
    assert!(proxy.ctx.policy.learned_pins().is_empty());
    assert_eq!(origin.requests(), 0);

    // An unreachable host, still named with the words log scans look for.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    for _ in 0..2 {
        let url = format!("https://127.0.0.1:{port}/");
        assert!(proxy_try_get(proxy.addr, &url, &[]).await.is_none());
    }
    let lines = upstream_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let expected = format!("upstream 127.0.0.1:{port}: unreachable (");
    assert!(lines[0].starts_with(&expected), "{lines:?}");

    // A certificate the proxy cannot verify is learned as a pin, which is logged on its own
    // line, not as an upstream failure.
    let other = tls_origin::for_name(ca("Other CA"), "localhost").await;
    let url = format!("https://localhost:{}/", other.port());
    let tcp = connect(proxy.addr, &format!("localhost:{}", other.port())).await;
    let client = tls(tcp, tls_config(&[&tollgate_ca], &[b"h2"]), "localhost")
        .await
        .unwrap();
    let mut h2 = http2(client).await;
    assert!(h2.send_request(get(&url, &[])).await.is_err());
    assert!(upstream_lines().is_empty());
    assert_eq!(proxy.ctx.policy.learned_pins().len(), 1);
}

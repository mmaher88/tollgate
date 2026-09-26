//! WebSocket upgrades on intercepted connections go over their own HTTP/1.1 upstream.

mod support;

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tollgate_mitm::CertAuthority;
use tollgate_policy::Config;

use support::client::{get, http1, read_reply};
use support::tunnel::{connect, tls, tls_config};
use support::{proxy, tls_origin};

const RULES: &str = "||ws.tollgate.test^*/blocked$websocket\n";
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// Answers `101` to WebSocket upgrades and echoes every byte afterwards; other requests
/// get `200 plain <version>`.
async fn echo_origin(ca: Arc<CertAuthority>) -> u16 {
    let key = ca.leaf("ws.tollgate.test").unwrap();
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(key)));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = service_fn(handle);
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    port
}

async fn handle(mut request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    if !request.headers().contains_key("upgrade") {
        let body = format!("plain {:?}", request.version());
        return Ok(Response::new(Full::new(Bytes::from(body))));
    }
    let key = request.headers()["sec-websocket-key"]
        .to_str()
        .unwrap()
        .to_string();
    let upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        let mut io = TokioIo::new(upgrade.await.unwrap());
        let mut buf = [0u8; 1024];
        loop {
            match io.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => io.write_all(&buf[..n]).await.unwrap(),
            }
        }
    });
    let response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("upgrade", "websocket")
        .header("connection", "upgrade")
        .header("sec-websocket-accept", format!("accept-{key}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    Ok(response)
}

fn upgrade_request(path: &str) -> Request<http_body_util::Empty<Bytes>> {
    get(
        path,
        &[
            ("host", "ws.tollgate.test"),
            ("connection", "Upgrade"),
            ("upgrade", "websocket"),
            ("sec-websocket-key", KEY),
            ("sec-websocket-version", "13"),
        ],
    )
}

#[tokio::test]
async fn websocket_is_forwarded_and_echoes() {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let port = echo_origin(origin_ca.clone()).await;
    let ctx = proxy::context(ca.clone(), &Config::default(), Some(RULES));
    let proxy = proxy::start(ctx, tls_origin::trusting(&origin_ca)).await;

    let tcp = connect(proxy.addr, &format!("127.0.0.1:{port}")).await;
    let tls = tls(tcp, tls_config(&[&ca], &[b"http/1.1"]), "ws.tollgate.test")
        .await
        .unwrap();
    let mut h1 = http1(tls).await;
    let mut response = h1.send_request(upgrade_request("/chat")).await.unwrap();

    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(
        response.headers()["sec-websocket-accept"],
        format!("accept-{KEY}")
    );
    assert_eq!(response.headers()["upgrade"], "websocket");
    let mut socket = TokioIo::new(hyper::upgrade::on(&mut response).await.unwrap());
    socket.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    socket.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
}

#[tokio::test]
async fn websocket_rules_block_upgrades_only() {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let port = echo_origin(origin_ca.clone()).await;
    let ctx = proxy::context(ca.clone(), &Config::default(), Some(RULES));
    let proxy = proxy::start(ctx, tls_origin::trusting(&origin_ca)).await;

    let tcp = connect(proxy.addr, &format!("127.0.0.1:{port}")).await;
    let tls = tls(tcp, tls_config(&[&ca], &[b"http/1.1"]), "ws.tollgate.test")
        .await
        .unwrap();
    let mut h1 = http1(tls).await;

    let plain = get("/blocked", &[("host", "ws.tollgate.test")]);
    let reply = read_reply(h1.send_request(plain).await.unwrap()).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, "plain HTTP/2.0");

    let reply = read_reply(h1.send_request(upgrade_request("/blocked")).await.unwrap()).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(proxy.stats().http_blocked, 1);
}

static WS_ADDRESS_PRESENT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

fn ws_address_present(_: std::net::IpAddr) -> bool {
    WS_ADDRESS_PRESENT.load(std::sync::atomic::Ordering::SeqCst)
}

/// A WebSocket relay has no idle limit, so after a network change it would stay open on
/// a dead path until the page's own heartbeat notices. A reset closes it when its upstream
/// source address is gone, and keeps it otherwise.
#[tokio::test]
async fn a_reset_closes_websockets_whose_source_address_is_gone() {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let port = echo_origin(origin_ca.clone()).await;
    let ctx = proxy::context(ca.clone(), &Config::default(), Some(RULES));
    let mut options = tls_origin::trusting(&origin_ca);
    options.local_address_present = ws_address_present;
    let proxy = proxy::start(ctx, options).await;

    let tcp = connect(proxy.addr, &format!("127.0.0.1:{port}")).await;
    let tls = tls(tcp, tls_config(&[&ca], &[b"http/1.1"]), "ws.tollgate.test")
        .await
        .unwrap();
    let mut h1 = http1(tls).await;
    let mut response = h1.send_request(upgrade_request("/chat")).await.unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    let mut socket = TokioIo::new(hyper::upgrade::on(&mut response).await.unwrap());

    proxy.ctx.reset_upstream_connections();
    tokio::time::sleep(Duration::from_millis(50)).await;
    socket.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    socket.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping", "a healthy WebSocket survives a reset");

    WS_ADDRESS_PRESENT.store(false, Ordering::SeqCst);
    proxy.ctx.reset_upstream_connections();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), socket.read(&mut byte)).await;
    assert!(
        matches!(read, Ok(Ok(0) | Err(_))),
        "the WebSocket is closed: {read:?}"
    );
}

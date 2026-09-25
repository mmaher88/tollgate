//! What the proxy learns from the first bytes after `CONNECT`: non-TLS traffic and silent
//! clients are tunneled, and the SNI and ALPN of a ClientHello can still turn an
//! interception into a tunnel. Every byte read to decide is replayed to the origin.

mod support;

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tollgate_mitm::{CertAuthority, ServeOptions};
use tollgate_policy::Config;

use support::tunnel::{connect, issuer_via, peer_issuer, tls, tls_config};
use support::{origin, proxy, tls_origin};

const TOLLGATE: &str = "CN=Tollgate Test CA, O=Tollgate";
const ORIGIN: &str = "CN=Origin CA, O=Tollgate";

struct Setup {
    ca: Arc<CertAuthority>,
    origin_ca: Arc<CertAuthority>,
    origin: origin::Origin,
    proxy: proxy::TestProxy,
}

impl Setup {
    fn target(&self) -> String {
        format!("127.0.0.1:{}", self.origin.port())
    }

    /// The issuer a client trusting both CAs sees for `name`.
    async fn issuer_for(&self, name: &str) -> String {
        let roots = [&*self.ca, &*self.origin_ca];
        issuer_via(self.proxy.addr, &self.target(), &roots, name).await
    }
}

/// The origin also offers `imap`, so a client asking only for it can finish a handshake.
async fn setup(config: Config, options: ServeOptions) -> Setup {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2", b"http/1.1", b"imap"]).await;
    let ctx = proxy::context(ca.clone(), &config, None);
    let options = ServeOptions {
        upstream_tls: tls_origin::trusting(&origin_ca).upstream_tls,
        ..options
    };
    let proxy = proxy::start(ctx, options).await;
    Setup {
        ca,
        origin_ca,
        origin,
        proxy,
    }
}

#[tokio::test]
async fn sni_passthrough_replays_the_client_hello() {
    let config = Config {
        passthrough: vec!["*.bank.tollgate.test".to_string()],
        ..Config::default()
    };
    let s = setup(config, ServeOptions::default()).await;

    assert_eq!(s.issuer_for("login.bank.tollgate.test").await, ORIGIN);
    assert_eq!(s.issuer_for("www.tollgate.test").await, TOLLGATE);
    let stats = s.proxy.stats();
    assert_eq!(stats.connections_passthrough, 1);
    assert_eq!(stats.connections_intercepted, 1);
}

#[tokio::test]
async fn bundled_sni_passes_through() {
    let s = setup(Config::default(), ServeOptions::default()).await;
    assert_eq!(s.issuer_for("www.apple.com").await, ORIGIN);
    assert_eq!(s.issuer_for("gateway.icloud.com").await, ORIGIN);
}

#[tokio::test]
async fn tls_without_an_http_protocol_passes_through() {
    let s = setup(Config::default(), ServeOptions::default()).await;
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let config = tls_config(&[&s.origin_ca], &[b"imap"]);

    let tls = tls(tcp, config, "mail.tollgate.test").await.unwrap();

    assert_eq!(peer_issuer(&tls), ORIGIN);
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"imap"[..]));
}

#[tokio::test]
async fn plain_http_inside_connect_is_tunneled_with_its_first_bytes() {
    let s = setup(Config::default(), ServeOptions::default()).await;
    let plain = origin::http().await;
    let mut tcp = connect(s.proxy.addr, &format!("127.0.0.1:{}", plain.port())).await;

    tcp.write_all(b"GET /inside HTTP/1.1\r\nHost: plain.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    tcp.read_to_string(&mut response).await.unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    let line = "GET /inside authority=plain.test version=HTTP/1.1 conn=1 cookie=";
    assert!(response.ends_with(line), "{response}");
    assert_eq!(s.proxy.stats().connections_passthrough, 1);
}

#[tokio::test]
async fn silent_client_gets_a_tunnel_for_server_first_protocols() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        tcp.write_all(b"220 mail.tollgate.test ESMTP\r\n")
            .await
            .unwrap();
        let mut rest = Vec::new();
        let _ = tcp.read_to_end(&mut rest).await;
    });
    let options = ServeOptions {
        first_bytes_timeout: Duration::from_millis(200),
        ..ServeOptions::default()
    };
    let s = setup(Config::default(), options).await;

    let mut tcp = connect(s.proxy.addr, &format!("127.0.0.1:{port}")).await;
    let mut banner = [0u8; 30];
    tokio::time::timeout(Duration::from_secs(5), tcp.read_exact(&mut banner))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&banner, b"220 mail.tollgate.test ESMTP\r\n");
    assert_eq!(s.proxy.stats().connections_passthrough, 1);
}

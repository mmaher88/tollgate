//! `CONNECT` tunnels decided before or without interception: passthrough hosts, MITM
//! switched off, low memory, a full interception table, the cap on tunnels and their idle
//! timeout.

mod support;

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tollgate_mitm::{CertAuthority, ProxyContext, ServeOptions};
use tollgate_policy::Config;

use support::origin::closed_port;
use support::tunnel::{connect, connect_status, issuer_via, tls, tls_config};
use support::{proxy, tls_origin};

const TOLLGATE: &str = "CN=Tollgate Test CA, O=Tollgate";
const ORIGIN: &str = "CN=Origin CA, O=Tollgate";

struct Setup {
    ca: Arc<CertAuthority>,
    origin_ca: Arc<CertAuthority>,
    origin: support::origin::Origin,
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

async fn setup(config: Config, edit: impl FnOnce(&mut ProxyContext)) -> Setup {
    setup_with(config, edit, |_| {}).await
}

async fn setup_with(
    config: Config,
    edit: impl FnOnce(&mut ProxyContext),
    edit_options: impl FnOnce(&mut ServeOptions),
) -> Setup {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2", b"http/1.1"]).await;
    let mut ctx = proxy::context(ca.clone(), &config, None);
    edit(&mut ctx);
    let mut options = tls_origin::trusting(&origin_ca);
    edit_options(&mut options);
    let proxy = proxy::start(ctx, options).await;
    Setup {
        ca,
        origin_ca,
        origin,
        proxy,
    }
}

#[tokio::test]
async fn passthrough_connect_host_is_tunneled_untouched() {
    let config = Config {
        passthrough: vec!["127.0.0.1".to_string()],
        ..Config::default()
    };
    let s = setup(config, |_| {}).await;

    assert_eq!(s.issuer_for("www.tollgate.test").await, ORIGIN);
    let stats = s.proxy.stats();
    assert_eq!(stats.connections_passthrough, 1);
    assert_eq!(stats.connections_intercepted, 0);
}

#[tokio::test]
async fn nothing_is_intercepted_when_mitm_is_off() {
    let config = Config {
        mitm_enabled: false,
        ..Config::default()
    };
    let s = setup(config, |_| {}).await;
    assert_eq!(s.issuer_for("www.tollgate.test").await, ORIGIN);
}

#[tokio::test]
async fn unreachable_passthrough_host_gets_502() {
    let config = Config {
        passthrough: vec!["127.0.0.1".to_string()],
        ..Config::default()
    };
    let s = setup(config, |_| {}).await;
    let port = closed_port().await;

    let (status, _) = connect_status(s.proxy.addr, &format!("127.0.0.1:{port}")).await;
    assert_eq!(status, 502);
    assert_eq!(s.proxy.stats().connections_passthrough, 0);
}

#[tokio::test]
async fn low_memory_passes_new_connections_through() {
    let low = setup(Config::default(), |ctx| {
        ctx.available_memory = || Some(8 * 1024 * 1024 - 1);
    })
    .await;
    assert_eq!(low.issuer_for("www.tollgate.test").await, ORIGIN);

    let enough = setup(Config::default(), |ctx| {
        ctx.available_memory = || Some(8 * 1024 * 1024);
    })
    .await;
    assert_eq!(enough.issuer_for("www.tollgate.test").await, TOLLGATE);
}

#[tokio::test]
async fn connections_above_the_cap_pass_through() {
    let s = setup(Config::default(), |ctx| ctx.max_intercepted = 1).await;
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let held = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), "www.tollgate.test")
        .await
        .unwrap();

    assert_eq!(s.issuer_for("www.tollgate.test").await, ORIGIN);
    assert_eq!(s.proxy.stats().connections_passthrough, 1);

    drop(held);
    let mut issuer = String::new();
    for _ in 0..100 {
        issuer = s.issuer_for("www.tollgate.test").await;
        if issuer == TOLLGATE {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        issuer, TOLLGATE,
        "interception resumes once the slot is free"
    );
}

/// A TCP origin that accepts connections and echoes what it reads, or stays silent.
async fn raw_origin(echo: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut tcp, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                loop {
                    match tcp.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) if echo => {
                            if tcp.write_all(&buffer[..n]).await.is_err() {
                                return;
                            }
                        }
                        Ok(_) => {}
                    }
                }
            });
        }
    });
    port
}

/// Passthrough by `CONNECT` host: `localhost`, while `127.0.0.1` is intercepted.
fn localhost_passes_through() -> Config {
    Config {
        passthrough: vec!["localhost".to_string(), "pinned.tollgate.test".to_string()],
        ..Config::default()
    }
}

#[tokio::test]
async fn passthrough_tunnels_above_the_cap_are_refused() {
    let s = setup_with(
        localhost_passes_through(),
        |_| {},
        |options| {
            options.max_passthrough = 1;
        },
    )
    .await;
    let passthrough = format!("localhost:{}", s.origin.port());

    let held = connect(s.proxy.addr, &passthrough).await;
    let (status, _) = connect_status(s.proxy.addr, &passthrough).await;
    assert_eq!(status, 503, "a passthrough host over the cap is refused");

    // Passed through after reading the ClientHello: the client is closed instead.
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let config = tls_config(&[&s.ca, &s.origin_ca], &[b"h2"]);
    assert!(tls(tcp, config, "pinned.tollgate.test").await.is_err());
    assert_eq!(s.proxy.stats().connections_passthrough, 1);

    // Interception does not use the tunnel cap.
    assert_eq!(s.issuer_for("www.tollgate.test").await, TOLLGATE);

    drop(held);
    let mut status = 0;
    for _ in 0..100 {
        (status, _) = connect_status(s.proxy.addr, &passthrough).await;
        if status == 200 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(status, 200, "a closed tunnel frees its slot");
}

#[tokio::test]
async fn idle_tunnels_are_closed_and_free_their_slot() {
    let s = setup_with(
        localhost_passes_through(),
        |_| {},
        |options| {
            options.max_passthrough = 1;
            options.tunnel_idle_timeout = Duration::from_millis(300);
        },
    )
    .await;
    let silent = format!("localhost:{}", raw_origin(false).await);

    let mut idle = connect(s.proxy.addr, &silent).await;
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), idle.read(&mut byte)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_))),
        "the idle tunnel is closed: {read:?}"
    );

    let mut status = 0;
    for _ in 0..100 {
        (status, _) = connect_status(s.proxy.addr, &silent).await;
        if status == 200 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(status, 200, "the idle tunnel's slot is free again");
}

#[tokio::test]
async fn busy_tunnels_outlive_the_idle_timeout() {
    let s = setup_with(
        localhost_passes_through(),
        |_| {},
        |options| {
            options.tunnel_idle_timeout = Duration::from_millis(300);
        },
    )
    .await;
    let echo = format!("localhost:{}", raw_origin(true).await);

    let mut tunnel = connect(s.proxy.addr, &echo).await;
    for i in 0..10u8 {
        tunnel.write_all(&[i]).await.unwrap();
        let mut byte = [0u8; 1];
        tunnel.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte[0], i);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

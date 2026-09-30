//! `CONNECT` tunnels decided before or without interception: passthrough hosts, MITM
//! switched off, low memory, a full interception table, the cap on tunnels and their idle
//! timeout.

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tollgate_common::resolve::{LookupFuture, Resolve};
use tollgate_mitm::{CertAuthority, ProxyContext, ServeOptions};
use tollgate_policy::Config;

use support::client::wait_for;
use support::origin::closed_port;
use support::tunnel::{connect, connect_status, issuer_via, peer_issuer, tls, tls_config};
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

/// A passthrough host gets `200` before it is dialed. When it cannot be reached, the
/// client connection is closed, so the client's TLS handshake fails, and the slot is free
/// again.
#[tokio::test]
async fn an_unreachable_passthrough_host_gets_its_connection_closed() {
    let config = Config {
        passthrough: vec!["127.0.0.1".to_string()],
        ..Config::default()
    };
    let s = setup_with(config, |_| {}, |options| options.max_passthrough = 1).await;
    let port = closed_port().await;

    let (status, tcp) = connect_status(s.proxy.addr, &format!("127.0.0.1:{port}")).await;
    assert_eq!(status, 200);
    let config = tls_config(&[&s.ca, &s.origin_ca], &[b"h2"]);
    assert!(tls(tcp, config, "www.tollgate.test").await.is_err());
    assert_eq!(s.proxy.stats().connections_passthrough, 0);

    // The one passthrough slot was given back.
    let mut issuer = String::new();
    for _ in 0..100 {
        issuer = s.issuer_for("www.tollgate.test").await;
        if issuer == ORIGIN {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(issuer, ORIGIN);
    assert_eq!(s.proxy.stats().connections_passthrough, 1);
}

/// Resolves every name to 127.0.0.1 after a delay, like a slow DNS lookup.
#[derive(Debug)]
struct SlowLookup(Duration);

impl Resolve for SlowLookup {
    fn lookup<'a>(&'a self, _host: &'a str) -> LookupFuture<'a> {
        Box::pin(async move {
            tokio::time::sleep(self.0).await;
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        })
    }
}

/// The dial (here a lookup that takes 300 ms) no longer delays the `200`: the client
/// starts its TLS handshake meanwhile, and the handshake completes with the origin once
/// the tunnel is up.
#[tokio::test]
async fn a_passthrough_host_gets_200_before_it_is_dialed() {
    let lookup = Duration::from_millis(300);
    let s = setup_with(
        localhost_passes_through(),
        |_| {},
        |options| options.resolver = Some(Arc::new(SlowLookup(lookup))),
    )
    .await;
    let target = format!("pinned.tollgate.test:{}", s.origin.port());

    let start = Instant::now();
    let (status, tcp) = connect_status(s.proxy.addr, &target).await;
    assert_eq!(status, 200);
    assert!(
        start.elapsed() < lookup,
        "answered after {:?}",
        start.elapsed()
    );
    let config = tls_config(&[&s.ca, &s.origin_ca], &[b"h2"]);
    let tls = tls(tcp, config, "pinned.tollgate.test").await.unwrap();
    assert_eq!(peer_issuer(&tls), ORIGIN);
    assert!(start.elapsed() >= lookup, "{:?}", start.elapsed());
    assert_eq!(s.proxy.stats().connections_passthrough, 1);
}

/// A passthrough host holds its slot while it is dialed, so the cap counts it.
#[tokio::test]
async fn a_passthrough_host_holds_its_slot_while_it_is_dialed() {
    let s = setup_with(
        localhost_passes_through(),
        |_| {},
        |options| {
            options.max_passthrough = 1;
            options.resolver = Some(Arc::new(SlowLookup(Duration::from_millis(300))));
        },
    )
    .await;
    let target = format!("pinned.tollgate.test:{}", s.origin.port());

    let (status, _dialing) = connect_status(s.proxy.addr, &target).await;
    assert_eq!(status, 200);
    let (status, _) = connect_status(s.proxy.addr, &target).await;
    assert_eq!(status, 503);
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
    // Answered before it is dialed; counted once the dial is done.
    wait_for("the held tunnel to be up", || {
        s.proxy.stats().connections_passthrough == 1
    })
    .await;
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

static TUNNEL_ADDRESS_PRESENT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

fn tunnel_address_present(_: std::net::IpAddr) -> bool {
    TUNNEL_ADDRESS_PRESENT.load(std::sync::atomic::Ordering::SeqCst)
}

async fn echoes(tunnel: &mut tokio::net::TcpStream, byte: u8) -> bool {
    if tunnel.write_all(&[byte]).await.is_err() {
        return false;
    }
    let mut got = [0u8; 1];
    matches!(
        tokio::time::timeout(Duration::from_secs(2), tunnel.read_exact(&mut got)).await,
        Ok(Ok(_)) if got[0] == byte
    )
}

async fn closes_within(tunnel: &mut tokio::net::TcpStream, limit: Duration) -> bool {
    let mut byte = [0u8; 1];
    matches!(
        tokio::time::timeout(limit, tunnel.read(&mut byte)).await,
        Ok(Ok(0) | Err(_))
    )
}

/// After a wake or a network change, a passthrough tunnel whose upstream socket's source
/// address is gone is closed, so the app reconnects on the new path instead of sending
/// into a dead one. Tunnels whose address is still there keep going.
#[tokio::test]
async fn a_reset_closes_tunnels_whose_source_address_is_gone() {
    use std::sync::atomic::Ordering;

    let s = setup_with(
        localhost_passes_through(),
        |_| {},
        |options| options.local_address_present = tunnel_address_present,
    )
    .await;
    let echo = format!("localhost:{}", raw_origin(true).await);

    // A reset while the address is still assigned keeps the tunnel.
    let mut kept = connect(s.proxy.addr, &echo).await;
    assert!(echoes(&mut kept, 1).await);
    s.proxy.ctx.reset_upstream_connections();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        echoes(&mut kept, 2).await,
        "a healthy tunnel survives a reset"
    );

    // The address can disappear a moment after the path change: checked again shortly.
    TUNNEL_ADDRESS_PRESENT.store(false, Ordering::SeqCst);
    assert!(
        closes_within(&mut kept, Duration::from_secs(5)).await,
        "closed once its address is gone"
    );

    // A tunnel whose address is gone at the reset is closed at once.
    TUNNEL_ADDRESS_PRESENT.store(true, Ordering::SeqCst);
    let mut gone = connect(s.proxy.addr, &echo).await;
    assert!(echoes(&mut gone, 3).await);
    TUNNEL_ADDRESS_PRESENT.store(false, Ordering::SeqCst);
    s.proxy.ctx.reset_upstream_connections();
    assert!(closes_within(&mut gone, Duration::from_millis(500)).await);
}

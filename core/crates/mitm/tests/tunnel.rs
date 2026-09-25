//! `CONNECT` tunnels decided before or without interception: passthrough hosts, MITM
//! switched off, low memory and a full interception table.

mod support;

use std::sync::Arc;
use std::time::Duration;

use tollgate_mitm::{CertAuthority, ProxyContext};
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
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2", b"http/1.1"]).await;
    let mut ctx = proxy::context(ca.clone(), &config, None);
    edit(&mut ctx);
    let proxy = proxy::start(ctx, tls_origin::trusting(&origin_ca)).await;
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

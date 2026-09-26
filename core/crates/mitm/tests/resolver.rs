//! Upstream host names are looked up with the configured resolver (DoH in the tunnel), and
//! with the system resolver when it finds nothing or its addresses do not answer.

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hyper::StatusCode;
use tollgate_common::resolve::{LookupFuture, Resolve};
use tollgate_mitm::{CertAuthority, ServeOptions};
use tollgate_policy::Config;

use support::client::proxy_get;
use support::tunnel::connect_status;
use support::{origin, proxy};

/// Answers every name with `addresses` and counts the lookups.
#[derive(Debug)]
struct Fixed {
    addresses: Vec<IpAddr>,
    lookups: AtomicUsize,
}

impl Resolve for Fixed {
    fn lookup<'a>(&'a self, _host: &'a str) -> LookupFuture<'a> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { self.addresses.clone() })
    }
}

fn fixed(addresses: &[[u8; 4]]) -> Arc<Fixed> {
    Arc::new(Fixed {
        addresses: addresses
            .iter()
            .map(|a| IpAddr::V4(Ipv4Addr::from(*a)))
            .collect(),
        lookups: AtomicUsize::new(0),
    })
}

async fn start(resolver: Arc<Fixed>, config: Config) -> proxy::TestProxy {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let ctx = proxy::context(ca, &config, None);
    let options = ServeOptions {
        resolver: Some(resolver),
        ..ServeOptions::default()
    };
    proxy::start(ctx, options).await
}

#[tokio::test]
async fn pooled_and_tunneled_connections_use_the_resolver() {
    let origin = origin::http().await;
    let resolver = fixed(&[[127, 0, 0, 1]]);
    let config = Config {
        passthrough: vec!["tunnel.tollgate.test".to_string()],
        ..Config::default()
    };
    let proxy = start(resolver.clone(), config).await;

    // Names only the resolver knows.
    let url = format!("http://origin.tollgate.test:{}/", origin.port());
    let reply = proxy_get(proxy.addr, &url, &[]).await;
    assert_eq!(reply.status, StatusCode::OK);
    let target = format!("tunnel.tollgate.test:{}", origin.port());
    let (status, _) = connect_status(proxy.addr, &target).await;
    assert_eq!(status, 200);
    assert_eq!(resolver.lookups.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_system_resolver_is_the_fallback() {
    let origin = origin::http().await;
    let url = format!("http://localhost:{}/", origin.port());

    // Nothing found.
    let proxy = start(fixed(&[]), Config::default()).await;
    assert_eq!(
        proxy_get(proxy.addr, &url, &[]).await.status,
        StatusCode::OK
    );

    // Found, but nothing listens there.
    let proxy = start(fixed(&[[127, 0, 0, 2]]), Config::default()).await;
    assert_eq!(
        proxy_get(proxy.addr, &url, &[]).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn addresses_are_not_looked_up() {
    let origin = origin::http().await;
    let resolver = fixed(&[[127, 0, 0, 2]]);
    let proxy = start(resolver.clone(), Config::default()).await;
    let url = format!("http://127.0.0.1:{}/", origin.port());
    assert_eq!(
        proxy_get(proxy.addr, &url, &[]).await.status,
        StatusCode::OK
    );
    assert_eq!(resolver.lookups.load(Ordering::SeqCst), 0);
}

//! Starting a proxy for a test.

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tollgate_common::stats::{Stats, StatsSnapshot};
use tollgate_filter::{FilterEngine, ListFormat, ListSource};
use tollgate_mitm::{CertAuthority, ProxyContext, ServeOptions, serve_with_options};
use tollgate_policy::{Config, Policy};

pub struct TestProxy {
    pub addr: SocketAddr,
    pub ctx: Arc<ProxyContext>,
    stop: Option<oneshot::Sender<()>>,
    pub task: JoinHandle<()>,
}

impl TestProxy {
    pub fn stats(&self) -> StatsSnapshot {
        self.ctx.stats.snapshot()
    }

    /// Resolves the shutdown future and waits for `serve` to return.
    pub async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.task.await.unwrap();
    }
}

/// A context with a fresh policy for `config`, and a filter engine when `rules` is given.
/// Memory is unknown, 32 connections may be intercepted and no events are recorded.
pub fn context(ca: Arc<CertAuthority>, config: &Config, rules: Option<&str>) -> ProxyContext {
    let filter = rules.map(|text| {
        let list = ListSource {
            name: "test",
            text,
            format: ListFormat::Adblock,
        };
        Arc::new(FilterEngine::from_lists(&[list], false))
    });
    ProxyContext {
        policy: Arc::new(Policy::new(config, None).unwrap()),
        filter: ArcSwapOption::new(filter),
        domains: ArcSwapOption::empty(),
        ca,
        stats: Arc::new(Stats::default()),
        max_intercepted: config.max_intercepted_connections as usize,
        available_memory: || None,
        events: None,
        upstream_resets: Default::default(),
    }
}

pub async fn start(ctx: ProxyContext, options: ServeOptions) -> TestProxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ctx = Arc::new(ctx);
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(serve_with_options(
        listener,
        ctx.clone(),
        options,
        async move {
            let _ = stopped.await;
        },
    ));
    TestProxy {
        addr,
        ctx,
        stop: Some(stop),
        task,
    }
}

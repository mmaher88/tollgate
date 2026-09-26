//! The proxy's listener, its shared state and the first request on each connection.

use std::convert::Infallible;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use rustls::crypto::CryptoProvider;
use rustls::server::{ServerSessionMemoryCache, StoresServerSessions};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tollgate_common::events::EventLog;
use tollgate_common::stats::Stats;
use tollgate_filter::{DomainSet, FilterEngine};
use tollgate_policy::Policy;

use crate::body::{Body, DoneBody};
use crate::idle::{self, Activity, InFlight};
use crate::limits::{
    H1_MAX_BUF, H2_CONNECTION_WINDOW, H2_MAX_SEND_BUF, H2_STREAM_WINDOW, KEEP_ALIVE_TIMEOUT,
    MAX_HEADER_LIST, MAX_HEADERS, MIN_IDLE_TO_RECLAIM,
};
use crate::shutdown::{self, Shutdown};
use crate::upstream::{Pool, PoolOptions};
use crate::{CertAuthority, ServeOptions, connect, forward};

/// TLS sessions remembered for resumption across intercepted connections.
const TLS_SESSION_CACHE: usize = 256;

/// Everything the proxy needs from the engine that owns it.
pub struct ProxyContext {
    pub policy: Arc<Policy>,
    pub filter: ArcSwapOption<FilterEngine>,
    /// The DNS blocklist, the same one the tunnel's DNS responder uses. Clients using the
    /// proxy do not look names up themselves, so the proxy refuses blocked hosts itself.
    pub domains: ArcSwapOption<DomainSet>,
    pub ca: Arc<CertAuthority>,
    pub stats: Arc<Stats>,
    pub max_intercepted: usize,
    /// Returns available memory in bytes; `None` where unknown (Linux dev runs).
    pub available_memory: fn() -> Option<u64>,
    /// Where blocked requests are recorded; `None` records nothing.
    pub events: Option<Arc<EventLog>>,
    /// Bumped by [`ProxyContext::reset_upstream_connections`]; start it at 0.
    pub upstream_resets: AtomicU64,
}

impl ProxyContext {
    /// Closes every pooled upstream connection that is not carrying a request, so the next
    /// request dials again. Call it when the device wakes or the network path changes: a
    /// connection on the old path usually still looks open, and a request sent on it would
    /// hang until TCP gives up. Requests in flight finish on their connections.
    pub fn reset_upstream_connections(&self) {
        self.upstream_resets.fetch_add(1, Ordering::AcqRel);
    }
}

/// Shared by every task of one `serve` call.
pub(crate) struct State {
    pub(crate) ctx: Arc<ProxyContext>,
    pub(crate) options: ServeOptions,
    pub(crate) pool: Pool,
    pub(crate) shutdown: Shutdown,
    pub(crate) intercept_slots: Arc<Semaphore>,
    /// One per passthrough tunnel, held from before dialing until the tunnel ends, so
    /// overflow cannot take the file descriptors that DNS and the pool need.
    pub(crate) passthrough_slots: Arc<Semaphore>,
    /// The intercepted connections past their TLS handshake, for reclaiming the slot of an
    /// idle one when the table is full.
    pub(crate) intercepted: Mutex<Vec<Weak<Activity>>>,
    pub(crate) provider: Arc<CryptoProvider>,
    pub(crate) sessions: Arc<dyn StoresServerSessions>,
    /// Serves intercepted connections: HTTP/1.1 or HTTP/2, with the mandatory limits.
    pub(crate) server: auto::Builder<TokioExecutor>,
}

impl State {
    fn intercepted(&self) -> std::sync::MutexGuard<'_, Vec<Weak<Activity>>> {
        let mut list = self
            .intercepted
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        list.retain(|activity| activity.strong_count() > 0);
        list
    }

    /// Records an intercepted connection that completed its TLS handshake.
    pub(crate) fn add_intercepted(&self, activity: &Arc<Activity>) {
        self.intercepted().push(Arc::downgrade(activity));
    }

    /// Asks the intercepted connection that has had nothing in flight the longest, and for
    /// at least [`MIN_IDLE_TO_RECLAIM`], to close. False when there is none.
    pub(crate) fn close_longest_idle(&self) -> bool {
        let now = tokio::time::Instant::now();
        let oldest = self
            .intercepted()
            .iter()
            .filter_map(Weak::upgrade)
            .filter_map(|activity| Some((activity.idle_since()?, activity)))
            .filter(|(since, _)| now.saturating_duration_since(*since) >= MIN_IDLE_TO_RECLAIM)
            .min_by_key(|(since, _)| *since);
        match oldest {
            Some((_, activity)) => {
                activity.request_close();
                true
            }
            None => false,
        }
    }
}

/// Delay after the given number of consecutive `accept` errors: 10 ms, doubling, at most
/// 1 s. Errors such as running out of file descriptors would otherwise spin the loop.
pub fn accept_backoff(consecutive_errors: u32) -> Duration {
    if consecutive_errors == 0 {
        return Duration::ZERO;
    }
    let factor = 1u64 << (consecutive_errors - 1).min(16);
    Duration::from_millis((10 * factor).min(1000))
}

/// Serves until `shutdown` resolves. Must be spawned on a current-thread tokio runtime.
pub async fn serve(
    listener: TcpListener,
    ctx: Arc<ProxyContext>,
    shutdown: impl Future<Output = ()>,
) {
    serve_with_options(listener, ctx, ServeOptions::default(), shutdown).await;
}

/// [`serve`] with explicit options. When it returns, every connection and task it started
/// is dropped.
///
/// Upstream names are resolved with `options.resolver` when set, and otherwise (or when it
/// fails) with `getaddrinfo` on tokio's blocking pool, so the runtime should cap
/// `max_blocking_threads`.
pub async fn serve_with_options(
    listener: TcpListener,
    ctx: Arc<ProxyContext>,
    options: ServeOptions,
    shutdown: impl Future<Output = ()>,
) {
    let (closer, tasks) = shutdown::channel();
    let pool = Pool::new(
        &options.upstream_tls,
        PoolOptions {
            connect_timeout: options.connect_timeout,
            idle_timeout: options.idle_timeout,
            keep_alive_interval: options.keep_alive_interval,
            max_connections: options.max_upstream_connections,
            max_h1_per_host: options.max_h1_per_host,
            clock: options.clock,
            resolver: options.resolver.clone(),
        },
        tasks.clone(),
        ctx.clone(),
    );
    let mut server = auto::Builder::new(TokioExecutor::new());
    server
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(options.header_read_timeout)
        .max_buf_size(H1_MAX_BUF)
        .max_headers(MAX_HEADERS);
    server
        .http2()
        .timer(TokioTimer::new())
        .initial_stream_window_size(H2_STREAM_WINDOW)
        .initial_connection_window_size(H2_CONNECTION_WINDOW)
        .max_send_buf_size(H2_MAX_SEND_BUF)
        .max_header_list_size(MAX_HEADER_LIST)
        .keep_alive_interval(options.keep_alive_interval)
        .keep_alive_timeout(KEEP_ALIVE_TIMEOUT);
    let state = Arc::new(State {
        intercept_slots: Arc::new(Semaphore::new(ctx.max_intercepted)),
        passthrough_slots: Arc::new(Semaphore::new(options.max_passthrough)),
        intercepted: Mutex::new(Vec::new()),
        ctx,
        pool,
        shutdown: tasks.clone(),
        provider: Arc::new(rustls::crypto::ring::default_provider()),
        sessions: ServerSessionMemoryCache::new(TLS_SESSION_CACHE),
        server,
        options,
    });

    let reaper = state.clone();
    tasks.spawn(async move {
        let period = (reaper.options.idle_timeout / 4).max(Duration::from_millis(50));
        let mut tick = tokio::time::interval(period);
        loop {
            tick.tick().await;
            reaper.pool.reap();
        }
    });

    let mut shutdown = std::pin::pin!(shutdown);
    let mut errors = 0u32;
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok((tcp, _)) => {
                    errors = 0;
                    let _ = tcp.set_nodelay(true);
                    tasks.spawn(serve_client(state.clone(), tcp));
                }
                Err(e) => {
                    errors = errors.saturating_add(1);
                    let delay = accept_backoff(errors);
                    log::warn!("accept failed ({errors} in a row), retrying in {delay:?}: {e}");
                    tokio::select! {
                        () = &mut shutdown => break,
                        () = tokio::time::sleep(delay) => {}
                    }
                }
            },
        }
    }
    closer.close();
}

/// One client connection to the proxy: plain HTTP requests and `CONNECT`.
async fn serve_client(state: Arc<State>, tcp: TcpStream) {
    let activity = Activity::new();
    let service = {
        let state = state.clone();
        let activity = activity.clone();
        service_fn(move |request| front(state.clone(), activity.start(), request))
    };
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(state.options.header_read_timeout)
        .max_buf_size(H1_MAX_BUF)
        .max_headers(MAX_HEADERS);
    let conn = builder
        .serve_connection(TokioIo::new(tcp), service)
        .with_upgrades();
    let (result, _) = idle::serve(conn, &activity, state.options.idle_timeout, |conn| {
        conn.graceful_shutdown()
    })
    .await;
    if let Err(e) = result {
        log::debug!("client connection: {e}");
    }
}

async fn front(
    state: Arc<State>,
    in_flight: InFlight,
    request: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let response = if request.method() == Method::CONNECT {
        connect::connect(&state, request).await
    } else {
        forward::forward(&state, request).await
    };
    Ok(response.map(|body| DoneBody::new(body, move || drop(in_flight)).boxed_unsync()))
}

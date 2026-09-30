//! The proxy's listener, its shared state and the first request on each connection.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
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
use tokio::sync::{Semaphore, watch};
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
use crate::request::NoResponse;
use crate::shutdown::{self, Shutdown};
use crate::throttle::LogThrottle;
use crate::upstream::{Pool, PoolOptions, UpstreamError, certificate_problem, is_unreachable};
use crate::{CertAuthority, ServeOptions, connect, forward};

/// TLS sessions remembered for resumption across intercepted connections.
const TLS_SESSION_CACHE: usize = 256;
/// An upstream failure logged at info level (see [`State::log_upstream_failure`]) is
/// logged at most once in this interval for each host.
const UPSTREAM_LOG_INTERVAL: Duration = Duration::from_secs(60);
/// Each cause of refusing a blocked host a blocked connection is logged at info level at most
/// once in this interval.
const REFUSED_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Everything the proxy needs from the engine that owns it.
pub struct ProxyContext {
    pub policy: Arc<Policy>,
    pub filter: ArcSwapOption<FilterEngine>,
    /// The DNS blocklist, the same one the tunnel's DNS responder uses. Clients using the
    /// proxy do not look names up themselves, so the proxy blocks those hosts itself: a
    /// `CONNECT` gets a connection whose requests are all answered as blocked (see
    /// `crate::sink`, and `ServeOptions::max_blocked` for when it gets `403` instead), and
    /// a request in absolute form is answered like a request the filter engine blocks (see
    /// `crate::request::answer_blocked`).
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
    /// Bumped with `upstream_resets`, for the relays (passthrough tunnels, WebSockets) to
    /// check whether their path is gone. Start it with `Default::default()`.
    pub path_resets: watch::Sender<u64>,
}

impl ProxyContext {
    /// Closes every pooled upstream connection that is not carrying a request, so the next
    /// request dials again. Call it when the device wakes or the network path changes: a
    /// connection on the old path usually still looks open, and a request sent on it would
    /// hang until TCP gives up. Connections carrying requests (streaming responses, long
    /// polls, downloads), passthrough tunnels and WebSockets are closed only if their
    /// upstream source address is no longer assigned to the device (checked now and again
    /// shortly after), so the client sees the failure and retries on the new path while
    /// healthy transfers keep going.
    pub fn reset_upstream_connections(&self) {
        self.upstream_resets.fetch_add(1, Ordering::AcqRel);
        // send_modify works without receivers, unlike send.
        self.path_resets.send_modify(|resets| *resets += 1);
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
    /// One per blocked host's connection (see `crate::sink`), held from the `200` answering
    /// its `CONNECT` (or from reading a blocked server name) until the connection ends.
    pub(crate) blocked_slots: Arc<Semaphore>,
    /// The intercepted connections past their TLS handshake, for reclaiming the slot of an
    /// idle one when the table is full.
    pub(crate) intercepted: Mutex<Vec<Weak<Activity>>>,
    /// The blocked connections past their TLS handshake, for reclaiming the slot of an idle
    /// one when `blocked_slots` is full.
    pub(crate) blocked: Mutex<Vec<Weak<Activity>>>,
    pub(crate) provider: Arc<CryptoProvider>,
    pub(crate) sessions: Arc<dyn StoresServerSessions>,
    /// Serves intercepted and blocked connections: HTTP/1.1 or HTTP/2, with the mandatory
    /// limits.
    pub(crate) server: auto::Builder<TokioExecutor>,
    /// Keeps the upstream failures logged at info level to one line per host a minute.
    pub(crate) upstream_log: LogThrottle,
    /// Keeps blocked hosts refused a blocked connection (see `crate::connect`) to one info
    /// line a minute for each cause.
    pub(crate) refused_log: LogThrottle,
}

impl State {
    /// Logs a failed upstream request to `authority`. An unreachable host, and a server
    /// whose certificate the client would reject too (see [`info_level_failure`]), are
    /// logged at info level, which the tunnel's log shows, at most once a minute per host;
    /// anything else at debug level.
    pub(crate) fn log_upstream_failure(&self, authority: &str, error: &UpstreamError) {
        let Some(what) = info_level_failure(error) else {
            return log::debug!("upstream {authority}: {error}");
        };
        if self.upstream_log.allow(authority) {
            log::info!("upstream {authority}: {what} ({error})");
        }
    }

    /// Records an intercepted connection that completed its TLS handshake.
    pub(crate) fn add_intercepted(&self, activity: &Arc<Activity>) {
        live(&self.intercepted).push(Arc::downgrade(activity));
    }

    /// Records a blocked connection that completed its TLS handshake.
    pub(crate) fn add_blocked(&self, activity: &Arc<Activity>) {
        live(&self.blocked).push(Arc::downgrade(activity));
    }

    /// Asks the intercepted connection that has had nothing in flight the longest, and for
    /// at least [`MIN_IDLE_TO_RECLAIM`], to close. False when there is none.
    pub(crate) fn close_longest_idle(&self) -> bool {
        reclaim_longest_idle(&self.intercepted, MIN_IDLE_TO_RECLAIM).is_some()
    }

    /// Asks the blocked connection that has had nothing in flight the longest, however
    /// briefly, to close, and returns it; `None` when there is none. No minimum: closing a
    /// blocked connection past its handshake costs its client nothing, since the client's
    /// attempt was ready already, so iOS does not retry it over cellular, and the client's
    /// next request to the host opens a new `CONNECT` and gets another. And a burst of
    /// blocked hosts (an ad-block test page) needs the slots of connections idle for only
    /// milliseconds.
    pub(crate) fn close_longest_idle_blocked(&self) -> Option<Weak<Activity>> {
        reclaim_longest_idle(&self.blocked, Duration::ZERO)
    }
}

/// What an upstream failure logged at info level is called in the line, or `None` for one
/// logged at debug level. Info level is for failures that name a host worth knowing and
/// that nothing else logs at info: an unreachable host, and a server whose certificate the
/// client would reject too (see `upstream::certificate_problem`), which is never learned as
/// a pin, so `upstream::learn_from_failure` does not log it. The tunnel passes nothing
/// below info to the device's log, and a client's own lines there name the host only by a
/// hash, so without this line nothing says which host an app's `502` came from.
fn info_level_failure(error: &UpstreamError) -> Option<&'static str> {
    if is_unreachable(error) {
        Some("unreachable")
    } else if certificate_problem(error).is_some() {
        Some("certificate rejected")
    } else {
        None
    }
}

/// The connections in `list`, locked, without those that have ended.
fn live(list: &Mutex<Vec<Weak<Activity>>>) -> MutexGuard<'_, Vec<Weak<Activity>>> {
    let mut list = list.lock().unwrap_or_else(PoisonError::into_inner);
    list.retain(|activity| activity.strong_count() > 0);
    list
}

/// Asks the connection in `list` that has had nothing in flight the longest, and for at
/// least `min_idle`, to close (see [`Activity::request_reclaim`]), and returns it; `None`
/// when there is none. A connection already asked to close is not idle (see
/// [`Activity::idle_since`]), so it is never picked twice.
fn reclaim_longest_idle(
    list: &Mutex<Vec<Weak<Activity>>>,
    min_idle: Duration,
) -> Option<Weak<Activity>> {
    let now = tokio::time::Instant::now();
    let (_, activity) = live(list)
        .iter()
        .filter_map(Weak::upgrade)
        .filter_map(|activity| Some((activity.idle_since()?, activity)))
        .filter(|(since, _)| now.saturating_duration_since(*since) >= min_idle)
        .min_by_key(|(since, _)| *since)?;
    activity.request_reclaim();
    Some(Arc::downgrade(&activity))
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
            local_address_present: options.local_address_present,
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
        blocked_slots: Arc::new(Semaphore::new(options.max_blocked)),
        intercepted: Mutex::new(Vec::new()),
        blocked: Mutex::new(Vec::new()),
        ctx,
        pool,
        shutdown: tasks.clone(),
        provider: Arc::new(rustls::crypto::ring::default_provider()),
        sessions: ServerSessionMemoryCache::new(TLS_SESSION_CACHE),
        server,
        upstream_log: LogThrottle::new(UPSTREAM_LOG_INTERVAL),
        refused_log: LogThrottle::new(REFUSED_LOG_INTERVAL),
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
    match result {
        Some(Err(e)) => log::debug!("client connection: {e}"),
        Some(Ok(())) => {}
        None => log::debug!("client connection did not close in time, dropped"),
    }
}

/// The service for one request on a client connection. [`NoResponse`] from a plain
/// request closes the connection without a response.
async fn front(
    state: Arc<State>,
    in_flight: InFlight,
    request: Request<Incoming>,
) -> Result<Response<Body>, NoResponse> {
    let response = if request.method() == Method::CONNECT {
        connect::connect(&state, request).await
    } else {
        forward::forward(&state, request).await?
    };
    Ok(response.map(|body| DoneBody::new(body, move || drop(in_flight)).boxed_unsync()))
}

#[cfg(test)]
mod tests {
    use std::io;

    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::{AlertDescription, CertificateError, ExtendedKeyPurpose};

    use super::*;

    fn tls_failure(error: rustls::Error) -> UpstreamError {
        UpstreamError::Connect(io::Error::new(io::ErrorKind::InvalidData, error))
    }

    fn certificate(error: CertificateError) -> UpstreamError {
        tls_failure(rustls::Error::InvalidCertificate(error))
    }

    #[test]
    fn unreachable_hosts_and_certificates_the_client_would_reject_are_logged_at_info() {
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        for error in [UpstreamError::Timeout, UpstreamError::Connect(refused)] {
            assert_eq!(info_level_failure(&error), Some("unreachable"), "{error}");
        }

        // What rustls reports is the variant with context.
        let at = |secs| UnixTime::since_unix_epoch(Duration::from_secs(secs));
        let now = 1_790_000_000;
        for error in [
            CertificateError::NotValidForNameContext {
                expected: ServerName::try_from("api.tollgate.test")
                    .unwrap()
                    .to_owned(),
                presented: vec![r#"DnsName("*.cdn.tollgate.test")"#.to_string()],
            },
            CertificateError::ExpiredContext {
                time: at(now),
                not_after: at(now - 86_400),
            },
            CertificateError::NotValidYetContext {
                time: at(now),
                not_before: at(now + 86_400),
            },
            CertificateError::InvalidPurposeContext {
                required: ExtendedKeyPurpose::ServerAuth,
                presented: vec![ExtendedKeyPurpose::ClientAuth],
            },
            CertificateError::NotValidForName,
            CertificateError::Revoked,
        ] {
            let failure = certificate(error.clone());
            assert_eq!(
                info_level_failure(&failure),
                Some("certificate rejected"),
                "{error:?}"
            );
        }

        // An unverified certificate is learned as a pin, which `learn_from_failure` logs;
        // the rest name nothing worth a line at info level.
        for error in [
            certificate(CertificateError::UnknownIssuer),
            tls_failure(rustls::Error::AlertReceived(
                AlertDescription::InternalError,
            )),
            UpstreamError::Exhausted,
        ] {
            assert_eq!(info_level_failure(&error), None, "{error}");
        }
    }
}

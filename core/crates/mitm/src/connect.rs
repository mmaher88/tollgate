//! `CONNECT`: classify, then tunnel the bytes untouched, intercept TLS, or serve a blocked
//! host's connection.
//!
//! A host the DNS blocklist blocks gets `200` and a connection that completes TLS with a
//! Tollgate leaf and then answers every request as blocked (an app's with `403`, a
//! browser's with no response), without anything being dialed; so does a TLS server name
//! the blocklist blocks behind another `CONNECT` host (see [`crate::sink`] for why they are
//! not refused). A blocked host that the policy passes through gets `403`
//! instead, because intercepting it is against the policy or known to fail in the client,
//! and so does any blocked host when memory is low. When `ServeOptions::max_blocked`
//! blocked connections are open, the one idle longest is closed to make room, however
//! briefly it has been idle; only when none becomes idle within [`BLOCKED_SLOT_WAIT`] does
//! the host get `403`. A blocked server name refused in any of these cases is closed.
//!
//! The host is classified from the `CONNECT` target first; a passthrough host is tunneled
//! without reading anything. It gets `200` at once and is dialed while the client starts
//! its TLS handshake, so the DNS lookup and the TCP connection do not delay the answer; a
//! host that cannot be reached gets its client connection closed, so the client sees its
//! handshake fail. Otherwise the first bytes are read and kept for replay.
//! Non-TLS traffic, and a client that waits for the server to speak first, is tunneled
//! with those bytes replayed. For TLS the SNI is classified as well; passthrough, TLS
//! without an HTTP protocol, low memory and a full interception table also tunnel, with
//! the ClientHello replayed. A full table first closes its longest idle connection, if one
//! has been idle for a while, and takes over its slot.
//!
//! Passthrough tunnels are capped (`ServeOptions::max_passthrough`): over the cap a
//! passthrough host gets `503` and a connection passed through after reading its first
//! bytes is closed. A tunnel idle for `ServeOptions::tunnel_idle_timeout` is closed.

use std::sync::{Arc, Weak};
use std::time::Duration;

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::Instant;
use tollgate_common::clock::unix_secs;
use tollgate_common::stats::Stats;
use tollgate_policy::{Decision, PassthroughReason};

use crate::body::{Body, blocked, status};
use crate::filtering::{BlockedBy, domain_blocked_by};
use crate::hello::{self, ClientHelloInfo, HelloError};
use crate::http::bare_host;
use crate::idle::Activity;
use crate::intercept::{self, Origin};
use crate::limits::LOW_MEMORY_BYTES;
use crate::proxy::State;
use crate::rewind::Rewind;
use crate::sink::{self, Blocked};
use crate::tunnel::{Ended, copy_until_idle, until_path_gone};
use crate::upstream::{UpstreamError, connect_tcp};

/// How long a new connection waits for the slot of an idle one it asked to close. Longer
/// than the connection may take to close before it is dropped.
const RECLAIM_WAIT: Duration = Duration::from_millis(100);
const _: () = assert!(crate::idle::RECLAIM_GRACE.as_millis() * 2 <= RECLAIM_WAIT.as_millis());

/// How long a blocked host waits for a blocked-connection slot while all are taken. Short
/// enough that the `CONNECT` answer and the TLS handshake that follow still finish well
/// inside the few hundred milliseconds after which iOS starts its attempt over cellular
/// (see `crate::sink`), and longer than a blocked connection asked to close may take to
/// close before it is dropped.
const BLOCKED_SLOT_WAIT: Duration = Duration::from_millis(150);
const _: () = assert!(crate::idle::RECLAIM_GRACE.as_millis() * 2 <= BLOCKED_SLOT_WAIT.as_millis());

/// While a blocked host waits for a slot, how often it looks again for a blocked connection
/// to close. In a burst the connections holding the slots are still in their handshakes,
/// and become idle as soon as those and their first requests are done.
const BLOCKED_SLOT_RETRY: Duration = Duration::from_millis(10);

pub(crate) async fn connect(state: &Arc<State>, request: Request<Incoming>) -> Response<Body> {
    let Some(authority) = request.uri().authority() else {
        return status(StatusCode::BAD_REQUEST);
    };
    let host = bare_host(authority.host()).to_string();
    let port = authority.port_u16().unwrap_or(443);
    diag_connect(state, &request, &host, port);

    if let Some(by) = domain_blocked_by(&state.ctx, &host) {
        let Some(slot) = blocked_slot(state, &host, "with 403").await else {
            return blocked();
        };
        let task_state = state.clone();
        state.shutdown.spawn(async move {
            match hyper::upgrade::on(request).await {
                Ok(client) => {
                    sink::sink(task_state, TokioIo::new(client), host, port, by, slot).await;
                }
                Err(e) => log::debug!("CONNECT upgrade: {e}"),
            }
        });
        return status(StatusCode::OK);
    }
    if let Decision::Passthrough(reason) = state.ctx.policy.classify(&host, unix_secs()) {
        let Some(slot) = passthrough_slot(state) else {
            log::debug!("CONNECT {host}:{port}: too many passthrough tunnels");
            return status(StatusCode::SERVICE_UNAVAILABLE);
        };
        let task_state = state.clone();
        state.shutdown.spawn(async move {
            let _slot = slot;
            let why = format!("{reason:?}");
            passthrough_at_once(&task_state, request, &host, port, &why).await;
        });
        return status(StatusCode::OK);
    }

    let task_state = state.clone();
    state.shutdown.spawn(async move {
        match hyper::upgrade::on(request).await {
            Ok(client) => inspect(task_state, TokioIo::new(client), host, port).await,
            Err(e) => log::debug!("CONNECT upgrade: {e}"),
        }
    });
    status(StatusCode::OK)
}

/// What to do with a tunnel after reading its first bytes.
enum Plan {
    Close,
    Tunnel(String),
    Intercept(Origin, Arc<CertifiedKey>, OwnedSemaphorePermit),
    /// A blocked server name: serve it as a blocked connection.
    Sink(Blocked),
}

async fn inspect<C>(state: Arc<State>, mut client: C, host: String, port: u16)
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut buffer = Vec::new();
    match plan(&state, &mut client, &mut buffer, &host, port).await {
        Plan::Close => {}
        Plan::Tunnel(why) => {
            let client = Rewind::new(buffer, client);
            passthrough(&state, client, &host, port, &why).await;
        }
        Plan::Intercept(origin, leaf, permit) => {
            let client = Rewind::new(buffer, client);
            intercept::intercept(state, client, origin, leaf, permit).await;
        }
        Plan::Sink(blocked) => {
            let client = Rewind::new(buffer, client);
            sink::serve(state, client, blocked).await;
        }
    }
}

/// Why [`read_hello`] found no ClientHello.
pub(crate) enum NoHello {
    /// The first bytes are not TLS, or the client sent nothing within
    /// `first_bytes_timeout`: it may be waiting for the server to speak first.
    NotTls,
    /// The client closed or failed, or did not complete its ClientHello within
    /// `handshake_timeout`.
    Closed,
}

/// Reads the client's first bytes and, when they look like TLS, the rest of its
/// ClientHello, within `first_bytes_timeout` and `handshake_timeout`. Every byte read stays
/// in `buffer` for replay.
pub(crate) async fn read_hello<C>(
    state: &State,
    client: &mut C,
    buffer: &mut Vec<u8>,
    host: &str,
    port: u16,
) -> Result<ClientHelloInfo, NoHello>
where
    C: AsyncRead + Unpin,
{
    let first = tokio::time::timeout(
        state.options.first_bytes_timeout,
        hello::read_more(client, buffer),
    )
    .await;
    match first {
        // A silent client is probably waiting for the server to speak first.
        Err(_) => return Err(NoHello::NotTls),
        Ok(Ok(0)) => return Err(NoHello::Closed),
        Ok(Err(e)) => {
            log::debug!("CONNECT {host}:{port}: {e}");
            return Err(NoHello::Closed);
        }
        Ok(Ok(_)) => {}
    }
    if !hello::looks_like_tls(buffer) {
        return Err(NoHello::NotTls);
    }

    let read = tokio::time::timeout(
        state.options.handshake_timeout,
        hello::read_client_hello(client, buffer),
    )
    .await;
    match read {
        Err(_) => {
            log::debug!("no complete ClientHello for {host}:{port} in time");
            Err(NoHello::Closed)
        }
        Ok(Err(HelloError::NotTls)) => Err(NoHello::NotTls),
        Ok(Err(HelloError::Io(e))) => {
            log::debug!("ClientHello for {host}:{port}: {e}");
            Err(NoHello::Closed)
        }
        Ok(Ok(hello)) => Ok(hello),
    }
}

/// Reads as little as needed to decide; every byte read stays in `buffer` for replay.
async fn plan<C>(state: &State, client: &mut C, buffer: &mut Vec<u8>, host: &str, port: u16) -> Plan
where
    C: AsyncRead + Unpin,
{
    let not_tls = || Plan::Tunnel(format!("{:?}", PassthroughReason::NotTls));
    let hello = match read_hello(state, client, buffer, host, port).await {
        Ok(hello) => hello,
        Err(NoHello::NotTls) => return not_tls(),
        Err(NoHello::Closed) => return Plan::Close,
    };

    let name = hello
        .server_name
        .clone()
        .unwrap_or_else(|| host.to_string());
    if !name.eq_ignore_ascii_case(host) {
        if let Some(by) = domain_blocked_by(&state.ctx, &name) {
            return blocked_plan(state, name, &hello, by).await;
        }
        if let Decision::Passthrough(reason) = state.ctx.policy.classify(&name, unix_secs()) {
            return Plan::Tunnel(format!("{reason:?} for {name}"));
        }
    }
    if !hello.offers_http() {
        return not_tls();
    }
    if low_memory(state).is_some() {
        return Plan::Tunnel(format!("{:?}", PassthroughReason::LowMemory));
    }
    let Some(permit) = intercept_slot(state).await else {
        return Plan::Tunnel(format!("{:?}", PassthroughReason::Capacity));
    };
    match state.ctx.ca.leaf(&name) {
        Ok(leaf) => {
            let origin = Origin {
                name,
                host: host.to_string(),
                port,
            };
            Plan::Intercept(origin, leaf, permit)
        }
        Err(e) => Plan::Tunnel(format!("no certificate for {name}: {e}")),
    }
}

/// A blocked server name behind another `CONNECT` host, which was answered `200` already,
/// and `by` the list that blocked it: a blocked connection with a leaf for the name, or
/// closed when [`blocked_slot`] refuses one or no leaf can be issued.
async fn blocked_plan(state: &State, name: String, hello: &ClientHelloInfo, by: BlockedBy) -> Plan {
    let Some(slot) = blocked_slot(state, &name, "by closing the connection").await else {
        return Plan::Close;
    };
    Blocked::new(state, name, hello, by, slot).map_or(Plan::Close, Plan::Sink)
}

/// A slot for a blocked connection to the blocked host `name`, or `None` when the host
/// must be refused instead (`refusal` says how, for the log): the policy passes it through
/// (intercepting it is against the policy or known to fail in the client), memory is low,
/// or `ServeOptions::max_blocked` blocked connections are open and none of them can be
/// closed within [`BLOCKED_SLOT_WAIT`].
///
/// While every slot is taken, the blocked connection that has been idle longest is asked to
/// close, however briefly it has been idle (see [`State::close_longest_idle_blocked`]), and
/// the host waits for a slot: that connection's, or any other released meanwhile. Another is
/// asked to close whenever none was idle, or the one asked has closed and its slot went to
/// a host that was waiting longer.
async fn blocked_slot(state: &State, name: &str, refusal: &str) -> Option<OwnedSemaphorePermit> {
    if let Decision::Passthrough(reason) = state.ctx.policy.classify(name, unix_secs()) {
        log::debug!("blocked {name}: refused {refusal}, it is passed through ({reason:?})");
        return None;
    }
    if let Some(bytes) = low_memory(state) {
        let message =
            format!("blocked {name}: refused {refusal}, {bytes} bytes of memory available");
        log_refusal(state, "memory", &message);
        return None;
    }
    let slots = &state.blocked_slots;
    if let Ok(slot) = slots.clone().try_acquire_owned() {
        return Some(slot);
    }
    let deadline = Instant::now() + BLOCKED_SLOT_WAIT;
    // One acquire for the whole wait, so the host keeps its place in the semaphore's queue.
    let mut acquire = std::pin::pin!(slots.clone().acquire_owned());
    let mut asked: Option<Weak<Activity>> = None;
    loop {
        if asked.as_ref().is_none_or(|asked| asked.strong_count() == 0) {
            asked = state.close_longest_idle_blocked();
        }
        let wake = deadline.min(Instant::now() + BLOCKED_SLOT_RETRY);
        tokio::select! {
            biased;
            slot = acquire.as_mut() => return slot.ok(),
            () = tokio::time::sleep_until(wake) => {
                if wake >= deadline {
                    break;
                }
            }
        }
    }
    let open = state
        .options
        .max_blocked
        .saturating_sub(slots.available_permits());
    let message = format!(
        "blocked {name}: refused {refusal}, {open} blocked connections open and none could \
         be closed in time"
    );
    log_refusal(state, "cap", &message);
    None
}

/// Logs why a blocked host was refused a blocked connection: at info level, which the
/// tunnel's log shows, at most once a minute for each `cause`, and at debug level otherwise.
fn log_refusal(state: &State, cause: &str, message: &str) {
    if state.refused_log.allow(cause) {
        log::info!("{message}");
    } else {
        log::debug!("{message}");
    }
}

/// The available memory in bytes, when it is known and below [`LOW_MEMORY_BYTES`].
fn low_memory(state: &State) -> Option<u64> {
    (state.ctx.available_memory)().filter(|bytes| *bytes < LOW_MEMORY_BYTES)
}

/// A free interception slot, or the slot of the longest idle intercepted connection, which
/// is asked to close (one per new connection, so a burst cannot close them all).
async fn intercept_slot(state: &State) -> Option<OwnedSemaphorePermit> {
    if let Ok(permit) = state.intercept_slots.clone().try_acquire_owned() {
        return Some(permit);
    }
    if !state.close_longest_idle() {
        return None;
    }
    tokio::time::timeout(RECLAIM_WAIT, state.intercept_slots.clone().acquire_owned())
        .await
        .ok()?
        .ok()
}

/// A passthrough tunnel slot, if one is free.
fn passthrough_slot(state: &State) -> Option<OwnedSemaphorePermit> {
    state.passthrough_slots.clone().try_acquire_owned().ok()
}

/// Tunnels the passthrough host `host` of a `CONNECT` answered `200` without waiting for
/// the dial: dials while hyper hands over the client connection, then tunnels. The dial
/// (a DNS lookup, over DNS over HTTPS in the tunnel, and a TCP connection) no longer delays
/// the answer, and the client sends its ClientHello meanwhile, which waits in the socket
/// until the tunnel starts. When the dial fails the client connection is closed: the
/// client sees its TLS handshake fail, as it would for a host that cannot be reached
/// without the proxy, and as a connection passed through after its first bytes were read
/// does ([`passthrough`]). The caller holds the passthrough slot until this returns.
async fn passthrough_at_once(
    state: &State,
    request: Request<Incoming>,
    host: &str,
    port: u16,
    why: &str,
) {
    /// Why the tunnel could not start.
    enum Failed {
        Dial(UpstreamError),
        Upgrade(hyper::Error),
    }
    // try_join stops at the first failure: a failed dial drops the pending upgrade, and
    // hyper then closes the client connection once it has written the `200`.
    let dial = async { dial(state, host, port).await.map_err(Failed::Dial) };
    let upgrade = async { hyper::upgrade::on(request).await.map_err(Failed::Upgrade) };
    match tokio::try_join!(dial, upgrade) {
        Ok((upstream, client)) => {
            Stats::inc(&state.ctx.stats.connections_passthrough);
            log::debug!("passthrough {host}:{port} ({why})");
            tunnel(state, TokioIo::new(client), upstream, host, port).await;
        }
        Err(Failed::Dial(e)) => log::debug!("passthrough {host}:{port} ({why}): {e}, closing"),
        Err(Failed::Upgrade(e)) => log::debug!("CONNECT upgrade: {e}"),
    }
}

/// Tunnels `client`, whose replay buffer (if any) goes upstream first. Over the cap the
/// client is closed: it was already told `200`.
async fn passthrough<C>(state: &State, client: C, host: &str, port: u16, why: &str)
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let Some(_slot) = passthrough_slot(state) else {
        log::debug!("passthrough {host}:{port} ({why}): too many tunnels, closing");
        return;
    };
    match dial(state, host, port).await {
        Ok(upstream) => {
            Stats::inc(&state.ctx.stats.connections_passthrough);
            log::debug!("passthrough {host}:{port} ({why})");
            tunnel(state, client, upstream, host, port).await;
        }
        Err(e) => log::debug!("passthrough {host}:{port} ({why}): {e}"),
    }
}

async fn dial(state: &State, host: &str, port: u16) -> Result<TcpStream, UpstreamError> {
    tokio::time::timeout(
        state.options.connect_timeout,
        connect_tcp(state.options.resolver.as_deref(), host, port),
    )
    .await
    .map_err(|_| UpstreamError::Timeout)?
    .map_err(UpstreamError::from)
}

/// Copies until either side closes, the tunnel is idle for `tunnel_idle_timeout`, or a
/// reset finds that the upstream socket's source address is gone.
async fn tunnel<C>(state: &State, mut client: C, mut upstream: TcpStream, host: &str, port: u16)
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let idle = state.options.tunnel_idle_timeout;
    let resets = state.ctx.path_resets.subscribe();
    let local = upstream.local_addr().ok().map(|addr| addr.ip());
    let copy = copy_until_idle(&mut client, &mut upstream, idle);
    match until_path_gone(copy, resets, local, state.options.local_address_present).await {
        None => log::debug!("tunnel {host}:{port}: its network is gone, closing"),
        Some(Ok(Ended::Closed)) => {}
        Some(Ok(Ended::Idle)) => log::debug!("tunnel {host}:{port}: idle for {idle:?}, closing"),
        Some(Err(e)) => log::debug!("tunnel {host}:{port}: {e}"),
    }
}

/// Diagnostic build only: logs at info level how a client identifies itself when it opens a
/// connection through the proxy (its User-Agent and the names of the headers it sends), at
/// most once a minute per host and User-Agent. It answers whether connections from web
/// content and from apps' own code can be told apart before deciding to decrypt them.
fn diag_connect(state: &State, request: &Request<Incoming>, host: &str, port: u16) {
    let headers = request.headers();
    let ua = headers
        .get(hyper::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-");
    if !state.diag_log.allow(&format!("connect {host} {ua}")) {
        return;
    }
    let names: Vec<&str> = headers.keys().map(|name| name.as_str()).collect();
    log::info!(
        "diag CONNECT {host}:{port} ua={ua:?} headers={names:?} version={:?}",
        request.version()
    );
}

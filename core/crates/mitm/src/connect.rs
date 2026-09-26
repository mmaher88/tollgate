//! `CONNECT`: classify, then tunnel the bytes untouched or intercept TLS.
//!
//! A host the DNS blocklist blocks gets `403`, whether it would be intercepted or passed
//! through, and so does a TLS server name that differs from it.
//!
//! The host is classified from the `CONNECT` target first; a passthrough host is tunneled
//! without reading anything. Otherwise the first bytes are read and kept for replay.
//! Non-TLS traffic, and a client that waits for the server to speak first, is tunneled
//! with those bytes replayed. For TLS the SNI is classified as well; passthrough, TLS
//! without an HTTP protocol, low memory and a full interception table also tunnel, with
//! the ClientHello replayed. A full table first closes its longest idle connection, if one
//! has been idle for a while, and takes over its slot.
//!
//! Passthrough tunnels are capped (`ServeOptions::max_passthrough`): over the cap a
//! passthrough host gets `503` and a connection passed through after reading its first
//! bytes is closed. A tunnel idle for `ServeOptions::tunnel_idle_timeout` is closed.

use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tollgate_common::clock::unix_secs;
use tollgate_common::stats::Stats;
use tollgate_policy::{Decision, PassthroughReason};

use crate::body::{Body, blocked, status};
use crate::filtering::is_domain_blocked;
use crate::hello::{self, HelloError};
use crate::http::bare_host;
use crate::intercept::{self, Origin};
use crate::limits::LOW_MEMORY_BYTES;
use crate::proxy::State;
use crate::rewind::Rewind;
use crate::tunnel::{Ended, copy_until_idle, until_path_gone};
use crate::upstream::{UpstreamError, connect_tcp};

/// How long a new connection waits for the slot of an idle one it asked to close. Longer
/// than the connection may take to close before it is dropped.
const RECLAIM_WAIT: Duration = Duration::from_millis(100);
const _: () = assert!(crate::idle::RECLAIM_GRACE.as_millis() * 2 <= RECLAIM_WAIT.as_millis());

pub(crate) async fn connect(state: &Arc<State>, request: Request<Incoming>) -> Response<Body> {
    let Some(authority) = request.uri().authority() else {
        return status(StatusCode::BAD_REQUEST);
    };
    let host = bare_host(authority.host()).to_string();
    let port = authority.port_u16().unwrap_or(443);

    if is_domain_blocked(&state.ctx, &host) {
        return blocked();
    }
    if let Decision::Passthrough(reason) = state.ctx.policy.classify(&host, unix_secs()) {
        let Some(slot) = passthrough_slot(state) else {
            log::debug!("CONNECT {host}:{port}: too many passthrough tunnels");
            return status(StatusCode::SERVICE_UNAVAILABLE);
        };
        // Dial before answering, so an unreachable host gets 502 instead of a dead tunnel.
        let upstream = match dial(state, &host, port).await {
            Ok(upstream) => upstream,
            Err(e) => {
                log::debug!("CONNECT {host}:{port}: {e}");
                return status(StatusCode::BAD_GATEWAY);
            }
        };
        Stats::inc(&state.ctx.stats.connections_passthrough);
        log::debug!("passthrough {host}:{port} ({reason:?})");
        let task_state = state.clone();
        state.shutdown.spawn(async move {
            let _slot = slot;
            match hyper::upgrade::on(request).await {
                Ok(client) => {
                    tunnel(&task_state, TokioIo::new(client), upstream, &host, port).await;
                }
                Err(e) => log::debug!("CONNECT upgrade: {e}"),
            }
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
    }
}

/// Reads as little as needed to decide; every byte read stays in `buffer` for replay.
async fn plan<C>(state: &State, client: &mut C, buffer: &mut Vec<u8>, host: &str, port: u16) -> Plan
where
    C: AsyncRead + Unpin,
{
    let not_tls = || Plan::Tunnel(format!("{:?}", PassthroughReason::NotTls));
    let first = tokio::time::timeout(
        state.options.first_bytes_timeout,
        hello::read_more(client, buffer),
    )
    .await;
    match first {
        // A silent client is probably waiting for the server to speak first.
        Err(_) => return not_tls(),
        Ok(Ok(0)) => return Plan::Close,
        Ok(Err(e)) => {
            log::debug!("CONNECT {host}:{port}: {e}");
            return Plan::Close;
        }
        Ok(Ok(_)) => {}
    }
    if !hello::looks_like_tls(buffer) {
        return not_tls();
    }

    let read = tokio::time::timeout(
        state.options.handshake_timeout,
        hello::read_client_hello(client, buffer),
    )
    .await;
    let hello = match read {
        Err(_) => {
            log::debug!("no complete ClientHello for {host}:{port} in time");
            return Plan::Close;
        }
        Ok(Err(HelloError::NotTls)) => return not_tls(),
        Ok(Err(HelloError::Io(e))) => {
            log::debug!("ClientHello for {host}:{port}: {e}");
            return Plan::Close;
        }
        Ok(Ok(hello)) => hello,
    };

    let name = hello
        .server_name
        .clone()
        .unwrap_or_else(|| host.to_string());
    if !name.eq_ignore_ascii_case(host) {
        if is_domain_blocked(&state.ctx, &name) {
            return Plan::Close;
        }
        if let Decision::Passthrough(reason) = state.ctx.policy.classify(&name, unix_secs()) {
            return Plan::Tunnel(format!("{reason:?} for {name}"));
        }
    }
    if !hello.offers_http() {
        return not_tls();
    }
    if (state.ctx.available_memory)().is_some_and(|bytes| bytes < LOW_MEMORY_BYTES) {
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

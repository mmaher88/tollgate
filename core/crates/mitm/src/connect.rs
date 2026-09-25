//! `CONNECT`: classify, then tunnel the bytes untouched or intercept TLS.
//!
//! The host is classified from the `CONNECT` target; a passthrough host is tunneled
//! without reading anything. Otherwise the ClientHello is read and kept for replay: low
//! memory and a full interception table tunnel with it replayed, everything else is
//! intercepted.

use std::sync::Arc;

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

use crate::body::{Body, status};
use crate::hello::{self, HelloError};
use crate::http::bare_host;
use crate::intercept::{self, Origin};
use crate::limits::LOW_MEMORY_BYTES;
use crate::proxy::State;
use crate::rewind::Rewind;
use crate::upstream::{UpstreamError, connect_tcp};

pub(crate) async fn connect(state: &Arc<State>, request: Request<Incoming>) -> Response<Body> {
    let Some(authority) = request.uri().authority() else {
        return status(StatusCode::BAD_REQUEST);
    };
    let host = bare_host(authority.host()).to_string();
    let port = authority.port_u16().unwrap_or(443);

    if let Decision::Passthrough(reason) = state.ctx.policy.classify(&host, unix_secs()) {
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
        state.shutdown.spawn(async move {
            match hyper::upgrade::on(request).await {
                Ok(client) => tunnel(TokioIo::new(client), upstream).await,
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
        Ok(Err(HelloError::NotTls)) => {
            log::debug!("CONNECT {host}:{port} does not start with a ClientHello");
            return Plan::Close;
        }
        Ok(Err(HelloError::Io(e))) => {
            log::debug!("ClientHello for {host}:{port}: {e}");
            return Plan::Close;
        }
        Ok(Ok(hello)) => hello,
    };

    let name = hello.server_name.unwrap_or_else(|| host.to_string());
    if (state.ctx.available_memory)().is_some_and(|bytes| bytes < LOW_MEMORY_BYTES) {
        return Plan::Tunnel(format!("{:?}", PassthroughReason::LowMemory));
    }
    let Ok(permit) = state.intercept_slots.clone().try_acquire_owned() else {
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

/// Tunnels `client`, whose replay buffer (if any) goes upstream first.
async fn passthrough<C>(state: &State, client: C, host: &str, port: u16, why: &str)
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    match dial(state, host, port).await {
        Ok(upstream) => {
            Stats::inc(&state.ctx.stats.connections_passthrough);
            log::debug!("passthrough {host}:{port} ({why})");
            tunnel(client, upstream).await;
        }
        Err(e) => log::debug!("passthrough {host}:{port} ({why}): {e}"),
    }
}

async fn dial(state: &State, host: &str, port: u16) -> Result<TcpStream, UpstreamError> {
    tokio::time::timeout(state.options.connect_timeout, connect_tcp(host, port))
        .await
        .map_err(|_| UpstreamError::Timeout)?
        .map_err(UpstreamError::from)
}

async fn tunnel<C>(mut client: C, mut upstream: TcpStream)
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        log::debug!("tunnel: {e}");
    }
}

//! Blocked hosts behind `CONNECT`: a connection that works, carrying requests that are
//! blocked.
//!
//! A host the DNS blocklist blocks is not refused. iOS 27 and later race each connection
//! (Connectivity Assist): when the attempt over Wi-Fi, which goes through this proxy, fails
//! or is not ready within a few hundred milliseconds, iOS starts another over cellular,
//! which uses the carrier's DNS and no proxy. So a refused `CONNECT` is retried where
//! nothing blocks it, and the blocked host loads. An attempt is ready once the `CONNECT`
//! answer and the TLS handshake, including the client's check of the certificate, are
//! done. So the proxy answers `200` at once, without dialing anything, completes the
//! handshake with a leaf for the host, and answers each request on the connection itself
//! (see `crate::request::answer_on_blocked_connection`). A browser's request, which carries
//! `Sec-Fetch-Dest`, fails without a response ([`NoResponse::Blocked`]): for HTTP/2 hyper
//! resets the request's stream and keeps the connection open for the next request; for
//! HTTP/1.1 it ends the connection with the error, without writing anything, and the
//! socket is closed (without a TLS close_notify). To the page each request is a network
//! error, as a refused `CONNECT` was, so pages that treat a failed request as blocked still
//! do. An app's request, which carries no such header, gets the empty `403` of a request
//! the filter engine blocks, so an SDK that retries network errors stops, and the
//! connection stays open. Its body is not read, though: hyper drains once what has arrived
//! of it and otherwise gives up on the connection. So an HTTP/1.1 request whose body has
//! not all arrived when the answer is sent (in tests, a body of 16 KiB or more, which no
//! longer fits in the TLS record of the request's head) gets the `403` with `connection:
//! close`, and the connection closes; the client still reads the `403`. To iOS the
//! connection works either way, so it has no reason to try another network.
//!
//! A client whose ClientHello offers ALPN protocols but no HTTP one (an app's own protocol
//! over TLS) would fail the handshake if the proxy insisted on HTTP, so it gets no ALPN
//! instead: the handshake completes, and the connection is closed right after it.
//!
//! The DNS blocklist can be reloaded while a blocked connection is open, and may no longer
//! block its host. So once the lists have changed, the next request is refused
//! ([`NoResponse::ListsChanged`]) and the connection closes, and the client retries on a
//! new `CONNECT`, which is classified again.
//!
//! This is not interception: the connection takes no interception slot, is not counted as
//! intercepted and has no upstream. A failed handshake is only logged, even when the
//! client rejects the leaf, and teaches no pin: a pin is kept per host, so one client that
//! pins a blocked host (an app's SDK, say) would make the host passed through for every
//! client, and a blocked host that is passed through gets `403`, which is what this module
//! avoids. Blocked connections are capped (`ServeOptions::max_blocked`): when the cap is
//! reached, the one idle longest is closed to make room for a new one, however briefly it
//! has been idle (see `crate::connect`). A blocked connection is also closed once nothing
//! has been in flight for `ServeOptions::blocked_idle_timeout`.

use std::future::ready;
use std::sync::Arc;

use hyper::Request;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::OwnedSemaphorePermit;
use tokio_rustls::TlsAcceptor;

use crate::connect::{NoHello, read_hello};
use crate::filtering::BlockedBy;
use crate::hello::ClientHelloInfo;
use crate::idle::{self, Activity};
use crate::intercept::{HTTP_ALPN, server_config};
use crate::proxy::State;
use crate::request::{NoResponse, answer_on_blocked_connection};
use crate::rewind::Rewind;

/// A blocked connection about to be served: what was settled when its host, or its TLS
/// server name, was found blocked and its ClientHello read.
pub(crate) struct Blocked {
    /// The SNI, or the `CONNECT` host when the client sent none.
    name: String,
    /// A leaf for `name`.
    leaf: Arc<CertifiedKey>,
    /// False when the ClientHello offered ALPN protocols and none of them is HTTP.
    http: bool,
    /// The DNS blocklist that blocked the name.
    by: BlockedBy,
    /// The blocked-connection slot, held until the connection ends.
    slot: OwnedSemaphorePermit,
}

impl Blocked {
    /// A blocked connection for `name`, whose ClientHello is `hello`, with a leaf for the
    /// name; `None` when no leaf can be issued, which is logged.
    pub(crate) fn new(
        state: &State,
        name: String,
        hello: &ClientHelloInfo,
        by: BlockedBy,
        slot: OwnedSemaphorePermit,
    ) -> Option<Blocked> {
        match state.ctx.ca.leaf(&name) {
            Ok(leaf) => Some(Blocked {
                http: hello.offers_http(),
                name,
                leaf,
                by,
                slot,
            }),
            Err(e) => {
                log::debug!("blocked {name}: no certificate: {e}");
                None
            }
        }
    }
}

/// Serves the blocked host `host`, whose `CONNECT` was just answered `200` and which `by`
/// blocked: reads the ClientHello as an intercepted connection does, then serves the
/// connection with a leaf for the SNI, or for `host` when the client sent none. A client
/// that sends anything but a ClientHello in time is closed. Holds `slot` until the
/// connection ends.
pub(crate) async fn sink<C>(
    state: Arc<State>,
    mut client: C,
    host: String,
    port: u16,
    by: BlockedBy,
    slot: OwnedSemaphorePermit,
) where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut buffer = Vec::new();
    let hello = match read_hello(&state, &mut client, &mut buffer, &host, port).await {
        Ok(hello) => hello,
        Err(NoHello::NotTls) => return log::debug!("blocked {host}:{port}: not TLS, closing"),
        Err(NoHello::Closed) => return,
    };
    let name = hello.server_name.clone().unwrap_or(host);
    let Some(blocked) = Blocked::new(&state, name, &hello, by, slot) else {
        return;
    };
    serve(state, Rewind::new(buffer, client), blocked).await;
}

/// Completes the TLS handshake with the blocked connection's leaf (the ClientHello is
/// replayed by `client` when it was read already) and answers every request without an
/// upstream (see `crate::request::answer_on_blocked_connection`), until the client closes,
/// nothing has been in flight for `blocked_idle_timeout`, a new blocked connection needs
/// the slot of this idle one, the lists change, or the proxy shuts down. A client that
/// offered no HTTP protocol is closed right after the handshake. Holds the slot until the
/// connection ends.
pub(crate) async fn serve<C>(state: Arc<State>, client: C, blocked: Blocked)
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Blocked {
        name,
        leaf,
        http,
        by,
        slot,
    } = blocked;
    let _slot = slot;
    let alpn = if http { HTTP_ALPN } else { &[] };
    let acceptor = TlsAcceptor::from(server_config(&state, leaf, alpn));
    let handshake =
        tokio::time::timeout(state.options.handshake_timeout, acceptor.accept(client)).await;
    let mut tls = match handshake {
        Err(_) => return log::debug!("blocked {name}: TLS handshake timed out"),
        // Not `intercept::report_handshake_failure`: see the module docs.
        Ok(Err(e)) => return log::debug!("blocked {name}: TLS handshake failed: {e}"),
        Ok(Ok(tls)) => tls,
    };
    if !http {
        // The client's connection is ready, which is all it gets: close it (close_notify).
        let _ = tokio::time::timeout(idle::CLOSE_GRACE, tls.shutdown()).await;
        return log::debug!("blocked {name}: no HTTP offered, closed after the handshake");
    }

    let activity = Activity::new();
    state.add_blocked(&activity);
    let service = {
        let state = state.clone();
        let activity = activity.clone();
        service_fn(move |request: Request<Incoming>| {
            let in_flight = activity.start();
            let answer = if by.lists_changed(&state.ctx) {
                Err(NoResponse::lists_changed())
            } else {
                answer_on_blocked_connection(request.headers())
            };
            if answer.as_ref().is_err_and(NoResponse::closes_connection) {
                in_flight.request_close();
            }
            // In flight only for this moment, which restarts the idle timeout.
            drop(in_flight);
            ready(answer)
        })
    };
    let conn = state.server.serve_connection(TokioIo::new(tls), service);
    let idle = state.options.blocked_idle_timeout;
    let (result, _) = idle::serve(conn, &activity, idle, |conn| conn.graceful_shutdown()).await;
    match result {
        // HTTP/1.1 ends here with the first request that gets a NoResponse.
        Some(Err(e)) => log::debug!("blocked connection to {name}: {e}"),
        Some(Ok(())) => {}
        None => {
            log::debug!("blocked connection to {name}: the client did not close in time, dropped")
        }
    }
}

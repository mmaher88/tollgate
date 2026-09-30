//! Terminating TLS for an intercepted connection and serving its HTTP requests.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{AlertDescription, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::OwnedSemaphorePermit;
use tokio_rustls::TlsAcceptor;
use tollgate_common::clock::unix_secs;
use tollgate_common::stats::Stats;
use tollgate_policy::RejectionKind;

use crate::flight::FlightWatch;
use crate::http::{authority, bare_host};
use crate::idle::{self, Activity};
use crate::proxy::State;
use crate::request;
use crate::upstream::Target;

/// The site an intercepted connection talks to.
pub(crate) struct Origin {
    /// The SNI, or the `CONNECT` host when the client sent none. Used for the leaf, the
    /// URL, the upstream TLS name and pin learning.
    pub(crate) name: String,
    /// The `CONNECT` host, which is dialed.
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl Origin {
    pub(crate) fn authority(&self) -> String {
        authority(&self.name, self.port, 443)
    }

    pub(crate) fn target(&self) -> Target {
        Target {
            tls: true,
            host: self.host.clone(),
            port: self.port,
            server_name: self.name.clone(),
        }
    }

    /// True when an HTTP/2 `:authority` names this origin.
    pub(crate) fn matches(&self, authority: &hyper::http::uri::Authority) -> bool {
        bare_host(authority.host()).eq_ignore_ascii_case(&self.name)
            && authority.port_u16().unwrap_or(443) == self.port
    }
}

#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// The ALPN protocols of a client connection the proxy serves HTTP on.
pub(crate) const HTTP_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

/// The TLS configuration for a client connection the proxy terminates, intercepted or
/// blocked (see `crate::sink`): `leaf`, the ALPN protocols `alpn` ([`HTTP_ALPN`], or none,
/// which ignores the client's ALPN and negotiates none), and the shared session cache. The
/// leaf is issued before the handshake, so a certificate problem can never look like a
/// client rejecting us.
pub(crate) fn server_config(
    state: &State,
    leaf: Arc<CertifiedKey>,
    alpn: &[&[u8]],
) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(state.provider.clone())
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports TLS 1.2 and 1.3")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedCert(leaf)));
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    config.session_storage = state.sessions.clone();
    Arc::new(config)
}

/// Holds `permit` until the client connection ends.
pub(crate) async fn intercept<C>(
    state: Arc<State>,
    client: C,
    origin: Origin,
    leaf: Arc<CertifiedKey>,
    permit: OwnedSemaphorePermit,
) where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _permit = permit;
    Stats::inc(&state.ctx.stats.connections_intercepted);
    let acceptor = TlsAcceptor::from(server_config(&state, leaf, HTTP_ALPN));
    let accept = acceptor.accept(FlightWatch::new(client)).into_fallible();
    let handshake = tokio::time::timeout(state.options.handshake_timeout, accept).await;
    let tls = match handshake {
        Err(_) => return log::debug!("TLS handshake for {} timed out", origin.name),
        Ok(Err((e, client))) => return report_handshake_failure(&state, &origin.name, &e, &client),
        Ok(Ok(tls)) => tls,
    };
    state
        .ctx
        .policy
        .record_intercepted_handshake(&origin.name, unix_secs());

    let activity = Activity::new();
    state.add_intercepted(&activity);
    let requests = Arc::new(AtomicU64::new(0));
    let origin = Arc::new(origin);
    let service = {
        let state = state.clone();
        let origin = origin.clone();
        let activity = activity.clone();
        let requests = requests.clone();
        service_fn(move |req| {
            requests.fetch_add(1, Ordering::Relaxed);
            request::handle(state.clone(), origin.clone(), activity.start(), req)
        })
    };
    let conn = state
        .server
        .serve_connection_with_upgrades(TokioIo::new(tls), service);
    let (result, closed_idle) = idle::serve(conn, &activity, state.options.idle_timeout, |conn| {
        conn.graceful_shutdown()
    })
    .await;
    if requests.load(Ordering::Relaxed) == 0 && !closed_idle {
        // A statistic only, until E4 shows how iOS clients fail: trusted clients that
        // preconnect and never use the connection look the same.
        Stats::inc(&state.ctx.stats.tls_abandoned_after_handshake);
        log::debug!(
            "{} closed after the handshake without a request",
            origin.name
        );
    }
    match result {
        Some(Err(e)) => log::debug!("intercepted connection to {}: {e}", origin.name),
        Some(Ok(())) => {}
        None => log::debug!(
            "intercepted connection to {}: the client did not close in time, dropped",
            origin.name
        ),
    }
}

/// Two kinds of handshake failure feed pin learning: an alert that rejects our certificate,
/// and a client that hangs up without one after our certificate reached it (a silent
/// refusal, see `crate::flight`), which the policy learns from under a stricter rule.
/// Anything else (no shared cipher suite, a client that hangs up before our certificate
/// reached it, garbage) is our problem or noise, and is only logged.
fn report_handshake_failure<C>(
    state: &State,
    name: &str,
    error: &io::Error,
    client: &FlightWatch<C>,
) {
    let Some(kind) = rejection_kind(error) else {
        if hung_up(error) && client.certificate_delivered() {
            return report_silent_refusal(state, name, error);
        }
        return log::debug!("TLS handshake for {name} failed: {error}");
    };
    Stats::inc(&state.ctx.stats.tls_client_rejections);
    if state
        .ctx
        .policy
        .record_client_rejection(name, kind, unix_secs())
    {
        log::info!("{name} rejects our certificate; passing it through from now on");
    } else {
        log::debug!("client rejected our certificate for {name}: {kind:?}");
    }
}

fn rejection_kind(error: &io::Error) -> Option<RejectionKind> {
    match error.get_ref()?.downcast_ref::<rustls::Error>()? {
        rustls::Error::AlertReceived(AlertDescription::UnknownCA) => Some(RejectionKind::UnknownCa),
        rustls::Error::AlertReceived(AlertDescription::BadCertificate) => {
            Some(RejectionKind::BadCertificate)
        }
        rustls::Error::AlertReceived(AlertDescription::CertificateUnknown) => {
            Some(RejectionKind::CertificateUnknown)
        }
        rustls::Error::AlertReceived(AlertDescription::DecryptError) => {
            Some(RejectionKind::DecryptError)
        }
        _ => None,
    }
}

/// A client hung up during the handshake for `name` after our certificate reached it,
/// with `error`: counted, and taught to the policy, which decides whether it is a pin.
fn report_silent_refusal(state: &State, name: &str, error: &io::Error) {
    Stats::inc(&state.ctx.stats.tls_silent_refusals);
    if state.ctx.policy.record_silent_refusal(name, unix_secs()) {
        log::info!(
            "{name} hangs up on our certificate without an alert; passing it through from now \
             on"
        );
    } else {
        log::debug!("{name} hung up during the handshake after our certificate: {error}");
    }
}

/// Whether a failed handshake is the client hanging up without saying why: the connection
/// ended (end of stream or a reset), or the client sent close_notify, which rustls reports
/// as a received alert during a TLS 1.3 handshake (TLS 1.2 ignores it and then sees the end
/// of stream), or user_canceled at the fatal level (at the warning level it is ignored).
fn hung_up(error: &io::Error) -> bool {
    match error.kind() {
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted => true,
        _ => matches!(
            error
                .get_ref()
                .and_then(|e| e.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::AlertReceived(
                AlertDescription::CloseNotify | AlertDescription::UserCanceled
            ))
        ),
    }
}

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

/// The leaf is issued before the handshake, so a certificate problem can never look like a
/// client rejecting us.
fn server_config(state: &State, leaf: Arc<CertifiedKey>) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(state.provider.clone())
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports TLS 1.2 and 1.3")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedCert(leaf)));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
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
    let acceptor = TlsAcceptor::from(server_config(&state, leaf));
    let handshake =
        tokio::time::timeout(state.options.handshake_timeout, acceptor.accept(client)).await;
    let tls = match handshake {
        Err(_) => return log::debug!("TLS handshake for {} timed out", origin.name),
        Ok(Err(e)) => return report_handshake_failure(&state, &origin.name, &e),
        Ok(Ok(tls)) => tls,
    };

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
    if let Err(e) = result {
        log::debug!("intercepted connection to {}: {e}", origin.name);
    }
}

/// Only alerts that reject our certificate feed pin learning. Anything else (no shared
/// cipher suite, a reset, garbage) is our problem or noise, and is only logged.
fn report_handshake_failure(state: &State, name: &str, error: &io::Error) {
    let Some(kind) = rejection_kind(error) else {
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

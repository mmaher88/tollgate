//! Terminating TLS for an intercepted connection and serving its HTTP requests.

use std::sync::Arc;

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::OwnedSemaphorePermit;
use tokio_rustls::TlsAcceptor;
use tollgate_common::stats::Stats;

use crate::http::{authority, bare_host};
use crate::idle::{self, Activity};
use crate::proxy::State;
use crate::request;
use crate::upstream::Target;

/// The site an intercepted connection talks to.
pub(crate) struct Origin {
    /// The SNI, or the `CONNECT` host when the client sent none. Used for the leaf, the
    /// URL and the upstream TLS name.
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
        Ok(Err(e)) => return log::debug!("TLS handshake for {} failed: {e}", origin.name),
        Ok(Ok(tls)) => tls,
    };

    let activity = Activity::new();
    let origin = Arc::new(origin);
    let service = {
        let state = state.clone();
        let origin = origin.clone();
        let activity = activity.clone();
        service_fn(move |req| request::handle(state.clone(), origin.clone(), activity.start(), req))
    };
    let conn = state
        .server
        .serve_connection_with_upgrades(TokioIo::new(tls), service);
    let (result, _) = idle::serve(conn, &activity, state.options.idle_timeout, |conn| {
        conn.graceful_shutdown()
    })
    .await;
    if let Err(e) = result {
        log::debug!("intercepted connection to {}: {e}", origin.name);
    }
}

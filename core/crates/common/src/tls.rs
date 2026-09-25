//! The rustls client configuration shared by the DoH resolver and the proxy's upstream side.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};

/// Mozilla's root certificates from webpki-roots. The certificates are compiled in, so the
/// result is the same on every platform and never reads the system trust store.
pub fn webpki_root_store() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// rustls client configuration with the ring provider and webpki roots.
///
/// `alpn` is offered in the given order, for example `&[b"h2"]` for DNS over HTTPS or
/// `&[b"h2", b"http/1.1"]` for the proxy. The provider is passed explicitly, so this never
/// depends on a process-wide default provider being installed.
pub fn client_config(alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports TLS 1.2 and 1.3")
        .with_root_certificates(webpki_root_store())
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

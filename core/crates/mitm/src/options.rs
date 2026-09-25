//! Timeouts and limits for one `serve` call.

use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;

use crate::limits::{MAX_H1_PER_HOST, MAX_UPSTREAM_CONNECTIONS};

/// Timeouts and limits for [`crate::serve_with_options`]. [`Default`] gives the production
/// values.
#[derive(Clone, Debug)]
pub struct ServeOptions {
    /// Roots for upstream TLS. ALPN is set by the proxy. Default: webpki roots through
    /// `tollgate_common::tls::client_config`. Tests use it to trust a local origin.
    pub upstream_tls: Arc<ClientConfig>,
    /// Wait for the first bytes after `CONNECT`; a silent client gets a plain tunnel,
    /// because some protocols wait for the server to speak first. Default 10 s.
    pub first_bytes_timeout: Duration,
    /// Limit for reading the ClientHello and for the TLS handshake with the client.
    /// Default 10 s.
    pub handshake_timeout: Duration,
    /// Limit for reading HTTP/1.1 request headers. Default 30 s.
    pub header_read_timeout: Duration,
    /// Client connections without a request in flight for this long are closed; upstream
    /// connections idle this long are closed too. Default 60 s.
    pub idle_timeout: Duration,
    /// Limit for opening an upstream connection, TCP and TLS together. Default 10 s.
    pub connect_timeout: Duration,
    /// HTTP/2 keep-alive ping interval on both sides. Default 30 s.
    pub keep_alive_interval: Duration,
    /// Upstream connections in total. Default 64.
    pub max_upstream_connections: usize,
    /// HTTP/1.1 upstream connections per origin. Default 6.
    pub max_h1_per_host: usize,
}

impl Default for ServeOptions {
    fn default() -> ServeOptions {
        ServeOptions {
            upstream_tls: tollgate_common::tls::client_config(&[b"h2", b"http/1.1"]),
            first_bytes_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            header_read_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(10),
            keep_alive_interval: Duration::from_secs(30),
            max_upstream_connections: MAX_UPSTREAM_CONNECTIONS,
            max_h1_per_host: MAX_H1_PER_HOST,
        }
    }
}

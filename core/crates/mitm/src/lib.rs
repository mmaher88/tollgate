//! The local HTTP and HTTPS proxy: the certificate authority, leaf certificates, the iOS
//! profile that installs the root, and the filtering proxy itself.
//!
//! Built directly on hyper, hyper-util, tokio-rustls and rustls with the ring provider.

mod body;
mod ca;
mod connect;
mod cut;
mod filtering;
mod forward;
mod hello;
mod http;
mod idle;
mod intercept;
mod mobileconfig;
mod options;
mod proxy;
mod request;
mod rewind;
mod shutdown;
mod tunnel;
mod upstream;
mod websocket;

pub use ca::{
    CA_VALIDITY_DAYS, CertAuthority, LEAF_CACHE_SIZE, LEAF_REISSUE_SECS, LEAF_VALIDITY_DAYS,
};
pub use options::ServeOptions;
pub use proxy::{ProxyContext, accept_backoff, serve, serve_with_options};

/// Fixed limits. They are not options: with hyper's default flow-control windows, 20 slow
/// intercepted downloads used 52 MB instead of 12 MB.
pub mod limits {
    use std::time::Duration;

    /// HTTP/2 stream receive window, client and server side.
    pub const H2_STREAM_WINDOW: u32 = 128 * 1024;
    /// HTTP/2 connection receive window, client and server side. Clients that stop reading
    /// can fill it with two stream windows, so an upstream connection whose stalled streams
    /// could hold half of it takes no new requests (see the upstream pool).
    pub const H2_CONNECTION_WINDOW: u32 = 256 * 1024;
    /// HTTP/2 send buffer per stream.
    pub const H2_MAX_SEND_BUF: usize = 128 * 1024;
    /// HTTP/1.1 read buffer, client and server side.
    pub const H1_MAX_BUF: usize = 128 * 1024;
    /// Largest decoded HTTP/2 header block accepted, client and server side. hyper's
    /// default of 16 KiB turns responses with several large cookies or a large
    /// Content-Security-Policy into proxy failures that the browser would accept.
    pub const MAX_HEADER_LIST: u32 = 64 * 1024;
    /// Most HTTP/1.1 header lines accepted in one message, client and server side (hyper's
    /// default is 100). Their bytes stay capped by [`H1_MAX_BUF`].
    pub const MAX_HEADERS: usize = 256;
    /// Below this much available memory new connections are passed through.
    pub const LOW_MEMORY_BYTES: u64 = 8 * 1024 * 1024;
    /// Default for `ServeOptions::max_upstream_connections`.
    pub const MAX_UPSTREAM_CONNECTIONS: usize = 64;
    /// Default for `ServeOptions::max_passthrough`. A tunnel holds two sockets and about
    /// 20 KiB, so 128 stay well inside the file descriptor limit the tunnel sets (2048) and
    /// use under 3 MiB.
    pub const MAX_PASSTHROUGH: usize = 128;
    /// Default for `ServeOptions::max_h1_per_host`.
    pub const MAX_H1_PER_HOST: usize = 6;
    /// An HTTP/2 connection whose keep-alive ping is not answered in time is closed.
    pub const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);
    /// When every interception slot is taken, an intercepted client connection that has had
    /// nothing in flight for this long may be closed to make room for a new one. Shorter
    /// gaps are normal while a page loads.
    pub const MIN_IDLE_TO_RECLAIM: Duration = Duration::from_secs(3);
}

/// Errors from the certificate authority.
#[derive(Debug, thiserror::Error)]
pub enum MitmError {
    #[error("invalid CA certificate: {0}")]
    InvalidCertificate(String),
    #[error("invalid CA key: {0}")]
    InvalidKey(String),
    #[error("the certificate is not a CA")]
    NotCa,
    #[error("the key does not belong to the certificate")]
    KeyMismatch,
    #[error("cannot issue a certificate for {0:?}")]
    InvalidHost(String),
    #[error("certificate generation failed: {0}")]
    Certificate(String),
    #[error("TLS: {0}")]
    Tls(String),
}

impl From<rcgen::Error> for MitmError {
    fn from(e: rcgen::Error) -> MitmError {
        MitmError::Certificate(e.to_string())
    }
}

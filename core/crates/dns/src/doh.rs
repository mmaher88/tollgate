//! DNS over HTTPS (RFC 8484). For now only the error type, which
//! [`crate::DnsHandler::complete`] takes.

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DohError {
    #[error("no usable DoH upstream is configured")]
    NoUpstream,
    #[error("the query is shorter than a DNS header")]
    BadQuery,
    #[error("too many queries are in flight")]
    Busy,
    /// Not produced by the resolver: for callers that answer queued queries after stopping.
    #[error("the resolver is stopped")]
    Stopped,
    #[error("no answer before the deadline")]
    Timeout,
    #[error("connecting failed: {0}")]
    Connect(String),
    #[error("TLS failed: {0}")]
    Tls(String),
    #[error("HTTP/2 failed: {0}")]
    Http(String),
    #[error("upstream answered with HTTP status {0}")]
    Status(u16),
    #[error("unusable answer: {0}")]
    BadAnswer(String),
    #[error("invalid TLS configuration: {0}")]
    Config(String),
}

//! The local HTTP and HTTPS proxy: the certificate authority, leaf certificates, the iOS
//! profile that installs the root, and the filtering proxy itself.
//!
//! Built directly on hyper, hyper-util, tokio-rustls and rustls with the ring provider.

mod ca;

pub use ca::{
    CA_VALIDITY_DAYS, CertAuthority, LEAF_CACHE_SIZE, LEAF_REISSUE_SECS, LEAF_VALIDITY_DAYS,
};

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

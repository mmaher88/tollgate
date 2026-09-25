//! Which connections the proxy may intercept: the configuration shared with Swift, host
//! patterns, the bundled passthrough list and certificate pin learning.

mod config;

pub use config::{Config, DohUpstream};

/// Errors from parsing configuration and host patterns.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid configuration: {0}")]
    Config(String),
}

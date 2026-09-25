//! Which connections the proxy may intercept: the configuration shared with Swift, host
//! patterns, the bundled passthrough list and certificate pin learning.

mod config;
mod pattern;

pub use config::{Config, DohUpstream};
pub use pattern::HostPattern;

/// Errors from parsing configuration and host patterns.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("invalid host pattern {pattern:?}: {reason}")]
    InvalidPattern {
        pattern: String,
        reason: &'static str,
    },
}

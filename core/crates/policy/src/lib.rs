//! Which connections the proxy may intercept: the configuration shared with Swift, host
//! patterns, the bundled passthrough list and certificate pin learning.

mod bundled;
mod config;
mod pattern;
mod policy;

pub use bundled::bundled_passthrough;
pub use config::{Config, DohUpstream};
pub use pattern::HostPattern;
pub use policy::{
    Decision, PIN_LIFETIME_SECS, PassthroughReason, Policy, REJECTION_WINDOW_SECS, RejectionKind,
};

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

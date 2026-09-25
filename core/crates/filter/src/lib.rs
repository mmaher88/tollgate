//! Request filtering: the adblock engine for URLs seen by the proxy, the hashed DNS
//! blocklist, and compiling both from filter lists.

mod domain_rules;
mod domain_set;
mod engine;
mod request_type;

use std::path::PathBuf;

pub use domain_rules::DomainRules;
pub use domain_set::{DomainSet, DomainSetError};
pub use engine::{
    FilterEngine, REGEX_CLEANUP_INTERVAL, REGEX_DISCARD_UNUSED, Verdict, network_rule_count,
};
pub use request_type::{request_type, source_url};

/// How a list is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListFormat {
    /// Adblock Plus, uBlock Origin and AdGuard syntax.
    Adblock,
    /// `0.0.0.0 host` lines, or one bare host per line.
    Hosts,
}

/// One filter list's text.
pub struct ListSource<'a> {
    /// Used in log messages only.
    pub name: &'a str,
    pub text: &'a str,
    pub format: ListFormat,
}

#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("engine data rejected: {0}")]
    Engine(String),
    #[error("domain set rejected: {0}")]
    DomainSet(#[from] DomainSetError),
}

//! Request filtering: the adblock engine for URLs seen by the proxy, the hashed DNS
//! blocklist, and compiling both from filter lists.

mod compile;
mod detect;
mod domain_rules;
mod domain_set;
mod engine;
mod exempt;
mod request_type;
mod wildcard;

use std::path::PathBuf;

pub use compile::{
    CompileReport, DOMAINS_FILE, ENGINE_FILE, compile, compile_split, compile_split_exempting,
};
pub use detect::detect_format;
pub use domain_rules::{DomainRules, MAX_UNKEYED_PATTERNS, MAX_WILDCARD_PATTERNS};
pub use domain_set::{DomainSet, DomainSetError};
pub use engine::{
    FilterEngine, REGEX_CLEANUP_INTERVAL, REGEX_DISCARD_UNUSED, Verdict, network_rule_count,
};
pub use exempt::Exemption;
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
#[derive(Clone, Copy)]
pub struct ListSource<'a> {
    /// Used in log messages only.
    pub name: &'a str,
    pub text: &'a str,
    pub format: ListFormat,
}

/// A list for the DNS blocklist, and the hosts its blocks must leave alone.
#[derive(Clone, Copy)]
pub struct DnsList<'a> {
    pub source: ListSource<'a>,
    /// Hosts this list must not block, or `None`. Each of the list's block rules that
    /// covers one of them (see [`Exemption`]) is left out, while the same rule in another
    /// list still blocks. Its exceptions are kept, since they block nothing. This lets a
    /// list that blocks more than the others be added without it blocking what an app
    /// needs, such as the telemetry hosts of a bank.
    pub exempt: Option<&'a Exemption>,
}

impl<'a> From<ListSource<'a>> for DnsList<'a> {
    /// The list with no exempt hosts.
    fn from(source: ListSource<'a>) -> DnsList<'a> {
        DnsList {
            source,
            exempt: None,
        }
    }
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

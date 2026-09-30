//! Hosts that the blocks of some DNS lists must leave alone (see [`crate::DnsList`]).

use std::collections::HashSet;

use crate::wildcard::glob_matches;

/// Hosts that a list's blocks must not cover, given as host patterns in the syntax of
/// Tollgate's passthrough lists: `name` for that host only, `*.name` for the name and
/// every subdomain. ASCII case, surrounding whitespace and one trailing dot are ignored. A
/// name needs no dot, so `*.mil` covers every host under `mil`.
///
/// A block rule covers an exempt host when it would block one:
///
/// - a block of a name and its subdomains (`||name^`, a hosts line, `$important`): when the
///   name is exempt, or when an exempt name is under it, since the block would take that
///   name down with it;
/// - a block of one host (`|name^`): when that host is exempt;
/// - a wildcard block: when it matches an exempt host, or could match a name under an
///   exempt `*.name`, or (for `||` patterns, which also match parents) matches a name that
///   an exempt name is under. A pattern open at the end, such as `ads-*.example.*`, could
///   match a name under any `*.name`, so it always covers one.
#[derive(Clone, Debug, Default)]
pub struct Exemption {
    /// The names of `*.name` patterns: each name and its subdomains are exempt.
    domains: HashSet<String>,
    /// The names of `name` patterns: exactly those hosts are exempt.
    hosts: HashSet<String>,
    /// Every name that the name of a pattern is under: `example.com` and `com` for
    /// `*.a.example.com`. A block of one of them covers exempt hosts.
    ancestors: HashSet<String>,
}

impl Exemption {
    /// The exemption for `patterns`. Entries that are empty once trimmed are ignored.
    pub fn new<'a>(patterns: impl IntoIterator<Item = &'a str>) -> Exemption {
        let mut exemption = Exemption::default();
        for pattern in patterns {
            let pattern = pattern.trim();
            let (domain, name) = match pattern.strip_prefix("*.") {
                Some(name) => (true, name),
                None => (false, pattern),
            };
            let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
            if name.is_empty() {
                continue;
            }
            for (i, _) in name.match_indices('.') {
                exemption.ancestors.insert(name[i + 1..].to_string());
            }
            if domain {
                exemption.domains.insert(name);
            } else {
                exemption.hosts.insert(name);
            }
        }
        exemption
    }

    /// Whether `host` is exempt. ASCII case and one trailing dot are ignored.
    pub fn covers(&self, host: &str) -> bool {
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        self.covers_host(&host)
    }

    /// Whether `name` (lowercase, without a trailing dot) is exempt: an exempt host, or
    /// an exempt `*.name` or a name under one.
    pub(crate) fn covers_host(&self, name: &str) -> bool {
        self.hosts.contains(name)
            || std::iter::once(name)
                .chain(name.match_indices('.').map(|(i, _)| &name[i + 1..]))
                .any(|suffix| self.domains.contains(suffix))
    }

    /// Whether a block of `name` and its subdomains (lowercase, without a trailing dot)
    /// would block an exempt host: `name` is exempt, or an exempt name is under it.
    pub(crate) fn covers_subtree(&self, name: &str) -> bool {
        self.covers_host(name) || self.ancestors.contains(name)
    }

    /// Whether a wildcard block pattern (in the stored form, see [`crate::DomainRules`])
    /// would block an exempt host: whether it matches an exempt host, could match a name
    /// under an exempt `*.name`, or, when `parents` is set (`||` patterns), matches a name
    /// that an exempt name is under.
    pub(crate) fn covers_pattern(&self, pattern: &str, parents: bool) -> bool {
        let glob = pattern.as_bytes();
        let above = |name: &str| {
            parents
                && name
                    .match_indices('.')
                    .any(|(i, _)| glob_matches(glob, &name.as_bytes()[i + 1..]))
        };
        let domain_hit = |name: &String| {
            glob_matches(glob, name.as_bytes())
                || matches_some_name_under(glob, name.as_bytes())
                || above(name)
        };
        let host_hit = |name: &String| glob_matches(glob, name.as_bytes()) || above(name);
        self.domains.iter().any(domain_hit) || self.hosts.iter().any(host_hit)
    }
}

/// Whether `glob` (see [`glob_matches`]) matches some text that ends in `.name`, as the
/// names under `name` do.
///
/// A matching text must end in the glob's literal tail, the text after its last `*`, and
/// nothing else constrains its end, since that `*` can take whatever comes before the
/// tail. So a matching text can also end in `.name` exactly when the tail and `.name`
/// agree at the end: one of them ends the other. Without a `*` the glob matches only
/// itself. The text found this way may not be a valid host name (`.name` alone); counting
/// it keeps the answer on the safe side.
fn matches_some_name_under(glob: &[u8], name: &[u8]) -> bool {
    let mut dotted = Vec::with_capacity(name.len() + 1);
    dotted.push(b'.');
    dotted.extend_from_slice(name);
    match glob.iter().rposition(|&b| b == b'*') {
        Some(star) => {
            let tail = &glob[star + 1..];
            dotted.ends_with(tail) || tail.ends_with(&dotted)
        }
        None => glob.ends_with(&dotted),
    }
}

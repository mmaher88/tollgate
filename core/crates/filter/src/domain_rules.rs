//! Host rules for the DNS blocklist, extracted from filter lists.

use std::collections::HashSet;

use crate::{ListFormat, ListSource};

/// Host names taken from filter lists, lowercase, without a trailing dot, sorted, unique,
/// and without names whose parent is in the same set (a lookup checks every parent, so
/// those children can never change a result).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DomainRules {
    /// `$important` blocks. They win over `allow`.
    pub important: Vec<String>,
    /// `@@` exceptions. They win over `block`.
    pub allow: Vec<String>,
    pub block: Vec<String>,
    /// Lines that are neither comments nor host rules: rules with other options, paths,
    /// wildcards, regexes, and hosts lines without a usable name.
    pub skipped: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Important,
    Allow,
    Block,
}

enum Line {
    Comment,
    Skip,
    Rule {
        kind: Kind,
        name: String,
        badfilter: bool,
    },
}

#[derive(Default)]
struct Builder {
    important: HashSet<String>,
    allow: HashSet<String>,
    block: HashSet<String>,
    badfilter: HashSet<(Kind, String)>,
    skipped: u64,
}

impl DomainRules {
    /// Adblock lists contribute `||name^`, `||name^|`, `||name` (no caret, when the name
    /// does not end in a dot), `.name^` (treated as the name and its subdomains), their
    /// `@@` forms, `$important` and `$badfilter`. Any other option, a path, a wildcard, a
    /// regex or a `|` prefix rule is skipped. Hosts lists contribute every name on
    /// `address name...` lines and bare `name` lines.
    pub fn parse(lists: &[ListSource]) -> DomainRules {
        let mut builder = Builder::default();
        for list in lists {
            let text = list.text.strip_prefix('\u{feff}').unwrap_or(list.text);
            let before = builder.skipped;
            match list.format {
                ListFormat::Adblock => text.lines().for_each(|line| builder.add_adblock_line(line)),
                ListFormat::Hosts => text.lines().for_each(|line| builder.add_hosts_line(line)),
            }
            log::info!(
                "{}: skipped {} lines for the DNS blocklist",
                list.name,
                builder.skipped - before
            );
        }
        builder.finish()
    }
}

impl Builder {
    fn add_adblock_line(&mut self, line: &str) {
        match parse_adblock_line(line) {
            Line::Comment => {}
            Line::Skip => self.skipped += 1,
            Line::Rule {
                kind,
                name,
                badfilter: true,
            } => {
                self.badfilter.insert((kind, name));
            }
            Line::Rule { kind, name, .. } => {
                let set = match kind {
                    Kind::Important => &mut self.important,
                    Kind::Allow => &mut self.allow,
                    Kind::Block => &mut self.block,
                };
                set.insert(name);
            }
        }
    }

    fn add_hosts_line(&mut self, line: &str) {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            return;
        }
        let mut fields = line.split_whitespace();
        let Some(first) = fields.next() else {
            return;
        };
        // `0.0.0.0 name`, `::1 name` and `fe80::1%lo0 name` start with an address; a line
        // without one is a bare name.
        let starts_with_address = first.parse::<std::net::IpAddr>().is_ok() || first.contains(':');
        let names = std::iter::once(first)
            .filter(|_| !starts_with_address)
            .chain(fields);
        let mut accepted = 0;
        for name in names {
            if name.eq_ignore_ascii_case("localhost.localdomain") {
                continue;
            }
            if let Some(name) = normalize_name(name) {
                self.block.insert(name);
                accepted += 1;
            }
        }
        if accepted == 0 {
            self.skipped += 1;
        }
    }

    fn finish(mut self) -> DomainRules {
        for (kind, name) in &self.badfilter {
            let set = match kind {
                Kind::Important => &mut self.important,
                Kind::Allow => &mut self.allow,
                Kind::Block => &mut self.block,
            };
            set.remove(name);
        }
        DomainRules {
            important: without_redundant_children(&self.important),
            allow: without_redundant_children(&self.allow),
            block: without_redundant_children(&self.block),
            skipped: self.skipped,
        }
    }
}

fn parse_adblock_line(line: &str) -> Line {
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') || line.starts_with('[') {
        return Line::Comment;
    }
    let (exception, rule) = match line.strip_prefix("@@") {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    let (pattern, options) = match rule.split_once('$') {
        Some((pattern, options)) => (pattern, Some(options)),
        None => (rule, None),
    };
    let mut important = false;
    let mut badfilter = false;
    for option in options.into_iter().flat_map(|o| o.split(',')) {
        match option.trim() {
            "important" => important = true,
            "badfilter" => badfilter = true,
            _ => return Line::Skip,
        }
    }
    let name = if let Some(rest) = pattern.strip_prefix("||") {
        if let Some(name) = rest.strip_suffix("^|").or_else(|| rest.strip_suffix('^')) {
            name
        } else if rest.ends_with('.') {
            // `||ads.` matches every host that starts with `ads.`: a prefix, not a host.
            return Line::Skip;
        } else {
            rest
        }
    } else if let Some(rest) = pattern.strip_prefix('.') {
        match rest.strip_suffix('^') {
            Some(name) => name,
            None => return Line::Skip,
        }
    } else {
        return Line::Skip;
    };
    let Some(name) = normalize_name(name) else {
        return Line::Skip;
    };
    // An important exception is kept as a plain exception, so an important block for
    // the same host still wins. adblock would let the exception win; no DNS list uses it.
    let kind = match (exception, important) {
        (true, _) => Kind::Allow,
        (false, true) => Kind::Important,
        (false, false) => Kind::Block,
    };
    Line::Rule {
        kind,
        name,
        badfilter,
    }
}

/// Lowercases a host name and strips one trailing dot. Rejects names that DNS never
/// asks for: no dot, empty labels, labels over 63 bytes, names over 253 bytes, characters
/// other than letters, digits, `-` and `_`, and a numeric last label (IPv4 addresses).
fn normalize_name(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.len() > 253 || !name.contains('.') {
        return None;
    }
    let mut last = "";
    for label in name.split('.') {
        let valid = !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !valid {
            return None;
        }
        last = label;
    }
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

/// Sorted names, leaving out any whose parent is also in the set.
fn without_redundant_children(names: &HashSet<String>) -> Vec<String> {
    let mut kept: Vec<String> = names
        .iter()
        .filter(|name| {
            !name
                .match_indices('.')
                .map(|(i, _)| &name[i + 1..])
                .any(|parent| names.contains(parent))
        })
        .cloned()
        .collect();
    kept.sort_unstable();
    kept
}

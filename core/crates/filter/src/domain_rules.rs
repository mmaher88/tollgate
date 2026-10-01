//! Host rules for the DNS blocklist, extracted from filter lists.

use std::collections::HashSet;

use crate::wildcard::{is_unkeyed, is_valid_pattern};
use crate::{DnsList, Exemption, ListFormat, ListSource};

/// The most wildcard patterns, blocks and exceptions together, that one compile keeps.
/// The tunnel parses every pattern into its heap when it loads `domains.bin`, up to about
/// 170 bytes each with its place in the lookup index, and holds the old and the new set at
/// once during a reload; the AdGuard DNS filter has about 420.
pub const MAX_WILDCARD_PATTERNS: usize = 4096;
/// The most patterns kept that start and end with `*`, out of [`MAX_WILDCARD_PATTERNS`].
/// Such a pattern has no literal head or tail to be looked up by, so every lookup tries it
/// in full (see `wildcard.rs`); the AdGuard DNS filter has one.
pub const MAX_UNKEYED_PATTERNS: usize = 64;

/// Host names taken from filter lists, lowercase, without a trailing dot, sorted, unique,
/// and without names whose parent is in the same set (a lookup checks every parent, so
/// those children can never change a result).
///
/// Rules whose name has a `*` become patterns instead, in which `*` matches any run of
/// characters (dots included, and none). A pattern means what the rule means to adblock
/// for a request to `https://host/`: `||log*.example.com^` becomes the pattern
/// `log*.example.com` for the host and its parents, `|ads.*.example^` and
/// `://ads.*.example^` become `ads.*.example` for the host only, an unanchored rule such
/// as `-ulog*.example^` may start anywhere in the host (`*-ulog*.example`, host only), and
/// a rule without a caret may end anywhere in it (`||adx-*.example.` becomes
/// `adx-*.example.*`). Patterns are sorted and unique.
///
/// One form is read otherwise: an unanchored `*.name`, with or without a caret, where
/// `name` has no other `*`. DNS lists in the wildcard domains format write one per line
/// for `name` and its subdomains. It becomes the name, as `||name^` would, so it blocks
/// `name` itself too, as the adblock editions of the same lists do. As a pattern it would
/// be `*.name*`, which also matches `a.name.other.example` and, with no literal head or
/// tail, is tried on every lookup; a whole list of them would fill the tunnel's heap.
///
/// At most [`MAX_WILDCARD_PATTERNS`] patterns are kept, of which at most
/// [`MAX_UNKEYED_PATTERNS`] start and end with `*`: exceptions first, since leaving one out
/// would block what a list unblocks, then blocks, each in the order the lists give them.
/// Each pattern left out counts as one skipped line.
///
/// A list may exempt hosts (see [`DnsList::exempt`]): its block rules that cover one are
/// left out and counted in `exempted`, before `$badfilter` and the limits apply.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DomainRules {
    /// `$important` blocks. They win over every exception.
    pub important: Vec<String>,
    /// `@@` exceptions. They win over every block but `important`.
    pub allow: Vec<String>,
    pub block: Vec<String>,
    /// `@@|name^|` and `@@|name^` exceptions: the host itself, not its subdomains. They win
    /// over every block but `important`, so a list can unblock one host under a blocked
    /// parent. Kept even when a parent is in `block`.
    pub exact_allow: Vec<String>,
    /// `|name^|` and `|name^`: the host itself, not its subdomains.
    pub exact_block: Vec<String>,
    /// Exception patterns matched against the host and its parents (`@@||pattern^`). Like
    /// the other exceptions they win over every block but `important`.
    pub wildcard_allow: Vec<String>,
    /// Exception patterns matched against the host only (`@@|pattern^|`, and unanchored
    /// rules).
    pub exact_wildcard_allow: Vec<String>,
    /// Block patterns matched against the host and its parents (`||pattern^`). They are
    /// plain blocks: every kind of exception wins over them.
    pub wildcard_block: Vec<String>,
    /// Block patterns matched against the host only (`|pattern^|`, `://pattern^`, and
    /// unanchored rules).
    pub exact_wildcard_block: Vec<String>,
    /// Lines that are neither comments nor host rules: rules with other options, paths,
    /// regexes, `$important` exact-host and wildcard blocks, and hosts lines without a
    /// usable name. Also one for each pattern over the limits.
    pub skipped: u64,
    /// Block rules left out because they cover a host their list exempts: one for each
    /// rule, and one for each name of a hosts line.
    pub exempted: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Important,
    Allow,
    Block,
    ExactAllow,
    ExactBlock,
    WildcardAllow,
    ExactWildcardAllow,
    WildcardBlock,
    ExactWildcardBlock,
}

impl Kind {
    /// Whether a rule of this kind covers a host `exempt` exempts, so that a list with the
    /// exemption leaves it out. Exceptions never do: they block nothing.
    fn covers_exempt(self, name: &str, exempt: &Exemption) -> bool {
        match self {
            Kind::Important | Kind::Block => exempt.covers_subtree(name),
            Kind::ExactBlock => exempt.covers_host(name),
            Kind::WildcardBlock => exempt.covers_pattern(name, true),
            Kind::ExactWildcardBlock => exempt.covers_pattern(name, false),
            Kind::Allow | Kind::ExactAllow | Kind::WildcardAllow | Kind::ExactWildcardAllow => {
                false
            }
        }
    }

    fn is_pattern(self) -> bool {
        matches!(
            self,
            Kind::WildcardAllow
                | Kind::ExactWildcardAllow
                | Kind::WildcardBlock
                | Kind::ExactWildcardBlock
        )
    }

    fn is_exception(self) -> bool {
        matches!(
            self,
            Kind::Allow | Kind::ExactAllow | Kind::WildcardAllow | Kind::ExactWildcardAllow
        )
    }
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
struct Builder<'a> {
    /// The hosts the list being added exempts.
    exempt: Option<&'a Exemption>,
    important: HashSet<String>,
    allow: HashSet<String>,
    block: HashSet<String>,
    exact_allow: HashSet<String>,
    exact_block: HashSet<String>,
    wildcard_allow: HashSet<String>,
    exact_wildcard_allow: HashSet<String>,
    wildcard_block: HashSet<String>,
    exact_wildcard_block: HashSet<String>,
    badfilter: HashSet<(Kind, String)>,
    /// Each pattern the first time it was added, in the order the lists give them, for the
    /// limits [`Builder::limit_patterns`] applies.
    pattern_order: Vec<(Kind, String)>,
    skipped: u64,
    exempted: u64,
}

impl DomainRules {
    /// Adblock lists contribute `||name^`, `||name^|`, `||name` (no caret, when the name
    /// does not end in a dot), `.name^`, the unanchored `name^` and `name^|` (the name
    /// must start with a letter or digit) and the wildcard domains format's `*.name`,
    /// `*.name^` and `*.name^|` (all treated as the name and its subdomains), the
    /// exact-host forms `|name^|`, `|name^`, `://name^` and `://name^|` (the name only),
    /// their `@@` forms, `$important` (not on exact-host blocks) and `$badfilter`. A rule
    /// of any other of these forms whose name has a `*` is kept as a pattern (see
    /// [`DomainRules`]), and so are other unanchored and caretless rules with a `*`;
    /// `$important` is not supported on those. Any other option, a path, a regex, a rule
    /// without a `*` and without a caret such as `ads.example`, a `|` prefix rule such as
    /// `|ads.`, `*.zip` (like `||zip^`, no name without a dot is stored) and the patterns
    /// over the limits in [`DomainRules`] are skipped. Hosts lists contribute every name on
    /// `address name...` lines and bare `name` lines.
    pub fn parse(lists: &[ListSource]) -> DomainRules {
        let lists: Vec<DnsList> = lists.iter().copied().map(DnsList::from).collect();
        DomainRules::parse_exempting(&lists)
    }

    /// Like [`DomainRules::parse`], leaving out each list's block rules that cover a host
    /// it exempts (see [`DnsList::exempt`]).
    pub fn parse_exempting(lists: &[DnsList]) -> DomainRules {
        let mut builder = Builder::default();
        for list in lists {
            let DnsList { source, exempt } = *list;
            builder.exempt = exempt;
            let text = source.text.strip_prefix('\u{feff}').unwrap_or(source.text);
            let (skipped, exempted) = (builder.skipped, builder.exempted);
            match source.format {
                ListFormat::Adblock => text.lines().for_each(|line| builder.add_adblock_line(line)),
                ListFormat::Hosts => text.lines().for_each(|line| builder.add_hosts_line(line)),
            }
            log::info!(
                "{}: skipped {} lines for the DNS blocklist",
                source.name,
                builder.skipped - skipped
            );
            if exempt.is_some() {
                log::info!(
                    "{}: left out {} blocks of exempt hosts",
                    source.name,
                    builder.exempted - exempted
                );
            }
        }
        builder.finish()
    }
}

impl Builder<'_> {
    /// Whether the list being added exempts a host that a rule of `kind` for `name`
    /// covers; if so, counts the rule as exempted.
    fn exempts(&mut self, kind: Kind, name: &str) -> bool {
        let exempted = self
            .exempt
            .is_some_and(|exempt| kind.covers_exempt(name, exempt));
        self.exempted += u64::from(exempted);
        exempted
    }

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
            Line::Rule { kind, name, .. } if self.exempts(kind, &name) => {}
            Line::Rule { kind, name, .. } if kind.is_pattern() => {
                if self.set(kind).insert(name.clone()) {
                    self.pattern_order.push((kind, name));
                }
            }
            Line::Rule { kind, name, .. } => {
                self.set(kind).insert(name);
            }
        }
    }

    fn set(&mut self, kind: Kind) -> &mut HashSet<String> {
        match kind {
            Kind::Important => &mut self.important,
            Kind::Allow => &mut self.allow,
            Kind::Block => &mut self.block,
            Kind::ExactAllow => &mut self.exact_allow,
            Kind::ExactBlock => &mut self.exact_block,
            Kind::WildcardAllow => &mut self.wildcard_allow,
            Kind::ExactWildcardAllow => &mut self.exact_wildcard_allow,
            Kind::WildcardBlock => &mut self.wildcard_block,
            Kind::ExactWildcardBlock => &mut self.exact_wildcard_block,
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
                if !self.exempts(Kind::Block, &name) {
                    self.block.insert(name);
                }
                accepted += 1;
            }
        }
        if accepted == 0 {
            self.skipped += 1;
        }
    }

    /// Leaves out the patterns over [`MAX_WILDCARD_PATTERNS`] or [`MAX_UNKEYED_PATTERNS`],
    /// keeping exceptions first, then blocks, each in the order they were added, and counts
    /// each one left out as a skipped line. Patterns `$badfilter` cancelled must be gone
    /// already, so they take no room.
    fn limit_patterns(&mut self) {
        let order = std::mem::take(&mut self.pattern_order);
        let exceptions = order.iter().filter(|(kind, _)| kind.is_exception());
        let blocks = order.iter().filter(|(kind, _)| !kind.is_exception());
        let (mut kept, mut kept_unkeyed) = (0, 0);
        let (mut left_out, mut left_out_unkeyed) = (0_u64, 0_u64);
        for (kind, pattern) in exceptions.chain(blocks) {
            let set = self.set(*kind);
            if !set.contains(pattern) {
                continue;
            }
            let unkeyed = is_unkeyed(pattern);
            let room =
                kept < MAX_WILDCARD_PATTERNS && (!unkeyed || kept_unkeyed < MAX_UNKEYED_PATTERNS);
            if room {
                kept += 1;
                kept_unkeyed += usize::from(unkeyed);
            } else {
                set.remove(pattern);
                left_out += 1;
                left_out_unkeyed += u64::from(unkeyed);
            }
        }
        if left_out > 0 {
            log::warn!(
                "left {left_out} wildcard patterns out of the DNS blocklist, \
                 {left_out_unkeyed} of them without a literal head or tail: at most \
                 {MAX_WILDCARD_PATTERNS} are kept, {MAX_UNKEYED_PATTERNS} of those without one"
            );
            self.skipped += left_out;
        }
    }

    fn finish(mut self) -> DomainRules {
        for (kind, name) in std::mem::take(&mut self.badfilter) {
            self.set(kind).remove(&name);
        }
        self.limit_patterns();
        DomainRules {
            important: without_redundant_children(&self.important),
            allow: without_redundant_children(&self.allow),
            block: without_redundant_children(&self.block),
            exact_allow: sorted(&self.exact_allow),
            exact_block: sorted(&self.exact_block),
            wildcard_allow: sorted(&self.wildcard_allow),
            exact_wildcard_allow: sorted(&self.exact_wildcard_allow),
            wildcard_block: sorted(&self.wildcard_block),
            exact_wildcard_block: sorted(&self.exact_wildcard_block),
            skipped: self.skipped,
            exempted: self.exempted,
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
    if let Some(name) = wildcard_domain(pattern) {
        // A list in the wildcard domains format (see `DomainRules`): the name and its
        // subdomains, hashed like `||name^`, rather than a pattern tried on every lookup.
        let Some(name) = normalize_name(name) else {
            return Line::Skip;
        };
        let kind = match (exception, important) {
            (true, _) => Kind::Allow,
            (false, true) => Kind::Important,
            (false, false) => Kind::Block,
        };
        return Line::Rule {
            kind,
            name,
            badfilter,
        };
    }
    if pattern.contains('*') {
        // Lists unblock hosts that break sites with wildcard exceptions such as
        // `@@||clk*.tradedoubler.com^|`, and block families of hosts with wildcard blocks
        // such as `||log*.example.com^`.
        let Some((parents, glob)) = wildcard_pattern(pattern) else {
            return Line::Skip;
        };
        let kind = match (exception, important, parents) {
            (true, _, true) => Kind::WildcardAllow,
            (true, _, false) => Kind::ExactWildcardAllow,
            // An important pattern would need a section of its own; no DNS list uses one.
            (false, true, _) => return Line::Skip,
            (false, false, true) => Kind::WildcardBlock,
            (false, false, false) => Kind::ExactWildcardBlock,
        };
        return Line::Rule {
            kind,
            name: glob,
            badfilter,
        };
    }
    let mut exact = false;
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
    } else if let Some(rest) = pattern.strip_prefix('|') {
        // `|name^` and `|name^|` match the host name from its start to its end: exactly
        // that host. Without the caret it would be a prefix (`|ads.` matches `ads.x.com`).
        match rest.strip_suffix("^|").or_else(|| rest.strip_suffix('^')) {
            Some(name) => {
                exact = true;
                name
            }
            None => return Line::Skip,
        }
    } else if let Some(rest) = pattern.strip_prefix("://") {
        // `://name^` and `://name^|` match right after the scheme, up to the end of the
        // host: exactly that host, like `|name^`.
        match rest.strip_suffix("^|").or_else(|| rest.strip_suffix('^')) {
            Some(name) => {
                exact = true;
                name
            }
            None => return Line::Skip,
        }
    } else if pattern.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        // `name^` and `name^|` without an anchor match wherever the name ends at a
        // separator, so also in longer names; the DNS blocklist keeps the part it can
        // decide, the host and its subdomains, like `||name^`. The first character must
        // start a label: `-pia.example^` is a suffix of `x-pia.example`, not a block of
        // `pia.example`.
        match pattern
            .strip_suffix("^|")
            .or_else(|| pattern.strip_suffix('^'))
        {
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
    let kind = match (exception, important, exact) {
        (true, _, false) => Kind::Allow,
        (true, _, true) => Kind::ExactAllow,
        (false, true, false) => Kind::Important,
        // An important block of one host would need a section of its own; no DNS list
        // uses it.
        (false, true, true) => return Line::Skip,
        (false, false, false) => Kind::Block,
        (false, false, true) => Kind::ExactBlock,
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

/// The name of an unanchored rule in the wildcard domains format, `*.name`, `*.name^` or
/// `*.name^|` where `name` has no `*`: the name as written, not yet checked. `None` for
/// any other rule.
fn wildcard_domain(pattern: &str) -> Option<&str> {
    let rest = pattern.strip_prefix("*.")?;
    let name = rest
        .strip_suffix("^|")
        .or_else(|| rest.strip_suffix('^'))
        .unwrap_or(rest);
    (!name.contains('*')).then_some(name)
}

/// The pattern for the host part of a rule whose name has a `*`, and whether it also
/// covers parents (`||`), or `None` when it is not one [`is_valid_pattern`] accepts.
///
/// The pattern means what the rule means to adblock for a request to `https://host/`,
/// where `||` starts the match at the start of the host or of one of its labels, `|` and
/// `://` at the start of the host, and no anchor anywhere, while `^` (or `^|`) ends it at
/// the end of the host. So an unanchored rule gets a leading `*` and a rule without a caret
/// a trailing one. A caret after one trailing dot (`||x*.example.^`) ends the host as well.
/// Runs of `*` are merged, so `$badfilter` finds the same pattern however it is written.
fn wildcard_pattern(pattern: &str) -> Option<(bool, String)> {
    let (parents, start, rest) = if let Some(rest) = pattern.strip_prefix("||") {
        (true, "", rest)
    } else if let Some(rest) = pattern
        .strip_prefix("://")
        .or_else(|| pattern.strip_prefix('|'))
    {
        (false, "", rest)
    } else {
        (false, "*", pattern)
    };
    let mut glob = String::with_capacity(rest.len() + 2);
    glob.push_str(start);
    match rest.strip_suffix("^|").or_else(|| rest.strip_suffix('^')) {
        Some(name) => glob.push_str(name.strip_suffix('.').unwrap_or(name)),
        None => {
            glob.push_str(rest);
            glob.push('*');
        }
    }
    let mut merged = String::with_capacity(glob.len());
    for c in glob.chars() {
        if c != '*' || !merged.ends_with('*') {
            merged.push(c.to_ascii_lowercase());
        }
    }
    is_valid_pattern(&merged).then_some((parents, merged))
}

fn sorted(names: &HashSet<String>) -> Vec<String> {
    let mut names: Vec<String> = names.iter().cloned().collect();
    names.sort_unstable();
    names
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

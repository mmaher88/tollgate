//! Wildcard host patterns of the DNS blocklist (`||log*.example.com^`) and the index that
//! keeps looking them up cheap.
//!
//! A pattern is lowercase and made of letters, digits, `-`, `_`, `.` and `*`, where `*`
//! matches any run of characters, dots included, and the empty run. It must match a whole
//! name: the host, or with `||` a parent of the host as well.
//!
//! Every lookup of a host that no hash decides checks the wildcard blocks, so a lookup must
//! not try each pattern in turn. Each pattern is filed under its literal head (the text
//! before its first `*`) or its literal tail (the text after its last `*`), whichever is
//! longer. A matching name starts with the head, and the host ends with the tail, so a
//! lookup finds the heads that start the host or one of its labels and the tails that end
//! the host, and matches only the patterns filed under those in full. A pattern with a `*`
//! at both ends has neither and is tried for every host; lists rarely have one.

use std::collections::VecDeque;
use std::ops::Range;

/// Whether `pattern` has the stored form: at most 253 bytes, at least one dot, not only `*`
/// and dots (that would match nearly every name), lowercase labels of 1 to 63 letters,
/// digits, `-`, `_` and `*`, and a last label that is not all digits (IPv4 addresses).
/// These are the checks every build since wildcard exceptions has applied, so files written
/// by earlier builds still load.
pub(crate) fn is_valid_pattern(pattern: &str) -> bool {
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && label.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'*'
            })
    };
    pattern.len() <= 253
        && pattern.contains('.')
        && !pattern.bytes().all(|b| b == b'*' || b == b'.')
        && pattern.split('.').all(label_ok)
        && !pattern
            .rsplit('.')
            .next()
            .is_some_and(|last| last.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `text` matches `glob`, where `*` matches any run of bytes (dots included) and
/// ASCII letters in `text` match in either case. `glob` is lowercase.
pub(crate) fn glob_matches(glob: &[u8], text: &[u8]) -> bool {
    let (mut g, mut t) = (0, 0);
    // The last `*` seen and the text position it currently stands in for.
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if glob.get(g) == Some(&b'*') {
            star = Some((g, t));
            g += 1;
        } else if glob.get(g) == Some(&text[t].to_ascii_lowercase()) {
            g += 1;
            t += 1;
        } else if let Some((star_g, star_t)) = star {
            g = star_g + 1;
            t = star_t + 1;
            star = Some((star_g, star_t + 1));
        } else {
            return false;
        }
    }
    glob[g..].iter().all(|&b| b == b'*')
}

/// The name after each dot of `host`: its parents, and the last label alone.
fn parents(host: &[u8]) -> impl Iterator<Item = &[u8]> {
    host.iter()
        .enumerate()
        .filter(|&(_, &b)| b == b'.')
        .map(move |(i, _)| &host[i + 1..])
}

/// A wildcard pattern, parsed once at load.
pub(crate) struct Pattern {
    /// In the stored form, see [`is_valid_pattern`].
    glob: Box<[u8]>,
    /// Whether a parent of the host may match too (`||`), not only the host (`|`).
    parents: bool,
}

impl Pattern {
    /// Parses one line of a pattern section: `||pattern` or `|pattern`, the pattern in the
    /// stored form.
    pub(crate) fn parse(line: &str) -> Option<Pattern> {
        let (parents, glob) = match line.strip_prefix("||") {
            Some(glob) => (true, glob),
            None => (false, line.strip_prefix('|')?),
        };
        is_valid_pattern(glob).then(|| Pattern {
            glob: glob.as_bytes().into(),
            parents,
        })
    }

    /// Whether the pattern matches the host or, for `||` patterns, one of its parents.
    fn matches(&self, host: &[u8]) -> bool {
        glob_matches(&self.glob, host)
            || (self.parents && parents(host).any(|name| glob_matches(&self.glob, name)))
    }

    /// The text before the first `*`.
    fn head(&self) -> &[u8] {
        let end = self.glob.iter().position(|&b| b == b'*');
        &self.glob[..end.unwrap_or(self.glob.len())]
    }

    /// The text after the last `*`.
    fn tail(&self) -> &[u8] {
        let start = self.glob.iter().rposition(|&b| b == b'*');
        &self.glob[start.map_or(0, |i| i + 1)..]
    }
}

/// Wildcard patterns of one kind (blocks or exceptions), filed for lookup. `Send + Sync`;
/// lookups never allocate.
#[derive(Default)]
pub(crate) struct PatternSet {
    patterns: Vec<Pattern>,
    /// Patterns filed under their head.
    heads: Trie,
    /// Patterns filed under their tail, reversed so the tails are prefixes of the reversed
    /// host.
    tails: Trie,
    /// Patterns that start and end with `*`.
    unkeyed: Vec<u32>,
}

impl PatternSet {
    pub(crate) fn new(patterns: Vec<Pattern>) -> PatternSet {
        let mut heads = Vec::new();
        let mut tails = Vec::new();
        let mut unkeyed = Vec::new();
        for (id, pattern) in patterns.iter().enumerate() {
            let id = u32::try_from(id).expect("fewer than 2^32 patterns");
            let (head, tail) = (pattern.head(), pattern.tail());
            // The longer literal matches fewer hosts, so fewer candidates are tried in full.
            // A tail is looked up once per host and a head once per label, so a tail wins
            // a tie.
            if !tail.is_empty() && tail.len() >= head.len() {
                tails.push((tail.iter().rev().copied().collect(), id));
            } else if !head.is_empty() {
                heads.push((head.to_vec(), id));
            } else {
                unkeyed.push(id);
            }
        }
        PatternSet {
            patterns,
            heads: Trie::new(heads),
            tails: Trie::new(tails),
            unkeyed,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Whether a pattern matches `host` (lowercase or not, without a trailing dot) or, for
    /// `||` patterns, one of its parents.
    pub(crate) fn matches(&self, host: &[u8]) -> bool {
        let lower = |b: &u8| b.to_ascii_lowercase();
        let tail_found = self.tails.any(host.iter().rev().map(lower), |id| {
            self.patterns[id as usize].matches(host)
        });
        if tail_found {
            return true;
        }
        if !self.heads.is_empty() {
            // A name that matches starts with the head: the host itself, or for `||` patterns
            // the name after one of its dots. Only that name needs to be tried.
            let starts =
                std::iter::once(0).chain(parents(host).map(|name| host.len() - name.len()));
            for start in starts {
                let name = &host[start..];
                let head_found = self.heads.any(name.iter().map(lower), |id| {
                    let pattern = &self.patterns[id as usize];
                    (start == 0 || pattern.parents) && glob_matches(&pattern.glob, name)
                });
                if head_found {
                    return true;
                }
            }
        }
        self.unkeyed
            .iter()
            .any(|&id| self.patterns[id as usize].matches(host))
    }
}

/// Byte strings (the heads, or the reversed tails, of patterns) as a trie, each with the
/// patterns filed under it. Walking it along a text visits the strings that start the text,
/// and stops at the first byte that no string continues with, usually after a few bytes.
#[derive(Default)]
struct Trie {
    /// The child of the root for each byte, 0 for none. Every walk starts here, and the root
    /// has the most children, so it gets a table instead of a search. Empty when no string
    /// is stored.
    root: Vec<u32>,
    /// Per node, where its children start in `edge_bytes` and `edge_nodes`; one more entry
    /// marks the end of the last node's. Node 0 is the root, whose children are also here.
    edge_start: Vec<u32>,
    /// The byte leading to each child, sorted within a node.
    edge_bytes: Vec<u8>,
    edge_nodes: Vec<u32>,
    /// Per node, where the patterns filed under the string that ends there start in `ids`,
    /// with one more entry like `edge_start`.
    id_start: Vec<u32>,
    ids: Vec<u32>,
}

impl Trie {
    /// Files each pattern id under its string; strings must not be empty.
    ///
    /// The strings are sorted, so the strings under a node are a run of them that share
    /// its path, those that end there first, and its children follow in byte order. The
    /// nodes are numbered level by level, which gives every node's children consecutive
    /// numbers, so the arrays are written in node order without a map per node.
    fn new(mut entries: Vec<(Vec<u8>, u32)>) -> Trie {
        if entries.is_empty() {
            return Trie::default();
        }
        entries.sort_unstable();
        let offset = |n: usize| u32::try_from(n).expect("fewer than 2^32 entries");
        // Every node but the root ends a prefix of a string, so this bounds the edges; the
        // arrays are allocated once and trimmed, instead of leaving the buffers they would
        // outgrow behind in the tunnel's heap.
        let edges: usize = entries.iter().map(|(key, _)| key.len()).sum();
        let mut trie = Trie {
            root: vec![0; 256],
            edge_start: Vec::with_capacity(edges + 2),
            edge_bytes: Vec::with_capacity(edges),
            edge_nodes: Vec::with_capacity(edges),
            id_start: Vec::with_capacity(edges + 2),
            ids: Vec::with_capacity(entries.len()),
        };
        // The nodes numbered but not written yet, in node order: each one's run of
        // `entries` and the length of its path.
        let mut pending: VecDeque<(Range<usize>, usize)> = VecDeque::from([(0..entries.len(), 0)]);
        let mut numbered = 1;
        let mut root = true;
        while let Some((run, depth)) = pending.pop_front() {
            trie.edge_start.push(offset(trie.edge_bytes.len()));
            trie.id_start.push(offset(trie.ids.len()));
            let mut at = run.start;
            while at < run.end && entries[at].0.len() == depth {
                trie.ids.push(entries[at].1);
                at += 1;
            }
            while at < run.end {
                let byte = entries[at].0[depth];
                let mut end = at + 1;
                while end < run.end && entries[end].0[depth] == byte {
                    end += 1;
                }
                let child = offset(numbered);
                numbered += 1;
                if root {
                    trie.root[byte as usize] = child;
                }
                trie.edge_bytes.push(byte);
                trie.edge_nodes.push(child);
                pending.push_back((at..end, depth + 1));
                at = end;
            }
            root = false;
        }
        trie.edge_start.push(offset(trie.edge_bytes.len()));
        trie.id_start.push(offset(trie.ids.len()));
        for list in [
            &mut trie.edge_start,
            &mut trie.edge_nodes,
            &mut trie.id_start,
        ] {
            list.shrink_to_fit();
        }
        trie.edge_bytes.shrink_to_fit();
        trie.ids.shrink_to_fit();
        trie
    }

    fn is_empty(&self) -> bool {
        self.root.is_empty()
    }

    /// Calls `f` with the patterns filed under each string that starts `text`, shortest
    /// string first, until it returns true. Returns whether it did.
    fn any(&self, mut text: impl Iterator<Item = u8>, mut f: impl FnMut(u32) -> bool) -> bool {
        let Some(first) = text.next() else {
            return false;
        };
        let Some(&child) = self.root.get(first as usize) else {
            return false;
        };
        // The root is nobody's child, so 0 means none.
        if child == 0 {
            return false;
        }
        let mut node = child as usize;
        loop {
            let ids = self.id_start[node] as usize..self.id_start[node + 1] as usize;
            if self.ids[ids].iter().any(|&id| f(id)) {
                return true;
            }
            let Some(byte) = text.next() else {
                return false;
            };
            let edges = self.edge_start[node] as usize..self.edge_start[node + 1] as usize;
            let Ok(i) = self.edge_bytes[edges.clone()].binary_search(&byte) else {
                return false;
            };
            node = self.edge_nodes[edges.start + i] as usize;
        }
    }
}

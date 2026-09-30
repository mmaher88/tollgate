//! The DNS blocklist file (`domains.bin`) and lookups in it.
//!
//! Layout, all integers little-endian:
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 4 | magic `TGDS` |
//! | 4 | 4 | format version, 1 |
//! | 8 | 4 | block count |
//! | 12 | 4 | allow count |
//! | 16 | 4 | important count |
//! | 20 | 4 | pattern section length in bytes (0 in files without one) |
//! | 24 | 8 | FNV-1a 64 of every byte after the header |
//! | 32 | 8 each | block hashes, then allow hashes, then important hashes |
//! | after the hashes | as given | wildcard exception patterns |
//!
//! Each hash is FNV-1a 64 of the lowercase name without a trailing dot. An entry for one
//! host only, not its subdomains (`|name^` rules), is stored in the block or allow section
//! as the hash of `|` followed by the name, which no name can produce. Each section is
//! sorted ascending with no duplicates. A false positive needs a 64-bit collision: about
//! 5e-14 per lookup with 250,000 names.
//!
//! The pattern section holds the wildcard exceptions (`@@||clk*.tradedoubler.com^|`) as
//! text, one per line, each ending in `\n`: `||pattern` for the host and its parents,
//! `|pattern` for the host only. Patterns are lowercase and sorted, `||` ones first. Files
//! written before the section existed have 0 in its length field and load unchanged.

use std::fs::File;
use std::ops::Range;
use std::path::Path;

use memmap2::Mmap;

use crate::domain_rules::normalize_pattern;
use crate::{DomainRules, FilterError, ListSource};

const MAGIC: [u8; 4] = *b"TGDS";
const VERSION: u32 = 1;
const HEADER_LEN: usize = 32;

/// The number of hashes in an encoded file, for the compile report.
pub(crate) fn hash_count(bytes: &[u8]) -> u64 {
    [8, 12, 16]
        .iter()
        .map(|&at| u64::from(read_u32(bytes, at)))
        .sum()
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DomainSetError {
    #[error("shorter than the 32 byte header")]
    TooShort,
    #[error("not a domain set file")]
    BadMagic,
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u32),
    #[error("wildcard exception section is malformed")]
    BadPatterns,
    #[error("header promises {expected} bytes, file has {actual}")]
    LengthMismatch { expected: u64, actual: u64 },
    #[error("checksum mismatch")]
    BadChecksum,
    #[error("hashes are not sorted and unique")]
    Unsorted,
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// Prefix of the name in the hash of an entry for one host only.
const EXACT_TAG: &[u8] = b"|";

/// FNV-1a 64 over the bytes, lowercasing ASCII letters on the way.
fn fnv1a64(bytes: &[u8]) -> u64 {
    fnv1a64_from(FNV_OFFSET, bytes)
}

/// The hash of an entry for exactly `name`.
fn exact_hash(name: &[u8]) -> u64 {
    fnv1a64_from(fnv1a64(EXACT_TAG), name)
}

/// FNV-1a 64 continued from `hash` over more bytes, lowercasing ASCII letters.
fn fnv1a64_from(mut hash: u64, bytes: &[u8]) -> u64 {
    for b in bytes {
        hash ^= u64::from(b.to_ascii_lowercase());
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// FNV-1a 64 of the raw bytes, for the checksum.
fn checksum(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"))
}

/// The hashes of `names` and of the one-host entries `exact`, sorted and unique.
fn sorted_hashes(names: &[String], exact: &[String]) -> Vec<u64> {
    let mut hashes: Vec<u64> = names
        .iter()
        .map(|n| fnv1a64(n.as_bytes()))
        .chain(exact.iter().map(|n| exact_hash(n.as_bytes())))
        .collect();
    hashes.sort_unstable();
    hashes.dedup();
    hashes
}

impl DomainRules {
    /// The `domains.bin` bytes for these rules.
    pub fn encode(&self) -> Vec<u8> {
        let sections = [
            sorted_hashes(&self.block, &self.exact_block),
            sorted_hashes(&self.allow, &self.exact_allow),
            sorted_hashes(&self.important, &[]),
        ];
        let total: usize = sections.iter().map(Vec::len).sum();
        let mut patterns = String::new();
        for (prefix, list) in [
            ("||", &self.wildcard_allow),
            ("|", &self.exact_wildcard_allow),
        ] {
            for pattern in list {
                patterns.push_str(prefix);
                patterns.push_str(pattern);
                patterns.push('\n');
            }
        }
        let mut out = Vec::with_capacity(HEADER_LEN + 8 * total + patterns.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        for section in &sections {
            let count = u32::try_from(section.len()).expect("fewer than 2^32 names");
            out.extend_from_slice(&count.to_le_bytes());
        }
        let patterns_len = u32::try_from(patterns.len()).expect("patterns under 4 GiB");
        out.extend_from_slice(&patterns_len.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        for hash in sections.iter().flatten() {
            out.extend_from_slice(&hash.to_le_bytes());
        }
        out.extend_from_slice(patterns.as_bytes());
        let sum = checksum(&out[HEADER_LEN..]);
        out[24..32].copy_from_slice(&sum.to_le_bytes());
        out
    }
}

enum Backing {
    Mapped(Mmap),
    Owned(Vec<u8>),
}

impl Backing {
    fn bytes(&self) -> &[u8] {
        match self {
            Backing::Mapped(map) => map,
            Backing::Owned(bytes) => bytes,
        }
    }
}

/// A wildcard exception, parsed once at load.
struct Pattern {
    /// Lowercase, `*` matches any run of characters.
    glob: Box<[u8]>,
    /// Whether a parent of the host may match too (`||`), not only the host (`|`).
    parents: bool,
}

/// Parses the pattern section: every line must be `||pattern` or `|pattern` with a pattern
/// the list parser would have produced, and end in a newline.
fn parse_patterns(section: &[u8]) -> Option<Vec<Pattern>> {
    let text = std::str::from_utf8(section).ok()?;
    let body = match text.strip_suffix('\n') {
        Some(body) => body,
        None if text.is_empty() => return Some(Vec::new()),
        None => return None,
    };
    body.split('\n')
        .map(|line| {
            let (parents, pattern) = match line.strip_prefix("||") {
                Some(pattern) => (true, pattern),
                None => (false, line.strip_prefix('|')?),
            };
            (normalize_pattern(pattern).as_deref() == Some(pattern)).then(|| Pattern {
                glob: pattern.as_bytes().into(),
                parents,
            })
        })
        .collect()
}

/// Whether `text` matches `glob`, where `*` matches any run of bytes (dots included) and
/// ASCII letters in `text` match in either case. `glob` is lowercase.
fn glob_matches(glob: &[u8], text: &[u8]) -> bool {
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

/// The hashed DNS blocklist. `Send + Sync`; lookups never allocate.
pub struct DomainSet {
    data: Backing,
    block: Range<usize>,
    allow: Range<usize>,
    important: Range<usize>,
    patterns: Vec<Pattern>,
}

impl DomainSet {
    /// Parses the lists and returns the file bytes.
    pub fn build(lists: &[ListSource]) -> Vec<u8> {
        DomainRules::parse(lists).encode()
    }

    /// Maps the file; the hashes are never copied to the heap.
    pub fn load(path: &Path) -> Result<DomainSet, FilterError> {
        let io = |source| FilterError::Io {
            path: path.to_path_buf(),
            source,
        };
        let file = File::open(path).map_err(io)?;
        let len = file.metadata().map_err(io)?.len();
        if len < HEADER_LEN as u64 {
            return Err(DomainSetError::TooShort.into());
        }
        // SAFETY: compile() replaces domains.bin by renaming a new file over it and never
        // writes into an existing file, so the mapped bytes cannot change under us.
        let map = unsafe { Mmap::map(&file) }.map_err(io)?;
        DomainSet::new(Backing::Mapped(map))
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<DomainSet, FilterError> {
        DomainSet::new(Backing::Owned(bytes))
    }

    fn new(data: Backing) -> Result<DomainSet, FilterError> {
        let bytes = data.bytes();
        if bytes.len() < HEADER_LEN {
            return Err(DomainSetError::TooShort.into());
        }
        if bytes[0..4] != MAGIC {
            return Err(DomainSetError::BadMagic.into());
        }
        let version = read_u32(bytes, 4);
        if version != VERSION {
            return Err(DomainSetError::UnsupportedVersion(version).into());
        }
        let patterns_len = u64::from(read_u32(bytes, 20));
        let counts =
            [read_u32(bytes, 8), read_u32(bytes, 12), read_u32(bytes, 16)].map(|c| c as usize);
        let total: u64 = counts.iter().map(|&c| c as u64).sum();
        let expected = HEADER_LEN as u64 + 8 * total + patterns_len;
        if bytes.len() as u64 != expected {
            return Err(DomainSetError::LengthMismatch {
                expected,
                actual: bytes.len() as u64,
            }
            .into());
        }
        let stored = u64::from_le_bytes(bytes[24..32].try_into().expect("8 bytes"));
        if checksum(&bytes[HEADER_LEN..]) != stored {
            return Err(DomainSetError::BadChecksum.into());
        }
        let block = 0..counts[0];
        let allow = block.end..block.end + counts[1];
        let important = allow.end..allow.end + counts[2];
        let Some(patterns) = parse_patterns(&bytes[HEADER_LEN + 8 * important.end..]) else {
            return Err(DomainSetError::BadPatterns.into());
        };
        let set = DomainSet {
            data,
            block,
            allow,
            important,
            patterns,
        };
        for range in [&set.block, &set.allow, &set.important] {
            let hashes = &set.hashes()[range.clone()];
            if !hashes
                .windows(2)
                .all(|w| u64::from_le_bytes(w[0]) < u64::from_le_bytes(w[1]))
            {
                return Err(DomainSetError::Unsorted.into());
            }
        }
        Ok(set)
    }

    fn hashes(&self) -> &[[u8; 8]] {
        self.data.bytes()[HEADER_LEN..HEADER_LEN + 8 * self.important.end]
            .as_chunks::<8>()
            .0
    }

    /// Whether a wildcard exception matches the host (or, for `||` patterns, a parent).
    fn wildcard_allowed(&self, host: &[u8]) -> bool {
        self.patterns.iter().any(|pattern| {
            if !pattern.parents {
                return glob_matches(&pattern.glob, host);
            }
            let parents = host
                .iter()
                .enumerate()
                .filter(|&(_, &b)| b == b'.')
                .map(|(i, _)| &host[i + 1..]);
            std::iter::once(host)
                .chain(parents)
                .any(|name| glob_matches(&pattern.glob, name))
        })
    }

    fn contains(&self, range: &Range<usize>, hash: u64) -> bool {
        self.hashes()[range.clone()]
            .binary_search_by(|entry| u64::from_le_bytes(*entry).cmp(&hash))
            .is_ok()
    }

    /// True if an entry covers the host or one of its parents, taking important blocks
    /// first, then exceptions (for the host only, then for it and its parents), then blocks
    /// (the same way). A block is lifted when a wildcard exception matches. ASCII case and
    /// one trailing dot are ignored.
    pub fn is_blocked(&self, host: &str) -> bool {
        let host = host.strip_suffix('.').unwrap_or(host).as_bytes();
        // The host and each parent that still has a dot: names without a dot are never
        // stored.
        let mut hashes = [0u64; 127];
        let mut n = 0;
        let mut start = 0;
        while n < hashes.len() {
            let rest = &host[start..];
            let Some(dot) = rest.iter().position(|&b| b == b'.') else {
                break;
            };
            hashes[n] = fnv1a64(rest);
            n += 1;
            start += dot + 1;
        }
        let hashes = &hashes[..n];
        let covered = |range: &Range<usize>| {
            !range.is_empty() && hashes.iter().any(|&h| self.contains(range, h))
        };
        if hashes.is_empty() {
            return false;
        }
        let exact = exact_hash(host);
        let exactly = |range: &Range<usize>| !range.is_empty() && self.contains(range, exact);
        if covered(&self.important) {
            return true;
        }
        if exactly(&self.allow) || covered(&self.allow) {
            return false;
        }
        (exactly(&self.block) || covered(&self.block)) && !self.wildcard_allowed(host)
    }

    /// Number of stored hashes: blocks, exceptions and important blocks together. Wildcard
    /// exceptions are not counted.
    pub fn len(&self) -> usize {
        self.important.end
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

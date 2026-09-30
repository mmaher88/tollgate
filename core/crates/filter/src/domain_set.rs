//! The DNS blocklist file (`domains.bin`) and lookups in it.
//!
//! Layout of format version 2, all integers little-endian:
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 4 | magic `TGDS` |
//! | 4 | 4 | format version, 2 |
//! | 8 | 4 | block count |
//! | 12 | 4 | allow count |
//! | 16 | 4 | important count |
//! | 20 | 4 | wildcard exception section length in bytes |
//! | 24 | 8 | FNV-1a 64 of every byte after the header |
//! | 32 | 4 | wildcard block section length in bytes |
//! | 36 | 4 | padding, 0, so the hashes stay 8-byte aligned |
//! | 40 | 8 each | block hashes, then allow hashes, then important hashes |
//! | after the hashes | as given | wildcard exceptions, then wildcard blocks |
//!
//! Each hash is FNV-1a 64 of the lowercase name without a trailing dot. An entry for one
//! host only, not its subdomains (`|name^` rules), is stored in the block or allow section
//! as the hash of `|` followed by the name, which no name can produce. Each section is
//! sorted ascending with no duplicates. A false positive needs a 64-bit collision: about
//! 5e-14 per lookup with 250,000 names.
//!
//! The two wildcard sections hold patterns (see [`crate::DomainRules`]) as text, one per
//! line, each ending in `\n`: `||pattern` for the host and its parents, `|pattern` for the
//! host only. Patterns are lowercase and sorted, `||` ones first.
//!
//! Version 1 is the same without bytes 32 to 40 and the wildcard block section: a 32-byte
//! header, and only wildcard exceptions after the hashes (0 bytes of them in files written
//! before wildcard exceptions existed). After an app update the tunnel keeps loading the
//! file the previous version compiled until the lists are compiled again, so version 1
//! files still load; they block nothing by pattern.

use std::fs::File;
use std::ops::Range;
use std::path::Path;

use memmap2::Mmap;

use crate::wildcard::{Pattern, PatternSet};
use crate::{DomainRules, FilterError, ListSource};

const MAGIC: [u8; 4] = *b"TGDS";
/// The version [`DomainRules::encode`] writes.
const VERSION: u32 = 2;
/// The oldest version that still loads.
const OLDEST_VERSION: u32 = 1;
/// The header of version 1 files; also the shortest file there is.
const HEADER_LEN_V1: usize = 32;
const HEADER_LEN: usize = 40;

/// The number of hashes in an encoded file, for the compile report.
pub(crate) fn hash_count(bytes: &[u8]) -> u64 {
    [8, 12, 16]
        .iter()
        .map(|&at| u64::from(read_u32(bytes, at)))
        .sum()
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DomainSetError {
    #[error("shorter than its header")]
    TooShort,
    #[error("not a domain set file")]
    BadMagic,
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u32),
    #[error("header padding is not zero")]
    BadHeader,
    #[error("wildcard section is malformed")]
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

/// A wildcard section: `||pattern` lines for `parents`, then `|pattern` lines for `host`.
fn pattern_section(parents: &[String], host: &[String]) -> String {
    let mut section = String::new();
    for (prefix, list) in [("||", parents), ("|", host)] {
        for pattern in list {
            section.push_str(prefix);
            section.push_str(pattern);
            section.push('\n');
        }
    }
    section
}

fn section_len(section: &str) -> [u8; 4] {
    u32::try_from(section.len())
        .expect("wildcard section under 4 GiB")
        .to_le_bytes()
}

impl DomainRules {
    /// The `domains.bin` bytes for these rules, in the current format version.
    pub fn encode(&self) -> Vec<u8> {
        let sections = [
            sorted_hashes(&self.block, &self.exact_block),
            sorted_hashes(&self.allow, &self.exact_allow),
            sorted_hashes(&self.important, &[]),
        ];
        let total: usize = sections.iter().map(Vec::len).sum();
        let allow_patterns = pattern_section(&self.wildcard_allow, &self.exact_wildcard_allow);
        let block_patterns = pattern_section(&self.wildcard_block, &self.exact_wildcard_block);
        let mut out = Vec::with_capacity(
            HEADER_LEN + 8 * total + allow_patterns.len() + block_patterns.len(),
        );
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        for section in &sections {
            let count = u32::try_from(section.len()).expect("fewer than 2^32 names");
            out.extend_from_slice(&count.to_le_bytes());
        }
        out.extend_from_slice(&section_len(&allow_patterns));
        // The checksum, filled in below.
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&section_len(&block_patterns));
        out.extend_from_slice(&0u32.to_le_bytes());
        for hash in sections.iter().flatten() {
            out.extend_from_slice(&hash.to_le_bytes());
        }
        out.extend_from_slice(allow_patterns.as_bytes());
        out.extend_from_slice(block_patterns.as_bytes());
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

/// Parses a wildcard section: every line must be `||pattern` or `|pattern` with a pattern
/// in the stored form, and end in a newline.
fn parse_patterns(section: &[u8]) -> Option<PatternSet> {
    let text = std::str::from_utf8(section).ok()?;
    let body = match text.strip_suffix('\n') {
        Some(body) => body,
        None if text.is_empty() => return Some(PatternSet::default()),
        None => return None,
    };
    let patterns = body
        .split('\n')
        .map(Pattern::parse)
        .collect::<Option<_>>()?;
    Some(PatternSet::new(patterns))
}

/// The hashed DNS blocklist and its wildcard patterns. `Send + Sync`; lookups never
/// allocate.
pub struct DomainSet {
    data: Backing,
    /// Where the hashes start: after the header of the file's version.
    hashes_at: usize,
    block: Range<usize>,
    allow: Range<usize>,
    important: Range<usize>,
    wildcard_allow: PatternSet,
    wildcard_block: PatternSet,
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
        if len < HEADER_LEN_V1 as u64 {
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
        if bytes.len() < HEADER_LEN_V1 {
            return Err(DomainSetError::TooShort.into());
        }
        if bytes[0..4] != MAGIC {
            return Err(DomainSetError::BadMagic.into());
        }
        let version = read_u32(bytes, 4);
        if !(OLDEST_VERSION..=VERSION).contains(&version) {
            return Err(DomainSetError::UnsupportedVersion(version).into());
        }
        let (header_len, block_patterns_len) = if version == 1 {
            (HEADER_LEN_V1, 0)
        } else {
            if bytes.len() < HEADER_LEN {
                return Err(DomainSetError::TooShort.into());
            }
            if read_u32(bytes, 36) != 0 {
                return Err(DomainSetError::BadHeader.into());
            }
            (HEADER_LEN, u64::from(read_u32(bytes, 32)))
        };
        let allow_patterns_len = u64::from(read_u32(bytes, 20));
        let counts =
            [read_u32(bytes, 8), read_u32(bytes, 12), read_u32(bytes, 16)].map(|c| c as usize);
        let total: u64 = counts.iter().map(|&c| c as u64).sum();
        let expected = header_len as u64 + 8 * total + allow_patterns_len + block_patterns_len;
        if bytes.len() as u64 != expected {
            return Err(DomainSetError::LengthMismatch {
                expected,
                actual: bytes.len() as u64,
            }
            .into());
        }
        let stored = u64::from_le_bytes(bytes[24..32].try_into().expect("8 bytes"));
        if checksum(&bytes[header_len..]) != stored {
            return Err(DomainSetError::BadChecksum.into());
        }
        let block = 0..counts[0];
        let allow = block.end..block.end + counts[1];
        let important = allow.end..allow.end + counts[2];
        // The lengths add up to the file's, so these fit.
        let allow_at = header_len + 8 * important.end;
        let block_at = allow_at + allow_patterns_len as usize;
        let (Some(wildcard_allow), Some(wildcard_block)) = (
            parse_patterns(&bytes[allow_at..block_at]),
            parse_patterns(&bytes[block_at..]),
        ) else {
            return Err(DomainSetError::BadPatterns.into());
        };
        let set = DomainSet {
            data,
            hashes_at: header_len,
            block,
            allow,
            important,
            wildcard_allow,
            wildcard_block,
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
        self.data.bytes()[self.hashes_at..self.hashes_at + 8 * self.important.end]
            .as_chunks::<8>()
            .0
    }

    fn contains(&self, range: &Range<usize>, hash: u64) -> bool {
        self.hashes()[range.clone()]
            .binary_search_by(|entry| u64::from_le_bytes(*entry).cmp(&hash))
            .is_ok()
    }

    /// Whether the host is blocked. The first rule kind that has an entry for it decides:
    ///
    /// 1. an important block of the host or a parent: blocked;
    /// 2. an exception for the host only, or for the host or a parent: not blocked;
    /// 3. a wildcard exception that matches the host (or, for `||` patterns, a parent):
    ///    not blocked;
    /// 4. a block of the host only, a block of the host or a parent, or a wildcard block
    ///    that matches the host (or, for `||` patterns, a parent): blocked.
    ///
    /// Otherwise it is not blocked. So every exception, exact, hashed or wildcard, wins
    /// over every block but an important one, as in adblock. ASCII case and one trailing
    /// dot are ignored.
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
        // Blocks come before the wildcard exceptions, which only matter for a blocked host.
        let blocked =
            exactly(&self.block) || covered(&self.block) || self.wildcard_block.matches(host);
        blocked && !self.wildcard_allow.matches(host)
    }

    /// Number of stored hashes: blocks, exceptions and important blocks together. Wildcard
    /// patterns are not counted; see [`DomainSet::pattern_count`].
    pub fn len(&self) -> usize {
        self.important.end
    }

    /// Number of wildcard patterns: blocks and exceptions together.
    pub fn pattern_count(&self) -> usize {
        self.wildcard_allow.len() + self.wildcard_block.len()
    }

    /// Whether no hashes are stored, like `len() == 0`; wildcard patterns may still block.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

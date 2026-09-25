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
//! | 20 | 4 | reserved, 0 |
//! | 24 | 8 | FNV-1a 64 of every byte after the header |
//! | 32 | 8 each | block hashes, then allow hashes, then important hashes |
//!
//! Each hash is FNV-1a 64 of the lowercase name without a trailing dot. Each section is
//! sorted ascending with no duplicates. A false positive needs a 64-bit collision: about
//! 5e-14 per lookup with 250,000 names.

use std::fs::File;
use std::ops::Range;
use std::path::Path;

use memmap2::Mmap;

use crate::{DomainRules, FilterError, ListSource};

const MAGIC: [u8; 4] = *b"TGDS";
const VERSION: u32 = 1;
pub(crate) const HEADER_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DomainSetError {
    #[error("shorter than the 32 byte header")]
    TooShort,
    #[error("not a domain set file")]
    BadMagic,
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u32),
    #[error("reserved header field is not zero")]
    BadHeader,
    #[error("header promises {expected} bytes, file has {actual}")]
    LengthMismatch { expected: u64, actual: u64 },
    #[error("checksum mismatch")]
    BadChecksum,
    #[error("hashes are not sorted and unique")]
    Unsorted,
}

/// FNV-1a 64 over the bytes, lowercasing ASCII letters on the way.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
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

fn sorted_hashes(names: &[String]) -> Vec<u64> {
    let mut hashes: Vec<u64> = names.iter().map(|n| fnv1a64(n.as_bytes())).collect();
    hashes.sort_unstable();
    hashes.dedup();
    hashes
}

impl DomainRules {
    /// The `domains.bin` bytes for these rules.
    pub fn encode(&self) -> Vec<u8> {
        let sections = [
            sorted_hashes(&self.block),
            sorted_hashes(&self.allow),
            sorted_hashes(&self.important),
        ];
        let total: usize = sections.iter().map(Vec::len).sum();
        let mut out = Vec::with_capacity(HEADER_LEN + 8 * total);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        for section in &sections {
            let count = u32::try_from(section.len()).expect("fewer than 2^32 names");
            out.extend_from_slice(&count.to_le_bytes());
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        for hash in sections.iter().flatten() {
            out.extend_from_slice(&hash.to_le_bytes());
        }
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

/// The hashed DNS blocklist. `Send + Sync`; lookups never allocate.
pub struct DomainSet {
    data: Backing,
    block: Range<usize>,
    allow: Range<usize>,
    important: Range<usize>,
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
        if read_u32(bytes, 20) != 0 {
            return Err(DomainSetError::BadHeader.into());
        }
        let counts =
            [read_u32(bytes, 8), read_u32(bytes, 12), read_u32(bytes, 16)].map(|c| c as usize);
        let total: u64 = counts.iter().map(|&c| c as u64).sum();
        let expected = HEADER_LEN as u64 + 8 * total;
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
        let set = DomainSet {
            data,
            block,
            allow,
            important,
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
        self.data.bytes()[HEADER_LEN..].as_chunks::<8>().0
    }

    fn contains(&self, range: &Range<usize>, hash: u64) -> bool {
        self.hashes()[range.clone()]
            .binary_search_by(|entry| u64::from_le_bytes(*entry).cmp(&hash))
            .is_ok()
    }

    /// True if an entry covers the host or one of its parents, taking important blocks
    /// first, then exceptions, then blocks. ASCII case and one trailing dot are ignored.
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
        if covered(&self.important) {
            return true;
        }
        if covered(&self.allow) {
            return false;
        }
        covered(&self.block)
    }

    /// Number of stored hashes: blocks, exceptions and important blocks together.
    pub fn len(&self) -> usize {
        self.important.end
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

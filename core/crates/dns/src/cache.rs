//! The answer cache: upstream answers as wire bytes, keyed by question, aged with the
//! continuous clock that the caller passes in.

use std::num::NonZeroUsize;

use lru::LruCache;

use crate::answer::UpstreamAnswer;

/// Most answers kept; the least recently used one is dropped first.
pub const CACHE_CAPACITY: usize = 2000;
/// Shortest time an answer is kept, in seconds, even when its records say less.
pub const MIN_CACHE_TTL: u32 = 10;
/// Longest time an answer is kept, in seconds, even when its records say more.
pub const MAX_CACHE_TTL: u32 = 3600;

struct Entry {
    answer: UpstreamAnswer,
    stored_at: u64,
    lifetime: u32,
}

pub(crate) struct AnswerCache {
    entries: LruCache<Box<[u8]>, Entry>,
    max_ttl: u32,
}

impl AnswerCache {
    pub fn new() -> AnswerCache {
        AnswerCache::with_limits(CACHE_CAPACITY, MAX_CACHE_TTL)
    }

    /// A cache of at most `capacity` answers kept for at most `max_ttl` seconds.
    pub fn with_limits(capacity: usize, max_ttl: u32) -> AnswerCache {
        let capacity = NonZeroUsize::new(capacity.max(1)).expect("capacity is not zero");
        AnswerCache {
            entries: LruCache::new(capacity),
            max_ttl: max_ttl.max(MIN_CACHE_TTL),
        }
    }

    /// Keeps `answer` for its smallest record TTL, clamped to [`MIN_CACHE_TTL`] and the
    /// cache's longest time ([`MAX_CACHE_TTL`] for [`AnswerCache::new`]).
    pub fn insert(&mut self, key: Box<[u8]>, answer: UpstreamAnswer, now: u64) {
        let lifetime = answer.min_ttl().clamp(MIN_CACHE_TTL, self.max_ttl);
        let entry = Entry {
            answer,
            stored_at: now,
            lifetime,
        };
        self.entries.put(key, entry);
    }

    /// The live answer for `key` and the whole seconds since it was stored. An expired
    /// answer is removed.
    pub fn get(&mut self, key: &[u8], now: u64) -> Option<(&UpstreamAnswer, u32)> {
        let entry = self.entries.peek(key)?;
        let elapsed = now.saturating_sub(entry.stored_at);
        if elapsed >= u64::from(entry.lifetime) {
            self.entries.pop(key);
            return None;
        }
        let entry = self.entries.get(key)?;
        Some((&entry.answer, elapsed as u32))
    }
}

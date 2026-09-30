//! Logging a repeated condition at most once per key in a given interval.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Keys remembered at once; when full, a key not seen within the interval is allowed only
/// after the older ones expire, so the table stays small whatever the traffic.
const MAX_KEYS: usize = 256;

pub(crate) struct LogThrottle {
    interval: Duration,
    last: Mutex<HashMap<String, Instant>>,
}

impl LogThrottle {
    pub(crate) fn new(interval: Duration) -> LogThrottle {
        LogThrottle {
            interval,
            last: Mutex::new(HashMap::new()),
        }
    }

    /// True when nothing was logged for `key` within the interval; the caller logs then.
    pub(crate) fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        let recent = |at: &Instant| now.saturating_duration_since(*at) < self.interval;
        if last.get(key).is_some_and(recent) {
            return false;
        }
        if last.len() >= MAX_KEYS {
            last.retain(|_, at| recent(at));
            if last.len() >= MAX_KEYS {
                return false;
            }
        }
        last.insert(key.to_string(), now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logs_each_key_once_per_interval() {
        let throttle = LogThrottle::new(Duration::from_secs(60));
        assert!(throttle.allow("a.test"));
        assert!(!throttle.allow("a.test"));
        assert!(throttle.allow("b.test"));
        let short = LogThrottle::new(Duration::ZERO);
        assert!(short.allow("a.test"));
        assert!(short.allow("a.test"));
    }

    #[test]
    fn the_table_stays_bounded() {
        let throttle = LogThrottle::new(Duration::from_secs(60));
        for i in 0..MAX_KEYS {
            assert!(throttle.allow(&format!("{i}.test")));
        }
        assert!(!throttle.allow("one-more.test"));
        assert_eq!(throttle.last.lock().unwrap().len(), MAX_KEYS);
    }
}

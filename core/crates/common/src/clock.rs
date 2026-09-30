//! Clocks.
//!
//! [`now_secs`] keeps counting while the device sleeps, unlike `std::time::Instant`, which
//! stops during sleep on iOS. It restarts at boot, so it is only for in-memory expiry such
//! as the DNS cache. [`unix_secs`] is wall-clock time for timestamps that are persisted.
//! A [`Reading`] reads a clock that counts sleep and one that does not at once, so two
//! readings tell how long the device slept in between.

use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Seconds from a clock that keeps counting while the device sleeps.
///
/// `CLOCK_MONOTONIC` on Apple platforms (it is based on `mach_continuous_time`) and
/// `CLOCK_BOOTTIME` on Linux and Android. Other targets, and the unexpected case of
/// `clock_gettime` failing, fall back to the wall clock.
pub fn now_secs() -> u64 {
    clock_gettime(ids::CONTINUOUS).map_or_else(unix_secs, |since| since.as_secs())
}

/// Seconds since the Unix epoch from the wall clock. Use it for values that outlive the
/// process or a reboot, such as learned certificate pins.
pub fn unix_secs() -> u64 {
    unix_time().as_secs()
}

/// Two clocks read at once, in milliseconds: one that keeps counting while the device
/// sleeps and one that stops. Between two readings the first advances by the time that
/// passed and the second by the part of it the device was awake, so the difference is the
/// time it slept ([`Reading::slept_since`]). Both restart at boot, so readings are only
/// compared with readings from the same process.
///
/// On Apple platforms the clocks are `CLOCK_MONOTONIC_RAW` (`mach_continuous_time`) and
/// `CLOCK_UPTIME_RAW` (`mach_absolute_time`), which tick at the same rate and differ only
/// by sleep; on Linux and Android `CLOCK_BOOTTIME` and `CLOCK_MONOTONIC`, which the same
/// adjustments slew alike. Other targets, and the unexpected case of `clock_gettime`
/// failing, fall back to the wall clock and to `std::time::Instant`, where a jump of the
/// wall clock looks like sleep, and a sleep that `Instant` counts does not show.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Reading {
    /// Milliseconds on the clock that keeps counting while the device sleeps.
    pub total_ms: u64,
    /// Milliseconds on the clock that stops while the device sleeps.
    pub awake_ms: u64,
}

impl Reading {
    /// Both clocks now.
    pub fn now() -> Reading {
        Reading {
            total_ms: millis(clock_gettime(ids::WITH_SLEEP).unwrap_or_else(unix_time)),
            awake_ms: millis(clock_gettime(ids::AWAKE).unwrap_or_else(since_first_use)),
        }
    }

    /// Whole seconds on the clock that keeps counting while the device sleeps.
    pub fn total_secs(&self) -> u64 {
        self.total_ms / 1000
    }

    /// How much of the time since `earlier` the device was awake.
    pub fn awake_since(&self, earlier: &Reading) -> Duration {
        Duration::from_millis(self.awake_ms.saturating_sub(earlier.awake_ms))
    }

    /// How long the device slept since `earlier`: the time that passed, less the part of it
    /// the device was awake.
    pub fn slept_since(&self, earlier: &Reading) -> Duration {
        let passed = self.total_ms.saturating_sub(earlier.total_ms);
        let awake = self.awake_ms.saturating_sub(earlier.awake_ms);
        Duration::from_millis(passed.saturating_sub(awake))
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn unix_time() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// Time since the first call, from `std::time::Instant`.
fn since_first_use() -> Duration {
    static FIRST: OnceLock<Instant> = OnceLock::new();
    FIRST.get_or_init(Instant::now).elapsed()
}

/// The clocks of [`now_secs`] and of a [`Reading`].
#[cfg(target_vendor = "apple")]
mod ids {
    pub(super) const CONTINUOUS: libc::clockid_t = libc::CLOCK_MONOTONIC;
    pub(super) const WITH_SLEEP: libc::clockid_t = libc::CLOCK_MONOTONIC_RAW;
    pub(super) const AWAKE: libc::clockid_t = libc::CLOCK_UPTIME_RAW;
}

/// The clocks of [`now_secs`] and of a [`Reading`].
#[cfg(any(target_os = "linux", target_os = "android"))]
mod ids {
    pub(super) const CONTINUOUS: libc::clockid_t = libc::CLOCK_BOOTTIME;
    pub(super) const WITH_SLEEP: libc::clockid_t = libc::CLOCK_BOOTTIME;
    pub(super) const AWAKE: libc::clockid_t = libc::CLOCK_MONOTONIC;
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn clock_gettime(clock: libc::clockid_t) -> Option<Duration> {
    let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: `ts` points to writable memory for one timespec, which clock_gettime fills
    // in completely when it returns 0.
    let rc = unsafe { libc::clock_gettime(clock, ts.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    // SAFETY: clock_gettime returned 0, so `ts` is initialized.
    let ts = unsafe { ts.assume_init() };
    let secs = u64::try_from(ts.tv_sec).ok()?;
    let nanos = u32::try_from(ts.tv_nsec).ok()?;
    Some(Duration::new(secs, nanos))
}

/// No such clocks elsewhere: [`clock_gettime`] always falls back.
#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
mod ids {
    pub(super) const CONTINUOUS: i32 = 0;
    pub(super) const WITH_SLEEP: i32 = 0;
    pub(super) const AWAKE: i32 = 0;
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
fn clock_gettime(_: i32) -> Option<Duration> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reading_counts_awake_time_and_no_sleep_while_awake() {
        let before = Reading::now();
        std::thread::sleep(Duration::from_millis(50));
        let after = Reading::now();
        let awake = after.awake_since(&before);
        assert!(awake >= Duration::from_millis(49), "{awake:?}");
        assert!(awake < Duration::from_secs(5), "{awake:?}");
        // The test machine does not suspend within 50 ms; allow for rounding.
        let slept = after.slept_since(&before);
        assert!(slept <= Duration::from_millis(2), "{slept:?}");
    }

    #[test]
    fn sleep_is_the_time_passed_less_the_time_awake() {
        let earlier = Reading {
            total_ms: 10_000,
            awake_ms: 4_000,
        };
        let later = Reading {
            total_ms: 70_000,
            awake_ms: 14_000,
        };
        assert_eq!(later.awake_since(&earlier), Duration::from_secs(10));
        assert_eq!(later.slept_since(&earlier), Duration::from_secs(50));
        assert_eq!(later.total_secs(), 70);
        // Readings taken out of order never give a negative time.
        assert_eq!(earlier.awake_since(&later), Duration::ZERO);
        assert_eq!(earlier.slept_since(&later), Duration::ZERO);
    }

    /// The platform clocks are read, not the fallbacks: both count from boot, and the one
    /// that stops during sleep is not ahead (by more than the moment between the reads).
    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    #[test]
    fn a_reading_uses_the_boot_clocks() {
        let now = Reading::now();
        // The wall clock would be decades in.
        assert!(now.total_ms < unix_secs() * 1000 / 2, "{now:?}");
        assert!(now.awake_ms <= now.total_ms + 1, "{now:?}");
    }
}

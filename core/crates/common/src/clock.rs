//! Clocks.
//!
//! [`now_secs`] keeps counting while the device sleeps, unlike `std::time::Instant`, which
//! stops during sleep on iOS. It restarts at boot, so it is only for in-memory expiry such
//! as the DNS cache. [`unix_secs`] is wall-clock time for timestamps that are persisted.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds from a clock that keeps counting while the device sleeps.
///
/// `CLOCK_MONOTONIC` on Apple platforms (it is based on `mach_continuous_time`) and
/// `CLOCK_BOOTTIME` on Linux and Android. Other targets, and the unexpected case of
/// `clock_gettime` failing, fall back to the wall clock.
pub fn now_secs() -> u64 {
    continuous_secs().unwrap_or_else(unix_secs)
}

/// Seconds since the Unix epoch from the wall clock. Use it for values that outlive the
/// process or a reboot, such as learned certificate pins.
pub fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn continuous_secs() -> Option<u64> {
    #[cfg(target_vendor = "apple")]
    const CLOCK: libc::clockid_t = libc::CLOCK_MONOTONIC;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const CLOCK: libc::clockid_t = libc::CLOCK_BOOTTIME;

    let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: `ts` points to writable memory for one timespec, which clock_gettime fills
    // in completely when it returns 0.
    let rc = unsafe { libc::clock_gettime(CLOCK, ts.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    // SAFETY: clock_gettime returned 0, so `ts` is initialized.
    let ts = unsafe { ts.assume_init() };
    u64::try_from(ts.tv_sec).ok()
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
fn continuous_secs() -> Option<u64> {
    None
}

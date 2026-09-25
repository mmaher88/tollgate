use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tollgate_common::clock::{now_secs, unix_secs};

#[test]
fn now_secs_never_goes_backwards() {
    let mut previous = now_secs();
    for _ in 0..100_000 {
        let now = now_secs();
        assert!(now >= previous, "clock went from {previous} to {now}");
        previous = now;
    }
}

#[test]
fn now_secs_advances_with_real_time() {
    let start = now_secs();
    std::thread::sleep(Duration::from_millis(2_100));
    let elapsed = now_secs() - start;
    assert!((2..=3).contains(&elapsed), "elapsed {elapsed} s");
}

// /proc/uptime counts time spent suspended, like CLOCK_BOOTTIME and unlike
// CLOCK_MONOTONIC on Linux. On a machine that has been suspended the two differ by the
// suspended time, so this pins the clock choice.
#[cfg(target_os = "linux")]
#[test]
fn now_secs_matches_boot_time_on_linux() {
    let uptime = std::fs::read_to_string("/proc/uptime").unwrap();
    let uptime: f64 = uptime.split_whitespace().next().unwrap().parse().unwrap();
    let now = now_secs() as f64;
    assert!(
        (now - uptime).abs() <= 2.0,
        "now_secs {now}, uptime {uptime}"
    );
}

#[test]
fn unix_secs_is_the_wall_clock() {
    let system = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ours = unix_secs();
    assert!(
        ours.abs_diff(system) <= 1,
        "unix_secs {ours}, system {system}"
    );
    // 2026-01-01T00:00:00Z
    assert!(ours > 1_767_225_600);
}

//! Raising the open file limit. iOS starts the extension with a soft limit of 256, which the
//! proxy's sockets (client connections, passthrough tunnels, the upstream pool, DoH) could
//! reach under load; past it `accept` and every dial fail with EMFILE.

/// The soft limit the engine asks for. Darwin refuses more than `OPEN_MAX` (10240) even
/// when the hard limit is infinite, so this stays below it. `rlim_t` is `u64` on Darwin and
/// Linux.
pub(crate) const OPEN_FILES: u64 = 2048;

/// The soft limit to set for `wanted`, capped by the hard limit, or `None` when `soft` is
/// already at least that.
fn raised(soft: u64, hard: u64, wanted: u64) -> Option<u64> {
    let target = wanted.min(hard);
    (soft < target).then_some(target)
}

/// Raises the soft open file limit to [`OPEN_FILES`] (at most the hard limit). A failure is
/// logged, not fatal.
#[cfg(unix)]
pub(crate) fn raise_open_file_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable rlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        log::warn!(
            "reading the open file limit failed: {}",
            std::io::Error::last_os_error()
        );
        return;
    }
    let soft = limit.rlim_cur;
    let Some(target) = raised(soft, limit.rlim_max, OPEN_FILES) else {
        return;
    };
    let wanted = libc::rlimit {
        rlim_cur: target,
        rlim_max: limit.rlim_max,
    };
    // SAFETY: `wanted` is a valid rlimit that keeps the hard limit.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &wanted) } == 0 {
        log::info!("open file limit raised from {soft} to {target}");
    } else {
        log::warn!(
            "raising the open file limit from {soft} to {target} failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(unix))]
pub(crate) fn raise_open_file_limit() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limit_is_raised_up_to_the_hard_limit() {
        assert_eq!(raised(256, u64::MAX, 2048), Some(2048));
        assert_eq!(raised(256, 1024, 2048), Some(1024));
        assert_eq!(raised(4096, u64::MAX, 2048), None);
        assert_eq!(raised(2048, 2048, 2048), None);
    }

    #[cfg(unix)]
    fn limit() -> libc::rlimit {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid, writable rlimit.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        limit
    }

    #[cfg(unix)]
    #[test]
    fn a_low_limit_like_the_extension_default_is_raised() {
        let before = limit();
        // Lowering the soft limit is always allowed; start where iOS starts the extension.
        let low = libc::rlimit {
            rlim_cur: 256.min(before.rlim_cur),
            rlim_max: before.rlim_max,
        };
        // SAFETY: `low` is a valid rlimit that keeps the hard limit.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &low) }, 0);

        raise_open_file_limit();
        let after = limit();
        assert_eq!(after.rlim_cur, OPEN_FILES.min(before.rlim_max));
    }
}

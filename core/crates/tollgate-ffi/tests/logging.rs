//! One test function: the logger is process-wide, so the steps must not run in parallel.

use std::sync::{Arc, Mutex};

use tollgate_ffi::{CoreLogger, LogLevel, set_logger};

type Line = (LogLevel, String, String);

#[derive(Default)]
struct Capture {
    lines: Mutex<Vec<Line>>,
}

impl Capture {
    fn take(&self) -> Vec<Line> {
        std::mem::take(&mut *self.lines.lock().unwrap())
    }
}

impl CoreLogger for Capture {
    fn log(&self, level: LogLevel, target: String, message: String) {
        self.lines.lock().unwrap().push((level, target, message));
    }
}

/// Logs through Rust again from inside the callback.
#[derive(Default)]
struct Echo {
    inner: Capture,
}

impl CoreLogger for Echo {
    fn log(&self, level: LogLevel, target: String, message: String) {
        log::error!("logged from inside the logger");
        self.inner.log(level, target, message);
    }
}

struct Panicking;

impl CoreLogger for Panicking {
    fn log(&self, _level: LogLevel, _target: String, _message: String) {
        panic!("the Swift side failed");
    }
}

fn line(level: LogLevel, target: &str, message: &str) -> Line {
    (level, target.to_string(), message.to_string())
}

#[test]
fn records_reach_the_core_logger() {
    let capture = Arc::new(Capture::default());

    // Level filter: Info passes info, warn and error, drops debug and trace.
    set_logger(capture.clone(), LogLevel::Info);
    log::info!(target: "tollgate_dns", "query for {}", "example.com");
    log::debug!(target: "tollgate_dns", "dropped");
    log::trace!(target: "tollgate_dns", "dropped");
    log::warn!(target: "tollgate_mitm", "warned");
    log::error!(target: "tollgate_mitm", "failed");
    assert_eq!(
        capture.take(),
        vec![
            line(LogLevel::Info, "tollgate_dns", "query for example.com"),
            line(LogLevel::Warn, "tollgate_mitm", "warned"),
            line(LogLevel::Error, "tollgate_mitm", "failed"),
        ]
    );

    // A second call changes the level.
    set_logger(capture.clone(), LogLevel::Trace);
    log::trace!(target: "t", "traced");
    set_logger(capture.clone(), LogLevel::Error);
    log::warn!(target: "t", "dropped");
    assert_eq!(capture.take(), vec![line(LogLevel::Trace, "t", "traced")]);

    // A second call replaces the logger.
    let other = Arc::new(Capture::default());
    set_logger(other.clone(), LogLevel::Info);
    log::info!(target: "t", "to the new logger");
    assert_eq!(capture.take(), Vec::<Line>::new());
    assert_eq!(
        other.take(),
        vec![line(LogLevel::Info, "t", "to the new logger")]
    );

    // A logger that logs again does not recurse: its own record is dropped.
    let echo = Arc::new(Echo::default());
    set_logger(echo.clone(), LogLevel::Info);
    log::info!(target: "t", "outer");
    assert_eq!(echo.inner.take(), vec![line(LogLevel::Info, "t", "outer")]);

    // A logger that panics loses the record but does not unwind into the caller.
    set_logger(Arc::new(Panicking), LogLevel::Info);
    log::info!(target: "t", "lost");

    // Panics are logged at error level with target "panic" before the default hook runs.
    set_logger(capture.clone(), LogLevel::Info);
    let _ = std::panic::catch_unwind(|| panic!("hook test {}", 42));
    let lines = capture.take();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let (level, target, message) = &lines[0];
    assert_eq!((*level, target.as_str()), (LogLevel::Error, "panic"));
    assert!(message.contains("hook test 42"), "{message}");
}

//! Forwarding the `log` facade to Swift.
//!
//! The dns, mitm, filter and policy crates log through `log`. [`set_logger`] installs a
//! `log::Log` that hands each record to the Swift `CoreLogger`, which writes it to
//! `os_log`, and a panic hook that logs panics before the default hook runs.

use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Once, PoisonError, RwLock};

/// Severity of a log record, most severe first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn filter(self) -> log::LevelFilter {
        match self {
            LogLevel::Error => log::LevelFilter::Error,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Trace => log::LevelFilter::Trace,
        }
    }
}

impl From<log::Level> for LogLevel {
    fn from(level: log::Level) -> LogLevel {
        match level {
            log::Level::Error => LogLevel::Error,
            log::Level::Warn => LogLevel::Warn,
            log::Level::Info => LogLevel::Info,
            log::Level::Debug => LogLevel::Debug,
            log::Level::Trace => LogLevel::Trace,
        }
    }
}

/// Implemented in Swift; writes to `os_log`. Called from any Rust thread, including the
/// engine's runtime thread, so it must only hand the record off and return. Named
/// `CoreLogger` because a Swift protocol named `Logger` would shadow `os.Logger`.
#[uniffi::export(foreign)]
pub trait CoreLogger: Send + Sync {
    fn log(&self, level: LogLevel, target: String, message: String);
}

struct Bridge {
    logger: RwLock<Option<Arc<dyn CoreLogger>>>,
    /// The most verbose level forwarded, as `log::LevelFilter as usize`.
    max_level: AtomicUsize,
}

static BRIDGE: Bridge = Bridge {
    logger: RwLock::new(None),
    max_level: AtomicUsize::new(0),
};

static INSTALL: Once = Once::new();

thread_local! {
    /// Set while a record is being handed to Swift on this thread, so a logger that logs
    /// through Rust again cannot recurse.
    static FORWARDING: Cell<bool> = const { Cell::new(false) };
}

impl log::Log for Bridge {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() as usize <= self.max_level.load(Ordering::Relaxed)
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        // Clone the logger and release the lock before calling into Swift.
        let logger = self
            .logger
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(logger) = logger else {
            return;
        };
        FORWARDING.with(|busy| {
            if busy.replace(true) {
                return;
            }
            let level = LogLevel::from(record.level());
            let target = record.target().to_string();
            let message = record.args().to_string();
            // A failing Swift callback panics inside uniffi; losing one line is better
            // than unwinding into the code that logged.
            let _ = catch_unwind(AssertUnwindSafe(|| logger.log(level, target, message)));
            busy.set(false);
        });
    }

    fn flush(&self) {}
}

/// Sends every `log` record at `max_level` or more severe to `logger`, replacing any
/// logger set before. The first call also installs a panic hook that logs panics at
/// error level with target `panic`, then runs the previous hook.
///
/// If another `log` implementation was installed first (a Rust test harness, devproxy's
/// env_logger), records keep going there and `logger` receives nothing.
#[uniffi::export]
pub fn set_logger(logger: Arc<dyn CoreLogger>, max_level: LogLevel) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        *BRIDGE
            .logger
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(logger);
        let filter = max_level.filter();
        BRIDGE.max_level.store(filter as usize, Ordering::Relaxed);
        INSTALL.call_once(|| {
            if log::set_logger(&BRIDGE).is_err() {
                eprintln!("tollgate: another logger is installed; CoreLogger gets nothing");
            }
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                log::error!(target: "panic", "{info}");
                previous(info);
            }));
        });
        log::set_max_level(filter);
    }));
}

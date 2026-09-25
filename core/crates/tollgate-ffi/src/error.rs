//! The error Swift sees, and turning panics into it.

use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Errors returned to Swift. Every variant carries a message the app can show; the generated
/// Swift `errorDescription` does not use the text below, so Swift reads `message`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum TollgateError {
    /// `config.json` or a list input is invalid.
    #[error("invalid configuration: {message}")]
    Config { message: String },
    /// Reading or writing a file, binding a socket or starting a thread failed.
    #[error("I/O error: {message}")]
    Io { message: String },
    /// `engine.dat` or `domains.bin` could not be built or loaded.
    #[error("filter lists: {message}")]
    Lists { message: String },
    /// The certificate authority files are missing, invalid or could not be written.
    #[error("certificate authority: {message}")]
    Ca { message: String },
    /// `start` was called while the engine is running.
    #[error("the engine is already running")]
    AlreadyRunning,
    /// A bug in the Rust core: a panic was caught at the FFI boundary.
    #[error("internal error: {message}")]
    Internal { message: String },
}

impl TollgateError {
    pub(crate) fn io(e: impl std::fmt::Display) -> TollgateError {
        TollgateError::Io {
            message: e.to_string(),
        }
    }
}

/// The text of a panic payload: the message of `panic!("...")` with or without format
/// arguments, or a fixed text for any other payload.
pub fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "panic with a non-string payload".to_string()
    }
}

/// Runs `f` and turns a panic into [`TollgateError::Internal`] with the panic message.
/// The panic is also logged at error level.
pub fn catch_panic<T>(f: impl FnOnce() -> Result<T, TollgateError>) -> Result<T, TollgateError> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(payload) => {
            let message = panic_message(payload.as_ref());
            log::error!("caught a panic at the FFI boundary: {message}");
            Err(TollgateError::Internal { message })
        }
    }
}

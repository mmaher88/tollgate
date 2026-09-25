//! Pieces shared by the dns, mitm and ffi crates: a clock that keeps counting while the
//! device sleeps, the rustls client configuration and the statistics counters.
//!
//! Logging is not wrapped here: every crate logs through the `log` facade directly.

pub mod clock;

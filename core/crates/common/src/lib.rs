//! Pieces shared by the dns, mitm and ffi crates: a clock that keeps counting while the
//! device sleeps, the rustls client configuration, the statistics counters, the blocked log
//! and the host name resolver interface.
//!
//! Logging is not wrapped here: every crate logs through the `log` facade directly.

pub mod clock;
pub mod events;
pub mod resolve;
pub mod stats;
pub mod tls;

//! Swift-facing facade of the Tollgate core. Everything the iOS app and tunnel call
//! goes through this crate; the other crates stay free of FFI concerns.
//!
//! Every function on the tunnel path catches panics, so a Rust bug becomes a Swift error
//! (or a logged error for the functions that return no `Result`) instead of killing the
//! extension.

uniffi::setup_scaffolding!();

mod ca;
mod engine;
mod error;
mod lists;
mod logging;

pub use ca::{
    CA_CERT_FILE, CA_COMMON_NAME, CA_KEY_FILE, CaInfo, PROFILE_DISPLAY_NAME, PROFILE_IDENTIFIER,
    ca_mobileconfig, ca_test_leaf, generate_ca, load_ca,
};
pub use engine::{
    Engine, EngineOptions, FORWARD_QUEUE, LEARNED_PINS_FILE, PacketSink, RUNTIME_THREAD, Stats,
};
pub use error::{TollgateError, catch_panic, panic_message};
pub use lists::{CompileReport, ListFormat, ListInput, ListTarget, compile_lists};
pub use logging::{CoreLogger, LogLevel, set_logger};

/// Version of the Rust core, shown in the app and logged by the tunnel.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Round trip used by experiment E2 to prove Swift can call Rust and get data back.
#[uniffi::export]
pub fn ping(message: String) -> String {
    format!("pong: {message}")
}

/// SHA-256 through `ring`, used by experiment E2 to prove that ring's C and assembly
/// objects cross-compile and link into the extension.
#[uniffi::export]
pub fn sha256_hex(data: Vec<u8>) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, &data);
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_crate() {
        assert_eq!(core_version(), "0.1.0");
    }

    #[test]
    fn ping_echoes_message() {
        assert_eq!(ping("tunnel".into()), "pong: tunnel");
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b"tollgate".to_vec()),
            "4485ecf50fcb30d3c6aca2a2a69f7139e98cd7d52b075a9259036c3702fb61fd"
        );
        assert_eq!(
            sha256_hex(Vec::new()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}

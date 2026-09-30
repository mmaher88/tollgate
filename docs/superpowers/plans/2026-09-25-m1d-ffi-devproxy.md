# M1d: FFI Engine, devproxy and CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `tollgate-ffi` into the real Swift-facing engine (DNS answers on the packet path, the DNS forwarder and the HTTPS proxy on one runtime thread, CA files, list compilation, logging), add the Linux `devproxy` harness for Firefox with its manual checklist, and add the Rust 1.94 CI check, implementing the ffi contract exactly.

**Architecture:** `Engine` loads `engine.dat`, `domains.bin`, the CA and learned pins from the data directory, answers DNS packets synchronously through `tollgate_dns::DnsHandler`, and queues forwarded queries over a bounded channel to a current-thread tokio runtime on a named thread, which runs `tollgate_mitm::serve` and resolves queries with `DohResolver`, delivering answers through the Swift `PacketSink`. Every exported function catches panics and recovers poisoned locks; a `log::Log` bridge forwards to the Swift `CoreLogger`. `devproxy` composes the same crates on fixed local ports (UDP DNS through a payload wrapper, the proxy on TCP) and reuses the ffi CA and compile functions so its data directory matches the phone's.

**Tech Stack:** Rust 1.94+ (edition 2024; local toolchain 1.98.1), uniffi 0.32.2 (default features off), tokio 1.53.1, hyper 1.11.1, hyper-util 0.1.21, http-body-util 0.1.5, bytes 1.12.1, rustls 0.23.45 and tokio-rustls 0.26.5 (ring provider only), ring 0.17.14, arc-swap 1.9.2, log 0.4.34, thiserror 2.0.21, env_logger 0.11.11 (default features off), socket2 0.6.5; tests only: hickory-proto 0.26.3, rcgen 0.14.10, tempfile 3.27.0. Uses the M1a, M1b and M1c crates `tollgate-common`, `tollgate-policy`, `tollgate-filter`, `tollgate-dns` and `tollgate-mitm`.

**Spec:** docs/superpowers/specs/2026-09-24-tollgate-design.md (sections "Rust core", "Revisions after the M1 prototypes", "M1 crate contracts").

## Global Constraints

- No em-dashes (the character U+2014) anywhere in the plan, in code comments or in commit messages.
- Commit messages have no `Co-Authored-By` lines.
- Work happens on the branch `m1d-ffi-devproxy`, never on `main`; M1a, M1b and M1c are merged into `main` first.
- Rust crates: `edition = "2024"`, `rust-version = "1.94"`, dependency versions managed in `core/Cargo.toml` `[workspace.dependencies]`.
- rustls and tokio-rustls with `default-features = false` and the ring provider only; no aws-lc anywhere: `cargo tree -i aws-lc-sys` must report that nothing matches.
- `cargo clippy --workspace --all-targets -- -D warnings` is clean after every task.
- The M1 crate contracts in the spec are binding: every `tollgate-ffi` signature there is implemented exactly; this plan only adds private items and extra public helpers.

## Decisions

Choices the spec left to the plan, with the reason.

- **Swift surface.** The contract's functions keep their names; the generated Swift is `Engine(configJson:dataDir:)`, `start(sink:) -> UInt16`, `stop()`, `handlePackets(packets:) throws -> [Data]`, `reloadLists()`, `stats() -> Stats`, `learnedPinsJson() -> String`, `setLogger(logger:maxLevel:)`, `generateCa(dataDir:)`, `caMobileconfig(dataDir:)`, `compileLists(sources:dataDir:)`, and the protocols `CoreLogger` and `PacketSink`. Two extra read-only methods: `mitm_active()` (so the app knows whether HTTPS is filtered) and `port()`. The M0 functions `core_version`, `ping` and `sha256_hex` are unchanged, so the M0 Swift code compiles as it is and `ios.yml` needs no change; the M0 Swift sources use none of the new type names (`Engine`, `Stats`, `LogLevel`, `CaInfo`, `CompileReport`, `ListInput`, `ListFormat`, `ListTarget`, `TollgateError`), so even a name that shadows a framework type cannot break them. There are no uniffi `async` functions (`handle_packets` stays synchronous, as the spec revision chose), so uniffi's `tokio` feature and Swift task cancellation do not come into play.
- **Errors.** `TollgateError` has `Config`, `Io`, `Lists`, `Ca`, `AlreadyRunning` and `Internal`, each with a `message` except `AlreadyRunning`. The generated Swift `errorDescription` ignores Rust's `Display`, so Swift shows `message`.
- **Panics.** Every exported function runs its body in `catch_panic`, which maps a panic to `TollgateError::Internal { message }` and logs it. The contract functions without a `Result` (`stop`, `stats`, `learned_pins_json`, plus `port` and `set_logger`) log and return a default instead. Calls into Swift (`PacketSink.write_packets`, `CoreLogger.log`) run inside `catch_unwind`, because uniffi turns a failing callback into a Rust panic. The runtime thread's body is wrapped too, and tokio already contains panics in spawned tasks. Locks are taken with `unwrap_or_else(PoisonError::into_inner)`. `panic = "unwind"` (the default) must stay. The first `set_logger` call also installs a panic hook that logs the panic at error level (target `panic`) before the previous hook runs, so panics reach `os_log`.
- **Runtime thread.** `start` spawns the thread `tollgate-core`, builds a current-thread runtime inside it (`enable_all`, at most 4 blocking threads named `tollgate-blocking`, because the proxy resolves upstream names with `getaddrinfo` on the blocking pool), binds the `SocketAddr` `127.0.0.1:0` (never a host name), and reports the port or the error back over a `sync_channel`, so `start` returns only after the listener exists. `stop` sends the shutdown signal, joins the thread and saves the learned pins; it skips the join when it runs on the runtime thread itself (a `PacketSink` callback that stops or drops the last `Engine`), which the thread-id check detects. The runtime is shut down with `shutdown_timeout(1 s)`, so a hung `getaddrinfo` cannot block `stopTunnel`. `Drop` calls `stop`.
- **Forwarding.** `handle_packets` never blocks: forwarded queries go into a bounded tokio channel of 256 with `try_send`. The runtime's forward loop takes a semaphore permit (128, `tollgate_dns::MAX_IN_FLIGHT`) before it takes a job, so at most 128 queries resolve and at most 256 wait, and memory stays bounded (the ffi prototype review's fix). A full queue answers SERVFAIL at once (`DohError::Busy`); a stopped engine or a dead runtime answers SERVFAIL at once (`DohError::Stopped`). Each forwarded query is one tokio task, and its answer goes out alone through `PacketSink.write_packets([packet])`; batching can come in M2 if the call cost shows. Queries still queued at `stop` are dropped; clients retry. Each `start` builds a new `DohResolver`, because its HTTP/2 connections belong to the runtime that opened them.
- **When HTTPS is intercepted.** `mitm_active` is `config.mitm_enabled` and a loaded CA and a loaded `engine.dat` at construction (spec failure handling: no CA or no lists means no MITM). The `Policy` is built with that value. Without a CA the proxy still runs, passing everything through, with a throwaway in-memory CA that never issues a leaf, so the tunnel's proxy settings are the same in every state. A `reload_lists` that adds `engine.dat` later does not start interception; the app restarts the tunnel after its first compile (it reads `mitm_active()`).
- **Loading the data directory.** A missing file means "none". In `Engine::new` a file that fails to load is logged and skipped, so the tunnel still starts. `reload_lists` is strict: it loads both files first, returns the error and keeps the old lists if either fails, and a missing file clears that list. The two swaps are separate atomic stores, so a query between them may see the new filter with the old blocklist for an instant, which is harmless.
- **Learned pins** live in `learned-pins.json` in the data directory (the policy's format): read by `Engine::new`, written by `stop` (mode 0600, temporary file and rename), and returned by `learned_pins_json()` for the app's view.
- **Available memory** is `os_proc_available_memory()` on iOS, with 0 mapped to `None` (iOS returns 0 for processes without a limit), and `None` elsewhere.
- **CA files.** `ca.pem` and `ca.key` (PEM) in the data directory, each written with mode 0600 from creation through a temporary file and a rename, the key first. `generate_ca` is idempotent: a valid stored pair is returned with `created: false`; if either file is missing a new CA is made; a stored pair that does not load is an error and is left untouched, so an installed root is never replaced silently. Common name and profile display name `Tollgate Root CA`, profile identifier `dev.tollgate.ca` (the namespace of the log subsystems; it is not a bundle ID, so it is not in `tooling/config.env`). `CaInfo` has `cert_pem`, `sha256_fingerprint` (lowercase hex) and `created`. The file protection class is set by the Swift side in M3.
- **List inputs.** `ListInput { name, text, format, target }` with `ListFormat { Adblock, Hosts }` and `ListTarget { Url, Dns }`: `Url` lists build `engine.dat` and `Dns` lists build `domains.bin`, through `tollgate_filter::compile_split` as M1a recommends (a DNS list in the engine would more than double it). A hosts list with target `Url` is a `Config` error.
- **Logging.** `set_logger(logger, max_level)` installs the bridge with `log::set_logger` once; later calls replace the logger and the level. There is no `Off` level; `Error` is the quietest. A thread-local flag drops records logged from inside the Swift callback, so a logger that logs cannot recurse. If another `log` implementation was installed first (a test harness, devproxy's env_logger), `CoreLogger` receives nothing.
- **`EngineOptions`** (Rust only, not exported): extra DER roots for DoH upstreams and the queue and in-flight sizes, so tests reach a local DoH server and fill a small queue. `Engine::new` uses the defaults.
- **Tests** are integration tests against the public API, sharing `tests/support/`. `tests/lifecycle.rs` is its own binary with one test because it counts threads: it polls `/proc/self/task` every millisecond for up to 5 s for both the number of `tollgate-core` threads and the total, instead of asserting once (the review saw joined threads linger in `/proc` for a moment). The DoH server is local (rustls, HTTP/2, an rcgen CA) on its own thread. Only `devproxy`'s `downloads_easylist` needs the network and it is `#[ignore]`. The optional Python end-to-end test through uniffi's Python bindings is left out: the Rust tests call the same exported functions, and `ios.yml` compiles the Swift.
- **devproxy** is the package `devproxy` (library plus binary) in `core/tools/devproxy`. It composes `tollgate-dns` and `tollgate-mitm` directly (the `Engine` takes IP packets and an ephemeral port; devproxy needs UDP payloads and fixed ports) and uses `tollgate-ffi` for `generate_ca`, `load_ca` and `compile_lists`, so its data directory has the phone's layout. The explicit helper `devproxy::udp::PayloadHandler` wraps each DNS payload into the IPv4 packet the tunnel delivers (`198.18.0.2:53000` to `198.18.0.1:53`) and unwraps the reply; `tollgate-dns` is unchanged. The DNS socket is bound with `SO_REUSEADDR` (socket2 0.6.5, already in the tree through tokio) because an mDNS responder usually holds `0.0.0.0:5353`; unicast queries to `127.0.0.1:5353` reach the more specific socket. It runs one current-thread runtime like the tunnel, intercepts only when `engine.dat` exists (the tunnel's rule), downloads lists with a hyper HTTP/1.1 client over `tollgate_common::tls` (ALPN `http/1.1`, at most 5 redirects, 64 MiB, 60 s per request), makes the data directory absolute (default `./devproxy-data`), and saves the learned pins on Ctrl-C (tokio's `signal` feature, enabled for devproxy only). Logging is env_logger 0.11.11 with default features off (no regex, colors or timestamps), `info` unless `RUST_LOG` says otherwise.
- **CI.** A new `msrv` job runs `cargo check --workspace --locked` with `dtolnay/rust-toolchain@1.94` and its own cache key. The `test` job also checks that the generated Swift still has the three M0 functions and declares the `CoreLogger` and `PacketSink` protocols. `tooling/scripts/build-core-ios.sh` needs no change (verified with `--host`). The iOS static library references only libSystem symbols (verified on Linux in Task 14), so the Xcode link settings stay as they are.
- **Versions.** env_logger 0.11.11 and socket2 0.6.5 are the current releases on crates.io. `tollgate-ffi` gets a `[workspace.dependencies]` path entry for devproxy. uniffi keeps its default features off in the runtime crate (M1a), so the engine's new dependencies are the only additions to the iOS library.

---

## File map

```
core/Cargo.toml                                   (modify) member tools/devproxy; tollgate-ffi, env_logger, socket2 entries
core/crates/tollgate-ffi/Cargo.toml               (modify) engine dependencies, test dependencies
core/crates/tollgate-ffi/src/lib.rs               (modify) modules and exports; M0 functions unchanged
core/crates/tollgate-ffi/src/error.rs             TollgateError, catch_panic, panic_message
core/crates/tollgate-ffi/src/logging.rs           LogLevel, CoreLogger, set_logger, log bridge, panic hook
core/crates/tollgate-ffi/src/ca.rs                CaInfo, generate_ca, ca_mobileconfig, load_ca, 0600 writes
core/crates/tollgate-ffi/src/lists.rs             ListFormat, ListTarget, ListInput, CompileReport, compile_lists
core/crates/tollgate-ffi/src/engine.rs            Engine, PacketSink, Stats, EngineOptions, runtime thread
core/crates/tollgate-ffi/tests/support/mod.rs     DNS packets, data directories, sinks, polling
core/crates/tollgate-ffi/tests/support/doh.rs     local DoH server on its own thread
core/crates/tollgate-ffi/tests/panics.rs
core/crates/tollgate-ffi/tests/logging.rs
core/crates/tollgate-ffi/tests/ca.rs
core/crates/tollgate-ffi/tests/lists.rs
core/crates/tollgate-ffi/tests/engine_dns.rs
core/crates/tollgate-ffi/tests/lifecycle.rs       own binary: counts threads
core/crates/tollgate-ffi/tests/forward.rs
core/tools/devproxy/Cargo.toml
core/tools/devproxy/src/lib.rs
core/tools/devproxy/src/args.rs                   std::env::args parsing, default lists, usage
core/tools/devproxy/src/fetch.rs                  list downloads over hyper and tollgate_common::tls
core/tools/devproxy/src/udp.rs                    PayloadHandler, serve_dns
core/tools/devproxy/src/server.rs                 DevProxy: prepare the data directory, bind, serve; instructions
core/tools/devproxy/src/main.rs                   the binary
core/tools/devproxy/tests/args.rs
core/tools/devproxy/tests/fetch.rs                one #[ignore] network test
core/tools/devproxy/tests/udp.rs
core/tools/devproxy/tests/server.rs
.github/workflows/core.yml                        (modify) Swift bindings checks, msrv job
docs/experiments/m1-devproxy.md                   manual Firefox checklist
README.md                                         (modify) status and devproxy
```

`core/Cargo.lock` changes with the dependencies and is committed with each task that changes it.

---

### Task 1: TollgateError and panic mapping

**Files:**
- Modify: `core/crates/tollgate-ffi/Cargo.toml`, `core/crates/tollgate-ffi/src/lib.rs`
- Create: `core/crates/tollgate-ffi/src/error.rs`
- Test: `core/crates/tollgate-ffi/tests/panics.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces:

```rust
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum TollgateError {
    Config { message: String }, Io { message: String }, Lists { message: String },
    Ca { message: String }, AlreadyRunning, Internal { message: String },
}
pub fn catch_panic<T>(f: impl FnOnce() -> Result<T, TollgateError>) -> Result<T, TollgateError>;
pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String;
```

- [ ] **Step 1: Write the failing test**

`core/crates/tollgate-ffi/tests/panics.rs`:

```rust
use tollgate_ffi::{TollgateError, catch_panic, panic_message};

#[test]
fn a_panic_becomes_an_internal_error_with_its_message() {
    let result: Result<(), TollgateError> = catch_panic(|| panic!("boom"));
    assert_eq!(
        result,
        Err(TollgateError::Internal {
            message: "boom".to_string()
        })
    );
}

#[test]
fn a_formatted_panic_keeps_its_arguments() {
    let result: Result<u16, TollgateError> = catch_panic(|| panic!("bad packet {}", 7));
    assert_eq!(
        result,
        Err(TollgateError::Internal {
            message: "bad packet 7".to_string()
        })
    );
}

#[test]
fn a_panic_with_another_payload_gets_a_fixed_message() {
    let result: Result<(), TollgateError> = catch_panic(|| std::panic::panic_any(42_u32));
    assert_eq!(
        result,
        Err(TollgateError::Internal {
            message: "panic with a non-string payload".to_string()
        })
    );
}

#[test]
fn results_pass_through_unchanged() {
    assert_eq!(catch_panic(|| Ok(5)), Ok(5));
    assert_eq!(
        catch_panic::<()>(|| Err(TollgateError::AlreadyRunning)),
        Err(TollgateError::AlreadyRunning)
    );
}

#[test]
fn panic_message_reads_str_and_string_payloads() {
    let payload = std::panic::catch_unwind(|| panic!("plain")).unwrap_err();
    assert_eq!(panic_message(payload.as_ref()), "plain");
    let payload = std::panic::catch_unwind(|| panic!("{}-{}", "with", "args")).unwrap_err();
    assert_eq!(panic_message(payload.as_ref()), "with-args");
}

#[test]
fn errors_display_their_messages() {
    let cases = [
        (
            TollgateError::Config {
                message: "x".to_string(),
            },
            "invalid configuration: x",
        ),
        (
            TollgateError::Io {
                message: "x".to_string(),
            },
            "I/O error: x",
        ),
        (
            TollgateError::Lists {
                message: "x".to_string(),
            },
            "filter lists: x",
        ),
        (
            TollgateError::Ca {
                message: "x".to_string(),
            },
            "certificate authority: x",
        ),
        (
            TollgateError::AlreadyRunning,
            "the engine is already running",
        ),
        (
            TollgateError::Internal {
                message: "x".to_string(),
            },
            "internal error: x",
        ),
    ];
    for (error, text) in cases {
        assert_eq!(error.to_string(), text);
    }
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd core && cargo test -p tollgate-ffi --test panics`
Expected: FAIL to compile: `` error[E0432]: unresolved imports `tollgate_ffi::TollgateError`, `tollgate_ffi::catch_panic`, `tollgate_ffi::panic_message` ``

- [ ] **Step 3: Implement**

`core/crates/tollgate-ffi/Cargo.toml`:

```toml
[package]
name = "tollgate-ffi"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
publish.workspace = true

[lib]
name = "tollgate_ffi"
crate-type = ["lib", "staticlib"]

[dependencies]
log = { workspace = true }
ring = { workspace = true }
thiserror = { workspace = true }
uniffi = { workspace = true }
```

`core/crates/tollgate-ffi/src/error.rs`:

```rust
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
```

`core/crates/tollgate-ffi/src/lib.rs`:

```rust
//! Swift-facing facade of the Tollgate core. Everything the iOS app and tunnel call
//! goes through this crate; the other crates stay free of FFI concerns.
//!
//! Every function on the tunnel path catches panics, so a Rust bug becomes a Swift error
//! (or a logged error for the functions that return no `Result`) instead of killing the
//! extension.

uniffi::setup_scaffolding!();

mod error;

pub use error::{TollgateError, catch_panic, panic_message};

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
```

- [ ] **Step 4: Run the tests, fmt and clippy**

Run: `cd core && cargo test -p tollgate-ffi && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS: the 3 M0 unit tests and `tests/panics.rs` 6 passed; fmt and clippy print nothing

- [ ] **Step 5: Commit**

```bash
git add core/crates/tollgate-ffi/Cargo.toml core/crates/tollgate-ffi/src/lib.rs core/crates/tollgate-ffi/src/error.rs core/crates/tollgate-ffi/tests/panics.rs core/Cargo.lock
git commit -m "ffi: TollgateError and panic mapping at the FFI boundary"
```

---

### Task 2: Log bridge to the Swift CoreLogger

**Files:**
- Modify: `core/crates/tollgate-ffi/src/lib.rs`
- Create: `core/crates/tollgate-ffi/src/logging.rs`
- Test: `core/crates/tollgate-ffi/tests/logging.rs`

**Interfaces:**
- Consumes: the `log` facade (every core crate logs through it).
- Produces:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum LogLevel { Error, Warn, Info, Debug, Trace }
#[uniffi::export(foreign)]
pub trait CoreLogger: Send + Sync { fn log(&self, level: LogLevel, target: String, message: String); }
#[uniffi::export]
pub fn set_logger(logger: std::sync::Arc<dyn CoreLogger>, max_level: LogLevel);
```

Swift: `protocol CoreLogger: AnyObject, Sendable { func log(level: LogLevel, target: String, message: String) }` and `setLogger(logger:maxLevel:)`.

- [ ] **Step 1: Write the failing test**

`core/crates/tollgate-ffi/tests/logging.rs`:

```rust
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
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd core && cargo test -p tollgate-ffi --test logging`
Expected: FAIL to compile: `` error[E0432]: unresolved imports `tollgate_ffi::CoreLogger`, `tollgate_ffi::LogLevel`, `tollgate_ffi::set_logger` ``

- [ ] **Step 3: Implement**

`core/crates/tollgate-ffi/src/logging.rs`:

```rust
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
```

`core/crates/tollgate-ffi/src/lib.rs`:

```rust
//! Swift-facing facade of the Tollgate core. Everything the iOS app and tunnel call
//! goes through this crate; the other crates stay free of FFI concerns.
//!
//! Every function on the tunnel path catches panics, so a Rust bug becomes a Swift error
//! (or a logged error for the functions that return no `Result`) instead of killing the
//! extension.

uniffi::setup_scaffolding!();

mod error;
mod logging;

pub use error::{TollgateError, catch_panic, panic_message};
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
```

- [ ] **Step 4: Run the tests, fmt and clippy**

Run: `cd core && cargo test -p tollgate-ffi && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS: unit 3, `panics` 6 and `logging` 1 passed; fmt and clippy print nothing

- [ ] **Step 5: Commit**

```bash
git add core/crates/tollgate-ffi/src/lib.rs core/crates/tollgate-ffi/src/logging.rs core/crates/tollgate-ffi/tests/logging.rs
git commit -m "ffi: forward log records and panics to the Swift CoreLogger"
```

---

### Task 3: CA files, generate_ca and ca_mobileconfig

**Files:**
- Modify: `core/crates/tollgate-ffi/Cargo.toml`, `core/crates/tollgate-ffi/src/lib.rs`, `core/crates/tollgate-ffi/src/error.rs`
- Create: `core/crates/tollgate-ffi/src/ca.rs`
- Test: `core/crates/tollgate-ffi/tests/ca.rs`

**Interfaces:**
- Consumes: `tollgate_mitm::CertAuthority::{generate, from_pem, cert_pem, key_pem, cert_der, mobileconfig}` and `MitmError` (M1c).
- Produces:

```rust
pub const CA_CERT_FILE: &str = "ca.pem";
pub const CA_KEY_FILE: &str = "ca.key";
pub const CA_COMMON_NAME: &str = "Tollgate Root CA";
pub const PROFILE_DISPLAY_NAME: &str = "Tollgate Root CA";
pub const PROFILE_IDENTIFIER: &str = "dev.tollgate.ca";
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CaInfo { pub cert_pem: String, pub sha256_fingerprint: String, pub created: bool }
#[uniffi::export] pub fn generate_ca(data_dir: String) -> Result<CaInfo, TollgateError>;
#[uniffi::export] pub fn ca_mobileconfig(data_dir: String) -> Result<Vec<u8>, TollgateError>;
pub fn load_ca(dir: &std::path::Path) -> Result<Option<tollgate_mitm::CertAuthority>, TollgateError>;
pub(crate) fn write_private(path: &std::path::Path, text: &str) -> Result<(), TollgateError>;
impl TollgateError { pub(crate) fn io(e: impl std::fmt::Display) -> TollgateError; }
```

- [ ] **Step 1: Write the failing test**

The test needs `tempfile`; the manifest also gains `tollgate-mitm` for the implementation.

`core/crates/tollgate-ffi/Cargo.toml`:

```toml
[package]
name = "tollgate-ffi"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
publish.workspace = true

[lib]
name = "tollgate_ffi"
crate-type = ["lib", "staticlib"]

[dependencies]
log = { workspace = true }
ring = { workspace = true }
thiserror = { workspace = true }
tollgate-mitm = { workspace = true }
uniffi = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
```

`core/crates/tollgate-ffi/tests/ca.rs`:

```rust
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tollgate_ffi::{
    CA_CERT_FILE, CA_KEY_FILE, TollgateError, ca_mobileconfig, generate_ca, load_ca, sha256_hex,
};

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// The base64 body of a PEM block on one line, which is the base64 of the DER bytes.
fn pem_body(pem: &str) -> String {
    pem.lines().filter(|l| !l.starts_with("-----")).collect()
}

#[test]
fn generates_once_and_stores_private_files() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("group");
    let path = dir.to_str().unwrap().to_string();

    let first = generate_ca(path.clone()).unwrap();
    assert!(first.created);
    assert!(first.cert_pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert_eq!(first.sha256_fingerprint.len(), 64);
    assert_eq!(mode(&dir.join(CA_CERT_FILE)), 0o600);
    assert_eq!(mode(&dir.join(CA_KEY_FILE)), 0o600);
    assert_eq!(
        fs::read_to_string(dir.join(CA_CERT_FILE)).unwrap(),
        first.cert_pem
    );
    assert!(
        fs::read_to_string(dir.join(CA_KEY_FILE))
            .unwrap()
            .starts_with("-----BEGIN PRIVATE KEY-----\n")
    );

    let second = generate_ca(path).unwrap();
    assert!(!second.created);
    assert_eq!(second.cert_pem, first.cert_pem);
    assert_eq!(second.sha256_fingerprint, first.sha256_fingerprint);

    let ca = load_ca(&dir).unwrap().unwrap();
    assert_eq!(ca.cert_pem(), first.cert_pem);
    assert_eq!(sha256_hex(ca.cert_der()), first.sha256_fingerprint);
    // No temporary files are left behind.
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, vec!["ca.key", "ca.pem"]);
}

#[test]
fn a_missing_key_means_a_new_ca() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let first = generate_ca(path.clone()).unwrap();
    fs::remove_file(tmp.path().join(CA_KEY_FILE)).unwrap();
    assert!(load_ca(tmp.path()).unwrap().is_none());
    let second = generate_ca(path).unwrap();
    assert!(second.created);
    assert_ne!(second.cert_pem, first.cert_pem);
}

#[test]
fn an_invalid_stored_ca_is_an_error_and_is_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join(CA_CERT_FILE), "not a certificate").unwrap();
    fs::write(tmp.path().join(CA_KEY_FILE), "not a key").unwrap();
    let error = generate_ca(tmp.path().to_str().unwrap().to_string()).unwrap_err();
    assert!(
        matches!(&error, TollgateError::Ca { message } if message.starts_with("invalid CA")),
        "{error:?}"
    );
    assert_eq!(
        fs::read_to_string(tmp.path().join(CA_CERT_FILE)).unwrap(),
        "not a certificate"
    );
    assert!(load_ca(tmp.path()).is_err());
}

#[test]
fn no_ca_means_no_profile() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(
        ca_mobileconfig(tmp.path().to_str().unwrap().to_string()),
        Err(TollgateError::Ca {
            message: "no CA in the data directory; call generate_ca first".to_string()
        })
    );
}

#[test]
fn the_profile_installs_the_stored_root() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let info = generate_ca(path.clone()).unwrap();
    let profile = String::from_utf8(ca_mobileconfig(path.clone()).unwrap()).unwrap();
    assert!(profile.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
    for expected in [
        "<string>com.apple.security.root</string>",
        "<string>Configuration</string>",
        "<string>dev.tollgate.ca</string>",
        "<string>dev.tollgate.ca.certificate</string>",
        "<string>Tollgate Root CA</string>",
    ] {
        assert!(profile.contains(expected), "missing {expected}");
    }
    assert!(profile.contains(&format!("<data>{}</data>", pem_body(&info.cert_pem))));
    // The same CA always gives the same profile.
    assert_eq!(ca_mobileconfig(path).unwrap(), profile.into_bytes());
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd core && cargo test -p tollgate-ffi --test ca`
Expected: FAIL to compile: `` error[E0432]: unresolved imports `tollgate_ffi::CA_CERT_FILE`, `tollgate_ffi::CA_KEY_FILE`, `tollgate_ffi::ca_mobileconfig`, `tollgate_ffi::generate_ca`, `tollgate_ffi::load_ca` ``

- [ ] **Step 3: Implement**

`TollgateError` gains a private constructor for I/O errors:

`core/crates/tollgate-ffi/src/error.rs`:

```rust
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
```

`core/crates/tollgate-ffi/src/ca.rs`:

```rust
//! The certificate authority files in the data directory.
//!
//! `ca.pem` holds the root certificate and `ca.key` its private key, both PEM and both
//! readable only by the owner (mode 0600). The Swift side additionally applies the file
//! protection class `completeUntilFirstUserAuthentication` to the App Group directory.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use tollgate_mitm::CertAuthority;

use crate::error::{TollgateError, catch_panic};
use crate::sha256_hex;

/// Root certificate, PEM.
pub const CA_CERT_FILE: &str = "ca.pem";
/// Root private key, PEM (PKCS#8).
pub const CA_KEY_FILE: &str = "ca.key";
/// Subject common name of a generated root.
pub const CA_COMMON_NAME: &str = "Tollgate Root CA";
/// Name iOS shows for the configuration profile and the certificate.
pub const PROFILE_DISPLAY_NAME: &str = "Tollgate Root CA";
/// Reverse-DNS identifier of the configuration profile.
pub const PROFILE_IDENTIFIER: &str = "dev.tollgate.ca";

/// The root certificate the app asks the user to trust.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CaInfo {
    pub cert_pem: String,
    /// SHA-256 of the DER certificate, lowercase hex without separators.
    pub sha256_fingerprint: String,
    /// True when this call generated the CA, false when it was already stored.
    pub created: bool,
}

fn ca_error(e: impl std::fmt::Display) -> TollgateError {
    TollgateError::Ca {
        message: e.to_string(),
    }
}

fn info(ca: &CertAuthority, created: bool) -> CaInfo {
    CaInfo {
        cert_pem: ca.cert_pem(),
        sha256_fingerprint: sha256_hex(ca.cert_der()),
        created,
    }
}

fn read_optional(path: &Path) -> Result<Option<String>, TollgateError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TollgateError::io(format!("{}: {e}", path.display()))),
    }
}

/// Loads the CA from `dir`. `Ok(None)` unless both files exist; an error when both exist
/// but do not form a valid CA.
pub fn load_ca(dir: &Path) -> Result<Option<CertAuthority>, TollgateError> {
    let cert = read_optional(&dir.join(CA_CERT_FILE))?;
    let key = read_optional(&dir.join(CA_KEY_FILE))?;
    match (cert, key) {
        (Some(cert), Some(key)) => CertAuthority::from_pem(&cert, &key)
            .map(Some)
            .map_err(ca_error),
        _ => Ok(None),
    }
}

/// Writes `text` to `path` through a temporary file created with mode 0600, then renames
/// it into place, so the file is never readable by others and never half written.
pub(crate) fn write_private(path: &Path, text: &str) -> Result<(), TollgateError> {
    let name = path
        .file_name()
        .map_or_else(|| "file".into(), |name| name.to_string_lossy().into_owned());
    let tmp: PathBuf = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let result = options
        .open(&tmp)
        .and_then(|mut file| {
            file.write_all(text.as_bytes())?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&tmp, path));
    result.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        TollgateError::io(format!("{}: {e}", path.display()))
    })
}

fn generate_in(dir: &Path) -> Result<CaInfo, TollgateError> {
    if let Some(ca) = load_ca(dir)? {
        return Ok(info(&ca, false));
    }
    fs::create_dir_all(dir).map_err(|e| TollgateError::io(format!("{}: {e}", dir.display())))?;
    let ca = CertAuthority::generate(CA_COMMON_NAME).map_err(ca_error)?;
    // The key first: a certificate on disk always has its key next to it.
    write_private(&dir.join(CA_KEY_FILE), &ca.key_pem())?;
    write_private(&dir.join(CA_CERT_FILE), &ca.cert_pem())?;
    log::info!("generated a new root CA in {}", dir.display());
    Ok(info(&ca, true))
}

/// Returns the CA stored in `data_dir`, generating and storing one first when `ca.pem` or
/// `ca.key` is missing. A stored pair that is not a valid CA is an error and is left
/// untouched, so the user's installed root is never replaced silently.
#[uniffi::export]
pub fn generate_ca(data_dir: String) -> Result<CaInfo, TollgateError> {
    catch_panic(|| generate_in(Path::new(&data_dir)))
}

/// The iOS configuration profile (`.mobileconfig`) that installs the stored root. Fails
/// when no CA is stored.
#[uniffi::export]
pub fn ca_mobileconfig(data_dir: String) -> Result<Vec<u8>, TollgateError> {
    catch_panic(|| {
        let ca = load_ca(Path::new(&data_dir))?
            .ok_or_else(|| ca_error("no CA in the data directory; call generate_ca first"))?;
        Ok(ca.mobileconfig(PROFILE_DISPLAY_NAME, PROFILE_IDENTIFIER))
    })
}
```

`core/crates/tollgate-ffi/src/lib.rs`:

```rust
//! Swift-facing facade of the Tollgate core. Everything the iOS app and tunnel call
//! goes through this crate; the other crates stay free of FFI concerns.
//!
//! Every function on the tunnel path catches panics, so a Rust bug becomes a Swift error
//! (or a logged error for the functions that return no `Result`) instead of killing the
//! extension.

uniffi::setup_scaffolding!();

mod ca;
mod error;
mod logging;

pub use ca::{
    CA_CERT_FILE, CA_COMMON_NAME, CA_KEY_FILE, CaInfo, PROFILE_DISPLAY_NAME, PROFILE_IDENTIFIER,
    ca_mobileconfig, generate_ca, load_ca,
};
pub use error::{TollgateError, catch_panic, panic_message};
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
```

- [ ] **Step 4: Run the tests, fmt and clippy**

Run: `cd core && cargo test -p tollgate-ffi && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS: unit 3, `panics` 6, `logging` 1 and `ca` 5 passed; fmt and clippy print nothing

- [ ] **Step 5: Commit**

```bash
git add core/crates/tollgate-ffi/Cargo.toml core/crates/tollgate-ffi/src/lib.rs core/crates/tollgate-ffi/src/error.rs core/crates/tollgate-ffi/src/ca.rs core/crates/tollgate-ffi/tests/ca.rs core/Cargo.lock
git commit -m "ffi: generate_ca and ca_mobileconfig with 0600 CA files"
```

---

### Task 4: compile_lists

**Files:**
- Modify: `core/crates/tollgate-ffi/Cargo.toml`, `core/crates/tollgate-ffi/src/lib.rs`
- Create: `core/crates/tollgate-ffi/src/lists.rs`
- Test: `core/crates/tollgate-ffi/tests/lists.rs`

**Interfaces:**
- Consumes: `tollgate_filter::{compile_split, ListSource, ListFormat, CompileReport, FilterError}` (M1a), and in the test `DomainSet::load`, `FilterEngine::{load, check}`, `ENGINE_FILE`, `DOMAINS_FILE`.
- Produces:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)] pub enum ListFormat { Adblock, Hosts }
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)] pub enum ListTarget { Url, Dns }
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ListInput { pub name: String, pub text: String, pub format: ListFormat, pub target: ListTarget }
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CompileReport { pub network_rules: u64, pub domain_entries: u64, pub engine_bytes: u64, pub domains_bytes: u64 }
#[uniffi::export]
pub fn compile_lists(sources: Vec<ListInput>, data_dir: String) -> Result<CompileReport, TollgateError>;
```

- [ ] **Step 1: Write the failing test**

`core/crates/tollgate-ffi/Cargo.toml`:

```toml
[package]
name = "tollgate-ffi"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
publish.workspace = true

[lib]
name = "tollgate_ffi"
crate-type = ["lib", "staticlib"]

[dependencies]
log = { workspace = true }
ring = { workspace = true }
thiserror = { workspace = true }
tollgate-filter = { workspace = true }
tollgate-mitm = { workspace = true }
uniffi = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
```

`core/crates/tollgate-ffi/tests/lists.rs`:

```rust
use std::fs;

use tollgate_ffi::{ListFormat, ListInput, ListTarget, TollgateError, compile_lists};
use tollgate_filter::{DOMAINS_FILE, DomainSet, ENGINE_FILE, FilterEngine, Verdict};

const URL_RULES: &str =
    "! Title: test URL list\n||ads.example^\n||tracker.example^$third-party\n/banner/*$image\n";
const DNS_RULES: &str = "! Title: test DNS list\n||dns-block.example^\n@@||ok.dns-block.example^\n";
const HOSTS: &str = "# test hosts\n0.0.0.0 hosts-block.example\n127.0.0.1 localhost\n";

fn input(name: &str, text: &str, format: ListFormat, target: ListTarget) -> ListInput {
    ListInput {
        name: name.to_string(),
        text: text.to_string(),
        format,
        target,
    }
}

#[test]
fn url_lists_feed_the_engine_and_dns_lists_the_blocklist() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("lists");
    let report = compile_lists(
        vec![
            input("easylist", URL_RULES, ListFormat::Adblock, ListTarget::Url),
            input(
                "adguard-dns",
                DNS_RULES,
                ListFormat::Adblock,
                ListTarget::Dns,
            ),
            input("hosts", HOSTS, ListFormat::Hosts, ListTarget::Dns),
        ],
        dir.to_str().unwrap().to_string(),
    )
    .unwrap();
    assert_eq!(report.network_rules, 3);
    assert_eq!(report.domain_entries, 3);
    assert_eq!(
        report.engine_bytes,
        fs::metadata(dir.join(ENGINE_FILE)).unwrap().len()
    );
    assert_eq!(
        report.domains_bytes,
        fs::metadata(dir.join(DOMAINS_FILE)).unwrap().len()
    );

    let domains = DomainSet::load(&dir.join(DOMAINS_FILE)).unwrap();
    assert!(domains.is_blocked("dns-block.example"));
    assert!(domains.is_blocked("www.dns-block.example"));
    assert!(!domains.is_blocked("ok.dns-block.example"));
    assert!(domains.is_blocked("hosts-block.example"));
    // URL lists do not reach the DNS blocklist.
    assert!(!domains.is_blocked("ads.example"));

    let engine = FilterEngine::load(&dir.join(ENGINE_FILE)).unwrap();
    assert_eq!(
        engine.check(
            "https://ads.example/x.js",
            "https://site.example/",
            "script"
        ),
        Verdict::Block { rule: None }
    );
    // DNS lists do not reach the engine.
    assert_eq!(
        engine.check(
            "https://dns-block.example/x.js",
            "https://site.example/",
            "script"
        ),
        Verdict::Allow
    );
}

#[test]
fn a_hosts_list_cannot_feed_the_url_filter() {
    let tmp = tempfile::tempdir().unwrap();
    let result = compile_lists(
        vec![input("hosts", HOSTS, ListFormat::Hosts, ListTarget::Url)],
        tmp.path().to_str().unwrap().to_string(),
    );
    assert_eq!(
        result,
        Err(TollgateError::Config {
            message: "list \"hosts\" is in hosts format and can only feed the DNS blocklist"
                .to_string()
        })
    );
    assert!(!tmp.path().join(ENGINE_FILE).exists());
}

#[test]
fn no_lists_give_empty_files() {
    let tmp = tempfile::tempdir().unwrap();
    let report = compile_lists(Vec::new(), tmp.path().to_str().unwrap().to_string()).unwrap();
    assert_eq!(
        (
            report.network_rules,
            report.domain_entries,
            report.domains_bytes
        ),
        (0, 0, 32)
    );
    assert!(tmp.path().join(ENGINE_FILE).exists());
    assert!(tmp.path().join(DOMAINS_FILE).exists());
}

#[test]
fn an_unwritable_directory_is_a_lists_error() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("a-file");
    fs::write(&file, "").unwrap();
    let result = compile_lists(Vec::new(), file.to_str().unwrap().to_string());
    assert!(
        matches!(&result, Err(TollgateError::Lists { .. })),
        "{result:?}"
    );
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd core && cargo test -p tollgate-ffi --test lists`
Expected: FAIL to compile: `` error[E0432]: unresolved imports `tollgate_ffi::ListFormat`, `tollgate_ffi::ListInput`, `tollgate_ffi::ListTarget`, `tollgate_ffi::compile_lists` ``

- [ ] **Step 3: Implement**

`core/crates/tollgate-ffi/src/lists.rs`:

```rust
//! Compiling filter lists in the app process into the files the tunnel loads.

use std::path::Path;

use tollgate_filter::ListSource;

use crate::error::{TollgateError, catch_panic};

/// How a list is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ListFormat {
    /// Adblock Plus, uBlock Origin and AdGuard syntax.
    Adblock,
    /// `0.0.0.0 host` lines, or one bare host per line.
    Hosts,
}

/// Which file a list feeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ListTarget {
    /// URL rules for the proxy (`engine.dat`): EasyList, EasyPrivacy, AdGuard Mobile Ads.
    Url,
    /// Host names for the DNS blocklist (`domains.bin`): AdGuard DNS filter, hosts files.
    Dns,
}

/// One downloaded list.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ListInput {
    /// Used in log messages and errors only.
    pub name: String,
    pub text: String,
    pub format: ListFormat,
    pub target: ListTarget,
}

/// What `compile_lists` wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CompileReport {
    /// Network rules in `engine.dat`.
    pub network_rules: u64,
    /// Hashes in `domains.bin`.
    pub domain_entries: u64,
    pub engine_bytes: u64,
    pub domains_bytes: u64,
}

impl From<tollgate_filter::CompileReport> for CompileReport {
    fn from(report: tollgate_filter::CompileReport) -> CompileReport {
        CompileReport {
            network_rules: report.network_rules,
            domain_entries: report.domain_entries,
            engine_bytes: report.engine_bytes,
            domains_bytes: report.domains_bytes,
        }
    }
}

fn source(input: &ListInput) -> ListSource<'_> {
    ListSource {
        name: &input.name,
        text: &input.text,
        format: match input.format {
            ListFormat::Adblock => tollgate_filter::ListFormat::Adblock,
            ListFormat::Hosts => tollgate_filter::ListFormat::Hosts,
        },
    }
}

fn compile_in(sources: &[ListInput], dir: &Path) -> Result<CompileReport, TollgateError> {
    if let Some(list) = sources
        .iter()
        .find(|l| l.format == ListFormat::Hosts && l.target == ListTarget::Url)
    {
        return Err(TollgateError::Config {
            message: format!(
                "list {:?} is in hosts format and can only feed the DNS blocklist",
                list.name
            ),
        });
    }
    let pick = |target: ListTarget| -> Vec<ListSource<'_>> {
        sources
            .iter()
            .filter(|l| l.target == target)
            .map(source)
            .collect()
    };
    tollgate_filter::compile_split(&pick(ListTarget::Url), &pick(ListTarget::Dns), dir)
        .map(CompileReport::from)
        .map_err(|e| TollgateError::Lists {
            message: e.to_string(),
        })
}

/// Builds `engine.dat` from the `Url` lists and `domains.bin` from the `Dns` lists and
/// writes both into `data_dir` (created if missing), each file atomically. Runs in the
/// app, which has far more memory than the tunnel; the tunnel then calls
/// `Engine.reload_lists`.
#[uniffi::export]
pub fn compile_lists(
    sources: Vec<ListInput>,
    data_dir: String,
) -> Result<CompileReport, TollgateError> {
    catch_panic(|| compile_in(&sources, Path::new(&data_dir)))
}
```

`core/crates/tollgate-ffi/src/lib.rs`:

```rust
//! Swift-facing facade of the Tollgate core. Everything the iOS app and tunnel call
//! goes through this crate; the other crates stay free of FFI concerns.
//!
//! Every function on the tunnel path catches panics, so a Rust bug becomes a Swift error
//! (or a logged error for the functions that return no `Result`) instead of killing the
//! extension.

uniffi::setup_scaffolding!();

mod ca;
mod error;
mod lists;
mod logging;

pub use ca::{
    CA_CERT_FILE, CA_COMMON_NAME, CA_KEY_FILE, CaInfo, PROFILE_DISPLAY_NAME, PROFILE_IDENTIFIER,
    ca_mobileconfig, generate_ca, load_ca,
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
```

- [ ] **Step 4: Run the tests, fmt and clippy**

Run: `cd core && cargo test -p tollgate-ffi && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS: unit 3, `panics` 6, `logging` 1, `ca` 5 and `lists` 4 passed; fmt and clippy print nothing

- [ ] **Step 5: Commit**

```bash
git add core/crates/tollgate-ffi/Cargo.toml core/crates/tollgate-ffi/src/lib.rs core/crates/tollgate-ffi/src/lists.rs core/crates/tollgate-ffi/tests/lists.rs core/Cargo.lock
git commit -m "ffi: compile_lists routes URL lists to engine.dat and DNS lists to domains.bin"
```

---

### Task 5: Engine construction and local DNS answers

**Files:**
- Modify: `core/crates/tollgate-ffi/Cargo.toml`, `core/crates/tollgate-ffi/src/lib.rs`
- Create: `core/crates/tollgate-ffi/src/engine.rs`, `core/crates/tollgate-ffi/tests/support/mod.rs`
- Test: `core/crates/tollgate-ffi/tests/engine_dns.rs`

**Interfaces:**
- Consumes: `tollgate_policy::{Config::from_json, Policy::new, Policy::learned_pins_json}`, `tollgate_filter::{FilterEngine::load, DomainSet::load, FilterError, ENGINE_FILE, DOMAINS_FILE}`, `tollgate_dns::{DnsHandler::{new, handle_packet, complete, set_blocklist}, Outcome, DohError::Stopped}`, `tollgate_mitm::{ProxyContext, CertAuthority::generate}`, `tollgate_common::{clock::now_secs, stats::{Stats, StatsSnapshot}}`; in tests `tollgate_dns::packet::{build_udp, parse_udp}` and `tollgate_common::clock::unix_secs`.
- Produces (the rest of `Engine` follows in Tasks 6 and 7):

```rust
pub const LEARNED_PINS_FILE: &str = "learned-pins.json";
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct Stats { /* the twelve StatsSnapshot counters as u64 */ }
impl From<tollgate_common::stats::StatsSnapshot> for Stats;
#[derive(uniffi::Object)] pub struct Engine;
#[uniffi::export] impl Engine {
    #[uniffi::constructor]
    pub fn new(config_json: String, data_dir: String) -> Result<Arc<Engine>, TollgateError>;
    pub fn handle_packets(&self, packets: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, TollgateError>;
    pub fn reload_lists(&self) -> Result<(), TollgateError>;
    pub fn stats(&self) -> Stats;
    pub fn learned_pins_json(&self) -> String;
    pub fn mitm_active(&self) -> bool;
}
```

- [ ] **Step 1: Write the failing test**

`core/crates/tollgate-ffi/Cargo.toml`:

```toml
[package]
name = "tollgate-ffi"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
publish.workspace = true

[lib]
name = "tollgate_ffi"
crate-type = ["lib", "staticlib"]

[dependencies]
arc-swap = { workspace = true }
log = { workspace = true }
ring = { workspace = true }
thiserror = { workspace = true }
tollgate-common = { workspace = true }
tollgate-dns = { workspace = true }
tollgate-filter = { workspace = true }
tollgate-mitm = { workspace = true }
tollgate-policy = { workspace = true }
uniffi = { workspace = true }

[dev-dependencies]
hickory-proto = { workspace = true }
tempfile = { workspace = true }
```

`core/crates/tollgate-ffi/tests/support/mod.rs`:

```rust
//! Helpers shared by the integration tests; each test binary uses a different part.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use tempfile::TempDir;
use tollgate_dns::packet::{build_udp, parse_udp};
use tollgate_ffi::{ListFormat, ListInput, ListTarget, compile_lists};

/// The address the phone's DNS queries come from.
pub fn client() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)), 53001)
}

/// The tunnel's DNS server.
pub fn dns_server() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), 53)
}

/// A recursion-desired query for `name` wrapped in an IPv4 packet from the client to the
/// tunnel's DNS address.
pub fn query(id: u16, name: &str, rtype: RecordType) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    build_udp(client(), dns_server(), &message.to_vec().unwrap()).unwrap()
}

/// Decodes a reply packet after checking it goes from the DNS address to the client.
pub fn reply(packet: &[u8]) -> Message {
    let datagram = parse_udp(packet).expect("a UDP packet");
    assert_eq!(datagram.source, dns_server());
    assert_eq!(datagram.destination, client());
    Message::from_vec(datagram.payload).expect("a DNS message")
}

/// A temporary data directory with `url_rules` compiled into `engine.dat` and
/// `dns_rules` into `domains.bin`.
pub fn data_dir(url_rules: &str, dns_rules: &str) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    compile_into(&dir, url_rules, dns_rules);
    dir
}

pub fn compile_into(dir: &TempDir, url_rules: &str, dns_rules: &str) {
    let lists = vec![
        ListInput {
            name: "url".to_string(),
            text: url_rules.to_string(),
            format: ListFormat::Adblock,
            target: ListTarget::Url,
        },
        ListInput {
            name: "dns".to_string(),
            text: dns_rules.to_string(),
            format: ListFormat::Adblock,
            target: ListTarget::Dns,
        },
    ];
    compile_lists(lists, path(dir)).unwrap();
}

pub fn path(dir: &TempDir) -> String {
    dir.path().to_str().unwrap().to_string()
}
```

`core/crates/tollgate-ffi/tests/engine_dns.rs`:

```rust
//! The engine without its runtime: construction, local DNS answers, list reloads.

mod support;

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, RecordType};
use support::{client, compile_into, data_dir, path, query, reply};
use tollgate_dns::packet::build_udp;
use tollgate_ffi::{Engine, LEARNED_PINS_FILE, Stats, TollgateError, generate_ca};

const EMPTY_PINS: &str = r#"{"version":1,"pins":[]}"#;

fn engine(dir: &tempfile::TempDir) -> std::sync::Arc<Engine> {
    Engine::new("{}".to_string(), path(dir)).unwrap()
}

#[test]
fn invalid_config_is_a_config_error() {
    let dir = tempfile::tempdir().unwrap();
    let error = Engine::new("not json".to_string(), path(&dir))
        .err()
        .unwrap();
    assert!(
        matches!(&error, TollgateError::Config { message } if message.starts_with("invalid configuration: ")),
        "{error:?}"
    );
    let error = Engine::new(
        r#"{"passthrough":["exa mple.com"]}"#.to_string(),
        path(&dir),
    )
    .err()
    .unwrap();
    assert!(
        matches!(&error, TollgateError::Config { message } if message.starts_with("invalid host pattern \"exa mple.com\"")),
        "{error:?}"
    );
}

#[test]
fn an_empty_data_dir_gives_a_dns_only_engine() {
    let dir = tempfile::tempdir().unwrap();
    let engine = engine(&dir);
    assert!(!engine.mitm_active());
    assert_eq!(engine.stats(), Stats::default());
    assert_eq!(engine.learned_pins_json(), EMPTY_PINS);
}

#[test]
fn blocked_names_get_unspecified_addresses() {
    let dir = data_dir("", "||ads.example^\n");
    let engine = engine(&dir);
    let replies = engine
        .handle_packets(vec![
            query(0x0101, "ads.example.", RecordType::A),
            query(0x0202, "cdn.ads.example.", RecordType::AAAA),
        ])
        .unwrap();
    assert_eq!(replies.len(), 2);
    let v4 = reply(&replies[0]);
    assert_eq!(v4.metadata.id, 0x0101);
    assert_eq!(v4.metadata.response_code, ResponseCode::NoError);
    assert_eq!(v4.answers.len(), 1);
    assert_eq!(v4.answers[0].ttl, 60);
    assert_eq!(v4.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
    let v6 = reply(&replies[1]);
    assert_eq!(v6.metadata.id, 0x0202);
    assert_eq!(v6.answers[0].data, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
    assert_eq!(
        engine.stats(),
        Stats {
            dns_queries: 2,
            dns_blocked: 2,
            ..Stats::default()
        }
    );
}

#[test]
fn https_queries_get_an_empty_answer() {
    let dir = tempfile::tempdir().unwrap();
    let engine = engine(&dir);
    let replies = engine
        .handle_packets(vec![query(7, "example.com.", RecordType::HTTPS)])
        .unwrap();
    let message = reply(&replies[0]);
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(message.answers.is_empty());
}

#[test]
fn forwarded_queries_get_servfail_while_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let engine = engine(&dir);
    let replies = engine
        .handle_packets(vec![query(0x3333, "example.com.", RecordType::A)])
        .unwrap();
    assert_eq!(replies.len(), 1);
    let message = reply(&replies[0]);
    assert_eq!(message.metadata.id, 0x3333);
    assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(
        engine.stats(),
        Stats {
            dns_queries: 1,
            dns_forwarded: 1,
            dns_failed: 1,
            ..Stats::default()
        }
    );
}

#[test]
fn other_packets_are_dropped_and_order_is_kept() {
    let dir = data_dir("", "||ads.example^\n");
    let engine = engine(&dir);
    let not_dns = build_udp(client(), "198.18.0.1:80".parse().unwrap(), &[0u8; 20]).unwrap();
    let replies = engine
        .handle_packets(vec![
            query(1, "ads.example.", RecordType::A),
            not_dns,
            vec![0x45, 0x00, 0x01],
            query(2, "example.com.", RecordType::HTTPS),
        ])
        .unwrap();
    let ids: Vec<u16> = replies.iter().map(|r| reply(r).metadata.id).collect();
    assert_eq!(ids, vec![1, 2]);
    assert_eq!(
        engine.stats(),
        Stats {
            dns_queries: 2,
            dns_blocked: 1,
            packets_dropped: 2,
            ..Stats::default()
        }
    );
}

#[test]
fn reload_swaps_both_lists_or_neither() {
    let dir = tempfile::tempdir().unwrap();
    let engine = engine(&dir);
    let blocked = |engine: &Engine| {
        let replies = engine
            .handle_packets(vec![query(9, "ads.example.", RecordType::A)])
            .unwrap();
        reply(&replies[0]).metadata.response_code == ResponseCode::NoError
    };
    assert!(!blocked(&engine), "no blocklist yet: forwarded, SERVFAIL");

    compile_into(&dir, "||ads.example^\n", "||ads.example^\n");
    engine.reload_lists().unwrap();
    assert!(blocked(&engine));

    // Replaced by rename, like compile does: the loaded set maps the old file.
    let junk = dir.path().join("junk.tmp");
    fs::write(&junk, b"junk").unwrap();
    fs::rename(&junk, dir.path().join("domains.bin")).unwrap();
    let error = engine.reload_lists().unwrap_err();
    assert!(matches!(&error, TollgateError::Lists { .. }), "{error:?}");
    assert!(blocked(&engine), "the old lists stay after a failed reload");

    fs::remove_file(dir.path().join("domains.bin")).unwrap();
    fs::remove_file(dir.path().join("engine.dat")).unwrap();
    engine.reload_lists().unwrap();
    assert!(!blocked(&engine), "missing files clear the lists");
}

#[test]
fn interception_needs_the_flag_the_ca_and_the_engine() {
    let dir = data_dir("||ads.example^\n", "");
    assert!(!engine(&dir).mitm_active(), "no CA");
    generate_ca(path(&dir)).unwrap();
    assert!(engine(&dir).mitm_active());
    let off = Engine::new(r#"{"mitm_enabled":false}"#.to_string(), path(&dir)).unwrap();
    assert!(!off.mitm_active());
    fs::remove_file(dir.path().join("engine.dat")).unwrap();
    assert!(!engine(&dir).mitm_active(), "no engine.dat");
}

#[test]
fn unreadable_files_are_skipped() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("engine.dat"), b"junk").unwrap();
    fs::write(dir.path().join("domains.bin"), b"junk").unwrap();
    fs::write(dir.path().join("ca.pem"), b"junk").unwrap();
    fs::write(dir.path().join("ca.key"), b"junk").unwrap();
    fs::write(dir.path().join(LEARNED_PINS_FILE), b"junk").unwrap();
    let engine = engine(&dir);
    assert!(!engine.mitm_active());
    assert_eq!(engine.learned_pins_json(), EMPTY_PINS);
}

#[test]
fn learned_pins_are_loaded_from_the_data_dir() {
    let dir = tempfile::tempdir().unwrap();
    let now = tollgate_common::clock::unix_secs();
    let pins =
        format!(r#"{{"version":1,"pins":[{{"host":"pinned.example","learned_at":{now}}}]}}"#);
    fs::write(dir.path().join(LEARNED_PINS_FILE), &pins).unwrap();
    assert_eq!(engine(&dir).learned_pins_json(), pins);
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd core && cargo test -p tollgate-ffi --test engine_dns`
Expected: FAIL to compile: `` error[E0432]: unresolved imports `tollgate_ffi::Engine`, `tollgate_ffi::LEARNED_PINS_FILE`, `tollgate_ffi::Stats` ``

- [ ] **Step 3: Implement**

Until the runtime exists (Task 6), every query that needs the upstream is answered with SERVFAIL, which is also the final behavior while the engine is stopped.

`core/crates/tollgate-ffi/src/engine.rs`:

```rust
//! The engine the tunnel runs: DNS answers on the packet path, and the proxy plus the DNS
//! forwarder on one runtime thread.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use tollgate_common::clock;
use tollgate_common::stats::{Stats as Counters, StatsSnapshot};
use tollgate_dns::{DnsHandler, DohError, Outcome};
use tollgate_filter::{DOMAINS_FILE, DomainSet, ENGINE_FILE, FilterEngine, FilterError};
use tollgate_mitm::{CertAuthority, ProxyContext};
use tollgate_policy::{Config, Policy};

use crate::ca::load_ca;
use crate::error::{TollgateError, catch_panic};

/// Learned certificate pins, read by `Engine::new`.
pub const LEARNED_PINS_FILE: &str = "learned-pins.json";

/// Counters since the engine was created. Mirrors `tollgate_common::stats::StatsSnapshot`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct Stats {
    pub dns_queries: u64,
    pub dns_blocked: u64,
    pub dns_cache_hits: u64,
    pub dns_forwarded: u64,
    pub dns_failed: u64,
    pub packets_dropped: u64,
    pub http_requests: u64,
    pub http_blocked: u64,
    pub connections_intercepted: u64,
    pub connections_passthrough: u64,
    pub tls_client_rejections: u64,
    pub tls_abandoned_after_handshake: u64,
}

impl From<StatsSnapshot> for Stats {
    fn from(s: StatsSnapshot) -> Stats {
        Stats {
            dns_queries: s.dns_queries,
            dns_blocked: s.dns_blocked,
            dns_cache_hits: s.dns_cache_hits,
            dns_forwarded: s.dns_forwarded,
            dns_failed: s.dns_failed,
            packets_dropped: s.packets_dropped,
            http_requests: s.http_requests,
            http_blocked: s.http_blocked,
            connections_intercepted: s.connections_intercepted,
            connections_passthrough: s.connections_passthrough,
            tls_client_rejections: s.tls_client_rejections,
            tls_abandoned_after_handshake: s.tls_abandoned_after_handshake,
        }
    }
}

/// The tunnel's Rust side: DNS answers, the DNS forwarder and the HTTPS proxy.
#[derive(uniffi::Object)]
pub struct Engine {
    data_dir: PathBuf,
    mitm_active: bool,
    stats: Arc<Counters>,
    dns: Arc<DnsHandler>,
    proxy: Arc<ProxyContext>,
}

#[uniffi::export]
impl Engine {
    /// Parses `config_json` and loads what `data_dir` holds: `engine.dat`, `domains.bin`,
    /// `ca.pem` with `ca.key`, and `learned-pins.json`. Each file is optional; a file that
    /// cannot be loaded is logged and skipped. HTTPS interception needs both the CA and
    /// `engine.dat`; without them every connection is passed through.
    #[uniffi::constructor]
    pub fn new(config_json: String, data_dir: String) -> Result<Arc<Engine>, TollgateError> {
        catch_panic(|| Engine::open(&config_json, Path::new(&data_dir)))
    }

    /// Handles raw IP packets from the tunnel without waiting on the network. Returns the
    /// replies it can give at once: blocked names, HTTPS and SVCB queries, cache hits and
    /// errors. Until the engine has a runtime, queries that need the upstream get SERVFAIL.
    pub fn handle_packets(&self, packets: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, TollgateError> {
        catch_panic(|| Ok(self.answer(&packets)))
    }

    /// Loads `engine.dat` and `domains.bin` again and swaps both in. A missing file clears
    /// that list; a file that fails to load is an error and nothing is swapped.
    pub fn reload_lists(&self) -> Result<(), TollgateError> {
        catch_panic(|| {
            let filter = load_filter(&self.data_dir)?;
            let domains = load_domains(&self.data_dir)?;
            log::info!(
                "reloaded lists: engine {}, DNS blocklist {} hashes",
                if filter.is_some() {
                    "loaded"
                } else {
                    "missing"
                },
                domains.as_ref().map_or(0, |set| set.len())
            );
            self.proxy.filter.store(filter);
            self.dns.set_blocklist(domains);
            Ok(())
        })
    }

    pub fn stats(&self) -> Stats {
        catch_panic(|| Ok(self.stats.snapshot().into())).unwrap_or_default()
    }

    /// The learned pins as JSON, the format of `learned-pins.json`.
    pub fn learned_pins_json(&self) -> String {
        catch_panic(|| Ok(self.proxy.policy.learned_pins_json())).unwrap_or_default()
    }

    /// Whether HTTPS connections can be intercepted: `mitm_enabled` in the config, a CA and
    /// `engine.dat` were all present when the engine was created.
    pub fn mitm_active(&self) -> bool {
        self.mitm_active
    }
}

impl Engine {
    fn open(config_json: &str, data_dir: &Path) -> Result<Arc<Engine>, TollgateError> {
        let config = Config::from_json(config_json).map_err(|e| TollgateError::Config {
            message: e.to_string(),
        })?;
        let filter = load_filter(data_dir).unwrap_or_else(|e| {
            log::warn!("running without the URL filter: {e}");
            None
        });
        let domains = load_domains(data_dir).unwrap_or_else(|e| {
            log::warn!("running without the DNS blocklist: {e}");
            None
        });
        let ca = load_ca(data_dir).unwrap_or_else(|e| {
            log::warn!("running without the CA: {e}");
            None
        });
        let mitm_active = config.mitm_enabled && ca.is_some() && filter.is_some();
        if config.mitm_enabled && !mitm_active {
            log::warn!(
                "HTTPS interception is off: {}",
                if ca.is_none() {
                    "no CA"
                } else {
                    "no engine.dat"
                }
            );
        }
        let policy_config = Config {
            mitm_enabled: mitm_active,
            ..config.clone()
        };
        let pins = read_pins(data_dir);
        let policy =
            Policy::new(&policy_config, pins.as_deref()).map_err(|e| TollgateError::Config {
                message: e.to_string(),
            })?;
        // The proxy needs a CA even when it only passes connections through; this one is
        // never used to issue a leaf because the policy intercepts nothing.
        let ca = match ca {
            Some(ca) => ca,
            None => CertAuthority::generate("Tollgate unused").map_err(|e| TollgateError::Ca {
                message: e.to_string(),
            })?,
        };
        let stats = Arc::new(Counters::default());
        let proxy = Arc::new(ProxyContext {
            policy: Arc::new(policy),
            filter: ArcSwapOption::new(filter),
            ca: Arc::new(ca),
            stats: stats.clone(),
            max_intercepted: config.max_intercepted_connections as usize,
            available_memory,
        });
        let dns = Arc::new(DnsHandler::new(domains, stats.clone()));
        Ok(Arc::new(Engine {
            data_dir: data_dir.to_path_buf(),
            mitm_active,
            stats,
            dns,
            proxy,
        }))
    }

    fn answer(&self, packets: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let now = clock::now_secs();
        let mut replies = Vec::new();
        for packet in packets {
            match self.dns.handle_packet(packet, now) {
                Outcome::Reply(reply) => replies.push(reply),
                Outcome::Drop => {}
                Outcome::Forward(job) => {
                    replies.push(self.dns.complete(job, Err(DohError::Stopped), now));
                }
            }
        }
        replies
    }
}

fn load_filter(dir: &Path) -> Result<Option<Arc<FilterEngine>>, TollgateError> {
    match FilterEngine::load(&dir.join(ENGINE_FILE)) {
        Ok(engine) => Ok(Some(Arc::new(engine))),
        Err(FilterError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TollgateError::Lists {
            message: e.to_string(),
        }),
    }
}

fn load_domains(dir: &Path) -> Result<Option<Arc<DomainSet>>, TollgateError> {
    match DomainSet::load(&dir.join(DOMAINS_FILE)) {
        Ok(set) => Ok(Some(Arc::new(set))),
        Err(FilterError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TollgateError::Lists {
            message: e.to_string(),
        }),
    }
}

fn read_pins(dir: &Path) -> Option<String> {
    let path = dir.join(LEARNED_PINS_FILE);
    match std::fs::read_to_string(&path) {
        Ok(json) => Some(json),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => {
            log::warn!("ignoring {}: {e}", path.display());
            None
        }
    }
}

/// Bytes the extension may still allocate before jetsam ends it. `None` outside iOS, and
/// when iOS reports 0, which it does for processes without a limit.
#[cfg(target_os = "ios")]
fn available_memory() -> Option<u64> {
    unsafe extern "C" {
        fn os_proc_available_memory() -> usize;
    }
    // SAFETY: os_proc_available_memory takes no arguments and has no preconditions; it is
    // part of libSystem since iOS 13.
    let bytes = unsafe { os_proc_available_memory() };
    (bytes > 0).then_some(bytes as u64)
}

#[cfg(not(target_os = "ios"))]
fn available_memory() -> Option<u64> {
    None
}
```

`core/crates/tollgate-ffi/src/lib.rs`:

```rust
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
    ca_mobileconfig, generate_ca, load_ca,
};
pub use engine::{Engine, LEARNED_PINS_FILE, Stats};
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
```

- [ ] **Step 4: Run the tests, fmt and clippy**

Run: `cd core && cargo test -p tollgate-ffi && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS: unit 3, `panics` 6, `logging` 1, `ca` 5, `lists` 4 and `engine_dns` 10 passed; fmt and clippy print nothing

- [ ] **Step 5: Commit**

```bash
git add core/crates/tollgate-ffi/Cargo.toml core/crates/tollgate-ffi/src/lib.rs core/crates/tollgate-ffi/src/engine.rs core/crates/tollgate-ffi/tests/support/mod.rs core/crates/tollgate-ffi/tests/engine_dns.rs core/Cargo.lock
git commit -m "ffi: Engine loads the data directory and answers DNS packets locally"
```

---

### Task 6: Engine runtime: start, stop, the proxy and forwarding through PacketSink

**Files:**
- Modify: `core/crates/tollgate-ffi/Cargo.toml`, `core/crates/tollgate-ffi/src/lib.rs`, `core/crates/tollgate-ffi/src/engine.rs`, `core/crates/tollgate-ffi/tests/support/mod.rs`
- Test: `core/crates/tollgate-ffi/tests/lifecycle.rs`, and a unit test for a poisoned lock in `engine.rs`

**Interfaces:**
- Consumes: `tollgate_mitm::serve(listener, ctx, shutdown)`, `tollgate_dns::{DohResolver::{new, resolve}, ForwardJob::query, DohError::{Busy, Stopped}, MAX_IN_FLIGHT}`, tokio `mpsc`, `oneshot`, `Semaphore`, `runtime::Builder`.
- Produces:

```rust
pub const RUNTIME_THREAD: &str = "tollgate-core";
pub const FORWARD_QUEUE: usize = 256;
#[uniffi::export(foreign)]
pub trait PacketSink: Send + Sync { fn write_packets(&self, packets: Vec<Vec<u8>>); }
#[uniffi::export] impl Engine {
    pub fn start(&self, sink: Arc<dyn PacketSink>) -> Result<u16, TollgateError>;
    pub fn stop(&self);
    pub fn port(&self) -> Option<u16>;
}
impl Drop for Engine; // stop()
```

Swift: `protocol PacketSink: AnyObject, Sendable { func writePackets(packets: [Data]) }`, `start(sink:) throws -> UInt16`. The Swift sink must capture only the `NEPacketTunnelFlow` (never the provider), only hand packets off, and derive each packet's protocol family from the IP version nibble for `writePackets(_:withProtocols:)`; `stopTunnel` always calls `stop()` (M2 writes that code).

- [ ] **Step 1: Write the failing test**

`core/crates/tollgate-ffi/tests/support/mod.rs`:

```rust
//! Helpers shared by the integration tests; each test binary uses a different part.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use tempfile::TempDir;
use tollgate_dns::packet::{build_udp, parse_udp};
use tollgate_ffi::{ListFormat, ListInput, ListTarget, PacketSink, compile_lists};

/// The address the phone's DNS queries come from.
pub fn client() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)), 53001)
}

/// The tunnel's DNS server.
pub fn dns_server() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), 53)
}

/// A recursion-desired query for `name` wrapped in an IPv4 packet from the client to the
/// tunnel's DNS address.
pub fn query(id: u16, name: &str, rtype: RecordType) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    build_udp(client(), dns_server(), &message.to_vec().unwrap()).unwrap()
}

/// Decodes a reply packet after checking it goes from the DNS address to the client.
pub fn reply(packet: &[u8]) -> Message {
    let datagram = parse_udp(packet).expect("a UDP packet");
    assert_eq!(datagram.source, dns_server());
    assert_eq!(datagram.destination, client());
    Message::from_vec(datagram.payload).expect("a DNS message")
}

/// A temporary data directory with `url_rules` compiled into `engine.dat` and
/// `dns_rules` into `domains.bin`.
pub fn data_dir(url_rules: &str, dns_rules: &str) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    compile_into(&dir, url_rules, dns_rules);
    dir
}

pub fn compile_into(dir: &TempDir, url_rules: &str, dns_rules: &str) {
    let lists = vec![
        ListInput {
            name: "url".to_string(),
            text: url_rules.to_string(),
            format: ListFormat::Adblock,
            target: ListTarget::Url,
        },
        ListInput {
            name: "dns".to_string(),
            text: dns_rules.to_string(),
            format: ListFormat::Adblock,
            target: ListTarget::Dns,
        },
    ];
    compile_lists(lists, path(dir)).unwrap();
}

pub fn path(dir: &TempDir) -> String {
    dir.path().to_str().unwrap().to_string()
}

/// A config whose only DoH upstream is a local port where nothing listens, so forwarded
/// queries fail at once.
pub fn closed_upstream_config() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!(r#"{{"doh_upstreams":[{{"ip":"127.0.0.1","port":{port},"tls_name":"doh.test"}}]}}"#)
}

/// A PacketSink that sends every packet into a channel.
pub struct ChannelSink(Mutex<Sender<Vec<u8>>>);

impl PacketSink for ChannelSink {
    fn write_packets(&self, packets: Vec<Vec<u8>>) {
        let sender = self.0.lock().unwrap();
        for packet in packets {
            let _ = sender.send(packet);
        }
    }
}

pub fn sink() -> (Arc<ChannelSink>, Receiver<Vec<u8>>) {
    let (tx, rx) = channel();
    (Arc::new(ChannelSink(Mutex::new(tx))), rx)
}

/// Polls `condition` every millisecond for up to five seconds.
pub fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}
```

`core/crates/tollgate-ffi/tests/lifecycle.rs`:

```rust
//! Its own test binary, with one test, because it counts the process's threads.

mod support;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, OnceLock};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use support::{closed_upstream_config, data_dir, path, query, reply, sink, wait_until};
use tollgate_ffi::{Engine, LEARNED_PINS_FILE, PacketSink, RUNTIME_THREAD, TollgateError};

fn threads() -> Vec<String> {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|task| std::fs::read_to_string(task.ok()?.path().join("comm")).ok())
        .map(|name| name.trim_end().to_string())
        .collect()
}

fn runtime_threads() -> usize {
    threads()
        .iter()
        .filter(|name| *name == RUNTIME_THREAD)
        .count()
}

/// Sends one request to the proxy in absolute form and returns the whole response.
fn proxy_get(port: u16, url: &str, host: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

/// Stops the engine from inside the callback, which runs on the runtime thread.
struct StopSink {
    engine: OnceLock<Arc<Engine>>,
    seen: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl PacketSink for StopSink {
    fn write_packets(&self, packets: Vec<Vec<u8>>) {
        self.seen.lock().unwrap().extend(packets);
        if let Some(engine) = self.engine.get() {
            engine.stop();
        }
    }
}

#[test]
fn start_stop_restart_drop_and_stop_from_the_runtime_thread() {
    let dir = data_dir("||blocked.example^\n", "");
    let config = closed_upstream_config();
    let engine = Engine::new(config.clone(), path(&dir)).unwrap();
    let before = threads().len();
    assert_eq!(runtime_threads(), 0);

    // start() on one thread, stop() on another, like Swift does.
    let starter = engine.clone();
    let port = std::thread::spawn(move || starter.start(sink().0).unwrap())
        .join()
        .unwrap();
    assert_ne!(port, 0);
    assert_eq!(engine.port(), Some(port));
    wait_until("one runtime thread", || runtime_threads() == 1);
    assert_eq!(engine.start(sink().0), Err(TollgateError::AlreadyRunning));

    // The proxy listens as soon as start() returns and filters plain HTTP.
    let response = proxy_get(port, "http://blocked.example/ad.js", "blocked.example");
    assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("access-control-allow-origin: *"),
        "{response}"
    );
    let stats = engine.stats();
    assert_eq!((stats.http_requests, stats.http_blocked), (1, 1));

    let stopper = engine.clone();
    std::thread::spawn(move || stopper.stop()).join().unwrap();
    assert_eq!(engine.port(), None);
    wait_until("the runtime thread to end", || {
        runtime_threads() == 0 && threads().len() == before
    });
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    assert!(dir.path().join(LEARNED_PINS_FILE).exists());
    engine.stop();

    // Restart, then drop the last reference without stop().
    let port = engine.start(sink().0).unwrap();
    assert_ne!(port, 0);
    wait_until("one runtime thread", || runtime_threads() == 1);
    drop(engine);
    wait_until("the runtime thread to end after drop", || {
        runtime_threads() == 0 && threads().len() == before
    });

    // stop() from inside a PacketSink callback must not join its own thread.
    let engine = Engine::new(config, path(&dir)).unwrap();
    let stopping = Arc::new(StopSink {
        engine: OnceLock::new(),
        seen: std::sync::Mutex::new(Vec::new()),
    });
    engine.start(stopping.clone()).unwrap();
    stopping.engine.set(engine.clone()).ok().unwrap();
    let immediate = engine
        .handle_packets(vec![query(0x7777, "example.com.", RecordType::A)])
        .unwrap();
    assert!(immediate.is_empty());
    wait_until("the SERVFAIL through the sink", || {
        !stopping.seen.lock().unwrap().is_empty()
    });
    let message = reply(&stopping.seen.lock().unwrap()[0]);
    assert_eq!(message.metadata.id, 0x7777);
    assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
    wait_until("the runtime thread to end after stopping itself", || {
        runtime_threads() == 0 && threads().len() == before
    });
    assert_eq!(engine.port(), None);
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd core && cargo test -p tollgate-ffi --test lifecycle`
Expected: FAIL to compile: `` error[E0432]: unresolved import `tollgate_ffi::PacketSink` `` (in `tests/support/mod.rs`) and `` error[E0432]: unresolved imports `tollgate_ffi::PacketSink`, `tollgate_ffi::RUNTIME_THREAD` ``

- [ ] **Step 3: Implement**

`core/crates/tollgate-ffi/Cargo.toml`:

```toml
[package]
name = "tollgate-ffi"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
publish.workspace = true

[lib]
name = "tollgate_ffi"
crate-type = ["lib", "staticlib"]

[dependencies]
arc-swap = { workspace = true }
log = { workspace = true }
ring = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true }
tollgate-common = { workspace = true }
tollgate-dns = { workspace = true }
tollgate-filter = { workspace = true }
tollgate-mitm = { workspace = true }
tollgate-policy = { workspace = true }
uniffi = { workspace = true }

[dev-dependencies]
hickory-proto = { workspace = true }
tempfile = { workspace = true }
```

`core/crates/tollgate-ffi/src/engine.rs`:

```rust
//! The engine the tunnel runs: DNS answers on the packet path, and the proxy plus the DNS
//! forwarder on one runtime thread.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use tokio::net::TcpListener;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tollgate_common::clock;
use tollgate_common::stats::{Stats as Counters, StatsSnapshot};
use tollgate_dns::{DnsHandler, DohError, DohResolver, ForwardJob, Outcome};
use tollgate_filter::{DOMAINS_FILE, DomainSet, ENGINE_FILE, FilterEngine, FilterError};
use tollgate_mitm::{CertAuthority, ProxyContext};
use tollgate_policy::{Config, Policy};

use crate::ca::{load_ca, write_private};
use crate::error::{TollgateError, catch_panic, panic_message};

/// Name of the thread that runs the proxy and the DNS forwarder.
pub const RUNTIME_THREAD: &str = "tollgate-core";
/// Learned certificate pins, read by `Engine::new` and written by `Engine::stop`.
pub const LEARNED_PINS_FILE: &str = "learned-pins.json";
/// Forwarded queries waiting for the runtime; when full, new ones get SERVFAIL at once.
pub const FORWARD_QUEUE: usize = 256;
/// Threads tokio may start for blocking work (the proxy's `getaddrinfo` calls).
const MAX_BLOCKING_THREADS: usize = 4;
/// How long `stop` waits for blocking work such as a hung `getaddrinfo`.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// Implemented in Swift over `NEPacketTunnelFlow.writePackets`. Called on the runtime
/// thread with the answers to forwarded DNS queries, so it must only hand the packets off.
#[uniffi::export(foreign)]
pub trait PacketSink: Send + Sync {
    fn write_packets(&self, packets: Vec<Vec<u8>>);
}

/// Counters since the engine was created. Mirrors `tollgate_common::stats::StatsSnapshot`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct Stats {
    pub dns_queries: u64,
    pub dns_blocked: u64,
    pub dns_cache_hits: u64,
    pub dns_forwarded: u64,
    pub dns_failed: u64,
    pub packets_dropped: u64,
    pub http_requests: u64,
    pub http_blocked: u64,
    pub connections_intercepted: u64,
    pub connections_passthrough: u64,
    pub tls_client_rejections: u64,
    pub tls_abandoned_after_handshake: u64,
}

impl From<StatsSnapshot> for Stats {
    fn from(s: StatsSnapshot) -> Stats {
        Stats {
            dns_queries: s.dns_queries,
            dns_blocked: s.dns_blocked,
            dns_cache_hits: s.dns_cache_hits,
            dns_forwarded: s.dns_forwarded,
            dns_failed: s.dns_failed,
            packets_dropped: s.packets_dropped,
            http_requests: s.http_requests,
            http_blocked: s.http_blocked,
            connections_intercepted: s.connections_intercepted,
            connections_passthrough: s.connections_passthrough,
            tls_client_rejections: s.tls_client_rejections,
            tls_abandoned_after_handshake: s.tls_abandoned_after_handshake,
        }
    }
}

struct Running {
    port: u16,
    jobs: mpsc::Sender<ForwardJob>,
    shutdown: oneshot::Sender<()>,
    thread: JoinHandle<()>,
}

/// What the runtime thread needs.
struct Work {
    proxy: Arc<ProxyContext>,
    dns: Arc<DnsHandler>,
    resolver: DohResolver,
    sink: Arc<dyn PacketSink>,
    queue: mpsc::Receiver<ForwardJob>,
    in_flight: usize,
}

/// The tunnel's Rust side: DNS answers, the DNS forwarder and the HTTPS proxy.
#[derive(uniffi::Object)]
pub struct Engine {
    data_dir: PathBuf,
    config: Config,
    mitm_active: bool,
    stats: Arc<Counters>,
    dns: Arc<DnsHandler>,
    proxy: Arc<ProxyContext>,
    running: Mutex<Option<Running>>,
}

#[uniffi::export]
impl Engine {
    /// Parses `config_json` and loads what `data_dir` holds: `engine.dat`, `domains.bin`,
    /// `ca.pem` with `ca.key`, and `learned-pins.json`. Each file is optional; a file that
    /// cannot be loaded is logged and skipped. HTTPS interception needs both the CA and
    /// `engine.dat`; without them every connection is passed through.
    #[uniffi::constructor]
    pub fn new(config_json: String, data_dir: String) -> Result<Arc<Engine>, TollgateError> {
        catch_panic(|| Engine::open(&config_json, Path::new(&data_dir)))
    }

    /// Starts the runtime thread with the proxy on `127.0.0.1` and returns the proxy's port
    /// once it is listening. Answers to forwarded DNS queries go to `sink`.
    pub fn start(&self, sink: Arc<dyn PacketSink>) -> Result<u16, TollgateError> {
        catch_panic(|| self.start_runtime(sink))
    }

    /// Stops the proxy and the forwarder, joins the runtime thread and saves the learned
    /// pins. Does nothing when not running. Queries still queued are dropped.
    pub fn stop(&self) {
        let _ = catch_panic(|| {
            self.stop_runtime();
            Ok(())
        });
    }

    /// Handles raw IP packets from the tunnel without waiting on the network. Returns the
    /// replies it can give at once (blocked names, HTTPS and SVCB queries, cache hits,
    /// errors, and SERVFAIL when stopped or when the queue is full); the answers to
    /// forwarded queries arrive later through the `PacketSink`.
    pub fn handle_packets(&self, packets: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, TollgateError> {
        catch_panic(|| Ok(self.answer(&packets)))
    }

    /// Loads `engine.dat` and `domains.bin` again and swaps both in. A missing file clears
    /// that list; a file that fails to load is an error and nothing is swapped.
    pub fn reload_lists(&self) -> Result<(), TollgateError> {
        catch_panic(|| {
            let filter = load_filter(&self.data_dir)?;
            let domains = load_domains(&self.data_dir)?;
            log::info!(
                "reloaded lists: engine {}, DNS blocklist {} hashes",
                if filter.is_some() {
                    "loaded"
                } else {
                    "missing"
                },
                domains.as_ref().map_or(0, |set| set.len())
            );
            self.proxy.filter.store(filter);
            self.dns.set_blocklist(domains);
            Ok(())
        })
    }

    pub fn stats(&self) -> Stats {
        catch_panic(|| Ok(self.stats.snapshot().into())).unwrap_or_default()
    }

    /// The learned pins as JSON, the format of `learned-pins.json`.
    pub fn learned_pins_json(&self) -> String {
        catch_panic(|| Ok(self.proxy.policy.learned_pins_json())).unwrap_or_default()
    }

    /// Whether HTTPS connections can be intercepted: `mitm_enabled` in the config, a CA and
    /// `engine.dat` were all present when the engine was created.
    pub fn mitm_active(&self) -> bool {
        self.mitm_active
    }

    /// The proxy port while running.
    pub fn port(&self) -> Option<u16> {
        catch_panic(|| Ok(self.running().as_ref().map(|r| r.port))).unwrap_or_default()
    }
}

impl Engine {
    fn open(config_json: &str, data_dir: &Path) -> Result<Arc<Engine>, TollgateError> {
        let config = Config::from_json(config_json).map_err(|e| TollgateError::Config {
            message: e.to_string(),
        })?;
        let filter = load_filter(data_dir).unwrap_or_else(|e| {
            log::warn!("running without the URL filter: {e}");
            None
        });
        let domains = load_domains(data_dir).unwrap_or_else(|e| {
            log::warn!("running without the DNS blocklist: {e}");
            None
        });
        let ca = load_ca(data_dir).unwrap_or_else(|e| {
            log::warn!("running without the CA: {e}");
            None
        });
        let mitm_active = config.mitm_enabled && ca.is_some() && filter.is_some();
        if config.mitm_enabled && !mitm_active {
            log::warn!(
                "HTTPS interception is off: {}",
                if ca.is_none() {
                    "no CA"
                } else {
                    "no engine.dat"
                }
            );
        }
        let policy_config = Config {
            mitm_enabled: mitm_active,
            ..config.clone()
        };
        let pins = read_pins(data_dir);
        let policy =
            Policy::new(&policy_config, pins.as_deref()).map_err(|e| TollgateError::Config {
                message: e.to_string(),
            })?;
        // The proxy needs a CA even when it only passes connections through; this one is
        // never used to issue a leaf because the policy intercepts nothing.
        let ca = match ca {
            Some(ca) => ca,
            None => CertAuthority::generate("Tollgate unused").map_err(|e| TollgateError::Ca {
                message: e.to_string(),
            })?,
        };
        let stats = Arc::new(Counters::default());
        let proxy = Arc::new(ProxyContext {
            policy: Arc::new(policy),
            filter: ArcSwapOption::new(filter),
            ca: Arc::new(ca),
            stats: stats.clone(),
            max_intercepted: config.max_intercepted_connections as usize,
            available_memory,
        });
        let dns = Arc::new(DnsHandler::new(domains, stats.clone()));
        Ok(Arc::new(Engine {
            data_dir: data_dir.to_path_buf(),
            config,
            mitm_active,
            stats,
            dns,
            proxy,
            running: Mutex::new(None),
        }))
    }

    fn running(&self) -> MutexGuard<'_, Option<Running>> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn answer(&self, packets: &[Vec<u8>]) -> Vec<Vec<u8>> {
        // Clone the sender and release the lock at once, so stop() never waits on us.
        let jobs = self.running().as_ref().map(|r| r.jobs.clone());
        let now = clock::now_secs();
        let mut replies = Vec::new();
        for packet in packets {
            match self.dns.handle_packet(packet, now) {
                Outcome::Reply(reply) => replies.push(reply),
                Outcome::Drop => {}
                Outcome::Forward(job) => {
                    let failed = match &jobs {
                        None => Some((job, DohError::Stopped)),
                        Some(jobs) => match jobs.try_send(job) {
                            Ok(()) => None,
                            Err(TrySendError::Full(job)) => Some((job, DohError::Busy)),
                            Err(TrySendError::Closed(job)) => Some((job, DohError::Stopped)),
                        },
                    };
                    if let Some((job, error)) = failed {
                        replies.push(self.dns.complete(job, Err(error), now));
                    }
                }
            }
        }
        replies
    }

    fn start_runtime(&self, sink: Arc<dyn PacketSink>) -> Result<u16, TollgateError> {
        let mut running = self.running();
        if running.is_some() {
            return Err(TollgateError::AlreadyRunning);
        }
        let (jobs, queue) = mpsc::channel(FORWARD_QUEUE);
        let work = Work {
            proxy: self.proxy.clone(),
            dns: self.dns.clone(),
            resolver: DohResolver::new(self.config.doh_upstreams.clone()),
            sink,
            queue,
            in_flight: tollgate_dns::MAX_IN_FLIGHT,
        };
        let (shutdown, stopped) = oneshot::channel();
        let (ready_tx, ready) = std::sync::mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name(RUNTIME_THREAD.to_string())
            .spawn(move || run(work, stopped, ready_tx))
            .map_err(TollgateError::io)?;
        match ready.recv() {
            Ok(Ok(port)) => {
                log::info!("proxy listening on 127.0.0.1:{port}");
                *running = Some(Running {
                    port,
                    jobs,
                    shutdown,
                    thread,
                });
                Ok(port)
            }
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(TollgateError::Internal {
                    message: "the runtime thread ended while starting".to_string(),
                })
            }
        }
    }

    fn stop_runtime(&self) {
        let Some(running) = self.running().take() else {
            return;
        };
        let Running {
            port,
            jobs,
            shutdown,
            thread,
        } = running;
        let _ = shutdown.send(());
        drop(jobs);
        if thread.thread().id() == thread::current().id() {
            // Called from a callback on the runtime thread (for example the last Engine
            // reference dropped inside PacketSink.write_packets). Joining would deadlock;
            // the thread ends by itself once the callback returns.
            log::warn!("stop() ran on the runtime thread; not joining it");
        } else if thread.join().is_err() {
            log::error!("the runtime thread panicked");
        }
        self.save_pins();
        log::info!("engine stopped, proxy port {port} closed");
    }

    fn save_pins(&self) {
        let path = self.data_dir.join(LEARNED_PINS_FILE);
        if let Err(e) = write_private(&path, &self.proxy.policy.learned_pins_json()) {
            log::warn!("could not save learned pins: {e}");
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop();
    }
}

fn load_filter(dir: &Path) -> Result<Option<Arc<FilterEngine>>, TollgateError> {
    match FilterEngine::load(&dir.join(ENGINE_FILE)) {
        Ok(engine) => Ok(Some(Arc::new(engine))),
        Err(FilterError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TollgateError::Lists {
            message: e.to_string(),
        }),
    }
}

fn load_domains(dir: &Path) -> Result<Option<Arc<DomainSet>>, TollgateError> {
    match DomainSet::load(&dir.join(DOMAINS_FILE)) {
        Ok(set) => Ok(Some(Arc::new(set))),
        Err(FilterError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TollgateError::Lists {
            message: e.to_string(),
        }),
    }
}

fn read_pins(dir: &Path) -> Option<String> {
    let path = dir.join(LEARNED_PINS_FILE);
    match std::fs::read_to_string(&path) {
        Ok(json) => Some(json),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => {
            log::warn!("ignoring {}: {e}", path.display());
            None
        }
    }
}

/// Bytes the extension may still allocate before jetsam ends it. `None` outside iOS, and
/// when iOS reports 0, which it does for processes without a limit.
#[cfg(target_os = "ios")]
fn available_memory() -> Option<u64> {
    unsafe extern "C" {
        fn os_proc_available_memory() -> usize;
    }
    // SAFETY: os_proc_available_memory takes no arguments and has no preconditions; it is
    // part of libSystem since iOS 13.
    let bytes = unsafe { os_proc_available_memory() };
    (bytes > 0).then_some(bytes as u64)
}

#[cfg(not(target_os = "ios"))]
fn available_memory() -> Option<u64> {
    None
}

/// Body of the runtime thread. Reports the port (or why there is none) through `ready`.
fn run(work: Work, stopped: oneshot::Receiver<()>, ready: SyncSender<Result<u16, TollgateError>>) {
    let outcome = catch_unwind(AssertUnwindSafe(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(MAX_BLOCKING_THREADS)
            .thread_name("tollgate-blocking")
            .build()
        {
            Ok(runtime) => runtime,
            Err(e) => {
                let _ = ready.send(Err(TollgateError::io(e)));
                return;
            }
        };
        runtime.block_on(serve(work, stopped, ready));
        runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
    }));
    if let Err(payload) = outcome {
        log::error!(
            "the runtime thread panicked: {}",
            panic_message(payload.as_ref())
        );
    }
}

async fn serve(
    work: Work,
    stopped: oneshot::Receiver<()>,
    ready: SyncSender<Result<u16, TollgateError>>,
) {
    // A SocketAddr, not a host name, so binding never resolves anything.
    let listener = match TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await {
        Ok(listener) => listener,
        Err(e) => {
            let _ = ready.send(Err(TollgateError::io(e)));
            return;
        }
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(e) => {
            let _ = ready.send(Err(TollgateError::io(e)));
            return;
        }
    };
    let _ = ready.send(Ok(port));
    let Work {
        proxy,
        dns,
        resolver,
        sink,
        queue,
        in_flight,
    } = work;
    let forwarding = tokio::spawn(forward(queue, resolver, dns, sink, in_flight));
    tollgate_mitm::serve(listener, proxy, async move {
        let _ = stopped.await;
    })
    .await;
    forwarding.abort();
}

/// Resolves queued queries, at most `in_flight` at once, one task each.
async fn forward(
    mut queue: mpsc::Receiver<ForwardJob>,
    resolver: DohResolver,
    dns: Arc<DnsHandler>,
    sink: Arc<dyn PacketSink>,
    in_flight: usize,
) {
    let permits = Arc::new(Semaphore::new(in_flight));
    loop {
        // Take the permit first, so a job waits in the queue, where it counts against the
        // queue's capacity, not in this loop.
        let Ok(permit) = permits.clone().acquire_owned().await else {
            return;
        };
        let Some(job) = queue.recv().await else {
            return;
        };
        let (resolver, dns, sink) = (resolver.clone(), dns.clone(), sink.clone());
        tokio::spawn(async move {
            let answer = resolver.resolve(job.query()).await;
            let packet = dns.complete(job, answer, clock::now_secs());
            drop(permit);
            deliver(sink.as_ref(), vec![packet]);
        });
    }
}

fn deliver(sink: &dyn PacketSink, packets: Vec<Vec<u8>>) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| sink.write_packets(packets))) {
        log::error!(
            "PacketSink.write_packets panicked: {}",
            panic_message(payload.as_ref())
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NullSink;

    impl PacketSink for NullSink {
        fn write_packets(&self, _packets: Vec<Vec<u8>>) {}
    }

    #[test]
    fn a_poisoned_running_lock_is_recovered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap().to_string();
        let engine = Engine::new("{}".to_string(), path).unwrap();
        let poisoner = engine.clone();
        let _ = thread::spawn(move || {
            let _guard = poisoner.running.lock().unwrap();
            panic!("poisoning the lock on purpose");
        })
        .join();
        assert!(engine.running.is_poisoned());

        assert_eq!(
            engine.handle_packets(Vec::new()).unwrap(),
            Vec::<Vec<u8>>::new()
        );
        let port = engine.start(Arc::new(NullSink)).unwrap();
        assert_eq!(engine.port(), Some(port));
        engine.stop();
        assert_eq!(engine.port(), None);
    }
}
```

`core/crates/tollgate-ffi/src/lib.rs`:

```rust
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
    ca_mobileconfig, generate_ca, load_ca,
};
pub use engine::{Engine, FORWARD_QUEUE, LEARNED_PINS_FILE, PacketSink, RUNTIME_THREAD, Stats};
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
```

- [ ] **Step 4: Run the tests, fmt and clippy**

Run: `cd core && cargo test -p tollgate-ffi && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS: unit 4 (with `a_poisoned_running_lock_is_recovered`), `panics` 6, `logging` 1, `ca` 5, `lists` 4, `engine_dns` 10 and `lifecycle` 1 passed; fmt and clippy print nothing

- [ ] **Step 5: Run the lifecycle test repeatedly**

The thread counts are polled, so they must not flake:

```bash
cd core && for i in $(seq 1 30); do cargo test -q -p tollgate-ffi --test lifecycle > /dev/null 2>&1 || echo "run $i failed"; done; echo done
```

Expected: only `done`.

- [ ] **Step 6: Commit**

```bash
git add core/crates/tollgate-ffi/Cargo.toml core/crates/tollgate-ffi/src/lib.rs core/crates/tollgate-ffi/src/engine.rs core/crates/tollgate-ffi/tests/support/mod.rs core/crates/tollgate-ffi/tests/lifecycle.rs core/Cargo.lock
git commit -m "ffi: runtime thread with the proxy and DNS forwarding through PacketSink"
```

---

### Task 7: EngineOptions and forwarded answers from a local DoH server

**Files:**
- Modify: `core/crates/tollgate-ffi/Cargo.toml`, `core/crates/tollgate-ffi/src/lib.rs`, `core/crates/tollgate-ffi/src/engine.rs`, `core/crates/tollgate-ffi/tests/support/mod.rs`
- Create: `core/crates/tollgate-ffi/tests/support/doh.rs`
- Test: `core/crates/tollgate-ffi/tests/forward.rs`

**Interfaces:**
- Consumes: `tollgate_dns::DohResolver::with_extra_roots(upstreams, roots) -> Result<DohResolver, DohError>` (M1b).
- Produces:

```rust
#[derive(Clone, Debug)]
pub struct EngineOptions { pub doh_roots: Vec<Vec<u8>>, pub forward_queue: usize, pub forward_in_flight: usize }
impl Default for EngineOptions; // no extra roots, FORWARD_QUEUE, tollgate_dns::MAX_IN_FLIGHT
impl Engine {
    pub fn with_options(config_json: &str, data_dir: &std::path::Path, options: EngineOptions)
        -> Result<Arc<Engine>, TollgateError>;
}
```

- [ ] **Step 1: Write the failing test**

`core/crates/tollgate-ffi/Cargo.toml`:

```toml
[package]
name = "tollgate-ffi"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
publish.workspace = true

[lib]
name = "tollgate_ffi"
crate-type = ["lib", "staticlib"]

[dependencies]
arc-swap = { workspace = true }
log = { workspace = true }
ring = { workspace = true }
rustls = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true }
tollgate-common = { workspace = true }
tollgate-dns = { workspace = true }
tollgate-filter = { workspace = true }
tollgate-mitm = { workspace = true }
tollgate-policy = { workspace = true }
uniffi = { workspace = true }

[dev-dependencies]
bytes = { workspace = true }
hickory-proto = { workspace = true }
http-body-util = { workspace = true }
hyper = { workspace = true }
hyper-util = { workspace = true }
rcgen = { workspace = true }
tempfile = { workspace = true }
tokio-rustls = { workspace = true }
```

`core/crates/tollgate-ffi/tests/support/mod.rs`:

```rust
//! Helpers shared by the integration tests; each test binary uses a different part.
#![allow(dead_code)]

pub mod doh;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use tempfile::TempDir;
use tollgate_dns::packet::{build_udp, parse_udp};
use tollgate_ffi::{ListFormat, ListInput, ListTarget, PacketSink, compile_lists};

/// The address the phone's DNS queries come from.
pub fn client() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)), 53001)
}

/// The tunnel's DNS server.
pub fn dns_server() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), 53)
}

/// A recursion-desired query for `name` wrapped in an IPv4 packet from the client to the
/// tunnel's DNS address.
pub fn query(id: u16, name: &str, rtype: RecordType) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    build_udp(client(), dns_server(), &message.to_vec().unwrap()).unwrap()
}

/// Decodes a reply packet after checking it goes from the DNS address to the client.
pub fn reply(packet: &[u8]) -> Message {
    let datagram = parse_udp(packet).expect("a UDP packet");
    assert_eq!(datagram.source, dns_server());
    assert_eq!(datagram.destination, client());
    Message::from_vec(datagram.payload).expect("a DNS message")
}

/// A temporary data directory with `url_rules` compiled into `engine.dat` and
/// `dns_rules` into `domains.bin`.
pub fn data_dir(url_rules: &str, dns_rules: &str) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    compile_into(&dir, url_rules, dns_rules);
    dir
}

pub fn compile_into(dir: &TempDir, url_rules: &str, dns_rules: &str) {
    let lists = vec![
        ListInput {
            name: "url".to_string(),
            text: url_rules.to_string(),
            format: ListFormat::Adblock,
            target: ListTarget::Url,
        },
        ListInput {
            name: "dns".to_string(),
            text: dns_rules.to_string(),
            format: ListFormat::Adblock,
            target: ListTarget::Dns,
        },
    ];
    compile_lists(lists, path(dir)).unwrap();
}

pub fn path(dir: &TempDir) -> String {
    dir.path().to_str().unwrap().to_string()
}

/// A config whose only DoH upstream is a local port where nothing listens, so forwarded
/// queries fail at once.
pub fn closed_upstream_config() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!(r#"{{"doh_upstreams":[{{"ip":"127.0.0.1","port":{port},"tls_name":"doh.test"}}]}}"#)
}

/// A PacketSink that sends every packet into a channel.
pub struct ChannelSink(Mutex<Sender<Vec<u8>>>);

impl PacketSink for ChannelSink {
    fn write_packets(&self, packets: Vec<Vec<u8>>) {
        let sender = self.0.lock().unwrap();
        for packet in packets {
            let _ = sender.send(packet);
        }
    }
}

pub fn sink() -> (Arc<ChannelSink>, Receiver<Vec<u8>>) {
    let (tx, rx) = channel();
    (Arc::new(ChannelSink(Mutex::new(tx))), rx)
}

/// Polls `condition` every millisecond for up to five seconds.
pub fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}
```

`core/crates/tollgate-ffi/tests/support/doh.rs`:

```rust
//! A local DNS-over-HTTPS server on its own thread: HTTP/2 over rustls with a leaf for
//! `doh.test` from a certificate authority rcgen makes for each server. Every answer is
//! `192.0.2.1` with a TTL of 300.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

pub const TLS_NAME: &str = "doh.test";

pub struct DohServer {
    pub addr: SocketAddr,
    /// The test CA, to pass in `EngineOptions::doh_roots`.
    pub ca_der: Vec<u8>,
    requests: Arc<AtomicUsize>,
    gate: Option<Arc<Semaphore>>,
}

impl DohServer {
    /// A server that answers at once.
    pub fn start() -> DohServer {
        DohServer::launch(None)
    }

    /// A server that holds every request until `open_gate`.
    pub fn gated() -> DohServer {
        DohServer::launch(Some(Arc::new(Semaphore::new(0))))
    }

    fn launch(gate: Option<Arc<Semaphore>>) -> DohServer {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Tollgate ffi test CA");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec![TLS_NAME.to_string()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], key)
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let (counter, held) = (requests.clone(), gate.clone());
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = TcpListener::from_std(listener).unwrap();
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        continue;
                    };
                    let (acceptor, counter, held) =
                        (acceptor.clone(), counter.clone(), held.clone());
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let service = service_fn(move |request| {
                            answer(request, counter.clone(), held.clone())
                        });
                        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(tls), service)
                            .await;
                    });
                }
            });
        });
        DohServer {
            addr,
            ca_der: ca_cert.der().to_vec(),
            requests,
            gate,
        }
    }

    /// Engine configuration JSON with this server as the only upstream.
    pub fn config_json(&self) -> String {
        format!(
            r#"{{"doh_upstreams":[{{"ip":"{}","port":{},"tls_name":"{TLS_NAME}"}}]}}"#,
            self.addr.ip(),
            self.addr.port()
        )
    }

    /// Requests received so far.
    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    /// Lets every held and future request answer.
    pub fn open_gate(&self) {
        if let Some(gate) = &self.gate {
            gate.add_permits(10_000);
        }
    }
}

async fn answer(
    request: Request<Incoming>,
    requests: Arc<AtomicUsize>,
    gate: Option<Arc<Semaphore>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let query = request.into_body().collect().await?.to_bytes();
    requests.fetch_add(1, Ordering::SeqCst);
    if let Some(gate) = gate {
        gate.acquire().await.unwrap().forget();
    }
    Ok(Response::builder()
        .header("content-type", "application/dns-message")
        .body(Full::new(Bytes::from(answer_for(&query))))
        .unwrap())
}

/// The query's header and question with QR and RA set, and one A record `192.0.2.1` with a
/// TTL of 300 whose owner name points at the question.
fn answer_for(query: &[u8]) -> Vec<u8> {
    let mut end = 12;
    while query[end] != 0 {
        end += 1 + usize::from(query[end]);
    }
    end += 1 + 4;
    let mut answer = query[..end].to_vec();
    answer[2] |= 0x80;
    answer[3] = 0x80;
    answer[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 1]);
    answer
}
```

`core/crates/tollgate-ffi/tests/forward.rs`:

```rust
//! Forwarded queries through the runtime, a local DoH server and a PacketSink.

mod support;

use std::net::Ipv4Addr;
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, RecordType};
use support::doh::DohServer;
use support::{query, reply, sink};
use tollgate_ffi::{Engine, EngineOptions, PacketSink, Stats};

const WAIT: Duration = Duration::from_secs(5);

fn engine_for(server: &DohServer, options: EngineOptions) -> (tempfile::TempDir, Arc<Engine>) {
    let dir = tempfile::tempdir().unwrap();
    let options = EngineOptions {
        doh_roots: vec![server.ca_der.clone()],
        ..options
    };
    let engine = Engine::with_options(&server.config_json(), dir.path(), options).unwrap();
    (dir, engine)
}

#[test]
fn answers_arrive_through_the_sink_and_are_cached() {
    let server = DohServer::start();
    let (_dir, engine) = engine_for(&server, EngineOptions::default());
    let (sink, answers) = sink();
    engine.start(sink).unwrap();

    let immediate = engine
        .handle_packets(vec![query(0x1234, "Example.com.", RecordType::A)])
        .unwrap();
    assert!(immediate.is_empty());
    let message = reply(&answers.recv_timeout(WAIT).unwrap());
    assert_eq!(message.metadata.id, 0x1234);
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.queries[0].name().to_ascii(), "Example.com.");
    assert_eq!(
        message.answers[0].data,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))
    );

    // The same question again is answered from the cache, at once.
    let cached = engine
        .handle_packets(vec![query(0x4321, "example.com.", RecordType::A)])
        .unwrap();
    assert_eq!(cached.len(), 1);
    let message = reply(&cached[0]);
    assert_eq!(message.metadata.id, 0x4321);
    assert!((299..=300).contains(&message.answers[0].ttl));
    assert_eq!(server.requests(), 1);
    assert_eq!(
        engine.stats(),
        Stats {
            dns_queries: 2,
            dns_forwarded: 1,
            dns_cache_hits: 1,
            ..Stats::default()
        }
    );
    engine.stop();
}

#[test]
fn a_full_queue_answers_servfail_at_once() {
    let server = DohServer::gated();
    let options = EngineOptions {
        forward_queue: 2,
        forward_in_flight: 1,
        ..EngineOptions::default()
    };
    let (_dir, engine) = engine_for(&server, options);
    let (sink, answers) = sink();
    engine.start(sink).unwrap();

    let queries = (0..6)
        .map(|i| query(100 + i, &format!("host{i}.example."), RecordType::A))
        .collect();
    let immediate = engine.handle_packets(queries).unwrap();
    // Two wait in the queue and at most one has been taken by the runtime already.
    assert!(
        (3..=4).contains(&immediate.len()),
        "{} immediate replies",
        immediate.len()
    );
    for packet in &immediate {
        assert_eq!(reply(packet).metadata.response_code, ResponseCode::ServFail);
    }
    server.open_gate();
    for _ in 0..6 - immediate.len() {
        let message = reply(&answers.recv_timeout(WAIT).unwrap());
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    }
    let stats = engine.stats();
    assert_eq!(stats.dns_forwarded, 6);
    assert_eq!(stats.dns_failed, immediate.len() as u64);
    engine.stop();
}

/// Panics on its first call, then forwards packets.
struct FlakySink {
    calls: Mutex<u32>,
    out: Mutex<Sender<Vec<u8>>>,
}

impl PacketSink for FlakySink {
    fn write_packets(&self, packets: Vec<Vec<u8>>) {
        let first = {
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            *calls == 1
        };
        if first {
            panic!("the Swift side failed");
        }
        for packet in packets {
            self.out.lock().unwrap().send(packet).unwrap();
        }
    }
}

#[test]
fn a_panicking_sink_loses_one_answer_not_the_engine() {
    let server = DohServer::start();
    let (_dir, engine) = engine_for(&server, EngineOptions::default());
    let (tx, answers) = channel();
    let sink = Arc::new(FlakySink {
        calls: Mutex::new(0),
        out: Mutex::new(tx),
    });
    engine.start(sink.clone()).unwrap();

    engine
        .handle_packets(vec![query(1, "first.example.", RecordType::A)])
        .unwrap();
    support::wait_until("the first answer", || *sink.calls.lock().unwrap() == 1);
    engine
        .handle_packets(vec![query(2, "second.example.", RecordType::A)])
        .unwrap();
    let message = reply(&answers.recv_timeout(WAIT).unwrap());
    assert_eq!(message.metadata.id, 2);
    engine.stop();
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd core && cargo test -p tollgate-ffi --test forward`
Expected: FAIL to compile: `` error[E0432]: unresolved import `tollgate_ffi::EngineOptions` `` and `` error[E0599]: no associated function or constant named `with_options` found for struct `Engine` ``

- [ ] **Step 3: Implement**

`core/crates/tollgate-ffi/src/engine.rs`:

```rust
//! The engine the tunnel runs: DNS answers on the packet path, and the proxy plus the DNS
//! forwarder on one runtime thread.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tollgate_common::clock;
use tollgate_common::stats::{Stats as Counters, StatsSnapshot};
use tollgate_dns::{DnsHandler, DohError, DohResolver, ForwardJob, Outcome};
use tollgate_filter::{DOMAINS_FILE, DomainSet, ENGINE_FILE, FilterEngine, FilterError};
use tollgate_mitm::{CertAuthority, ProxyContext};
use tollgate_policy::{Config, Policy};

use crate::ca::{load_ca, write_private};
use crate::error::{TollgateError, catch_panic, panic_message};

/// Name of the thread that runs the proxy and the DNS forwarder.
pub const RUNTIME_THREAD: &str = "tollgate-core";
/// Learned certificate pins, read by `Engine::new` and written by `Engine::stop`.
pub const LEARNED_PINS_FILE: &str = "learned-pins.json";
/// Forwarded queries waiting for the runtime; when full, new ones get SERVFAIL at once.
pub const FORWARD_QUEUE: usize = 256;
/// Threads tokio may start for blocking work (the proxy's `getaddrinfo` calls).
const MAX_BLOCKING_THREADS: usize = 4;
/// How long `stop` waits for blocking work such as a hung `getaddrinfo`.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// Implemented in Swift over `NEPacketTunnelFlow.writePackets`. Called on the runtime
/// thread with the answers to forwarded DNS queries, so it must only hand the packets off.
#[uniffi::export(foreign)]
pub trait PacketSink: Send + Sync {
    fn write_packets(&self, packets: Vec<Vec<u8>>);
}

/// Counters since the engine was created. Mirrors `tollgate_common::stats::StatsSnapshot`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct Stats {
    pub dns_queries: u64,
    pub dns_blocked: u64,
    pub dns_cache_hits: u64,
    pub dns_forwarded: u64,
    pub dns_failed: u64,
    pub packets_dropped: u64,
    pub http_requests: u64,
    pub http_blocked: u64,
    pub connections_intercepted: u64,
    pub connections_passthrough: u64,
    pub tls_client_rejections: u64,
    pub tls_abandoned_after_handshake: u64,
}

impl From<StatsSnapshot> for Stats {
    fn from(s: StatsSnapshot) -> Stats {
        Stats {
            dns_queries: s.dns_queries,
            dns_blocked: s.dns_blocked,
            dns_cache_hits: s.dns_cache_hits,
            dns_forwarded: s.dns_forwarded,
            dns_failed: s.dns_failed,
            packets_dropped: s.packets_dropped,
            http_requests: s.http_requests,
            http_blocked: s.http_blocked,
            connections_intercepted: s.connections_intercepted,
            connections_passthrough: s.connections_passthrough,
            tls_client_rejections: s.tls_client_rejections,
            tls_abandoned_after_handshake: s.tls_abandoned_after_handshake,
        }
    }
}

/// Settings Swift never changes; tests use them to reach a local DoH server and to make
/// the forward queue small.
#[derive(Clone, Debug)]
pub struct EngineOptions {
    /// DER certificates trusted for DoH upstreams in addition to the webpki roots.
    pub doh_roots: Vec<Vec<u8>>,
    /// Capacity of the queue between `handle_packets` and the runtime.
    pub forward_queue: usize,
    /// DoH queries resolving at once; further jobs wait in the queue.
    pub forward_in_flight: usize,
}

impl Default for EngineOptions {
    fn default() -> EngineOptions {
        EngineOptions {
            doh_roots: Vec::new(),
            forward_queue: FORWARD_QUEUE,
            forward_in_flight: tollgate_dns::MAX_IN_FLIGHT,
        }
    }
}

struct Running {
    port: u16,
    jobs: mpsc::Sender<ForwardJob>,
    shutdown: oneshot::Sender<()>,
    thread: JoinHandle<()>,
}

/// What the runtime thread needs.
struct Work {
    proxy: Arc<ProxyContext>,
    dns: Arc<DnsHandler>,
    resolver: DohResolver,
    sink: Arc<dyn PacketSink>,
    queue: mpsc::Receiver<ForwardJob>,
    in_flight: usize,
}

/// The tunnel's Rust side: DNS answers, the DNS forwarder and the HTTPS proxy.
#[derive(uniffi::Object)]
pub struct Engine {
    data_dir: PathBuf,
    config: Config,
    options: EngineOptions,
    mitm_active: bool,
    stats: Arc<Counters>,
    dns: Arc<DnsHandler>,
    proxy: Arc<ProxyContext>,
    running: Mutex<Option<Running>>,
}

#[uniffi::export]
impl Engine {
    /// Parses `config_json` and loads what `data_dir` holds: `engine.dat`, `domains.bin`,
    /// `ca.pem` with `ca.key`, and `learned-pins.json`. Each file is optional; a file that
    /// cannot be loaded is logged and skipped. HTTPS interception needs both the CA and
    /// `engine.dat`; without them every connection is passed through.
    #[uniffi::constructor]
    pub fn new(config_json: String, data_dir: String) -> Result<Arc<Engine>, TollgateError> {
        catch_panic(|| {
            Engine::with_options(&config_json, Path::new(&data_dir), EngineOptions::default())
        })
    }

    /// Starts the runtime thread with the proxy on `127.0.0.1` and returns the proxy's port
    /// once it is listening. Answers to forwarded DNS queries go to `sink`.
    pub fn start(&self, sink: Arc<dyn PacketSink>) -> Result<u16, TollgateError> {
        catch_panic(|| self.start_runtime(sink))
    }

    /// Stops the proxy and the forwarder, joins the runtime thread and saves the learned
    /// pins. Does nothing when not running. Queries still queued are dropped.
    pub fn stop(&self) {
        let _ = catch_panic(|| {
            self.stop_runtime();
            Ok(())
        });
    }

    /// Handles raw IP packets from the tunnel without waiting on the network. Returns the
    /// replies it can give at once (blocked names, HTTPS and SVCB queries, cache hits,
    /// errors, and SERVFAIL when stopped or when the queue is full); the answers to
    /// forwarded queries arrive later through the `PacketSink`.
    pub fn handle_packets(&self, packets: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, TollgateError> {
        catch_panic(|| Ok(self.answer(&packets)))
    }

    /// Loads `engine.dat` and `domains.bin` again and swaps both in. A missing file clears
    /// that list; a file that fails to load is an error and nothing is swapped.
    pub fn reload_lists(&self) -> Result<(), TollgateError> {
        catch_panic(|| {
            let filter = load_filter(&self.data_dir)?;
            let domains = load_domains(&self.data_dir)?;
            log::info!(
                "reloaded lists: engine {}, DNS blocklist {} hashes",
                if filter.is_some() {
                    "loaded"
                } else {
                    "missing"
                },
                domains.as_ref().map_or(0, |set| set.len())
            );
            self.proxy.filter.store(filter);
            self.dns.set_blocklist(domains);
            Ok(())
        })
    }

    pub fn stats(&self) -> Stats {
        catch_panic(|| Ok(self.stats.snapshot().into())).unwrap_or_default()
    }

    /// The learned pins as JSON, the format of `learned-pins.json`.
    pub fn learned_pins_json(&self) -> String {
        catch_panic(|| Ok(self.proxy.policy.learned_pins_json())).unwrap_or_default()
    }

    /// Whether HTTPS connections can be intercepted: `mitm_enabled` in the config, a CA and
    /// `engine.dat` were all present when the engine was created.
    pub fn mitm_active(&self) -> bool {
        self.mitm_active
    }

    /// The proxy port while running.
    pub fn port(&self) -> Option<u16> {
        catch_panic(|| Ok(self.running().as_ref().map(|r| r.port))).unwrap_or_default()
    }
}

impl Engine {
    /// [`Engine::new`] with explicit options, for tests and tools.
    pub fn with_options(
        config_json: &str,
        data_dir: &Path,
        options: EngineOptions,
    ) -> Result<Arc<Engine>, TollgateError> {
        let config = Config::from_json(config_json).map_err(|e| TollgateError::Config {
            message: e.to_string(),
        })?;
        let filter = load_filter(data_dir).unwrap_or_else(|e| {
            log::warn!("running without the URL filter: {e}");
            None
        });
        let domains = load_domains(data_dir).unwrap_or_else(|e| {
            log::warn!("running without the DNS blocklist: {e}");
            None
        });
        let ca = load_ca(data_dir).unwrap_or_else(|e| {
            log::warn!("running without the CA: {e}");
            None
        });
        let mitm_active = config.mitm_enabled && ca.is_some() && filter.is_some();
        if config.mitm_enabled && !mitm_active {
            log::warn!(
                "HTTPS interception is off: {}",
                if ca.is_none() {
                    "no CA"
                } else {
                    "no engine.dat"
                }
            );
        }
        let policy_config = Config {
            mitm_enabled: mitm_active,
            ..config.clone()
        };
        let pins = read_pins(data_dir);
        let policy =
            Policy::new(&policy_config, pins.as_deref()).map_err(|e| TollgateError::Config {
                message: e.to_string(),
            })?;
        // The proxy needs a CA even when it only passes connections through; this one is
        // never used to issue a leaf because the policy intercepts nothing.
        let ca = match ca {
            Some(ca) => ca,
            None => CertAuthority::generate("Tollgate unused").map_err(|e| TollgateError::Ca {
                message: e.to_string(),
            })?,
        };
        let stats = Arc::new(Counters::default());
        let proxy = Arc::new(ProxyContext {
            policy: Arc::new(policy),
            filter: ArcSwapOption::new(filter),
            ca: Arc::new(ca),
            stats: stats.clone(),
            max_intercepted: config.max_intercepted_connections as usize,
            available_memory,
        });
        let dns = Arc::new(DnsHandler::new(domains, stats.clone()));
        Ok(Arc::new(Engine {
            data_dir: data_dir.to_path_buf(),
            config,
            options,
            mitm_active,
            stats,
            dns,
            proxy,
            running: Mutex::new(None),
        }))
    }

    fn running(&self) -> MutexGuard<'_, Option<Running>> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn answer(&self, packets: &[Vec<u8>]) -> Vec<Vec<u8>> {
        // Clone the sender and release the lock at once, so stop() never waits on us.
        let jobs = self.running().as_ref().map(|r| r.jobs.clone());
        let now = clock::now_secs();
        let mut replies = Vec::new();
        for packet in packets {
            match self.dns.handle_packet(packet, now) {
                Outcome::Reply(reply) => replies.push(reply),
                Outcome::Drop => {}
                Outcome::Forward(job) => {
                    let failed = match &jobs {
                        None => Some((job, DohError::Stopped)),
                        Some(jobs) => match jobs.try_send(job) {
                            Ok(()) => None,
                            Err(TrySendError::Full(job)) => Some((job, DohError::Busy)),
                            Err(TrySendError::Closed(job)) => Some((job, DohError::Stopped)),
                        },
                    };
                    if let Some((job, error)) = failed {
                        replies.push(self.dns.complete(job, Err(error), now));
                    }
                }
            }
        }
        replies
    }

    fn resolver(&self) -> Result<DohResolver, TollgateError> {
        let upstreams = self.config.doh_upstreams.clone();
        if self.options.doh_roots.is_empty() {
            return Ok(DohResolver::new(upstreams));
        }
        let roots: Vec<CertificateDer<'static>> = self
            .options
            .doh_roots
            .iter()
            .map(|der| CertificateDer::from(der.clone()))
            .collect();
        DohResolver::with_extra_roots(upstreams, &roots).map_err(|e| TollgateError::Config {
            message: e.to_string(),
        })
    }

    fn start_runtime(&self, sink: Arc<dyn PacketSink>) -> Result<u16, TollgateError> {
        let mut running = self.running();
        if running.is_some() {
            return Err(TollgateError::AlreadyRunning);
        }
        let (jobs, queue) = mpsc::channel(self.options.forward_queue.max(1));
        let work = Work {
            proxy: self.proxy.clone(),
            dns: self.dns.clone(),
            resolver: self.resolver()?,
            sink,
            queue,
            in_flight: self.options.forward_in_flight.max(1),
        };
        let (shutdown, stopped) = oneshot::channel();
        let (ready_tx, ready) = std::sync::mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name(RUNTIME_THREAD.to_string())
            .spawn(move || run(work, stopped, ready_tx))
            .map_err(TollgateError::io)?;
        match ready.recv() {
            Ok(Ok(port)) => {
                log::info!("proxy listening on 127.0.0.1:{port}");
                *running = Some(Running {
                    port,
                    jobs,
                    shutdown,
                    thread,
                });
                Ok(port)
            }
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(TollgateError::Internal {
                    message: "the runtime thread ended while starting".to_string(),
                })
            }
        }
    }

    fn stop_runtime(&self) {
        let Some(running) = self.running().take() else {
            return;
        };
        let Running {
            port,
            jobs,
            shutdown,
            thread,
        } = running;
        let _ = shutdown.send(());
        drop(jobs);
        if thread.thread().id() == thread::current().id() {
            // Called from a callback on the runtime thread (for example the last Engine
            // reference dropped inside PacketSink.write_packets). Joining would deadlock;
            // the thread ends by itself once the callback returns.
            log::warn!("stop() ran on the runtime thread; not joining it");
        } else if thread.join().is_err() {
            log::error!("the runtime thread panicked");
        }
        self.save_pins();
        log::info!("engine stopped, proxy port {port} closed");
    }

    fn save_pins(&self) {
        let path = self.data_dir.join(LEARNED_PINS_FILE);
        if let Err(e) = write_private(&path, &self.proxy.policy.learned_pins_json()) {
            log::warn!("could not save learned pins: {e}");
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop();
    }
}

fn load_filter(dir: &Path) -> Result<Option<Arc<FilterEngine>>, TollgateError> {
    match FilterEngine::load(&dir.join(ENGINE_FILE)) {
        Ok(engine) => Ok(Some(Arc::new(engine))),
        Err(FilterError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TollgateError::Lists {
            message: e.to_string(),
        }),
    }
}

fn load_domains(dir: &Path) -> Result<Option<Arc<DomainSet>>, TollgateError> {
    match DomainSet::load(&dir.join(DOMAINS_FILE)) {
        Ok(set) => Ok(Some(Arc::new(set))),
        Err(FilterError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TollgateError::Lists {
            message: e.to_string(),
        }),
    }
}

fn read_pins(dir: &Path) -> Option<String> {
    let path = dir.join(LEARNED_PINS_FILE);
    match std::fs::read_to_string(&path) {
        Ok(json) => Some(json),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => {
            log::warn!("ignoring {}: {e}", path.display());
            None
        }
    }
}

/// Bytes the extension may still allocate before jetsam ends it. `None` outside iOS, and
/// when iOS reports 0, which it does for processes without a limit.
#[cfg(target_os = "ios")]
fn available_memory() -> Option<u64> {
    unsafe extern "C" {
        fn os_proc_available_memory() -> usize;
    }
    // SAFETY: os_proc_available_memory takes no arguments and has no preconditions; it is
    // part of libSystem since iOS 13.
    let bytes = unsafe { os_proc_available_memory() };
    (bytes > 0).then_some(bytes as u64)
}

#[cfg(not(target_os = "ios"))]
fn available_memory() -> Option<u64> {
    None
}

/// Body of the runtime thread. Reports the port (or why there is none) through `ready`.
fn run(work: Work, stopped: oneshot::Receiver<()>, ready: SyncSender<Result<u16, TollgateError>>) {
    let outcome = catch_unwind(AssertUnwindSafe(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(MAX_BLOCKING_THREADS)
            .thread_name("tollgate-blocking")
            .build()
        {
            Ok(runtime) => runtime,
            Err(e) => {
                let _ = ready.send(Err(TollgateError::io(e)));
                return;
            }
        };
        runtime.block_on(serve(work, stopped, ready));
        runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
    }));
    if let Err(payload) = outcome {
        log::error!(
            "the runtime thread panicked: {}",
            panic_message(payload.as_ref())
        );
    }
}

async fn serve(
    work: Work,
    stopped: oneshot::Receiver<()>,
    ready: SyncSender<Result<u16, TollgateError>>,
) {
    // A SocketAddr, not a host name, so binding never resolves anything.
    let listener = match TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await {
        Ok(listener) => listener,
        Err(e) => {
            let _ = ready.send(Err(TollgateError::io(e)));
            return;
        }
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(e) => {
            let _ = ready.send(Err(TollgateError::io(e)));
            return;
        }
    };
    let _ = ready.send(Ok(port));
    let Work {
        proxy,
        dns,
        resolver,
        sink,
        queue,
        in_flight,
    } = work;
    let forwarding = tokio::spawn(forward(queue, resolver, dns, sink, in_flight));
    tollgate_mitm::serve(listener, proxy, async move {
        let _ = stopped.await;
    })
    .await;
    forwarding.abort();
}

/// Resolves queued queries, at most `in_flight` at once, one task each.
async fn forward(
    mut queue: mpsc::Receiver<ForwardJob>,
    resolver: DohResolver,
    dns: Arc<DnsHandler>,
    sink: Arc<dyn PacketSink>,
    in_flight: usize,
) {
    let permits = Arc::new(Semaphore::new(in_flight));
    loop {
        // Take the permit first, so a job waits in the queue, where it counts against the
        // queue's capacity, not in this loop.
        let Ok(permit) = permits.clone().acquire_owned().await else {
            return;
        };
        let Some(job) = queue.recv().await else {
            return;
        };
        let (resolver, dns, sink) = (resolver.clone(), dns.clone(), sink.clone());
        tokio::spawn(async move {
            let answer = resolver.resolve(job.query()).await;
            let packet = dns.complete(job, answer, clock::now_secs());
            drop(permit);
            deliver(sink.as_ref(), vec![packet]);
        });
    }
}

fn deliver(sink: &dyn PacketSink, packets: Vec<Vec<u8>>) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| sink.write_packets(packets))) {
        log::error!(
            "PacketSink.write_packets panicked: {}",
            panic_message(payload.as_ref())
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NullSink;

    impl PacketSink for NullSink {
        fn write_packets(&self, _packets: Vec<Vec<u8>>) {}
    }

    #[test]
    fn a_poisoned_running_lock_is_recovered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap().to_string();
        let engine = Engine::new("{}".to_string(), path).unwrap();
        let poisoner = engine.clone();
        let _ = thread::spawn(move || {
            let _guard = poisoner.running.lock().unwrap();
            panic!("poisoning the lock on purpose");
        })
        .join();
        assert!(engine.running.is_poisoned());

        assert_eq!(
            engine.handle_packets(Vec::new()).unwrap(),
            Vec::<Vec<u8>>::new()
        );
        let port = engine.start(Arc::new(NullSink)).unwrap();
        assert_eq!(engine.port(), Some(port));
        engine.stop();
        assert_eq!(engine.port(), None);
    }
}
```

`core/crates/tollgate-ffi/src/lib.rs`:

```rust
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
    ca_mobileconfig, generate_ca, load_ca,
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
```

- [ ] **Step 4: Run the tests, fmt and clippy**

Run: `cd core && cargo test -p tollgate-ffi && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS: unit 4, `panics` 6, `logging` 1, `ca` 5, `lists` 4, `engine_dns` 10, `lifecycle` 1 and `forward` 3 passed (34 in total); fmt and clippy print nothing

- [ ] **Step 5: Commit**

```bash
git add core/crates/tollgate-ffi/Cargo.toml core/crates/tollgate-ffi/src/lib.rs core/crates/tollgate-ffi/src/engine.rs core/crates/tollgate-ffi/tests/support/mod.rs core/crates/tollgate-ffi/tests/support/doh.rs core/crates/tollgate-ffi/tests/forward.rs core/Cargo.lock
git commit -m "ffi: EngineOptions; forwarded answers, the cache and a full queue against a local DoH server"
```

---

### Task 8: Swift bindings check and the Rust 1.94 CI job

**Files:**
- Modify: `.github/workflows/core.yml`

**Interfaces:**
- Consumes: `tooling/scripts/build-core-ios.sh --host` (unchanged) and the generated `build/bindings-host/Swift/tollgate_ffi.swift`.
- Produces: CI steps that fail when the bindings lose an M0 function or a foreign-trait protocol, and the `msrv` job.

- [ ] **Step 1: Generate the host bindings and check them by hand**

```bash
tooling/scripts/build-core-ios.sh --host > /dev/null
swift=build/bindings-host/Swift/tollgate_ffi.swift
grep -n -e '^public func coreVersion() -> String' -e '^public func ping(message: String) -> String' -e '^public func sha256Hex(data: Data) -> String' -e '^public protocol CoreLogger: AnyObject, Sendable {' -e '^public protocol PacketSink: AnyObject, Sendable {' -e 'func start(sink: PacketSink) throws  -> UInt16' -e 'func handlePackets(packets: \[Data\]) throws  -> \[Data\]' "$swift" | sed 's/^[0-9]*://'
```

Expected (line numbers stripped; the double spaces are uniffi's):

```
public protocol CoreLogger: AnyObject, Sendable {
    func handlePackets(packets: [Data]) throws  -> [Data]
    func start(sink: PacketSink) throws  -> UInt16
public protocol PacketSink: AnyObject, Sendable {
public func coreVersion() -> String  {
public func ping(message: String) -> String  {
public func sha256Hex(data: Data) -> String  {
```

- [ ] **Step 2: No dependency needs a Rust newer than 1.94**

The MSRV job cannot run locally without installing 1.94; this checks the declared `rust-version` of every package in the lock file instead (clippy's `incompatible_msrv` lint already covers our own use of std):

```bash
cd core && cargo metadata --format-version 1 | python3 -c 'import json,sys; v=lambda s: tuple(int(x) for x in s.split(".")); bad=[(p["name"],p["rust_version"]) for p in json.load(sys.stdin)["packages"] if p.get("rust_version") and v(p["rust_version"]) > (1,94)]; print(bad or "all packages build with 1.94")'
```

Expected: `all packages build with 1.94`

- [ ] **Step 3: Update the workflow**

`.github/workflows/core.yml`:

```yaml
name: core

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

concurrency:
  group: core-${{ github.ref }}
  cancel-in-progress: true

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
        with:
          workspaces: core
      - name: fmt
        working-directory: core
        run: cargo fmt --all --check
      - name: clippy
        working-directory: core
        run: cargo clippy --workspace --all-targets -- -D warnings
      - name: test
        working-directory: core
        run: cargo test --workspace
      - name: Swift bindings generate
        run: tooling/scripts/build-core-ios.sh --host
      - name: Swift bindings keep the M0 calls and declare the foreign traits
        run: |
          swift=build/bindings-host/Swift/tollgate_ffi.swift
          grep -q '^public func coreVersion() -> String' "$swift"
          grep -q '^public func ping(message: String) -> String' "$swift"
          grep -q '^public func sha256Hex(data: Data) -> String' "$swift"
          grep -q '^public protocol CoreLogger: AnyObject, Sendable {' "$swift"
          grep -q '^public protocol PacketSink: AnyObject, Sendable {' "$swift"

  msrv:
    name: check with Rust 1.94
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@1.94
      - uses: Swatinem/rust-cache@v2
        with:
          workspaces: core
          key: msrv
      - name: check
        working-directory: core
        run: cargo check --workspace --locked
```

- [ ] **Step 4: Run the new CI step locally**

```bash
swift=build/bindings-host/Swift/tollgate_ffi.swift
grep -q '^public func coreVersion() -> String' "$swift" && grep -q '^public func ping(message: String) -> String' "$swift" && grep -q '^public func sha256Hex(data: Data) -> String' "$swift" && grep -q '^public protocol CoreLogger: AnyObject, Sendable {' "$swift" && grep -q '^public protocol PacketSink: AnyObject, Sendable {' "$swift" && echo bindings ok
```

Expected: `bindings ok`

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/core.yml
git commit -m "ci: check the Swift bindings and the workspace with Rust 1.94"
```

---

### Task 9: devproxy crate and command line

**Files:**
- Modify: `core/Cargo.toml`
- Create: `core/tools/devproxy/Cargo.toml`, `core/tools/devproxy/src/lib.rs`, `core/tools/devproxy/src/args.rs`
- Test: `core/tools/devproxy/tests/args.rs`

**Interfaces:**
- Consumes: `std::env::args` only.
- Produces:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum ListKind { Url, Dns, Hosts }
#[derive(Clone, Debug, PartialEq, Eq)] pub struct ListSpec { pub kind: ListKind, pub source: String }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args { pub data_dir: PathBuf, pub config: Option<PathBuf>, pub lists: Vec<ListSpec>, pub dns: SocketAddr, pub proxy: SocketAddr }
#[derive(Clone, Debug, PartialEq, Eq)] pub enum Command { Run(Args), Help }
pub const DEFAULT_LISTS: [(ListKind, &str); 5];
pub const DEFAULT_DATA_DIR: &str = "devproxy-data";
pub const DEFAULT_DNS: &str = "127.0.0.1:5353";
pub const DEFAULT_PROXY: &str = "127.0.0.1:8080";
pub const USAGE: &str;
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Command, String>;
```

- [ ] **Step 1: Write the failing test**

The workspace gains the member and every entry devproxy uses later; the library starts empty.

`core/Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = [
    "crates/common",
    "crates/policy",
    "crates/filter",
    "crates/dns",
    "crates/mitm",
    "crates/tollgate-ffi",
    "tools/devproxy",
    "tools/uniffi-bindgen-swift",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"
rust-version = "1.94"
publish = false

[workspace.dependencies]
# Internal crates.
tollgate-common = { path = "crates/common" }
tollgate-policy = { path = "crates/policy" }
tollgate-filter = { path = "crates/filter" }
tollgate-dns = { path = "crates/dns" }
tollgate-mitm = { path = "crates/mitm" }
tollgate-ffi = { path = "crates/tollgate-ffi" }

# FFI. Default features are off so the runtime crate does not build cargo_metadata;
# tools/uniffi-bindgen-swift turns on the features it needs.
uniffi = { version = "0.32.2", default-features = false }
ring = "0.17.14"

# TLS with the ring provider only. Every rustls-based crate needs default-features = false,
# or aws-lc-sys comes back.
rustls = { version = "0.23.45", default-features = false, features = ["ring", "std", "logging", "tls12"] }
webpki-roots = "1.0.9"

# Filtering. adblock is pinned exactly: the app writes engine.dat and the extension reads it.
# default-features = false drops "single-thread", which would make the engine !Send.
adblock = { version = "=0.13.3", default-features = false, features = ["embedded-domain-resolver", "full-regex-handling"] }
memmap2 = "0.9.11"

libc = "0.2.189"
log = "0.4.34"
serde = { version = "1.0.229", features = ["derive"] }
serde_json = "1.0.151"
thiserror = "2.0.21"

# DNS: packet parsing, DNS messages, the answer cache and DNS over HTTPS. tokio-rustls, like
# rustls, needs default-features = false to keep aws-lc out.
etherparse = "0.21.0"
hickory-proto = { version = "0.26.3", default-features = false, features = ["std"] }
lru = { version = "0.18.5", default-features = false }
arc-swap = "1.9.2"

# Certificates. rcgen with ring only; tollgate-mitm adds the x509-parser feature so leaves
# are issued from the stored CA certificate.
rcgen = { version = "0.14.10", default-features = false, features = ["crypto", "ring", "pem"] }
x509-parser = "0.18.1"
time = { version = "0.3.55", default-features = false, features = ["std"] }

# Runtime, HTTP and TLS streams, shared by the DoH resolver and the proxy.
tokio = { version = "1.53.1", features = ["rt", "net", "io-util", "macros", "time", "sync"] }
tokio-rustls = { version = "0.26.5", default-features = false, features = ["ring", "logging", "tls12"] }
hyper = { version = "1.11.1", features = ["http1", "http2", "server", "client"] }
hyper-util = { version = "0.1.21", features = ["tokio", "server-auto", "http1", "http2"] }
http-body-util = "0.1.5"
bytes = "1.12.1"

# tools/devproxy only. env_logger without regex, colors or timestamps; socket2 (already in
# the tree through tokio) to share the DNS port with an mDNS responder.
env_logger = { version = "0.11.11", default-features = false }
socket2 = "0.6.5"

# Tests only.
tempfile = "3.27.0"

[profile.release]
opt-level = "s"
lto = "thin"
codegen-units = 1
debug = "line-tables-only"
```

`core/tools/devproxy/Cargo.toml`:

```toml
[package]
name = "devproxy"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
publish.workspace = true
```

`core/tools/devproxy/src/lib.rs` (for now):

```rust
//! A Linux harness that runs Tollgate's DNS responder and filtering proxy for a desktop
//! browser, with the same crates, configuration format and data directory layout as the
//! tunnel.
```

`core/tools/devproxy/tests/args.rs`:

```rust
use std::path::PathBuf;

use devproxy::args::{Args, Command, DEFAULT_LISTS, ListKind, ListSpec, parse};

fn run(args: &[&str]) -> Result<Command, String> {
    parse(args.iter().map(|a| a.to_string()))
}

fn defaults() -> Args {
    Args {
        data_dir: PathBuf::from("devproxy-data"),
        config: None,
        lists: Vec::new(),
        dns: "127.0.0.1:5353".parse().unwrap(),
        proxy: "127.0.0.1:8080".parse().unwrap(),
    }
}

#[test]
fn no_arguments_give_the_defaults() {
    assert_eq!(run(&[]), Ok(Command::Run(defaults())));
}

#[test]
fn every_option_is_read() {
    let parsed = run(&[
        "--data-dir",
        "/tmp/tg",
        "--config",
        "config.json",
        "--url-list",
        "easylist.txt",
        "--dns-list",
        "https://example.com/dns.txt",
        "--hosts-list",
        "hosts",
        "--dns",
        "127.0.0.1:0",
        "--proxy",
        "[::1]:8888",
    ]);
    assert_eq!(
        parsed,
        Ok(Command::Run(Args {
            data_dir: PathBuf::from("/tmp/tg"),
            config: Some(PathBuf::from("config.json")),
            lists: vec![
                ListSpec {
                    kind: ListKind::Url,
                    source: "easylist.txt".to_string()
                },
                ListSpec {
                    kind: ListKind::Dns,
                    source: "https://example.com/dns.txt".to_string()
                },
                ListSpec {
                    kind: ListKind::Hosts,
                    source: "hosts".to_string()
                },
            ],
            dns: "127.0.0.1:0".parse().unwrap(),
            proxy: "[::1]:8888".parse().unwrap(),
        }))
    );
}

#[test]
fn default_lists_expand_in_place() {
    let Ok(Command::Run(args)) = run(&["--url-list", "mine.txt", "--default-lists"]) else {
        panic!("expected run");
    };
    let sources: Vec<(ListKind, &str)> = args
        .lists
        .iter()
        .map(|l| (l.kind, l.source.as_str()))
        .collect();
    let mut expected = vec![(ListKind::Url, "mine.txt")];
    expected.extend(DEFAULT_LISTS);
    assert_eq!(sources, expected);
    assert_eq!(
        DEFAULT_LISTS.map(|(kind, _)| kind),
        [
            ListKind::Url,
            ListKind::Url,
            ListKind::Url,
            ListKind::Dns,
            ListKind::Hosts
        ]
    );
}

#[test]
fn help_wins_anywhere() {
    assert_eq!(run(&["--dns", "127.0.0.1:1", "-h"]), Ok(Command::Help));
    assert_eq!(run(&["--help"]), Ok(Command::Help));
}

#[test]
fn mistakes_are_reported() {
    assert_eq!(
        run(&["--data-dir"]),
        Err("--data-dir needs a value".to_string())
    );
    assert_eq!(
        run(&["--dns", "localhost:53"]),
        Err("--dns: invalid socket address \"localhost:53\"".to_string())
    );
    assert_eq!(
        run(&["--proxy", "8080"]),
        Err("--proxy: invalid socket address \"8080\"".to_string())
    );
    assert_eq!(
        run(&["--verbose"]),
        Err("unknown argument \"--verbose\"".to_string())
    );
    assert_eq!(
        run(&["lists.txt"]),
        Err("unknown argument \"lists.txt\"".to_string())
    );
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd core && cargo test -p devproxy --test args`
Expected: FAIL to compile: `` error[E0432]: unresolved import `devproxy::args` ``

- [ ] **Step 3: Implement**

`core/tools/devproxy/src/args.rs`:

```rust
//! Command line parsing with `std::env::args`, no parser crate.

use std::net::SocketAddr;
use std::path::PathBuf;

/// What a list is and which file it feeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListKind {
    /// Adblock syntax for URL filtering (`engine.dat`).
    Url,
    /// Adblock syntax for the DNS blocklist (`domains.bin`).
    Dns,
    /// Hosts format for the DNS blocklist (`domains.bin`).
    Hosts,
}

/// One list: a file path or an `http://` or `https://` URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListSpec {
    pub kind: ListKind,
    pub source: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    pub data_dir: PathBuf,
    pub config: Option<PathBuf>,
    pub lists: Vec<ListSpec>,
    pub dns: SocketAddr,
    pub proxy: SocketAddr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Run(Args),
    Help,
}

/// The lists the app ships with: three URL lists, then two DNS lists.
pub const DEFAULT_LISTS: [(ListKind, &str); 5] = [
    (ListKind::Url, "https://easylist.to/easylist/easylist.txt"),
    (
        ListKind::Url,
        "https://easylist.to/easylist/easyprivacy.txt",
    ),
    (
        ListKind::Url,
        "https://filters.adtidy.org/extension/ublock/filters/11.txt",
    ),
    (
        ListKind::Dns,
        "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    ),
    (
        ListKind::Hosts,
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
];

pub const DEFAULT_DATA_DIR: &str = "devproxy-data";
pub const DEFAULT_DNS: &str = "127.0.0.1:5353";
pub const DEFAULT_PROXY: &str = "127.0.0.1:8080";

pub const USAGE: &str = "\
Usage: devproxy [options]

Runs Tollgate's DNS responder and HTTPS filtering proxy on this machine.

Options:
  --data-dir DIR     engine.dat, domains.bin, ca.pem, ca.key and learned-pins.json
                     (default: devproxy-data)
  --config FILE      config.json in the tunnel's format (default: built-in defaults)
  --url-list SRC     adblock list for URL filtering; SRC is a file or an http(s) URL
  --dns-list SRC     adblock-syntax list for the DNS blocklist
  --hosts-list SRC   hosts-format list for the DNS blocklist
  --default-lists    EasyList, EasyPrivacy, AdGuard Mobile Ads, AdGuard DNS filter
                     and StevenBlack hosts, downloaded
  --dns ADDR         UDP address of the DNS responder (default: 127.0.0.1:5353)
  --proxy ADDR       TCP address of the proxy (default: 127.0.0.1:8080)
  -h, --help         this text

List options may repeat. With any list option the lists are compiled into the data
directory; without one, the files already there are used.
";

fn address(flag: &str, value: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|_| format!("{flag}: invalid socket address {value:?}"))
}

/// Parses the arguments after the program name.
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut parsed = Args {
        data_dir: PathBuf::from(DEFAULT_DATA_DIR),
        config: None,
        lists: Vec::new(),
        dns: address("--dns", DEFAULT_DNS)?,
        proxy: address("--proxy", DEFAULT_PROXY)?,
    };
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "--data-dir" => parsed.data_dir = PathBuf::from(value()?),
            "--config" => parsed.config = Some(PathBuf::from(value()?)),
            "--url-list" | "--dns-list" | "--hosts-list" => {
                let kind = match flag.as_str() {
                    "--url-list" => ListKind::Url,
                    "--dns-list" => ListKind::Dns,
                    _ => ListKind::Hosts,
                };
                parsed.lists.push(ListSpec {
                    kind,
                    source: value()?,
                });
            }
            "--default-lists" => {
                parsed
                    .lists
                    .extend(DEFAULT_LISTS.iter().map(|(kind, url)| ListSpec {
                        kind: *kind,
                        source: (*url).to_string(),
                    }));
            }
            "--dns" => parsed.dns = address("--dns", &value()?)?,
            "--proxy" => parsed.proxy = address("--proxy", &value()?)?,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(Command::Run(parsed))
}
```

`core/tools/devproxy/src/lib.rs`:

```rust
//! A Linux harness that runs Tollgate's DNS responder and filtering proxy for a desktop
//! browser, with the same crates, configuration format and data directory layout as the
//! tunnel.

pub mod args;
```

- [ ] **Step 4: Run the tests, fmt and clippy**

Run: `cd core && cargo test -p devproxy && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS: `tests/args.rs` 5 passed; fmt and clippy print nothing

- [ ] **Step 5: Commit**

```bash
git add core/Cargo.toml core/Cargo.lock core/tools/devproxy/Cargo.toml core/tools/devproxy/src/lib.rs core/tools/devproxy/src/args.rs core/tools/devproxy/tests/args.rs
git commit -m "devproxy: crate and command line parsing"
```

---

### Task 10: devproxy list downloads

**Files:**
- Modify: `core/tools/devproxy/Cargo.toml`, `core/tools/devproxy/src/lib.rs`
- Create: `core/tools/devproxy/src/fetch.rs`
- Test: `core/tools/devproxy/tests/fetch.rs`

**Interfaces:**
- Consumes: `tollgate_common::tls::client_config(&[b"http/1.1"])` (M1a), `hyper::client::conn::http1`, `tokio_rustls::TlsConnector`.
- Produces:

```rust
pub const MAX_REDIRECTS: usize = 5;
pub const MAX_BODY: usize = 64 * 1024 * 1024;
pub const REQUEST_TIMEOUT: std::time::Duration; // 60 s
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FetchError { InvalidUrl(String), Connect(String, String), Tls(String, String), Http(String), Status(u16), TooManyRedirects, TooLarge, Timeout }
pub struct Fetcher;
impl Fetcher {
    pub fn new() -> Fetcher;
    pub fn with_tls(config: Arc<rustls::ClientConfig>) -> Fetcher;
    pub async fn get_text(&self, url: &str) -> Result<String, FetchError>;
}
pub async fn load_source(fetcher: &Fetcher, source: &str) -> Result<String, String>;
```

- [ ] **Step 1: Write the failing test**

`core/tools/devproxy/Cargo.toml`:

```toml
[package]
name = "devproxy"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
publish.workspace = true

[dependencies]
bytes = { workspace = true }
http-body-util = { workspace = true }
hyper = { workspace = true }
hyper-util = { workspace = true }
log = { workspace = true }
rustls = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true, features = ["signal"] }
tokio-rustls = { workspace = true }
tollgate-common = { workspace = true }

[dev-dependencies]
rcgen = { workspace = true }
tempfile = { workspace = true }
```

`core/tools/devproxy/tests/fetch.rs`:

```rust
//! Downloads from local HTTP and HTTPS servers; one ignored test uses the network.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use devproxy::args::DEFAULT_LISTS;
use devproxy::fetch::{FetchError, Fetcher, MAX_REDIRECTS, load_source};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const LIST: &str = "! Title: local list\n||ads.example^\n";

async fn route(request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let response = |status: u16, location: Option<&str>, body: &'static str| {
        let mut builder = Response::builder().status(status);
        if let Some(location) = location {
            builder = builder.header("location", location);
        }
        Ok(builder
            .body(Full::new(Bytes::from_static(body.as_bytes())))
            .unwrap())
    };
    let host = request
        .headers()
        .get("host")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    match request.uri().path() {
        "/list.txt" => response(200, None, LIST),
        "/relative" => response(302, Some("/list.txt"), ""),
        "/absolute" => response(301, Some(&format!("http://{host}/list.txt")), ""),
        "/loop" => response(302, Some("/loop"), ""),
        "/odd" => response(302, Some("list.txt"), ""),
        _ => response(404, None, "not here"),
    }
}

/// A plain HTTP/1.1 server on 127.0.0.1.
async fn http_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service_fn(route)),
            );
        }
    });
    addr
}

/// An HTTPS server for `localhost` and a client configuration trusting its CA.
async fn https_server() -> (SocketAddr, Arc<ClientConfig>) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let mut roots = RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    let client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls = acceptor.accept(tcp).await.unwrap();
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service_fn(route))
                    .await;
            });
        }
    });
    (addr, Arc::new(client))
}

#[tokio::test]
async fn downloads_a_list_over_http() {
    let addr = http_server().await;
    let text = Fetcher::new()
        .get_text(&format!("http://{addr}/list.txt"))
        .await
        .unwrap();
    assert_eq!(text, LIST);
}

#[tokio::test]
async fn follows_relative_and_absolute_redirects() {
    let addr = http_server().await;
    let fetcher = Fetcher::new();
    for path in ["relative", "absolute"] {
        let text = fetcher
            .get_text(&format!("http://{addr}/{path}"))
            .await
            .unwrap();
        assert_eq!(text, LIST, "{path}");
    }
}

#[tokio::test]
async fn failures_are_errors() {
    let addr = http_server().await;
    let fetcher = Fetcher::new();
    assert_eq!(
        fetcher.get_text(&format!("http://{addr}/missing")).await,
        Err(FetchError::Status(404))
    );
    assert_eq!(
        fetcher.get_text(&format!("http://{addr}/loop")).await,
        Err(FetchError::TooManyRedirects)
    );
    assert_eq!(
        fetcher.get_text(&format!("http://{addr}/odd")).await,
        Err(FetchError::InvalidUrl("list.txt".to_string()))
    );
    assert_eq!(
        fetcher.get_text("ftp://example.com/list.txt").await,
        Err(FetchError::InvalidUrl(
            "ftp://example.com/list.txt".to_string()
        ))
    );
    assert_eq!(MAX_REDIRECTS, 5);
}

#[tokio::test]
async fn downloads_over_https_with_the_given_roots() {
    let (addr, client) = https_server().await;
    let url = format!("https://localhost:{}/list.txt", addr.port());
    let text = Fetcher::with_tls(client).get_text(&url).await.unwrap();
    assert_eq!(text, LIST);
    // The default roots do not trust the test CA.
    let error = Fetcher::new().get_text(&url).await.unwrap_err();
    assert!(matches!(error, FetchError::Tls(..)), "{error:?}");
}

#[tokio::test]
async fn sources_are_files_or_urls() {
    let addr = http_server().await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("list.txt");
    std::fs::write(&file, LIST).unwrap();
    let fetcher = Fetcher::new();
    assert_eq!(
        load_source(&fetcher, file.to_str().unwrap()).await.unwrap(),
        LIST
    );
    assert_eq!(
        load_source(&fetcher, &format!("http://{addr}/list.txt"))
            .await
            .unwrap(),
        LIST
    );
    let missing = dir.path().join("missing.txt");
    let error = load_source(&fetcher, missing.to_str().unwrap())
        .await
        .unwrap_err();
    assert!(error.starts_with(missing.to_str().unwrap()), "{error}");
}

/// Needs the network. Run with:
/// `cargo test -p devproxy --test fetch -- --ignored`
#[tokio::test]
#[ignore = "downloads EasyList from easylist.to"]
async fn downloads_easylist() {
    let (_, url) = DEFAULT_LISTS[0];
    let text = Fetcher::new().get_text(url).await.unwrap();
    assert!(text.contains("! Title: EasyList"), "{}", &text[..200]);
    assert!(text.lines().count() > 10_000);
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd core && cargo test -p devproxy --test fetch`
Expected: FAIL to compile: `` error[E0432]: unresolved import `devproxy::fetch` ``

- [ ] **Step 3: Implement**

`core/tools/devproxy/src/fetch.rs`:

```rust
//! Downloading filter lists over HTTP/1.1 with hyper and the shared rustls configuration.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Incoming;
use hyper::header::{ACCEPT, HOST, LOCATION, USER_AGENT};
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Redirects followed before giving up.
pub const MAX_REDIRECTS: usize = 5;
/// Largest list accepted; the biggest default list is about 4.5 MB.
pub const MAX_BODY: usize = 64 * 1024 * 1024;
/// Limit for one request, from connecting to the end of the body.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    #[error("invalid URL {0:?}")]
    InvalidUrl(String),
    #[error("connecting to {0} failed: {1}")]
    Connect(String, String),
    #[error("TLS with {0} failed: {1}")]
    Tls(String, String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("HTTP status {0}")]
    Status(u16),
    #[error("more than {MAX_REDIRECTS} redirects")]
    TooManyRedirects,
    #[error("the body is larger than {MAX_BODY} bytes")]
    TooLarge,
    #[error("no answer within {REQUEST_TIMEOUT:?}")]
    Timeout,
}

enum Step {
    Body(String),
    Redirect(String),
}

/// An HTTP/1.1 client for `http://` and `https://` URLs. Names are resolved by the system
/// resolver; TLS uses the ring provider and the webpki roots unless configured otherwise.
pub struct Fetcher {
    tls: TlsConnector,
}

impl Default for Fetcher {
    fn default() -> Fetcher {
        Fetcher::new()
    }
}

impl Fetcher {
    pub fn new() -> Fetcher {
        Fetcher::with_tls(tollgate_common::tls::client_config(&[b"http/1.1"]))
    }

    /// A fetcher with its own TLS configuration, for tests against a local server.
    pub fn with_tls(config: Arc<ClientConfig>) -> Fetcher {
        Fetcher {
            tls: TlsConnector::from(config),
        }
    }

    /// GETs `url`, following up to [`MAX_REDIRECTS`] redirects, and returns the body as
    /// text (invalid UTF-8 is replaced). Anything but `200` is an error.
    pub async fn get_text(&self, url: &str) -> Result<String, FetchError> {
        let mut uri: Uri = url
            .parse()
            .map_err(|_| FetchError::InvalidUrl(url.to_string()))?;
        for _ in 0..=MAX_REDIRECTS {
            let step = tokio::time::timeout(REQUEST_TIMEOUT, self.once(&uri))
                .await
                .map_err(|_| FetchError::Timeout)??;
            match step {
                Step::Body(text) => return Ok(text),
                Step::Redirect(location) => uri = follow(&uri, &location)?,
            }
        }
        Err(FetchError::TooManyRedirects)
    }

    async fn once(&self, uri: &Uri) -> Result<Step, FetchError> {
        let invalid = || FetchError::InvalidUrl(uri.to_string());
        let tls = match uri.scheme_str() {
            Some("http") => false,
            Some("https") => true,
            _ => return Err(invalid()),
        };
        let host = uri
            .host()
            .ok_or_else(invalid)?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
        let authority = uri.authority().ok_or_else(invalid)?.to_string();
        let request = Request::get(uri.path_and_query().map_or("/", |p| p.as_str()))
            .header(HOST, &authority)
            .header(
                USER_AGENT,
                concat!("tollgate-devproxy/", env!("CARGO_PKG_VERSION")),
            )
            .header(ACCEPT, "*/*")
            .body(Empty::<Bytes>::new())
            .map_err(|_| invalid())?;
        let tcp = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| FetchError::Connect(authority.clone(), e.to_string()))?;
        let response = if tls {
            let name = ServerName::try_from(host.clone()).map_err(|_| invalid())?;
            let stream = self
                .tls
                .connect(name, tcp)
                .await
                .map_err(|e| FetchError::Tls(authority.clone(), e.to_string()))?;
            exchange(stream, request).await?
        } else {
            exchange(tcp, request).await?
        };
        let status = response.status();
        if status.is_redirection()
            && let Some(location) = response.headers().get(LOCATION)
        {
            let location = location.to_str().map_err(|_| invalid())?;
            return Ok(Step::Redirect(location.to_string()));
        }
        if status != StatusCode::OK {
            return Err(FetchError::Status(status.as_u16()));
        }
        let body = Limited::new(response.into_body(), MAX_BODY)
            .collect()
            .await
            .map_err(|e| {
                if e.is::<http_body_util::LengthLimitError>() {
                    FetchError::TooLarge
                } else {
                    FetchError::Http(e.to_string())
                }
            })?
            .to_bytes();
        Ok(Step::Body(String::from_utf8_lossy(&body).into_owned()))
    }
}

async fn exchange<S>(
    stream: S,
    request: Request<Empty<Bytes>>,
) -> Result<Response<Incoming>, FetchError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| FetchError::Http(e.to_string()))?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            log::debug!("list download connection: {e}");
        }
    });
    sender
        .send_request(request)
        .await
        .map_err(|e| FetchError::Http(e.to_string()))
}

/// The URL a `Location` header points at: absolute, or a path on the same origin.
fn follow(base: &Uri, location: &str) -> Result<Uri, FetchError> {
    let invalid = || FetchError::InvalidUrl(location.to_string());
    let next = if location.starts_with("http://") || location.starts_with("https://") {
        location.to_string()
    } else if location.starts_with('/') {
        let scheme = base.scheme_str().ok_or_else(invalid)?;
        let authority = base.authority().ok_or_else(invalid)?;
        format!("{scheme}://{authority}{location}")
    } else {
        return Err(invalid());
    };
    next.parse().map_err(|_| invalid())
}

/// The text of a list: downloaded when `source` is an `http://` or `https://` URL,
/// otherwise read from the file `source`.
pub async fn load_source(fetcher: &Fetcher, source: &str) -> Result<String, String> {
    if source.starts_with("http://") || source.starts_with("https://") {
        fetcher
            .get_text(source)
            .await
            .map_err(|e| format!("{source}: {e}"))
    } else {
        std::fs::read_to_string(source).map_err(|e| format!("{source}: {e}"))
    }
}
```

`core/tools/devproxy/src/lib.rs`:

```rust
//! A Linux harness that runs Tollgate's DNS responder and filtering proxy for a desktop
//! browser, with the same crates, configuration format and data directory layout as the
//! tunnel.

pub mod args;
pub mod fetch;
```

- [ ] **Step 4: Run the tests, fmt and clippy**

Run: `cd core && cargo test -p devproxy && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS: `args` 5 and `fetch` 5 passed, 1 ignored (`downloads_easylist`); fmt and clippy print nothing

- [ ] **Step 5: Run the network test once**

Run: `cd core && cargo test -p devproxy --test fetch -- --ignored`
Expected: `test downloads_easylist ... ok` and `1 passed; 0 failed` (needs the network; it downloads EasyList).

- [ ] **Step 6: Commit**

```bash
git add core/Cargo.lock core/tools/devproxy/Cargo.toml core/tools/devproxy/src/lib.rs core/tools/devproxy/src/fetch.rs core/tools/devproxy/tests/fetch.rs
git commit -m "devproxy: download lists over hyper with the shared rustls configuration"
```

---

### Task 11: DNS payloads for DnsHandler and the UDP responder

**Files:**
- Modify: `core/tools/devproxy/Cargo.toml`, `core/tools/devproxy/src/lib.rs`
- Create: `core/tools/devproxy/src/udp.rs`
- Test: `core/tools/devproxy/tests/udp.rs`

**Interfaces:**
- Consumes: `tollgate_dns::{DnsHandler, DohResolver, DohError, ForwardJob, Outcome, TUNNEL_DNS_V4, packet::{build_udp, parse_udp}}` (M1b; `packet` is public for exactly this use), `tollgate_common::clock::now_secs`.
- Produces (the helper that runs `DnsHandler` on DNS payloads):

```rust
pub const WRAP_CLIENT: SocketAddr; // 198.18.0.2:53000
pub const WRAP_SERVER: SocketAddr; // 198.18.0.1:53
#[derive(Debug)] pub enum PayloadOutcome { Reply(Vec<u8>), Forward(ForwardJob), Drop }
pub struct PayloadHandler;
impl PayloadHandler {
    pub fn new(handler: Arc<DnsHandler>) -> PayloadHandler;
    /// Never blocks or awaits.
    pub fn handle(&self, payload: &[u8], now: u64) -> PayloadOutcome;
    pub fn complete(&self, job: ForwardJob, answer: Result<Vec<u8>, DohError>, now: u64) -> Vec<u8>;
}
pub async fn serve_dns(socket: tokio::net::UdpSocket, handler: PayloadHandler, resolver: DohResolver);
```

- [ ] **Step 1: Write the failing test**

`core/tools/devproxy/Cargo.toml`:

```toml
[package]
name = "devproxy"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
publish.workspace = true

[dependencies]
bytes = { workspace = true }
http-body-util = { workspace = true }
hyper = { workspace = true }
hyper-util = { workspace = true }
log = { workspace = true }
rustls = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true, features = ["signal"] }
tokio-rustls = { workspace = true }
tollgate-common = { workspace = true }
tollgate-dns = { workspace = true }
tollgate-filter = { workspace = true }
tollgate-policy = { workspace = true }

[dev-dependencies]
hickory-proto = { workspace = true }
rcgen = { workspace = true }
tempfile = { workspace = true }
```

`core/tools/devproxy/tests/udp.rs`:

```rust
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use devproxy::udp::{PayloadHandler, PayloadOutcome, serve_dns};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::net::UdpSocket;
use tollgate_common::stats::{Stats, StatsSnapshot};
use tollgate_dns::{DnsHandler, DohError, DohResolver};
use tollgate_filter::{DomainSet, ListFormat, ListSource};
use tollgate_policy::DohUpstream;

const NOW: u64 = 1_000;

fn query(id: u16, name: &str, rtype: RecordType) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    message.to_vec().unwrap()
}

fn blocklist() -> Arc<DomainSet> {
    let list = ListSource {
        name: "test",
        text: "||ads.example^\n",
        format: ListFormat::Adblock,
    };
    Arc::new(DomainSet::from_bytes(DomainSet::build(&[list])).unwrap())
}

fn handler() -> (PayloadHandler, Arc<Stats>) {
    let stats = Arc::new(Stats::default());
    let dns = Arc::new(DnsHandler::new(Some(blocklist()), stats.clone()));
    (PayloadHandler::new(dns), stats)
}

fn reply(outcome: PayloadOutcome) -> Message {
    match outcome {
        PayloadOutcome::Reply(payload) => Message::from_vec(&payload).unwrap(),
        other => panic!("expected a reply, got {other:?}"),
    }
}

#[test]
fn blocked_names_are_answered_from_the_payload() {
    let (handler, stats) = handler();
    let message = reply(handler.handle(&query(0x0a0b, "ads.example.", RecordType::A), NOW));
    assert_eq!(message.metadata.id, 0x0a0b);
    assert_eq!(message.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
    let message = reply(handler.handle(&query(2, "example.com.", RecordType::HTTPS), NOW));
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(message.answers.is_empty());
    assert_eq!(
        stats.snapshot(),
        StatsSnapshot {
            dns_queries: 2,
            dns_blocked: 1,
            ..StatsSnapshot::default()
        }
    );
}

#[test]
fn other_names_are_forwarded_with_the_payload_unchanged() {
    let (handler, stats) = handler();
    let payload = query(0x7777, "example.com.", RecordType::A);
    let PayloadOutcome::Forward(job) = handler.handle(&payload, NOW) else {
        panic!("expected a forward");
    };
    assert_eq!(job.query(), payload.as_slice());
    let message = Message::from_vec(&handler.complete(job, Err(DohError::Timeout), NOW)).unwrap();
    assert_eq!(message.metadata.id, 0x7777);
    assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(stats.snapshot().dns_failed, 1);
}

#[test]
fn responses_and_short_payloads_are_dropped() {
    let (handler, stats) = handler();
    let mut response = query(1, "example.com.", RecordType::A);
    response[2] |= 0x80;
    assert!(matches!(
        handler.handle(&response, NOW),
        PayloadOutcome::Drop
    ));
    assert!(matches!(
        handler.handle(&[1, 2, 3, 4, 5], NOW),
        PayloadOutcome::Drop
    ));
    assert_eq!(stats.snapshot().packets_dropped, 2);
}

async fn exchange(client: &UdpSocket, server: SocketAddr, payload: &[u8]) -> Message {
    client.send_to(payload, server).await.unwrap();
    let mut buf = [0u8; 1500];
    let (len, from) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, server);
    Message::from_vec(&buf[..len]).unwrap()
}

#[tokio::test]
async fn the_udp_responder_answers_and_forwards() {
    let (handler, _) = handler();
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = DohUpstream {
        ip: "127.0.0.1".parse().unwrap(),
        port: closed.local_addr().unwrap().port(),
        tls_name: "doh.test".to_string(),
        path: "/dns-query".to_string(),
    };
    drop(closed);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = socket.local_addr().unwrap();
    let responder = tokio::spawn(serve_dns(socket, handler, DohResolver::new(vec![upstream])));

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let blocked = exchange(&client, server, &query(11, "ads.example.", RecordType::A)).await;
    assert_eq!(blocked.metadata.id, 11);
    assert_eq!(blocked.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
    let failed = exchange(&client, server, &query(12, "example.com.", RecordType::A)).await;
    assert_eq!(failed.metadata.id, 12);
    assert_eq!(failed.metadata.response_code, ResponseCode::ServFail);
    responder.abort();
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd core && cargo test -p devproxy --test udp`
Expected: FAIL to compile: `` error[E0432]: unresolved import `devproxy::udp` ``

- [ ] **Step 3: Implement**

`core/tools/devproxy/src/udp.rs`:

```rust
//! DNS over plain UDP for tools that receive DNS payloads, not the tunnel's IP packets.
//!
//! [`PayloadHandler`] wraps each payload into the IPv4 packet the tunnel would deliver to
//! [`DnsHandler`] (from `198.18.0.2:53000` to `198.18.0.1:53`) and unwraps the reply, so
//! blocking, caching and forwarding behave exactly as on the phone.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tollgate_common::clock;
use tollgate_dns::packet::{build_udp, parse_udp};
use tollgate_dns::{DnsHandler, DohError, DohResolver, ForwardJob, Outcome, TUNNEL_DNS_V4};

/// Where wrapped queries appear to come from: the tunnel's own address.
pub const WRAP_CLIENT: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)), 53000);
/// Where wrapped queries go: the tunnel's DNS address.
pub const WRAP_SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(TUNNEL_DNS_V4), 53);

/// What to do with one DNS payload.
#[derive(Debug)]
pub enum PayloadOutcome {
    /// Send this payload back to the client now.
    Reply(Vec<u8>),
    /// Resolve upstream, then call [`PayloadHandler::complete`].
    Forward(ForwardJob),
    /// Not a query; nothing to send.
    Drop,
}

/// [`DnsHandler`] for DNS payloads.
pub struct PayloadHandler {
    handler: Arc<DnsHandler>,
}

fn payload_of(packet: &[u8]) -> Option<Vec<u8>> {
    parse_udp(packet).map(|datagram| datagram.payload.to_vec())
}

impl PayloadHandler {
    pub fn new(handler: Arc<DnsHandler>) -> PayloadHandler {
        PayloadHandler { handler }
    }

    /// Like [`DnsHandler::handle_packet`] for a DNS payload. Never blocks or awaits.
    pub fn handle(&self, payload: &[u8], now: u64) -> PayloadOutcome {
        let Some(packet) = build_udp(WRAP_CLIENT, WRAP_SERVER, payload) else {
            return PayloadOutcome::Drop;
        };
        match self.handler.handle_packet(&packet, now) {
            Outcome::Reply(reply) => {
                payload_of(&reply).map_or(PayloadOutcome::Drop, PayloadOutcome::Reply)
            }
            Outcome::Forward(job) => PayloadOutcome::Forward(job),
            Outcome::Drop => PayloadOutcome::Drop,
        }
    }

    /// Like [`DnsHandler::complete`], returning the reply payload.
    pub fn complete(
        &self,
        job: ForwardJob,
        answer: Result<Vec<u8>, DohError>,
        now: u64,
    ) -> Vec<u8> {
        payload_of(&self.handler.complete(job, answer, now)).unwrap_or_default()
    }
}

/// Answers DNS queries arriving on `socket` until the future is dropped. Each forwarded
/// query runs in its own task; `resolve` caps them at 128 in flight (more get SERVFAIL).
pub async fn serve_dns(socket: UdpSocket, handler: PayloadHandler, resolver: DohResolver) {
    let socket = Arc::new(socket);
    let handler = Arc::new(handler);
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(e) => {
                // Linux reports ICMP errors from earlier replies here; they are not fatal.
                log::debug!("DNS socket: {e}");
                tokio::task::yield_now().await;
                continue;
            }
        };
        match handler.handle(&buf[..len], clock::now_secs()) {
            PayloadOutcome::Reply(reply) => {
                let _ = socket.send_to(&reply, peer).await;
            }
            PayloadOutcome::Drop => {}
            PayloadOutcome::Forward(job) => {
                let (socket, handler, resolver) =
                    (socket.clone(), handler.clone(), resolver.clone());
                tokio::spawn(async move {
                    let answer = resolver.resolve(job.query()).await;
                    let reply = handler.complete(job, answer, clock::now_secs());
                    let _ = socket.send_to(&reply, peer).await;
                });
            }
        }
    }
}
```

`core/tools/devproxy/src/lib.rs`:

```rust
//! A Linux harness that runs Tollgate's DNS responder and filtering proxy for a desktop
//! browser, with the same crates, configuration format and data directory layout as the
//! tunnel.

pub mod args;
pub mod fetch;
pub mod udp;
```

- [ ] **Step 4: Run the tests, fmt and clippy**

Run: `cd core && cargo test -p devproxy && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS: `args` 5, `fetch` 5 (1 ignored) and `udp` 4 passed; fmt and clippy print nothing

- [ ] **Step 5: Commit**

```bash
git add core/Cargo.lock core/tools/devproxy/Cargo.toml core/tools/devproxy/src/lib.rs core/tools/devproxy/src/udp.rs core/tools/devproxy/tests/udp.rs
git commit -m "devproxy: run DnsHandler on UDP DNS payloads"
```

---

### Task 12: devproxy server and binary

**Files:**
- Modify: `core/tools/devproxy/Cargo.toml`, `core/tools/devproxy/src/lib.rs`
- Create: `core/tools/devproxy/src/server.rs`, `core/tools/devproxy/src/main.rs`
- Test: `core/tools/devproxy/tests/server.rs`

**Interfaces:**
- Consumes: `tollgate_ffi::{generate_ca, load_ca, compile_lists, ListInput, ListFormat, ListTarget, CA_CERT_FILE, LEARNED_PINS_FILE}` (Tasks 3 to 5), `tollgate_mitm::{serve, ProxyContext}`, `tollgate_policy::{Config, Policy}`, `tollgate_filter::{FilterEngine::load, DomainSet::load}`, and Tasks 9 to 11.
- Produces:

```rust
pub struct DevProxy;
impl DevProxy {
    pub async fn prepare(args: &Args) -> Result<DevProxy, String>;
    pub fn dns_addr(&self) -> SocketAddr;
    pub fn proxy_addr(&self) -> SocketAddr;
    pub fn ca_path(&self) -> PathBuf;
    /// Must run on a current-thread runtime.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) -> tollgate_common::stats::StatsSnapshot;
}
pub fn instructions(proxy: SocketAddr, dns: SocketAddr, ca_path: &Path) -> String;
```

The binary `devproxy` parses the arguments, prepares, prints `instructions`, serves until Ctrl-C and prints the counters.

- [ ] **Step 1: Write the failing test**

`core/tools/devproxy/Cargo.toml`:

```toml
[package]
name = "devproxy"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
publish.workspace = true

[dependencies]
arc-swap = { workspace = true }
bytes = { workspace = true }
env_logger = { workspace = true }
http-body-util = { workspace = true }
hyper = { workspace = true }
hyper-util = { workspace = true }
log = { workspace = true }
rustls = { workspace = true }
socket2 = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true, features = ["signal"] }
tokio-rustls = { workspace = true }
tollgate-common = { workspace = true }
tollgate-dns = { workspace = true }
tollgate-ffi = { workspace = true }
tollgate-filter = { workspace = true }
tollgate-mitm = { workspace = true }
tollgate-policy = { workspace = true }

[dev-dependencies]
hickory-proto = { workspace = true }
rcgen = { workspace = true }
tempfile = { workspace = true }
```

`core/tools/devproxy/tests/server.rs`:

```rust
//! The whole harness in-process: lists from files, both listeners on ephemeral ports.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use devproxy::args::{Args, ListKind, ListSpec};
use devproxy::server::{DevProxy, instructions};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::runtime::Runtime;

fn query(id: u16, name: &str, rtype: RecordType) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    message.to_vec().unwrap()
}

/// Sends one query and returns the decoded reply.
fn ask(server: SocketAddr, payload: &[u8]) -> Message {
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client.send_to(payload, server).unwrap();
    let mut buf = [0u8; 1500];
    let (len, from) = client.recv_from(&mut buf).unwrap();
    assert_eq!(from, server);
    Message::from_vec(&buf[..len]).unwrap()
}

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn args(dir: &Path, lists: Vec<ListSpec>) -> Args {
    Args {
        data_dir: dir.join("data"),
        config: None,
        lists,
        dns: "127.0.0.1:0".parse().unwrap(),
        proxy: "127.0.0.1:0".parse().unwrap(),
    }
}

fn list(kind: ListKind, path: &Path) -> ListSpec {
    ListSpec {
        kind,
        source: path.to_str().unwrap().to_string(),
    }
}

#[test]
fn compiles_serves_dns_and_filters_http() {
    let tmp = tempfile::tempdir().unwrap();
    let url_list = tmp.path().join("url.txt");
    std::fs::write(&url_list, "||blocked.example^\n").unwrap();
    let hosts = tmp.path().join("hosts");
    std::fs::write(&hosts, "0.0.0.0 ads.example\n").unwrap();
    let args = args(
        tmp.path(),
        vec![
            list(ListKind::Url, &url_list),
            list(ListKind::Hosts, &hosts),
        ],
    );
    let runtime = runtime();
    let proxy = runtime.block_on(DevProxy::prepare(&args)).unwrap();
    let (dns, http) = (proxy.dns_addr(), proxy.proxy_addr());
    let data = tmp.path().join("data");
    assert_eq!(proxy.ca_path(), data.join("ca.pem"));
    for file in ["engine.dat", "domains.bin"] {
        assert!(data.join(file).exists(), "{file}");
    }
    let mode = std::fs::metadata(data.join("ca.key"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = std::thread::spawn(move || {
        runtime.block_on(proxy.serve(async {
            let _ = stopped.await;
        }))
    });

    let message = ask(dns, &query(0x2222, "ads.example.", RecordType::A));
    assert_eq!(message.metadata.id, 0x2222);
    assert_eq!(message.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));

    let mut stream = TcpStream::connect(http).unwrap();
    stream
        .write_all(
            b"GET http://blocked.example/ad.js HTTP/1.1\r\nHost: blocked.example\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 403 "), "{response}");

    stop.send(()).unwrap();
    let stats = server.join().unwrap();
    assert_eq!((stats.dns_queries, stats.dns_blocked), (1, 1));
    assert_eq!((stats.http_requests, stats.http_blocked), (1, 1));
    assert_eq!(
        std::fs::read_to_string(data.join("learned-pins.json")).unwrap(),
        r#"{"version":1,"pins":[]}"#
    );
}

#[test]
fn a_second_run_reuses_the_data_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let url_list = tmp.path().join("url.txt");
    std::fs::write(&url_list, "||blocked.example^\n").unwrap();
    let runtime = runtime();
    let first = args(tmp.path(), vec![list(ListKind::Url, &url_list)]);
    let (ca, engine) = {
        let proxy = runtime.block_on(DevProxy::prepare(&first)).unwrap();
        let engine = std::fs::read(tmp.path().join("data/engine.dat")).unwrap();
        (std::fs::read_to_string(proxy.ca_path()).unwrap(), engine)
    };
    // No list options: the compiled files and the CA stay as they are.
    let proxy = runtime
        .block_on(DevProxy::prepare(&args(tmp.path(), Vec::new())))
        .unwrap();
    assert_eq!(std::fs::read_to_string(proxy.ca_path()).unwrap(), ca);
    assert_eq!(
        std::fs::read(tmp.path().join("data/engine.dat")).unwrap(),
        engine
    );
}

#[test]
fn a_missing_list_file_is_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("missing.txt");
    let error = runtime()
        .block_on(DevProxy::prepare(&args(
            tmp.path(),
            vec![list(ListKind::Dns, &missing)],
        )))
        .err()
        .unwrap();
    assert!(error.starts_with(missing.to_str().unwrap()), "{error}");
}

#[test]
fn the_dns_port_is_shared_with_an_mdns_responder() {
    // Like avahi on port 5353: the wildcard address with SO_REUSEADDR.
    let mdns = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    mdns.set_reuse_address(true).unwrap();
    mdns.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())
        .unwrap();
    let port = mdns.local_addr().unwrap().as_socket().unwrap().port();

    let tmp = tempfile::tempdir().unwrap();
    let mut args = args(tmp.path(), Vec::new());
    args.dns = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let runtime = runtime();
    let proxy = runtime.block_on(DevProxy::prepare(&args)).unwrap();
    assert_eq!(proxy.dns_addr(), args.dns);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = std::thread::spawn(move || {
        runtime.block_on(proxy.serve(async {
            let _ = stopped.await;
        }))
    });
    // HTTPS queries are answered locally, so no upstream is needed.
    let message = ask(args.dns, &query(0x3333, "example.com.", RecordType::HTTPS));
    assert_eq!(message.metadata.id, 0x3333);
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    stop.send(()).unwrap();
    server.join().unwrap();
}

#[test]
fn instructions_name_the_addresses_and_firefox_settings() {
    let text = instructions(
        "127.0.0.1:8080".parse().unwrap(),
        "127.0.0.1:5353".parse().unwrap(),
        Path::new("/tmp/tg/ca.pem"),
    );
    for expected in [
        "HTTP and HTTPS proxy  127.0.0.1:8080",
        "DNS over UDP          127.0.0.1:5353",
        "Root certificate      /tmp/tg/ca.pem",
        "HTTP Proxy 127.0.0.1, Port 8080",
        "Also use this proxy for HTTPS",
        "Import...: choose /tmp/tg/ca.pem",
        "Trust this CA to identify websites",
        "network.trr.mode to 5",
        "network.dns.echconfig.enabled to false",
        "dig @127.0.0.1 -p 5353 doubleclick.net A",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in\n{text}");
    }
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd core && cargo test -p devproxy --test server`
Expected: FAIL to compile: `` error[E0432]: unresolved import `devproxy::server` ``

- [ ] **Step 3: Implement**

`core/tools/devproxy/src/server.rs`:

```rust
//! Preparing the data directory and running the DNS responder and the proxy.

use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};
use tollgate_common::stats::{Stats, StatsSnapshot};
use tollgate_dns::{DnsHandler, DohResolver};
use tollgate_ffi::{
    CA_CERT_FILE, LEARNED_PINS_FILE, ListFormat, ListInput, ListTarget, compile_lists, generate_ca,
    load_ca,
};
use tollgate_filter::{DOMAINS_FILE, DomainSet, ENGINE_FILE, FilterEngine, FilterError};
use tollgate_mitm::ProxyContext;
use tollgate_policy::{Config, Policy};

use crate::args::{Args, ListKind};
use crate::fetch::{Fetcher, load_source};
use crate::udp::{PayloadHandler, serve_dns};

/// Everything bound and loaded, ready to serve.
pub struct DevProxy {
    data_dir: PathBuf,
    dns_socket: UdpSocket,
    proxy_listener: TcpListener,
    ctx: Arc<ProxyContext>,
    dns: Arc<DnsHandler>,
    resolver: DohResolver,
}

fn text<E: std::fmt::Display>(context: impl std::fmt::Display) -> impl FnOnce(E) -> String {
    move |e| format!("{context}: {e}")
}

fn optional<T>(result: Result<T, FilterError>) -> Result<Option<T>, String> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(FilterError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Downloads or reads the lists and compiles them into `data_dir`.
async fn compile(args: &Args, data_dir: &str) -> Result<(), String> {
    let fetcher = Fetcher::new();
    let mut inputs = Vec::new();
    for spec in &args.lists {
        let text = load_source(&fetcher, &spec.source).await?;
        log::info!("{}: {} bytes", spec.source, text.len());
        let (format, target) = match spec.kind {
            ListKind::Url => (ListFormat::Adblock, ListTarget::Url),
            ListKind::Dns => (ListFormat::Adblock, ListTarget::Dns),
            ListKind::Hosts => (ListFormat::Hosts, ListTarget::Dns),
        };
        inputs.push(ListInput {
            name: spec.source.clone(),
            text,
            format,
            target,
        });
    }
    let report = compile_lists(inputs, data_dir.to_string()).map_err(|e| e.to_string())?;
    log::info!(
        "compiled {} network rules ({} bytes) and {} DNS names ({} bytes)",
        report.network_rules,
        report.engine_bytes,
        report.domain_entries,
        report.domains_bytes
    );
    Ok(())
}

/// Binds with `SO_REUSEADDR`, so the responder can take `127.0.0.1:5353` while an mDNS
/// responder (avahi, systemd-resolved) holds `0.0.0.0:5353`; unicast queries to
/// `127.0.0.1` reach the more specific socket.
fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

impl DevProxy {
    /// Compiles the lists (when any are given), makes sure a CA exists, loads the data
    /// directory the way the tunnel does and binds both listeners.
    pub async fn prepare(args: &Args) -> Result<DevProxy, String> {
        // Absolute, so the printed certificate path works from any directory.
        let dir = &std::path::absolute(&args.data_dir).map_err(text(args.data_dir.display()))?;
        std::fs::create_dir_all(dir).map_err(text(dir.display()))?;
        let dir_str = dir.to_str().ok_or("the data directory must be UTF-8")?;
        let config = match &args.config {
            Some(path) => {
                let json = std::fs::read_to_string(path).map_err(text(path.display()))?;
                Config::from_json(&json).map_err(text(path.display()))?
            }
            None => Config::default(),
        };
        if !args.lists.is_empty() {
            compile(args, dir_str).await?;
        }
        let info = generate_ca(dir_str.to_string()).map_err(|e| e.to_string())?;
        if info.created {
            log::info!("generated a new root CA, import it into the browser");
        }
        let ca = load_ca(dir)
            .map_err(|e| e.to_string())?
            .ok_or("the CA disappeared from the data directory")?;
        let filter = optional(FilterEngine::load(&dir.join(ENGINE_FILE)))?;
        let domains = optional(DomainSet::load(&dir.join(DOMAINS_FILE)))?;
        if filter.is_none() {
            log::warn!(
                "no {ENGINE_FILE}: nothing is intercepted; pass --url-list or --default-lists"
            );
        }
        if domains.is_none() {
            log::warn!("no {DOMAINS_FILE}: DNS answers nothing locally");
        }
        // Like the tunnel: interception needs a filter engine.
        let policy_config = Config {
            mitm_enabled: config.mitm_enabled && filter.is_some(),
            ..config.clone()
        };
        let pins = std::fs::read_to_string(dir.join(LEARNED_PINS_FILE)).ok();
        let policy = Policy::new(&policy_config, pins.as_deref()).map_err(|e| e.to_string())?;
        let stats = Arc::new(Stats::default());
        let ctx = Arc::new(ProxyContext {
            policy: Arc::new(policy),
            filter: ArcSwapOption::new(filter.map(Arc::new)),
            ca: Arc::new(ca),
            stats: stats.clone(),
            max_intercepted: config.max_intercepted_connections as usize,
            available_memory: || None,
        });
        let dns = Arc::new(DnsHandler::new(domains.map(Arc::new), stats));
        let dns_socket = bind_udp(args.dns).map_err(text(format!("DNS listener {}", args.dns)))?;
        let proxy_listener = TcpListener::bind(args.proxy)
            .await
            .map_err(text(format!("proxy listener {}", args.proxy)))?;
        Ok(DevProxy {
            data_dir: dir.clone(),
            dns_socket,
            proxy_listener,
            ctx,
            dns,
            resolver: DohResolver::new(config.doh_upstreams),
        })
    }

    pub fn dns_addr(&self) -> SocketAddr {
        self.dns_socket.local_addr().expect("a bound socket")
    }

    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy_listener.local_addr().expect("a bound listener")
    }

    pub fn ca_path(&self) -> PathBuf {
        self.data_dir.join(CA_CERT_FILE)
    }

    /// Serves until `shutdown` resolves, then saves the learned pins and returns the
    /// final counters. Must run on a current-thread runtime.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) -> StatsSnapshot {
        let DevProxy {
            data_dir,
            dns_socket,
            proxy_listener,
            ctx,
            dns,
            resolver,
        } = self;
        let responder = tokio::spawn(serve_dns(dns_socket, PayloadHandler::new(dns), resolver));
        tollgate_mitm::serve(proxy_listener, ctx.clone(), shutdown).await;
        responder.abort();
        let pins = data_dir.join(LEARNED_PINS_FILE);
        if let Err(e) = std::fs::write(&pins, ctx.policy.learned_pins_json()) {
            log::warn!("{}: {e}", pins.display());
        }
        ctx.stats.snapshot()
    }
}

/// What to do in Firefox, printed once everything listens.
pub fn instructions(proxy: SocketAddr, dns: SocketAddr, ca_path: &Path) -> String {
    let (proxy_host, proxy_port) = (proxy.ip(), proxy.port());
    let (dns_host, dns_port) = (dns.ip(), dns.port());
    let ca = ca_path.display();
    format!(
        "\
Tollgate devproxy is running.

  HTTP and HTTPS proxy  {proxy}
  DNS over UDP          {dns}
  Root certificate      {ca}

Firefox, in a separate profile (firefox -P tollgate-dev --no-remote):
  1. Settings, General, Network Settings, Settings...: Manual proxy configuration,
     HTTP Proxy {proxy_host}, Port {proxy_port}, tick \"Also use this proxy for HTTPS\".
  2. Settings, Privacy & Security, Certificates, View Certificates..., Authorities,
     Import...: choose {ca} and tick \"Trust this CA to identify websites\".
  3. about:config: set network.trr.mode to 5 (Firefox's own DNS over HTTPS off) and
     network.dns.echconfig.enabled to false, so no Encrypted Client Hello hides the
     server name from the proxy.

DNS check: dig @{dns_host} -p {dns_port} doubleclick.net A
Stop with Ctrl-C; learned pins are saved in the data directory.
"
    )
}
```

`core/tools/devproxy/src/lib.rs`:

```rust
//! A Linux harness that runs Tollgate's DNS responder and filtering proxy for a desktop
//! browser, with the same crates, configuration format and data directory layout as the
//! tunnel.

pub mod args;
pub mod fetch;
pub mod server;
pub mod udp;
```

`core/tools/devproxy/src/main.rs`:

```rust
use std::process::ExitCode;

use devproxy::args::{self, Command, USAGE};
use devproxy::server::{DevProxy, instructions};

fn main() -> ExitCode {
    let args = match args::parse(std::env::args().skip(1)) {
        Ok(Command::Run(args)) => args,
        Ok(Command::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("devproxy: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    // One thread, like the tunnel's runtime.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("devproxy: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        let proxy = match DevProxy::prepare(&args).await {
            Ok(proxy) => proxy,
            Err(e) => {
                eprintln!("devproxy: {e}");
                return ExitCode::FAILURE;
            }
        };
        println!(
            "{}",
            instructions(proxy.proxy_addr(), proxy.dns_addr(), &proxy.ca_path())
        );
        let stats = proxy
            .serve(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await;
        println!("{stats:#?}");
        ExitCode::SUCCESS
    })
}
```

- [ ] **Step 4: Run the tests, fmt and clippy**

Run: `cd core && cargo test -p devproxy && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS: `args` 5, `fetch` 5 (1 ignored), `server` 5 and `udp` 4 passed; fmt and clippy print nothing

- [ ] **Step 5: Run the binary**

Run: `cd core && cargo run -q -p devproxy -- --help | head -n 3`
Expected:

```
Usage: devproxy [options]

Runs Tollgate's DNS responder and HTTPS filtering proxy on this machine.
```

Run: `cd core && cargo run -q -p devproxy -- --bogus; echo "exit $?"`
Expected: `devproxy: unknown argument "--bogus"`, a blank line, the usage text, then `exit 2`.

- [ ] **Step 6: Commit**

```bash
git add core/Cargo.lock core/tools/devproxy/Cargo.toml core/tools/devproxy/src/lib.rs core/tools/devproxy/src/server.rs core/tools/devproxy/src/main.rs core/tools/devproxy/tests/server.rs
git commit -m "devproxy: DNS on UDP and the proxy for Firefox, with Firefox instructions"
```

---

### Task 13: Manual checklist and README

**Files:**
- Create: `docs/experiments/m1-devproxy.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: the devproxy binary (Task 12).
- Produces: the manual end-to-end procedure with pass criteria.

- [ ] **Step 1: Write the checklist**

`docs/experiments/m1-devproxy.md`:

```markdown
# M1 devproxy checks

Manual end-to-end check of the Rust core on the Linux workstation: the DNS responder and the
filtering proxy from `tools/devproxy`, driven by `dig`, `curl`, `openssl s_client` and
Firefox. Record the date, the commit and the outcome of each step. Commands run from the
repo root and need the network. The data directory is `/tmp/tollgate-dev`.

## 1. Build and start with the default lists

1. `(cd core && cargo build --release -p devproxy)`
2. `rm -rf /tmp/tollgate-dev && RUST_LOG=info core/target/release/devproxy --data-dir /tmp/tollgate-dev --default-lists`
3. Pass: five `bytes` lines (one per list), a `compiled ... network rules ... DNS names` line
   with more than 100,000 network rules and more than 200,000 DNS names, a `generated a new
   root CA` line, and the "Tollgate devproxy is running." block naming `127.0.0.1:8080`,
   `127.0.0.1:5353` and `/tmp/tollgate-dev/ca.pem`.
4. `ls -l /tmp/tollgate-dev`. Pass: `ca.key` and `ca.pem` are `-rw-------`; `engine.dat` is
   about 5 MB and `domains.bin` about 1.7 MB.

If step 2 fails with `DNS listener 127.0.0.1:5353: Address already in use`, another program
holds 5353 without `SO_REUSEADDR`; add `--dns 127.0.0.1:5354` and use port 5354 below.

Result:

## 2. DNS

1. `dig @127.0.0.1 -p 5353 doubleclick.net A +short`. Pass: `0.0.0.0`.
2. `dig @127.0.0.1 -p 5353 doubleclick.net AAAA +short`. Pass: `::`.
3. `dig @127.0.0.1 -p 5353 example.com A +short`. Pass: one or more public IPv4 addresses.
4. Run step 3 again. Pass: the same addresses, answered at once (cache).
5. `dig @127.0.0.1 -p 5353 example.com HTTPS`. Pass: `status: NOERROR` and `ANSWER: 0`.

Result:

## 3. Proxy with curl

1. `curl -sS -x http://127.0.0.1:8080 -o /dev/null -w '%{http_code}\n' http://example.com/`.
   Pass: `200`.
2. `curl -sS -v -x http://127.0.0.1:8080 --cacert /tmp/tollgate-dev/ca.pem -o /dev/null -w '%{http_code} HTTP/%{http_version}\n' https://example.com/ 2>&1 | grep -E 'issuer|HTTP/'`.
   Pass: the output contains `issuer: CN=Tollgate Root CA; O=Tollgate` and ends with
   `200 HTTP/2`.
3. `curl -sS -x http://127.0.0.1:8080 --cacert /tmp/tollgate-dev/ca.pem -o /dev/null -w '%{http_code}\n' https://securepubads.g.doubleclick.net/tag/js/gpt.js`.
   Pass: `403`.
4. `curl -sS -v -x http://127.0.0.1:8080 -o /dev/null https://www.apple.com/ 2>&1 | grep issuer`.
   Pass: an Apple issuer, not Tollgate (bundled passthrough; no `--cacert` needed).
5. `ps -o rss= -C devproxy`. Pass: below 40,000 (KiB). The release build measured about
   16,000 on the workstation after three intercepted HTTPS pages; the phone's budget for the
   engine and the blocklist alone is about 10 MiB.

Result:

## 4. Pin learning

1. Run twice: `echo | openssl s_client -proxy 127.0.0.1:8080 -connect example.net:443 -servername example.net -verify_return_error 2>&1 | grep 'Verify return code'`.
   Pass: both print `Verify return code: 20 (unable to get local issuer certificate)`, and the
   devproxy log shows `learned certificate pin for example.net after UnknownCa` after the
   second run.
2. Run it a third time. Pass: `Verify return code: 0 (ok)`; the certificate is the site's own
   (passthrough).
3. Observation only (E4 decides how iOS clients fail): run
   `curl -sS -x http://127.0.0.1:8080 -o /dev/null https://example.org/` twice and note
   whether the counters printed at exit (step 6) grow `tls_client_rejections` or
   `tls_abandoned_after_handshake`. On the workstation used for this plan, curl 8.22 with
   OpenSSL 3.6 grew `tls_abandoned_after_handshake`, so curl alone never teaches a pin.

Result:

## 5. Firefox

1. `firefox -P tollgate-dev --no-remote` (create the profile when asked). Apply the three
   settings devproxy printed: manual proxy `127.0.0.1` port `8080` also for HTTPS, import
   `/tmp/tollgate-dev/ca.pem` under Authorities with "Trust this CA to identify websites",
   and in `about:config` `network.trr.mode` = 5 and `network.dns.echconfig.enabled` = false.
2. Open `https://example.com`. Pass: the page loads; the padlock's certificate viewer shows
   the issuer `Tollgate Root CA`.
3. Open a news site with ads, for example `https://www.theguardian.com/international`. Pass:
   the page loads and works; the network panel (F12) shows requests answered `403` for ad and
   tracker hosts; restart devproxy with `RUST_LOG=debug` to see `blocked ...` lines.
4. Open `https://www.icloud.com`. Pass: it loads with an Apple certificate (passthrough).
5. Log in to one site you use and click through a few pages. Pass: nothing breaks; if
   something does, note the URL and the blocked requests from the debug log.

Result:

## 6. Stop

1. Press Ctrl-C in the devproxy terminal. Pass: it prints the `StatsSnapshot` counters and
   exits; `/tmp/tollgate-dev/learned-pins.json` lists `example.net`.
2. Start it again without list options:
   `core/target/release/devproxy --data-dir /tmp/tollgate-dev`. Pass: no download or compile
   lines, no `generated a new root CA` line, and step 4.2 still passes at once (the pin was
   loaded).

Result:
```

- [ ] **Step 2: Update the README**

`README.md`:

````markdown
# Tollgate

Tollgate is a personal iOS ad blocker. It runs as an on-device packet tunnel (a Network
Extension "VPN" whose traffic never leaves the phone), blocks ad and tracker domains at the
DNS layer, and filters HTTPS requests through a local proxy that trusts a user-installed root
certificate, so full URL rules (EasyList, uBlock Origin and AdGuard syntax) apply to Safari,
web views and third-party apps.

It is not distributed through the App Store. It is built and signed by GitHub Actions with
the owner's Apple Developer account and installed from a Linux workstation.

Status: M1, the Rust core (DNS blocking, the HTTPS filtering proxy and the Swift-facing
engine), tested on Linux; the tunnel still runs the M0 first-light code. See the
[design](docs/superpowers/specs/2026-09-24-tollgate-design.md) and the
[feasibility research](docs/research/2026-09-23-feasibility-brief.md).

## How it is built

- `core/`: Rust workspace. Filtering, DNS and the HTTPS proxy live here and are developed and
  tested on Linux with `cargo test`. `tollgate-ffi` exposes them to Swift through uniffi.
- `core/tools/devproxy`: runs the same DNS responder and proxy on the workstation for
  Firefox; `devproxy --help` and [the checklist](docs/experiments/m1-devproxy.md).
- `ios/`: a thin SwiftUI app and a `NEPacketTunnelProvider` extension. The Xcode project is
  generated from `ios/project.yml` with XcodeGen; nobody edits a `.xcodeproj`.
- `.github/workflows/ios.yml`: on an Apple silicon runner, cross-compiles the Rust core for
  `aarch64-apple-ios`, generates the Swift bindings, generates the project, archives, signs
  and uploads `Tollgate.ipa` as a workflow artifact. Without signing secrets (for example on
  pull requests from forks) it only checks that everything compiles.
- Identifiers (bundle IDs, App Group, profile names) live in `tooling/config.env` only.

## One-time signing setup

1. In App Store Connect, Users and Access, Integrations, create a Team API key with Admin
   access and save the `.p8` file somewhere private, for example `~/.config/tollgate/`.
2. In the Apple Developer portal, register the App Group named in `tooling/config.env`.
3. With the iPhone connected over USB:

   ```bash
   export ASC_KEY_ID=... ASC_ISSUER_ID=... ASC_KEY_PATH=~/.config/tollgate/AuthKey_XXXX.p8
   tooling/asc/provision.py setup
   ```

   This registers the phone, creates both App IDs with the Network Extensions and App Groups
   capabilities, creates an Apple Development certificate and the development profiles.
4. In the portal, assign the App Group to both App IDs, then run
   `tooling/asc/provision.py profiles` again.
5. `tooling/asc/push-secrets.sh` stores the certificate and profiles as repository secrets.

Everything written by the provisioning tool goes to `tooling/asc/out/`, which is gitignored.

## Install and debug

```bash
tooling/scripts/fetch-ipa.sh      # latest successful CI build of main (or pass a branch)
tooling/scripts/install.sh        # install on the USB-connected iPhone
tooling/scripts/logs.sh tunnel    # stream the extension's logs
```

The first install of a development-signed app asks for Developer Mode on the phone
(Settings, Privacy & Security, Developer Mode), followed by a reboot.

## License

MIT
````

- [ ] **Step 3: Check the text**

Run: `grep -n "$(printf '\342\200\224')" docs/experiments/m1-devproxy.md README.md; echo "exit $?"`
Expected: `exit 1` (no em-dash).

- [ ] **Step 4: Commit**

```bash
git add docs/experiments/m1-devproxy.md README.md
git commit -m "docs: devproxy checklist and M1 status"
```

---

### Task 14: Workspace verification

**Files:** none changed.

**Interfaces:**
- Consumes: everything above. Produces: evidence that the branch is ready for review.

- [ ] **Step 1: Format, lint and test**

Run: `cd core && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace 2>&1 | grep -E '^test result' | awk '{p+=$4; f+=$6; i+=$8} END {print p " passed, " f " failed, " i " ignored"}'`
Expected: fmt and clippy clean, then `270 passed, 0 failed, 7 ignored`. Per crate: tollgate-common 12 passed and 1 ignored, tollgate-policy 34, tollgate-filter 45 and 2 ignored, tollgate-dns 68 and 2 ignored, tollgate-mitm 58 and 1 ignored, tollgate-ffi 34, devproxy 19 and 1 ignored.

- [ ] **Step 2: No aws-lc anywhere**

Run: `cd core && cargo tree -i aws-lc-sys; cargo tree -i aws-lc-rs`
Expected: both exit with status 101 and ``error: package ID specification `aws-lc-sys` did not match any packages`` (then the same for `aws-lc-rs`).

- [ ] **Step 3: Pinned versions**

Run: `cd core && cargo tree -p tollgate-ffi -e normal --depth 1 && cargo tree -p devproxy -e normal --depth 1`
Expected:

```
tollgate-ffi v0.1.0 (...)
├── arc-swap v1.9.2
├── log v0.4.34
├── ring v0.17.14
├── rustls v0.23.45
├── thiserror v2.0.21
├── tokio v1.53.1
├── tollgate-common v0.1.0 (...)
├── tollgate-dns v0.1.0 (...)
├── tollgate-filter v0.1.0 (...)
├── tollgate-mitm v0.1.0 (...)
├── tollgate-policy v0.1.0 (...)
└── uniffi v0.32.2
devproxy v0.1.0 (...)
├── arc-swap v1.9.2
├── bytes v1.12.1
├── env_logger v0.11.11
├── http-body-util v0.1.5
├── hyper v1.11.1
├── hyper-util v0.1.21
├── log v0.4.34
├── rustls v0.23.45
├── socket2 v0.6.5
├── thiserror v2.0.21
├── tokio v1.53.1
├── tokio-rustls v0.26.5
├── tollgate-common v0.1.0 (...)
├── tollgate-dns v0.1.0 (...)
├── tollgate-ffi v0.1.0 (...)
├── tollgate-filter v0.1.0 (...)
├── tollgate-mitm v0.1.0 (...)
└── tollgate-policy v0.1.0 (...)
```

- [ ] **Step 4: Type-check the non-test code for iOS**

On macOS with Xcode: `cd core && cargo check --workspace --target aarch64-apple-ios`.

On Linux, ring's build script needs an iOS C toolchain, so point it at a stub SDK and the host clang (`rustup target add aarch64-apple-ios` first if the target is missing):

```bash
STUB="$(mktemp -d)"
mkdir -p "$STUB/usr/include"
printf '#pragma once\n#define TARGET_OS_MAC 1\n#define TARGET_OS_IPHONE 1\n#define TARGET_OS_IOS 1\n#define TARGET_OS_OSX 0\n#define TARGET_OS_SIMULATOR 0\n#define TARGET_OS_TV 0\n#define TARGET_OS_WATCH 0\n#define TARGET_OS_VISION 0\n#define TARGET_OS_MACCATALYST 0\n' > "$STUB/usr/include/TargetConditionals.h"
printf '#pragma once\n#define assert(x) ((void)0)\n' > "$STUB/usr/include/assert.h"
printf '#pragma once\n#include <stddef.h>\nvoid *memcpy(void *, const void *, size_t);\nvoid *memset(void *, int, size_t);\nint memcmp(const void *, const void *, size_t);\nvoid *memmove(void *, const void *, size_t);\n' > "$STUB/usr/include/string.h"
(cd core && SDKROOT="$STUB" CC_aarch64_apple_ios=clang AR_aarch64_apple_ios=llvm-ar cargo check --workspace --target aarch64-apple-ios 2>&1 | tail -n 1)
rm -rf "$STUB"
```

Expected: `Finished` with no errors.

- [ ] **Step 5: The iOS static library needs only libSystem**

Builds the release staticlib the way `build-core-ios.sh` does, with the same stub SDK, and lists the symbols it takes from outside itself. Xcode links it with `-ltollgate_ffi` only, so none of them may come from a framework (CoreFoundation, Security, SystemConfiguration, Foundation, the Objective-C runtime) or from libiconv:

```bash
STUB="$(mktemp -d)"
mkdir -p "$STUB/usr/include"
printf '#pragma once\n#define TARGET_OS_MAC 1\n#define TARGET_OS_IPHONE 1\n#define TARGET_OS_IOS 1\n#define TARGET_OS_OSX 0\n#define TARGET_OS_SIMULATOR 0\n#define TARGET_OS_TV 0\n#define TARGET_OS_WATCH 0\n#define TARGET_OS_VISION 0\n#define TARGET_OS_MACCATALYST 0\n' > "$STUB/usr/include/TargetConditionals.h"
printf '#pragma once\n#define assert(x) ((void)0)\n' > "$STUB/usr/include/assert.h"
printf '#pragma once\n#include <stddef.h>\nvoid *memcpy(void *, const void *, size_t);\nvoid *memset(void *, int, size_t);\nint memcmp(const void *, const void *, size_t);\nvoid *memmove(void *, const void *, size_t);\n' > "$STUB/usr/include/string.h"
(cd core && SDKROOT="$STUB" CC_aarch64_apple_ios=clang AR_aarch64_apple_ios=llvm-ar IPHONEOS_DEPLOYMENT_TARGET=17.0 cargo build -q --release -p tollgate-ffi --target aarch64-apple-ios)
rm -rf "$STUB"
LIB=core/target/aarch64-apple-ios/release/libtollgate_ffi.a
UNDEF="$(mktemp)"
comm -23 <(llvm-nm -u "$LIB" 2>/dev/null | awk '{print $NF}' | grep -v ':$' | sort -u) <(llvm-nm -g --defined-only "$LIB" 2>/dev/null | awk 'NF>=3 {print $3}' | sort -u) > "$UNDEF"
grep -c -x -e _os_proc_available_memory -e _CCRandomGenerateBytes -e _kqueue -e _getaddrinfo "$UNDEF"
grep -E '^_(CF|Sec|SC[A-Z]|NS[A-Z]|objc_|OBJC_|iconv)' "$UNDEF"; echo "framework symbols: exit $?"
rm -f "$UNDEF"
```

Expected: `4` (the list is real: `os_proc_available_memory`, `CCRandomGenerateBytes`, `kqueue` and `getaddrinfo`, all libSystem), then `framework symbols: exit 1`.

- [ ] **Step 6: Swift bindings**

Run: `tooling/scripts/build-core-ios.sh --host > /dev/null && grep -c -e '^public protocol CoreLogger: AnyObject, Sendable {' -e '^public protocol PacketSink: AnyObject, Sendable {' build/bindings-host/Swift/tollgate_ffi.swift`
Expected: `2`

- [ ] **Step 7: The network tests**

Run: `cd core && cargo test -p devproxy --test fetch -- --ignored`
Expected: `test downloads_easylist ... ok` and `1 passed; 0 failed`

- [ ] **Step 8: No em-dashes**

Run: `grep -rn "$(printf '\342\200\224')" core/crates/tollgate-ffi core/tools/devproxy core/Cargo.toml .github/workflows/core.yml docs/experiments/m1-devproxy.md README.md docs/superpowers/plans/2026-09-25-m1d-ffi-devproxy.md; echo "exit $?"`
Expected: `exit 1`

- [ ] **Step 9: Manual check**

Work through `docs/experiments/m1-devproxy.md` with Firefox and record the results in that file (commit them on this branch).

- [ ] **Step 10: Push the branch for review**

Run: `git push -u origin m1d-ffi-devproxy`
Expected: the branch is on GitHub; the owner opens and merges the PR (PR text is drafted in the conversation first).

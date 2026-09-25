# M1a: Common, Policy and Filter Crates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the three foundation crates of the Rust core (`tollgate-common`, `tollgate-policy`, `tollgate-filter`) on Linux, implementing their M1 crate contracts exactly, with every prototype review fix the spec adopted.

**Architecture:** `tollgate-common` holds the continuous clock, the shared ring-only rustls client configuration and the statistics counters. `tollgate-policy` decides per host whether the proxy intercepts (user, bundled and learned passthrough, pin learning). `tollgate-filter` wraps adblock 0.13.3 for URL checks and adds a hashed, mmapped DNS blocklist (`domains.bin`), plus the compile step that writes `engine.dat` and `domains.bin` atomically.

**Tech Stack:** Rust 1.94+ (edition 2024; local toolchain 1.98.1), adblock =0.13.3, rustls 0.23.45 (ring provider), webpki-roots 1.0.9, ring 0.17.14, memmap2 0.9.11, libc 0.2.189, serde 1.0.229, serde_json 1.0.151, thiserror 2.0.21, log 0.4.34, uniffi 0.32.2 (default features off); tests only: rcgen 0.14.10, tempfile 3.27.0.

**Spec:** docs/superpowers/specs/2026-09-24-tollgate-design.md (sections "Rust core", "Revisions after the M1 prototypes", "M1 crate contracts").

## Global Constraints

- No em-dashes (the character U+2014) anywhere in the plan, in code comments or in commit messages.
- Commit messages have no `Co-Authored-By` lines.
- Work happens on the branch `m1a-common-policy-filter`, never on `main`.
- Rust crates: `edition = "2024"`, `rust-version = "1.94"`, dependency versions managed in `core/Cargo.toml` `[workspace.dependencies]`.
- rustls (and any later tokio-rustls) with `default-features = false` and the ring provider only; no aws-lc anywhere: `cargo tree -i aws-lc-sys` must report that nothing matches.
- `cargo clippy --workspace --all-targets -- -D warnings` is clean after every task.
- The M1 crate contracts in the spec are binding: every signature there is implemented exactly; this plan only adds private items and extra public helpers.

## Decisions

Choices the spec left to the plan, with the reason.

- **Policy time is wall-clock Unix seconds.** Every `now` passed to `Policy` comes from the new helper `tollgate_common::clock::unix_secs()`. Learned pins are saved to the App Group and must survive a reboot, and the continuous clock (`now_secs`) restarts at boot. `now_secs` stays the clock for in-memory expiry (the DNS cache).
- **Which list feeds which file.** `compile(lists, dir)` gives the engine every `Adblock` list and gives the DNS blocklist every list. A DNS list written in adblock syntax (the AdGuard DNS filter) must not reach the engine: measured with the cached lists, it grows `engine.dat` from 4.80 MiB to 12.2 MiB. The extra public helper `compile_split(engine_lists, dns_lists, dir)` routes lists explicitly; `compile` calls it. M1d should call `compile_split` with the URL lists (EasyList, EasyPrivacy, AdGuard Mobile Ads) and the DNS lists (AdGuard DNS filter, StevenBlack hosts).
- **`domains.bin` layout.** 32-byte little-endian header (`TGDS`, version 1, block, allow and important counts, a reserved zero field that keeps the body 8-byte aligned, FNV-1a 64 checksum of the body), then the three sorted hash sections. Load validates magic, version, reserved field, exact length, checksum and strict sort order of each section, and returns `DomainSetError` instead of panicking. Hashes are read with `as_chunks::<8>()` and `u64::from_le_bytes`, so lookups need no `unsafe`, no alignment and no particular byte order. The only `unsafe` is `Mmap::map`, which is sound because `compile` never writes into an existing file.
- **DNS name rules.** Names are lowercase ASCII without a trailing dot, at least one dot, labels of 1 to 63 letters, digits, `-` or `_`, at most 253 bytes, and a last label that is not all digits (drops IPv4 addresses). Lookups hash the host and each parent that still contains a dot. `.name^` is stored as the name (the apex is also blocked, as the review accepted). `||name` without a caret counts unless it ends in a dot (a prefix rule). `@@||name^$important` is kept as a plain exception, so an important block still wins; no DNS list uses it. Any option other than `important` and `badfilter` skips the line. `localhost.localdomain` is dropped from hosts lists.
- **Redundant children** are removed within each section (blocks, exceptions, important blocks). This cannot change a result because every lookup checks all parents.
- **Bundled passthrough snapshot (627 patterns).** All hosts in Apple support article 101555 (published 2026-08-07), collapsed to `*.domain`; all of AdGuard HttpsExclusions `exclusions/sensitive.txt`; and the second-level `.com`, `.org` and `.net` domains of `exclusions/banks.txt`, at commit a8eda6ecc184cc7000436302d64fb932d5205fe0 (2026-09-14). The full banks list has about 4,000 entries, 1,439 of them German regional banks; the rest would make the snapshot about six times larger, mostly with regional banks, and pin learning plus the user list cover them. AdGuard entries cover subdomains, so each becomes `*.domain`; `$app=` entries (desktop-app specific) are dropped.
- **HostPattern syntax.** Surrounding whitespace is trimmed; `*` is only valid as a leading `*.`; single-label names (`localhost`) and IPv4 literals are valid exact patterns; labels allow letters, digits, `-` and `_`. Matching compares bytes ASCII-case-insensitively, so non-ASCII input never panics.
- **Policy construction.** An invalid user pattern fails `Policy::new` with `PolicyError::InvalidPattern`; the app validates input with `HostPattern::parse` first. A learned pins file that cannot be read (bad JSON, other version) is logged and ignored, because it is a cache that rebuilds itself.
- **Pin learning details.** Every `RejectionKind` counts the same (M1c only reports the four alerts the spec lists). Two rejections count when at most 600 s apart (inclusive). A pin is live while `now - learned_at < 30 days`. Pins are per exact host, not per domain. Expired pins are dropped on the next recorded rejection. At most 1,024 hosts with a single pending rejection are remembered (stale ones first, then the oldest). The file format is `{"version":1,"pins":[{"host":...,"learned_at":...}]}`, sorted by host.
- **Request types.** `Sec-Fetch-Dest` table: `document` to `document`; `iframe`, `frame`, `fencedframe` to `sub_frame`; `style` to `stylesheet`; `script`, `worker`, `sharedworker`, `serviceworker`, `audioworklet`, `paintworklet` to `script`; `image`; `font`; `audio`, `video`, `track` to `media`; `object`, `embed` to `object`; `empty` and `json` to `xmlhttprequest`; `report` to `ping`; `manifest`, `webidentity`, `xslt` to `other`. An unknown value falls through to `Accept`, judged by its first media range, then to the path extension. A test proves adblock parses every produced string to the intended `RequestType`.
- **Source URL** is an extra helper `tollgate_filter::source_url(url, request_type, referer, origin)`: a `document` is its own source, then `Referer`, then `Origin` (`null` counts as missing), then empty. M1c can call it instead of re-implementing the rule.
- **`FilterEngine::check`** passes method `GET` (the contract has no method argument). Errors from adblock are mapped to `FilterError::Engine(String)` so adblock types stay out of the public API.
- **Atomic writes.** Each file is written to `.<name>.<pid>.tmp` in the target directory, `sync_all`, then renamed; the engine is replaced first, then the domain set. Each file is atomic on its own; the pair is not, which is harmless because they are loaded independently.
- **Logging** is the `log` facade used directly; `tollgate-common` has no logging wrapper.
- **Extra public helpers:** `clock::unix_secs`, `tls::webpki_root_store`, `Stats::inc`, `DohUpstream::cloudflare`/`quad9`, `HostPattern::name`/`is_wildcard` and `Display`, `REJECTION_WINDOW_SECS`, `PIN_LIFETIME_SECS`, `DomainRules`, `DomainSetError`, `DomainSet::is_empty` (required by clippy next to `len`), `network_rule_count`, `REGEX_CLEANUP_INTERVAL`, `REGEX_DISCARD_UNUSED`, `compile_split`. `DohUpstream` fields `port` and `path` default to 443 and `/dns-query` when missing from JSON.
- **Dependency requirements** are caret requirements at the pinned versions (the lock file resolves to exactly those), except adblock, which is `=0.13.3` because the app writes `engine.dat` and the extension reads it. `tempfile` 3.27.0 (current on crates.io) is a test-only dependency.
- **Tests are integration tests** (`crates/*/tests/*.rs`) against the public API, so each code block in this plan is a whole file.
- **iOS check on Linux.** ring's build script needs an iOS C toolchain, which Linux lacks; Task 15 type-checks for `aarch64-apple-ios` with a stub SDK (three headers) and the host clang, the same method the prototype review used. Linking still happens only in the macOS CI job.

---

## File map

```
core/Cargo.toml                                  (modify) members, [workspace.dependencies], uniffi default features off
core/tools/uniffi-bindgen-swift/Cargo.toml       (modify) enables uniffi cli + cargo-metadata
core/crates/common/Cargo.toml                    tollgate-common manifest
core/crates/common/src/lib.rs                    module list
core/crates/common/src/clock.rs                  now_secs (continuous), unix_secs (wall clock)
core/crates/common/src/tls.rs                    client_config, webpki_root_store
core/crates/common/src/stats.rs                  Stats, StatsSnapshot
core/crates/common/tests/clock.rs
core/crates/common/tests/tls.rs                  includes one #[ignore] network test
core/crates/common/tests/stats.rs
core/crates/policy/Cargo.toml                    tollgate-policy manifest
core/crates/policy/src/lib.rs                    exports, PolicyError
core/crates/policy/src/config.rs                 Config, DohUpstream
core/crates/policy/src/pattern.rs                HostPattern
core/crates/policy/src/bundled.rs                bundled passthrough snapshot (627 patterns)
core/crates/policy/src/policy.rs                 Policy, Decision, pin learning
core/crates/policy/tests/config.rs
core/crates/policy/tests/pattern.rs
core/crates/policy/tests/bundled.rs
core/crates/policy/tests/policy.rs
core/crates/filter/Cargo.toml                    tollgate-filter manifest
core/crates/filter/src/lib.rs                    exports, ListFormat, ListSource, FilterError
core/crates/filter/src/engine.rs                 FilterEngine, Verdict, network_rule_count
core/crates/filter/src/request_type.rs           request_type, source_url
core/crates/filter/src/domain_rules.rs           DomainRules: host rules parsed from lists
core/crates/filter/src/domain_set.rs             domains.bin format, DomainSet
core/crates/filter/src/compile.rs                compile, compile_split, CompileReport
core/crates/filter/tests/engine.rs
core/crates/filter/tests/request_type.rs
core/crates/filter/tests/domain_rules.rs
core/crates/filter/tests/domain_set.rs
core/crates/filter/tests/compile.rs
core/crates/filter/tests/measure.rs              #[ignore] measurement with real lists
```

`core/Cargo.lock` changes with the new dependencies and is committed with each task that changes it.

---

### Task 1: Workspace dependencies and uniffi without default features

**Files:**
- Modify: `core/Cargo.toml`, `core/tools/uniffi-bindgen-swift/Cargo.toml`
- Test: `cargo tree` checks (no Rust test; this task only changes manifests)

**Interfaces:**
- Consumes: the M0 workspace (`crates/tollgate-ffi`, `tools/uniffi-bindgen-swift`).
- Produces: `[workspace.dependencies]` entries `uniffi` (default features off), `ring`, `rustls` (ring, std, logging, tls12; no defaults), `webpki-roots`, `adblock` (`=0.13.3`, no defaults, `embedded-domain-resolver` + `full-regex-handling`), `memmap2`, `libc`, `log`, `serde` (derive), `serde_json`, `thiserror`, `rcgen` (ring, no defaults), `tempfile`. The runtime crate no longer builds `cargo_metadata`; the bindings tool still does.

- [ ] **Step 1: Create the branch**

Run: `git checkout main && git pull && git checkout -b m1a-common-policy-filter`
Expected: `Switched to a new branch 'm1a-common-policy-filter'`.

- [ ] **Step 2: Show that the runtime crate pulls in cargo_metadata today**

Run: `cd core && cargo tree -p tollgate-ffi -e normal --target aarch64-apple-ios | grep -c cargo_metadata`
Expected: `1`: uniffi's default `cargo-metadata` feature reaches the iOS static library.

- [ ] **Step 3: Workspace manifest**

`core/Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = [
    "crates/tollgate-ffi",
    "tools/uniffi-bindgen-swift",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"
rust-version = "1.94"
publish = false

[workspace.dependencies]
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

# Tests only.
rcgen = { version = "0.14.10", default-features = false, features = ["crypto", "ring", "pem"] }
tempfile = "3.27.0"

[profile.release]
opt-level = "s"
lto = "thin"
codegen-units = 1
debug = "line-tables-only"
```

`core/tools/uniffi-bindgen-swift/Cargo.toml`:

```toml
[package]
name = "uniffi-bindgen-swift"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
# The workspace turns uniffi's default features off; the bindings generator needs
# cargo-metadata to find each crate's uniffi configuration.
uniffi = { workspace = true, features = ["cli", "cargo-metadata"] }
```

- [ ] **Step 4: Verify the split and that both crates still build**

Run: `cd core && cargo tree -p tollgate-ffi -e normal --target aarch64-apple-ios | grep -c cargo_metadata`
Expected: `0`.

Run: `cd core && cargo tree -p uniffi-bindgen-swift -e normal | grep -c cargo_metadata`
Expected: `2`.

Run: `cd core && cargo test -p tollgate-ffi && cargo clippy --workspace --all-targets -- -D warnings`
Expected: 3 passed; clippy clean.

Run: `tooling/scripts/build-core-ios.sh --host && grep -cE 'func (coreVersion|ping|sha256Hex)\(' build/bindings-host/Swift/tollgate_ffi.swift`
Expected: the script lists `build/bindings-host`, then `3`.

- [ ] **Step 5: Commit**

```bash
git add core/Cargo.toml core/Cargo.lock core/tools/uniffi-bindgen-swift/Cargo.toml
git commit -m "Turn off uniffi default features and add M1 workspace dependencies"
```

---

### Task 2: tollgate-common crate with the continuous clock

**Files:**
- Modify: `core/Cargo.toml`
- Create: `core/crates/common/Cargo.toml`, `core/crates/common/src/lib.rs`, `core/crates/common/src/clock.rs`
- Test: `core/crates/common/tests/clock.rs`

**Interfaces:**
- Consumes: `libc` (workspace).
- Produces:
  - `pub fn tollgate_common::clock::now_secs() -> u64` (contract): `CLOCK_MONOTONIC` on `target_vendor = "apple"`, `CLOCK_BOOTTIME` on Linux and Android, wall clock elsewhere.
  - `pub fn tollgate_common::clock::unix_secs() -> u64` (extra): wall-clock Unix seconds.

- [ ] **Step 1: Add the crate with a failing test**

`core/Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = [
    "crates/common",
    "crates/tollgate-ffi",
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

# Tests only.
rcgen = { version = "0.14.10", default-features = false, features = ["crypto", "ring", "pem"] }
tempfile = "3.27.0"

[profile.release]
opt-level = "s"
lto = "thin"
codegen-units = 1
debug = "line-tables-only"
```

`core/crates/common/Cargo.toml`:

```toml
[package]
name = "tollgate-common"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
publish.workspace = true

[dependencies]
libc = { workspace = true }
```

`core/crates/common/src/lib.rs` (doc comment only for now):

```rust
//! Pieces shared by the dns, mitm and ffi crates: a clock that keeps counting while the
//! device sleeps, the rustls client configuration and the statistics counters.
//!
//! Logging is not wrapped here: every crate logs through the `log` facade directly.
```

`core/crates/common/tests/clock.rs`:

```rust
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd core && cargo test -p tollgate-common --test clock`
Expected: FAIL to compile with `` error[E0432]: unresolved import `tollgate_common::clock` ``.

- [ ] **Step 3: Implement the clock**

`core/crates/common/src/lib.rs`:

```rust
//! Pieces shared by the dns, mitm and ffi crates: a clock that keeps counting while the
//! device sleeps, the rustls client configuration and the statistics counters.
//!
//! Logging is not wrapped here: every crate logs through the `log` facade directly.

pub mod clock;
```

`core/crates/common/src/clock.rs`:

```rust
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd core && cargo test -p tollgate-common --test clock && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: 4 passed (`now_secs_advances_with_real_time` sleeps about 2 s); clippy and fmt clean.

- [ ] **Step 5: Commit**

```bash
git add core/Cargo.toml core/Cargo.lock core/crates/common
git commit -m "Add tollgate-common with a clock that keeps counting during sleep"
```

---

### Task 3: Shared rustls client configuration

**Files:**
- Modify: `core/crates/common/Cargo.toml`, `core/crates/common/src/lib.rs`
- Create: `core/crates/common/src/tls.rs`
- Test: `core/crates/common/tests/tls.rs`

**Interfaces:**
- Consumes: `rustls` (ring provider, no defaults), `webpki-roots`; `rcgen` in tests.
- Produces:
  - `pub fn tollgate_common::tls::client_config(alpn: &[&[u8]]) -> std::sync::Arc<rustls::ClientConfig>` (contract).
  - `pub fn tollgate_common::tls::webpki_root_store() -> rustls::RootCertStore` (extra).

- [ ] **Step 1: Manifest and failing tests**

`core/crates/common/Cargo.toml`:

```toml
[package]
name = "tollgate-common"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
publish.workspace = true

[dependencies]
libc = { workspace = true }
rustls = { workspace = true }
webpki-roots = { workspace = true }

[dev-dependencies]
rcgen = { workspace = true }
```

`core/crates/common/tests/tls.rs`:

```rust
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{CertificateError, ClientConnection, ServerConfig, ServerConnection};
use tollgate_common::tls::{client_config, webpki_root_store};

#[test]
fn alpn_is_offered_in_the_given_order() {
    let config = client_config(&[b"h2", b"http/1.1"]);
    assert_eq!(
        config.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert!(client_config(&[]).alpn_protocols.is_empty());
}

#[test]
fn uses_the_ring_provider() {
    let config = client_config(&[b"h2"]);
    let ring = rustls::crypto::ring::default_provider();
    let ours: Vec<_> = config
        .crypto_provider()
        .cipher_suites
        .iter()
        .map(|s| s.suite())
        .collect();
    let expected: Vec<_> = ring.cipher_suites.iter().map(|s| s.suite()).collect();
    assert_eq!(ours, expected);
    assert!(!ours.is_empty());
}

#[test]
fn root_store_holds_the_webpki_roots() {
    let roots = webpki_root_store();
    assert_eq!(roots.len(), webpki_roots::TLS_SERVER_ROOTS.len());
    assert!(roots.len() > 100, "only {} roots", roots.len());
}

fn self_signed_server(name: &str) -> Arc<ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    Arc::new(config)
}

/// Runs a handshake over in-memory buffers and returns the client's error, if any.
fn handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), rustls::Error> {
    for _ in 0..16 {
        let mut to_server = Vec::new();
        client.write_tls(&mut to_server).unwrap();
        if !to_server.is_empty() {
            server.read_tls(&mut to_server.as_slice()).unwrap();
            let _ = server.process_new_packets();
        }
        let mut to_client = Vec::new();
        server.write_tls(&mut to_client).unwrap();
        if !to_client.is_empty() {
            client.read_tls(&mut to_client.as_slice()).unwrap();
            client.process_new_packets()?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("handshake did not finish");
}

#[test]
fn rejects_a_certificate_from_an_unknown_issuer() {
    let server_config = self_signed_server("example.com");
    let mut server = ServerConnection::new(server_config).unwrap();
    let name = ServerName::try_from("example.com").unwrap();
    let mut client = ClientConnection::new(client_config(&[b"h2"]), name).unwrap();
    let err = handshake(&mut client, &mut server).unwrap_err();
    assert_eq!(
        err,
        rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)
    );
}

// Needs the network. Run with:
//   cargo test -p tollgate-common --test tls -- --ignored
#[test]
#[ignore = "needs network access to 1.1.1.1:443"]
fn connects_to_cloudflare_dns_with_h2() {
    use std::io::Write;
    use std::net::TcpStream;
    use std::time::Duration;

    let name = ServerName::try_from("cloudflare-dns.com").unwrap();
    let mut conn = ClientConnection::new(client_config(&[b"h2"]), name).unwrap();
    let mut sock =
        TcpStream::connect_timeout(&"1.1.1.1:443".parse().unwrap(), Duration::from_secs(5))
            .unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    while conn.is_handshaking() {
        conn.complete_io(&mut sock).unwrap();
    }
    assert_eq!(conn.alpn_protocol(), Some(&b"h2"[..]));
    conn.send_close_notify();
    let _ = conn.complete_io(&mut sock);
    sock.flush().unwrap();
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd core && cargo test -p tollgate-common --test tls`
Expected: FAIL to compile with `` error[E0432]: unresolved import `tollgate_common::tls` `` (and a follow-on `E0308` mismatched types error).

- [ ] **Step 3: Implement**

`core/crates/common/src/lib.rs`:

```rust
//! Pieces shared by the dns, mitm and ffi crates: a clock that keeps counting while the
//! device sleeps, the rustls client configuration and the statistics counters.
//!
//! Logging is not wrapped here: every crate logs through the `log` facade directly.

pub mod clock;
pub mod tls;
```

`core/crates/common/src/tls.rs`:

```rust
//! The rustls client configuration shared by the DoH resolver and the proxy's upstream side.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};

/// Mozilla's root certificates from webpki-roots. The certificates are compiled in, so the
/// result is the same on every platform and never reads the system trust store.
pub fn webpki_root_store() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// rustls client configuration with the ring provider and webpki roots.
///
/// `alpn` is offered in the given order, for example `&[b"h2"]` for DNS over HTTPS or
/// `&[b"h2", b"http/1.1"]` for the proxy. The provider is passed explicitly, so this never
/// depends on a process-wide default provider being installed.
pub fn client_config(alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports TLS 1.2 and 1.3")
        .with_root_certificates(webpki_root_store())
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd core && cargo test -p tollgate-common --test tls && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: 4 passed, 1 ignored; clippy and fmt clean.

Run: `cd core && cargo tree -i aws-lc-sys`
Expected: exit status 101 with `` error: package ID specification `aws-lc-sys` did not match any packages ``: rustls brought in no aws-lc.

- [ ] **Step 5: Run the network test once**

Run: `cd core && cargo test -p tollgate-common --test tls -- --ignored`
Expected: `connects_to_cloudflare_dns_with_h2 ... ok` (needs outbound access to 1.1.1.1:443; this proves the webpki roots verify a real chain and ALPN negotiates h2).

- [ ] **Step 6: Commit**

```bash
git add core/Cargo.lock core/crates/common
git commit -m "Add the shared ring-only rustls client configuration"
```

---

### Task 4: Statistics counters

**Files:**
- Modify: `core/crates/common/src/lib.rs`
- Create: `core/crates/common/src/stats.rs`
- Test: `core/crates/common/tests/stats.rs`

**Interfaces:**
- Produces (contract): `pub struct Stats` with the twelve `AtomicU64` fields (`#[derive(Default, Debug)]`), `pub struct StatsSnapshot` with the same fields as `u64` (`#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]`), `impl Stats { pub fn snapshot(&self) -> StatsSnapshot; }`.
- Produces (extra): `impl Stats { pub fn inc(counter: &AtomicU64); }`.

- [ ] **Step 1: Write the failing tests**

`core/crates/common/tests/stats.rs`:

```rust
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tollgate_common::stats::{Stats, StatsSnapshot};

#[test]
fn new_stats_are_zero() {
    assert_eq!(Stats::default().snapshot(), StatsSnapshot::default());
}

#[test]
fn snapshot_copies_each_counter_into_its_own_field() {
    let stats = Stats::default();
    let counters = [
        &stats.dns_queries,
        &stats.dns_blocked,
        &stats.dns_cache_hits,
        &stats.dns_forwarded,
        &stats.dns_failed,
        &stats.packets_dropped,
        &stats.http_requests,
        &stats.http_blocked,
        &stats.connections_intercepted,
        &stats.connections_passthrough,
        &stats.tls_client_rejections,
        &stats.tls_abandoned_after_handshake,
    ];
    for (i, counter) in counters.iter().enumerate() {
        counter.fetch_add(i as u64 + 1, Ordering::Relaxed);
    }
    assert_eq!(
        stats.snapshot(),
        StatsSnapshot {
            dns_queries: 1,
            dns_blocked: 2,
            dns_cache_hits: 3,
            dns_forwarded: 4,
            dns_failed: 5,
            packets_dropped: 6,
            http_requests: 7,
            http_blocked: 8,
            connections_intercepted: 9,
            connections_passthrough: 10,
            tls_client_rejections: 11,
            tls_abandoned_after_handshake: 12,
        }
    );
}

#[test]
fn inc_counts_from_many_threads() {
    let stats = Arc::new(Stats::default());
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let stats = Arc::clone(&stats);
            std::thread::spawn(move || {
                for _ in 0..10_000 {
                    Stats::inc(&stats.http_requests);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let snapshot = stats.snapshot();
    assert_eq!(snapshot.http_requests, 80_000);
    assert_eq!(snapshot.http_blocked, 0);
}

#[test]
fn stats_can_be_shared_across_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Stats>();
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd core && cargo test -p tollgate-common --test stats`
Expected: FAIL to compile with `` error[E0432]: unresolved import `tollgate_common::stats` ``.

- [ ] **Step 3: Implement**

`core/crates/common/src/lib.rs`:

```rust
//! Pieces shared by the dns, mitm and ffi crates: a clock that keeps counting while the
//! device sleeps, the rustls client configuration and the statistics counters.
//!
//! Logging is not wrapped here: every crate logs through the `log` facade directly.

pub mod clock;
pub mod stats;
pub mod tls;
```

`core/crates/common/src/stats.rs`:

```rust
//! Lock-free counters shared by dns, mitm and ffi.
//!
//! Counters are independent and only read for display, so every access is `Relaxed`.

use std::sync::atomic::{AtomicU64, Ordering};

/// Lock-free counters shared by dns, mitm and ffi.
#[derive(Default, Debug)]
pub struct Stats {
    pub dns_queries: AtomicU64,
    pub dns_blocked: AtomicU64,
    pub dns_cache_hits: AtomicU64,
    pub dns_forwarded: AtomicU64,
    pub dns_failed: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub http_requests: AtomicU64,
    pub http_blocked: AtomicU64,
    pub connections_intercepted: AtomicU64,
    pub connections_passthrough: AtomicU64,
    pub tls_client_rejections: AtomicU64,
    pub tls_abandoned_after_handshake: AtomicU64,
}

/// A copy of every counter at one moment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
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

impl Stats {
    /// Adds one to a counter, for example `Stats::inc(&stats.dns_queries)`.
    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Reads every counter. Counters are read one by one, so a snapshot taken while other
    /// threads are counting may mix values from slightly different moments.
    pub fn snapshot(&self) -> StatsSnapshot {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        StatsSnapshot {
            dns_queries: get(&self.dns_queries),
            dns_blocked: get(&self.dns_blocked),
            dns_cache_hits: get(&self.dns_cache_hits),
            dns_forwarded: get(&self.dns_forwarded),
            dns_failed: get(&self.dns_failed),
            packets_dropped: get(&self.packets_dropped),
            http_requests: get(&self.http_requests),
            http_blocked: get(&self.http_blocked),
            connections_intercepted: get(&self.connections_intercepted),
            connections_passthrough: get(&self.connections_passthrough),
            tls_client_rejections: get(&self.tls_client_rejections),
            tls_abandoned_after_handshake: get(&self.tls_abandoned_after_handshake),
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd core && cargo test -p tollgate-common && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: clock 4 passed, stats 4 passed, tls 4 passed and 1 ignored; clippy and fmt clean.

- [ ] **Step 5: Commit**

```bash
git add core/crates/common
git commit -m "Add lock-free statistics counters"
```

---

### Task 5: tollgate-policy crate with Config

**Files:**
- Modify: `core/Cargo.toml`
- Create: `core/crates/policy/Cargo.toml`, `core/crates/policy/src/lib.rs`, `core/crates/policy/src/config.rs`
- Test: `core/crates/policy/tests/config.rs`

**Interfaces:**
- Consumes: `serde`, `serde_json`, `thiserror`.
- Produces (contract): `pub struct DohUpstream { pub ip: IpAddr, pub port: u16, pub tls_name: String, pub path: String }`, `pub struct Config { pub doh_upstreams: Vec<DohUpstream>, pub passthrough: Vec<String>, pub mitm_enabled: bool, pub max_intercepted_connections: u32 }` with `#[serde(default)]`, `impl Default for Config`, `Config::from_json(s: &str) -> Result<Config, PolicyError>`, `Config::to_json(&self) -> String`; `pub enum PolicyError { Config(String), .. }`.
- Produces (extra): `DohUpstream::cloudflare() -> DohUpstream`, `DohUpstream::quad9() -> DohUpstream`.

- [ ] **Step 1: Add the crate with failing tests**

`core/Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = [
    "crates/common",
    "crates/policy",
    "crates/tollgate-ffi",
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

# Tests only.
rcgen = { version = "0.14.10", default-features = false, features = ["crypto", "ring", "pem"] }
tempfile = "3.27.0"

[profile.release]
opt-level = "s"
lto = "thin"
codegen-units = 1
debug = "line-tables-only"
```

`core/crates/policy/Cargo.toml`:

```toml
[package]
name = "tollgate-policy"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
publish.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
```

`core/crates/policy/src/lib.rs` (doc comment only for now):

```rust
//! Which connections the proxy may intercept: the configuration shared with Swift, host
//! patterns, the bundled passthrough list and certificate pin learning.
```

`core/crates/policy/tests/config.rs`:

```rust
use std::net::IpAddr;

use serde_json::json;
use tollgate_policy::{Config, DohUpstream, PolicyError};

#[test]
fn defaults_match_the_spec() {
    let config = Config::default();
    assert_eq!(
        config.doh_upstreams,
        vec![
            DohUpstream {
                ip: "1.1.1.1".parse().unwrap(),
                port: 443,
                tls_name: "cloudflare-dns.com".into(),
                path: "/dns-query".into(),
            },
            DohUpstream {
                ip: "9.9.9.9".parse().unwrap(),
                port: 443,
                tls_name: "dns.quad9.net".into(),
                path: "/dns-query".into(),
            },
        ]
    );
    assert!(config.passthrough.is_empty());
    assert!(config.mitm_enabled);
    assert_eq!(config.max_intercepted_connections, 32);
}

#[test]
fn default_json_has_stable_field_names() {
    let value: serde_json::Value = serde_json::from_str(&Config::default().to_json()).unwrap();
    assert_eq!(
        value,
        json!({
            "doh_upstreams": [
                {"ip": "1.1.1.1", "port": 443, "tls_name": "cloudflare-dns.com", "path": "/dns-query"},
                {"ip": "9.9.9.9", "port": 443, "tls_name": "dns.quad9.net", "path": "/dns-query"}
            ],
            "passthrough": [],
            "mitm_enabled": true,
            "max_intercepted_connections": 32
        })
    );
}

#[test]
fn empty_object_gives_defaults() {
    assert_eq!(Config::from_json("{}").unwrap(), Config::default());
}

#[test]
fn missing_fields_keep_their_defaults() {
    let config = Config::from_json(r#"{"mitm_enabled": false}"#).unwrap();
    assert_eq!(
        config,
        Config {
            mitm_enabled: false,
            ..Config::default()
        }
    );
}

#[test]
fn upstream_port_and_path_default() {
    let config = Config::from_json(
        r#"{"doh_upstreams": [{"ip": "2606:4700:4700::1111", "tls_name": "one.one.one.one"}]}"#,
    )
    .unwrap();
    assert_eq!(
        config.doh_upstreams,
        vec![DohUpstream {
            ip: "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
            port: 443,
            tls_name: "one.one.one.one".into(),
            path: "/dns-query".into(),
        }]
    );
}

#[test]
fn unknown_fields_are_ignored() {
    let config =
        Config::from_json(r#"{"future_option": [1, 2], "max_intercepted_connections": 8}"#)
            .unwrap();
    assert_eq!(config.max_intercepted_connections, 8);
}

#[test]
fn round_trip() {
    let config = Config {
        doh_upstreams: vec![DohUpstream {
            ip: "192.0.2.53".parse().unwrap(),
            port: 8443,
            tls_name: "dns.example".into(),
            path: "/q".into(),
        }],
        passthrough: vec!["*.bank.example".into(), "pinned.example.org".into()],
        mitm_enabled: false,
        max_intercepted_connections: 5,
    };
    assert_eq!(Config::from_json(&config.to_json()).unwrap(), config);
}

#[test]
fn invalid_json_is_an_error() {
    for bad in [
        "",
        "not json",
        r#"{"mitm_enabled": "yes"}"#,
        r#"{"max_intercepted_connections": -1}"#,
        r#"{"doh_upstreams": [{"ip": "not-an-ip", "tls_name": "x"}]}"#,
        r#"{"doh_upstreams": [{"ip": "1.1.1.1"}]}"#,
    ] {
        let err = Config::from_json(bad).unwrap_err();
        assert!(
            matches!(err, PolicyError::Config(_)),
            "{bad:?} gave {err:?}"
        );
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd core && cargo test -p tollgate-policy --test config`
Expected: FAIL to compile with `` error[E0432]: unresolved imports `tollgate_policy::Config`, `tollgate_policy::DohUpstream`, `tollgate_policy::PolicyError` ``.

- [ ] **Step 3: Implement**

`core/crates/policy/src/lib.rs`:

```rust
//! Which connections the proxy may intercept: the configuration shared with Swift, host
//! patterns, the bundled passthrough list and certificate pin learning.

mod config;

pub use config::{Config, DohUpstream};

/// Errors from parsing configuration and host patterns.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid configuration: {0}")]
    Config(String),
}
```

`core/crates/policy/src/config.rs`:

```rust
//! `config.json`, written by the app and read by the tunnel.

use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

use crate::PolicyError;

/// A DNS-over-HTTPS server reached by IP address, with the TLS name set explicitly so the
/// resolver never needs DNS to find its upstream.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DohUpstream {
    pub ip: IpAddr,
    #[serde(default = "default_port")]
    pub port: u16,
    pub tls_name: String,
    #[serde(default = "default_path")]
    pub path: String,
}

fn default_port() -> u16 {
    443
}

fn default_path() -> String {
    "/dns-query".to_string()
}

impl DohUpstream {
    /// Cloudflare, `1.1.1.1` as `cloudflare-dns.com`.
    pub fn cloudflare() -> DohUpstream {
        DohUpstream {
            ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            port: 443,
            tls_name: "cloudflare-dns.com".to_string(),
            path: "/dns-query".to_string(),
        }
    }

    /// Quad9, `9.9.9.9` as `dns.quad9.net`.
    pub fn quad9() -> DohUpstream {
        DohUpstream {
            ip: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            port: 443,
            tls_name: "dns.quad9.net".to_string(),
            path: "/dns-query".to_string(),
        }
    }
}

/// Tunnel configuration. Missing fields take their defaults and unknown fields are
/// ignored, so an older tunnel can read a file written by a newer app.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Tried in order. Default: Cloudflare, then Quad9.
    pub doh_upstreams: Vec<DohUpstream>,
    /// User host patterns that are never intercepted, see [`crate::HostPattern`].
    pub passthrough: Vec<String>,
    /// When false every connection is passed through untouched. Default true.
    pub mitm_enabled: bool,
    /// Intercepted client connections allowed at once; above it new ones pass through.
    /// Default 32.
    pub max_intercepted_connections: u32,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            doh_upstreams: vec![DohUpstream::cloudflare(), DohUpstream::quad9()],
            passthrough: Vec::new(),
            mitm_enabled: true,
            max_intercepted_connections: 32,
        }
    }
}

impl Config {
    pub fn from_json(s: &str) -> Result<Config, PolicyError> {
        serde_json::from_str(s).map_err(|e| PolicyError::Config(e.to_string()))
    }

    /// Pretty-printed JSON; the app shows the file in its debug view.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("Config holds only strings, numbers and bools")
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd core && cargo test -p tollgate-policy --test config && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: 8 passed; clippy and fmt clean.

- [ ] **Step 5: Commit**

```bash
git add core/Cargo.toml core/Cargo.lock core/crates/policy
git commit -m "Add tollgate-policy with the JSON configuration"
```

---

### Task 6: Host patterns

**Files:**
- Modify: `core/crates/policy/src/lib.rs`
- Create: `core/crates/policy/src/pattern.rs`
- Test: `core/crates/policy/tests/pattern.rs`

**Interfaces:**
- Produces (contract): `pub struct HostPattern`, `HostPattern::parse(s: &str) -> Result<HostPattern, PolicyError>`, `HostPattern::matches(&self, host: &str) -> bool`; `PolicyError::InvalidPattern { pattern: String, reason: &'static str }`.
- Produces (extra): `HostPattern::name(&self) -> &str`, `HostPattern::is_wildcard(&self) -> bool`, `impl Display for HostPattern` (canonical form, `*.example.com` or `example.com`).

- [ ] **Step 1: Write the failing tests**

`core/crates/policy/tests/pattern.rs`:

```rust
use tollgate_policy::{HostPattern, PolicyError};

fn pattern(s: &str) -> HostPattern {
    HostPattern::parse(s).unwrap()
}

#[test]
fn exact_pattern_matches_only_that_host() {
    let p = pattern("example.com");
    assert!(!p.is_wildcard());
    for host in ["example.com", "EXAMPLE.com", "Example.Com.", "example.com."] {
        assert!(p.matches(host), "{host}");
    }
    for host in [
        "www.example.com",
        "notexample.com",
        "example.co",
        "example.com..",
        "",
        "com",
    ] {
        assert!(!p.matches(host), "{host}");
    }
}

#[test]
fn wildcard_matches_the_domain_and_every_subdomain() {
    let p = pattern("*.example.com");
    assert!(p.is_wildcard());
    for host in [
        "example.com",
        "www.example.com",
        "a.b.example.com",
        "A.Example.COM.",
    ] {
        assert!(p.matches(host), "{host}");
    }
    for host in [
        "badexample.com",
        "example.com.evil.net",
        "example.org",
        ".example.co",
        "",
    ] {
        assert!(!p.matches(host), "{host}");
    }
}

#[test]
fn parse_normalizes_case_trailing_dot_and_whitespace() {
    let p = pattern("  *.Example.COM.  ");
    assert_eq!(p.name(), "example.com");
    assert_eq!(p.to_string(), "*.example.com");
    assert_eq!(pattern("Host.Example.").to_string(), "host.example");
    assert_eq!(pattern("*.Example.COM"), pattern("*.example.com"));
}

#[test]
fn single_labels_and_ip_literals_are_hosts_too() {
    assert!(pattern("localhost").matches("LOCALHOST"));
    assert!(pattern("*.test").matches("a.test"));
    assert!(pattern("192.168.1.1").matches("192.168.1.1"));
    assert!(pattern("under_score.example").matches("under_score.example"));
}

#[test]
fn non_ascii_hosts_do_not_panic() {
    assert!(pattern("*.example.com").matches("ü.example.com"));
    assert!(!pattern("example.com").matches("exämple.com"));
}

fn reason(s: &str) -> &'static str {
    match HostPattern::parse(s) {
        Err(PolicyError::InvalidPattern { pattern, reason }) => {
            assert_eq!(pattern, s);
            reason
        }
        other => panic!("{s:?} parsed as {other:?}"),
    }
}

#[test]
fn invalid_patterns_are_rejected_with_a_reason() {
    for s in ["", "   ", "*.", ".", "*..", "."] {
        assert!(!reason(s).is_empty(), "{s:?}");
    }
    assert_eq!(reason(""), "empty host name");
    assert_eq!(reason("*."), "empty host name");
    assert_eq!(
        reason("*"),
        "a wildcard is only allowed as a leading \"*.\""
    );
    assert_eq!(
        reason("*example.com"),
        "a wildcard is only allowed as a leading \"*.\""
    );
    assert_eq!(
        reason("a.*.com"),
        "a wildcard is only allowed as a leading \"*.\""
    );
    assert_eq!(
        reason("*.*.example.com"),
        "a wildcard is only allowed as a leading \"*.\""
    );
    assert_eq!(reason("a..b"), "empty label");
    assert_eq!(reason(".example.com"), "empty label");
    assert_eq!(reason("example.com.."), "empty label");
    let letters = "only letters, digits, '-', '_' and '.' are allowed";
    for s in [
        "exa mple.com",
        "http://example.com",
        "example.com/path",
        "[::1]",
        "ex$mple.com",
        "exämple.com",
    ] {
        assert_eq!(reason(s), letters, "{s:?}");
    }
    let long_label = format!("{}.com", "a".repeat(64));
    assert_eq!(reason(&long_label), "label longer than 63 bytes");
    let ok_label = format!("{}.com", "a".repeat(63));
    assert!(HostPattern::parse(&ok_label).is_ok());
    let long_name = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62),
    ]
    .join(".");
    assert_eq!(long_name.len(), 254);
    assert_eq!(reason(&long_name), "host name longer than 253 bytes");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd core && cargo test -p tollgate-policy --test pattern`
Expected: FAIL to compile with `` error[E0432]: unresolved import `tollgate_policy::HostPattern` `` and `` error[E0599]: no variant named `InvalidPattern` found for enum `PolicyError` ``.

- [ ] **Step 3: Implement**

`core/crates/policy/src/lib.rs`:

```rust
//! Which connections the proxy may intercept: the configuration shared with Swift, host
//! patterns, the bundled passthrough list and certificate pin learning.

mod config;
mod pattern;

pub use config::{Config, DohUpstream};
pub use pattern::HostPattern;

/// Errors from parsing configuration and host patterns.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("invalid host pattern {pattern:?}: {reason}")]
    InvalidPattern {
        pattern: String,
        reason: &'static str,
    },
}
```

`core/crates/policy/src/pattern.rs`:

```rust
//! Host patterns for passthrough lists.

use std::fmt;

use crate::PolicyError;

/// `example.com` matches exactly that host; `*.example.com` matches `example.com` and every
/// subdomain. Matching ignores ASCII case and one trailing dot.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostPattern {
    /// Lowercase, without the `*.` prefix or a trailing dot.
    name: String,
    wildcard: bool,
}

impl HostPattern {
    pub fn parse(s: &str) -> Result<HostPattern, PolicyError> {
        let invalid = |reason| PolicyError::InvalidPattern {
            pattern: s.to_string(),
            reason,
        };
        let trimmed = s.trim();
        let (wildcard, rest) = match trimmed.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, trimmed),
        };
        let rest = rest.strip_suffix('.').unwrap_or(rest);
        if rest.is_empty() {
            return Err(invalid("empty host name"));
        }
        if rest.contains('*') {
            return Err(invalid("a wildcard is only allowed as a leading \"*.\""));
        }
        let name = validate_name(rest).map_err(invalid)?;
        Ok(HostPattern { name, wildcard })
    }

    pub fn matches(&self, host: &str) -> bool {
        let host = host.strip_suffix('.').unwrap_or(host).as_bytes();
        let name = self.name.as_bytes();
        if host.len() == name.len() {
            return host.eq_ignore_ascii_case(name);
        }
        if !self.wildcard || host.len() <= name.len() {
            return false;
        }
        let split = host.len() - name.len();
        host[split - 1] == b'.' && host[split..].eq_ignore_ascii_case(name)
    }

    /// The host name without `*.`, lowercase.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_wildcard(&self) -> bool {
        self.wildcard
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.wildcard {
            write!(f, "*.{}", self.name)
        } else {
            f.write_str(&self.name)
        }
    }
}

/// Checks a host name (no trailing dot) and returns it lowercased.
fn validate_name(name: &str) -> Result<String, &'static str> {
    if name.len() > 253 {
        return Err("host name longer than 253 bytes");
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err("empty label");
        }
        if label.len() > 63 {
            return Err("label longer than 63 bytes");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("only letters, digits, '-', '_' and '.' are allowed");
        }
    }
    Ok(name.to_ascii_lowercase())
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd core && cargo test -p tollgate-policy && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: config 8 passed, pattern 6 passed; clippy and fmt clean.

- [ ] **Step 5: Commit**

```bash
git add core/crates/policy
git commit -m "Add host patterns for passthrough lists"
```

---

### Task 7: Bundled passthrough snapshot

**Files:**
- Modify: `core/crates/policy/src/lib.rs`
- Create: `core/crates/policy/src/bundled.rs`
- Test: `core/crates/policy/tests/bundled.rs`

**Interfaces:**
- Produces (contract): `pub fn bundled_passthrough() -> &'static [&'static str]`, 627 canonical `HostPattern` strings compiled in.

The snapshot was built once from Apple support article 101555 (published 2026-08-07) and AdGuard HttpsExclusions at commit a8eda6ecc184cc7000436302d64fb932d5205fe0; the file header records the sources and the selection rule. Updating it means repeating that selection and changing the count in the test.

- [ ] **Step 1: Write the failing tests**

`core/crates/policy/tests/bundled.rs`:

```rust
use std::collections::HashSet;

use tollgate_policy::{HostPattern, bundled_passthrough};

fn bundled_matches(host: &str) -> bool {
    bundled_passthrough()
        .iter()
        .any(|p| HostPattern::parse(p).unwrap().matches(host))
}

#[test]
fn every_entry_is_a_canonical_pattern() {
    for entry in bundled_passthrough() {
        let parsed = HostPattern::parse(entry).unwrap();
        assert_eq!(parsed.to_string(), *entry);
    }
}

#[test]
fn entries_are_unique_and_the_snapshot_is_complete() {
    let unique: HashSet<&str> = bundled_passthrough().iter().copied().collect();
    assert_eq!(unique.len(), bundled_passthrough().len());
    assert_eq!(bundled_passthrough().len(), 627);
}

#[test]
fn covers_apple_services() {
    for host in [
        "gateway.icloud.com",
        "p42-contacts.icloud.com",
        "mesu.apple.com",
        "api.apple-cloudkit.com",
        "cvws.icloud-content.com",
        "is1-ssl.mzstatic.com",
        "updates.cdn-apple.com",
        "token.safebrowsing.apple",
        "apple-relay.cloudflare.com",
        "ocsp.digicert.com",
        "www.icloud.com.cn",
    ] {
        assert!(bundled_matches(host), "{host}");
    }
}

#[test]
fn covers_banking_and_sensitive_services() {
    for host in [
        "www.chase.com",
        "secure.bankofamerica.com",
        "www.paypal.com",
        "api.stripe.com",
        "accounts.google.com",
        "vault.bitwarden.com",
        "my.1password.com",
        "login.live.com",
    ] {
        assert!(bundled_matches(host), "{host}");
    }
}

#[test]
fn leaves_ordinary_hosts_alone() {
    for host in [
        "www.google.com",
        "example.com",
        "securepubads.g.doubleclick.net",
        "apple.com.evil.example",
        "cloudflare.com",
    ] {
        assert!(!bundled_matches(host), "{host}");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd core && cargo test -p tollgate-policy --test bundled`
Expected: FAIL to compile with `` error[E0432]: unresolved import `tollgate_policy::bundled_passthrough` ``.

- [ ] **Step 3: Add the snapshot**

`core/crates/policy/src/lib.rs`:

```rust
//! Which connections the proxy may intercept: the configuration shared with Swift, host
//! patterns, the bundled passthrough list and certificate pin learning.

mod bundled;
mod config;
mod pattern;

pub use bundled::bundled_passthrough;
pub use config::{Config, DohUpstream};
pub use pattern::HostPattern;

/// Errors from parsing configuration and host patterns.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("invalid host pattern {pattern:?}: {reason}")]
    InvalidPattern {
        pattern: String,
        reason: &'static str,
    },
}
```

`core/crates/policy/src/bundled.rs`:

```rust
//! Hosts that are never intercepted, compiled in.
//!
//! Sources, fetched 2026-09-25:
//! - Apple: every host in support.apple.com/101555, collapsed to `*.domain` where the
//!   article lists the whole domain or several of its hosts.
//! - AdGuard HttpsExclusions (github.com/AdguardTeam/HttpsExclusions) at commit
//!   a8eda6ecc184cc7000436302d64fb932d5205fe0 (2026-09-14): all of
//!   `exclusions/sensitive.txt`, and the second-level `.com`, `.org` and `.net` domains of
//!   `exclusions/banks.txt`. The rest of banks.txt (about 3,600 domains, mostly regional
//!   banks, 1,439 of them German) is left to pin learning and the user list. AdGuard excludes
//!   each listed domain with its subdomains, so every entry becomes `*.domain`. Entries
//!   limited to a desktop app (`$app=`) are left out.
//!
//! Each group is sorted; a host listed in an earlier group is not repeated.

/// The compiled-in passthrough patterns, in [`crate::HostPattern`] syntax.
pub fn bundled_passthrough() -> &'static [&'static str] {
    BUNDLED
}

#[rustfmt::skip]
static BUNDLED: &[&str] = &[
    // Apple, support article 101555 "Use Apple products on enterprise networks"
    // (published 2026-08-07): Apple services fail when HTTPS is intercepted.
    "*.apple", "*.apple-cloudkit.com", "*.apple-dns.net", "*.apple-livephotoskit.com",
    "*.apple-mapkit.com", "*.apple.com", "*.appleschoolcontent.com", "*.apzones.com",
    "*.axm-usercontent-apple.com", "*.cdn-apple.com", "*.icloud-content.com", "*.icloud.com",
    "*.icloud.com.cn", "*.itunes.com", "*.mzstatic.com", "*.vertexsmb.com",
    "appldnld.apple.com.edgesuite.net", "apple-relay.cloudflare.com",
    "apple-relay.fastly-edge.com", "cp4.cloudflare.com", "crl3.digicert.com", "crl4.digicert.com",
    "ocsp.digicert.cn", "ocsp.digicert.com",

    // AdGuard HttpsExclusions exclusions/sensitive.txt: identity, password managers,
    // health, government and other services with sensitive personal information.
    "*.1177.se", "*.1password.ca", "*.1password.com", "*.1password.eu", "*.4user.yeskey.or.kr",
    "*.account.idocs.kz", "*.accounts.google.com", "*.accounts.kakao.com",
    "*.agenciatributaria.gob.es", "*.anaf.ro", "*.anonaddy.com", "*.app.deel.com",
    "*.app.traderepublic.com", "*.apps.cybonline.co.uk", "*.bbss.softbankbb.co.jp",
    "*.besoklegen.no", "*.binance.com", "*.bitwarden.com", "*.bitwarden.eu", "*.bolagsverket.se",
    "*.cable.auth.com", "*.cable.ua5v.com", "*.canadapost.ca", "*.cdn-secuchart.com",
    "*.cert.vno.co.kr", "*.certapi.yeskey.or.kr", "*.certcld.yeskey.or.kr", "*.certsign.ro",
    "*.cfg.smt.docomo.ne.jp", "*.checkout.bambora.com", "*.clave.gob.es", "*.cmbchina.com",
    "*.cnisnet.inss.gov.br", "*.completeid.com", "*.connect.auone.jp", "*.cra-arc.gc.ca",
    "*.dashlane.com", "*.dec.fazenda.df.gov.br", "*.digisign.ro", "*.diskstation.me",
    "*.dscloud.biz", "*.dscloud.me", "*.dscloud.mobi", "*.dsmynas.com", "*.dsmynas.org",
    "*.e-tjanster.1177.se", "*.ebs.ru", "*.ekb.esplus.ru", "*.enclave.ua5v.com", "*.enpass.io",
    "*.equifax.com", "*.experian.com", "*.f-cdn.com", "*.f-secure.com", "*.familyds.com",
    "*.familyds.net", "*.familyds.org", "*.fastmail.com", "*.fido.kt.com", "*.freelancer.ca",
    "*.freelancer.cl", "*.freelancer.cn", "*.freelancer.co.id", "*.freelancer.co.it",
    "*.freelancer.co.uk", "*.freelancer.com", "*.freelancer.com.au", "*.freelancer.com.bd",
    "*.freelancer.is", "*.freelancer.jp", "*.freelancer.ph", "*.freshbooks.com", "*.gate.io",
    "*.go.kr", "*.gorzdrav.spb.ru", "*.gosuslugi.ru", "*.gov.au", "*.gov.in", "*.gov.kr",
    "*.gov.pl", "*.gov.rs", "*.gov.ru", "*.gov.tw", "*.hanko.io", "*.home.mijngezondheid.net",
    "*.hotdoc.com.au", "*.hrblock.com", "*.i234.me", "*.id.biltema.com", "*.id.pilet.ee",
    "*.id.smt.docomo.ne.jp", "*.id.yandex.by", "*.id.yandex.com", "*.id.yandex.com.tr",
    "*.id.yandex.kz", "*.id.yandex.ru", "*.id.yandex.ua", "*.identity.idocs.kz",
    "*.identity.virginmedia.com", "*.idnotify.com", "*.idwatchdog.com", "*.inspectiamuncii.ro",
    "*.intelink.gov", "*.kashflow.com", "*.kau.gov.hu", "*.kauth.kakao.com", "*.kontur-ca.ru",
    "*.kronofogden.se", "*.kurlypay.co.kr", "*.lastpass.com", "*.lifelock.com",
    "*.lisa.motivtelecom.ru", "*.lk.billing74.ru", "*.lk.megafon.ru", "*.lk.sesb.ru",
    "*.lkk-ekb.esplus.ru", "*.login.kt.com", "*.login.live.com", "*.mail.tutanota.com",
    "*.mailbox.org", "*.mailfence.com", "*.meu.inss.gov.br", "*.mexc.com", "*.mijnpazio.nl",
    "*.mil", "*.mos.ru", "*.mvd.dor.ga.gov", "*.my.softbank.jp", "*.mydocomo.com", "*.myds.me",
    "*.myob.com", "*.navyfederal.org", "*.nid.naver.com", "*.nordpass.com",
    "*.nwdealer.megafon.ru", "*.ok.webhop.net", "*.onpointcu.com", "*.papara.com",
    "*.passport.yandex.by", "*.passport.yandex.com", "*.passport.yandex.com.tr",
    "*.passport.yandex.kz", "*.passport.yandex.ru", "*.passport.yandex.ua", "*.pay.naver.com",
    "*.paypal-topup.ee", "*.posteo.de", "*.prestigecu.org", "*.proton.me", "*.protonmail.ch",
    "*.protonmail.com", "*.protonvpn.com", "*.quickconnect.to", "*.raonsecure.co.kr",
    "*.raonsecure.com", "*.receiptbank.com", "*.receita.economia.gov.br", "*.roboform.com",
    "*.rzd.ru", "*.sdk.yeskey.or.kr", "*.secuchart.com", "*.securesafe.com", "*.seg-social.es",
    "*.signal-iduna.de", "*.simplelogin.io", "*.skatteverket.se", "*.sophos.com", "*.synology.me",
    "*.termius.com", "*.tikker.emta.ee", "*.transunion.com", "*.trbinance.com",
    "*.trueidentity.com", "*.trustedid.com", "*.turkiye.gov.tr", "*.tutanota.com",
    "*.uwzorgonline.nl", "*.vd.l.qq.com", "*.web.whatsapp.com", "*.websign.ro",
    "*.workflow.idocs.kz", "*.xero.com", "*.zakupki.gov.ru",

    // AdGuard HttpsExclusions exclusions/banks.txt: second-level .com, .org and .net
    // domains (banks, card issuers, payment processors, brokers, exchanges).
    "*.1stnorcalcu.org", "*.2checkout.com", "*.53.com", "*.abanca.com", "*.abchina.com",
    "*.accessbankplc.com", "*.acledabank-internetbanking.com", "*.acorns.com",
    "*.acs-education.com", "*.adelfibanking.com", "*.adyen.com", "*.agranisme.org", "*.akbank.com",
    "*.alahli.com", "*.alawwalbank.com", "*.alinma.com", "*.alipay.com", "*.allegacy.org",
    "*.alliantcreditunion.com", "*.alliantcreditunion.org", "*.ally.com", "*.altbank.com",
    "*.amedigital.com", "*.amerantbank.com", "*.americanexpress.com", "*.amundi-tc.com",
    "*.anz.com", "*.apsiyon.com", "*.atabank.com", "*.auxmoney.com", "*.avangate.com",
    "*.axisbank.com", "*.bancnetonline.com", "*.bancoactivo.com", "*.bancocajasocial.com",
    "*.bancodebogota.com", "*.bancoexterior.com", "*.bancofinandina.com", "*.bancoldex.com",
    "*.bancomer.com", "*.bancrecerdigital.com", "*.bancsabadell.com", "*.banesconline.com",
    "*.bangkokbank.com", "*.bankalbilad.com", "*.bankchb.com", "*.bankcomm.com", "*.bankinter.com",
    "*.bankofamerica.com", "*.bankofbaku.com", "*.bankofbeirut.com", "*.banorte.com",
    "*.banplusonline.com", "*.barclaycardus.com", "*.bbacbank.com", "*.bcblbd.com", "*.bcu.org",
    "*.becu.org", "*.betterment.com", "*.bhf-bank.com", "*.bidv.com", "*.bil.com",
    "*.billdesk.com", "*.bitfinex.com", "*.bitget.com", "*.bitpanda.com", "*.bitso.com",
    "*.bitstamp.net", "*.bittrex.com", "*.bitwala.com", "*.bity.com", "*.blockfi.com",
    "*.blombank.com", "*.bmo.com", "*.bmoharris.com", "*.bnpparibas.com", "*.bobibanking.com",
    "*.bochk.com", "*.boursobank.com", "*.bpcprocessing.com", "*.bpiexpressonline.com",
    "*.btc-e.com", "*.btgpactual.com", "*.btpn.com", "*.bunq.com", "*.bybit.com",
    "*.caixa-enginyers.com", "*.campuscu.com", "*.capfed.com", "*.capitalone.com", "*.cardpay.com",
    "*.cbcfcu.org", "*.ccb.com", "*.ccservicing.com", "*.changelly.com", "*.chase.com",
    "*.chime.com", "*.chinatrust.com", "*.cibc.com", "*.citi.com", "*.citibankonline.com",
    "*.citizensbank.com", "*.citizensbankonline.com", "*.citybankplc.com", "*.cnb.com",
    "*.coastal24.com", "*.coastalbank.com", "*.coastcapitalsavings.com", "*.cobinhood.com",
    "*.coinbase.com", "*.colpatria.com", "*.combankdigital.com", "*.commerzfinanz.com",
    "*.computershare.com", "*.copayco.com", "*.credit-suisse.com", "*.creditbank.com",
    "*.creditdnepr.com", "*.creditonebank.com", "*.criptointercambio.com", "*.ctbcbank.com",
    "*.currency.com", "*.danamonline.com", "*.danskebank.com", "*.davivienda.com", "*.db.com",
    "*.dcu-online.org", "*.dcu.org", "*.desjardins.com", "*.devbnkphl.com", "*.dhakabankltd.com",
    "*.dhbbank.com", "*.directnet.com", "*.discover.com", "*.docfcu.org", "*.dutchbanglabank.com",
    "*.dvbbank.com", "*.e-bankofbaku.com", "*.eastwestbanker.com", "*.ebase.com", "*.ecommpay.com",
    "*.elevationsbanking.com", "*.elevationscu.com", "*.ellisbank.com", "*.emiratesnbd.com",
    "*.enpara.com", "*.etrade.com", "*.eurobank-ua.com", "*.evobanco.com", "*.fairfx.com",
    "*.farmersebank.com", "*.fastbill.com", "*.fbtonline.com", "*.fbtonline.net", "*.fbwebpos.com",
    "*.fednetbank.com", "*.feniciabank.com", "*.fidelity.com", "*.finansonline.com",
    "*.finecobank.com", "*.firstbankcard.com", "*.firsttechfed.com", "*.fnbba.com",
    "*.fosterswiss.com", "*.frostbank.com", "*.fsibplc.com", "*.ftx.com", "*.fubon.com",
    "*.getpenta.com", "*.globalhbl.com", "*.greensill-bank.com", "*.grenke.net",
    "*.grenkeonline.com", "*.growfinancial.org", "*.grupobancolombia.com", "*.gtbank.com",
    "*.gunaybank.com", "*.hanabank.com", "*.hangseng.com", "*.harrisbank.com", "*.hdfcbank.com",
    "*.hellenicnetbanking.com", "*.hellostake.com", "*.hitbtc.com", "*.hlebroking.com",
    "*.holvi.com", "*.hsbc.com", "*.hsbcnet.com", "*.hsbcprivatebank.com", "*.hubank.com",
    "*.huntington.com", "*.ibanking-services.com", "*.icicibank.com", "*.icon25-bank.com",
    "*.idbi.com", "*.idbibank.com", "*.independentreserve.com", "*.inetpayonline.com",
    "*.ingonline.com", "*.ingwb.com", "*.inicis.com", "*.instamojo.com",
    "*.interactivebrokers.com", "*.internetpanin.com", "*.intesasanpaolo.com", "*.jago.com",
    "*.jenius.com", "*.jkopay.com", "*.juliusbaer.com", "*.kbstar.com", "*.kebhana.com",
    "*.key.com", "*.kgibank.com", "*.klarna.com", "*.klikbca.com", "*.kokobank.com",
    "*.kontist.com", "*.kraken.com", "*.kreditprombank.com", "*.krungsri.com",
    "*.krungsribizonline.com", "*.krungsrionline.com", "*.ktbnetbank.com", "*.kucoin.com",
    "*.leboutique.com", "*.legalandgeneral.com", "*.leomoney.com", "*.lgbbank.com", "*.liqpay.com",
    "*.lloydsbank.com", "*.localbitcoins.com", "*.localethereum.com", "*.lzo.com",
    "*.m1finance.com", "*.marcus.com", "*.marinecu.com", "*.maritimebank.com",
    "*.master-capital.org", "*.masterpass.com", "*.mctcu.org", "*.meabank.com", "*.mebytmb.com",
    "*.megabank.net", "*.memberdirect.net", "*.mercantilbanco.com", "*.metzler.com",
    "*.midoregon.com", "*.mitfcu.org", "*.ml.com", "*.mobikwik.com", "*.modhumotibankltd.com",
    "*.mohela.com", "*.monese.com", "*.monzo.com", "*.mtochka.com", "*.myetherwallet.com",
    "*.myfedloan.org", "*.mymerrill.com", "*.myoccu.org", "*.myvoba.com", "*.n26.com",
    "*.natwest.com", "*.neteller.com", "*.netpnb.com", "*.netteller.com", "*.nonghyup.com",
    "*.nordea.com", "*.nsandi.com", "*.nwolb.com", "*.o-bank.com", "*.oddo-bhf.com",
    "*.oneaccount.com", "*.onfastspring.com", "*.onlinebanking-ibb-ag.com", "*.optumbank.com",
    "*.oregonstatecu.com", "*.oschad24.com", "*.pagbrasil.com", "*.palmettohealthcu.org",
    "*.payco.com", "*.payeer.com", "*.paykun.com", "*.payonlinesystem.com", "*.paypal-nakit.com",
    "*.paypal.com", "*.paypalobjects.com", "*.payproglobal.com", "*.paytm.com", "*.paytr.com",
    "*.payture.com", "*.pbbdirekt.com", "*.pbebank.com", "*.pcbac.com", "*.pearler.com",
    "*.penfed.org", "*.picpay.com", "*.pictet.com", "*.piraeusbank.com", "*.plategka.com",
    "*.plimus.com", "*.pnc.com", "*.pocketsmith.com", "*.portaldepagosmercantil.com",
    "*.priovtb.com", "*.privatbank1891.com", "*.prosperitybankusa.com", "*.pxpayplus.com",
    "*.qantas.com", "*.qantasmoney.com", "*.qiwi.com", "*.qnb.com", "*.qnbfinansbank.com",
    "*.questrade.com", "*.razorpay.com", "*.rbcroyalbank.com", "*.rblbank.com", "*.rbsdigital.com",
    "*.rbsinternational.com", "*.rcbconline-corporate.com", "*.rcbconlinebanking.com",
    "*.rcuonline.org", "*.redwoodcu.org", "*.revolut.com", "*.rfcu.com", "*.riyadbank.com",
    "*.robinhood.com", "*.rusnarbank.com", "*.russobank.com", "*.sabb.com", "*.saferpay.com",
    "*.samba.com", "*.sampathvishwa.com", "*.samsungpop.com", "*.santanderbank.com",
    "*.sberbank.com", "*.sbicard.com", "*.sbiepay.com", "*.sc.com", "*.scbeasy.com",
    "*.schwab.com", "*.scotiabank.com", "*.secureinternetbank.com", "*.securitybank.com",
    "*.selco.org", "*.sendwyre.com", "*.settrade.com", "*.sharesight.com", "*.shinhan.com",
    "*.shinseibank.com", "*.signicat.com", "*.simple.com", "*.simplii.com", "*.sinopac.com",
    "*.smbc-card.com", "*.societegenerale.com", "*.sorexpay.com", "*.southindianbank.com",
    "*.spectrocoin.com", "*.sslcommerz.com", "*.stanbicibtcbank.com", "*.starlingbank.com",
    "*.start2pay.com", "*.stripe.com", "*.suncoast.com", "*.td.com", "*.tdameritrade.com",
    "*.tdbank.com", "*.tdcanadatrust.com", "*.tescobank.com", "*.theinstapay.com",
    "*.theworldexchange.net", "*.tiaa.org", "*.tiscoasset.com", "*.titanvest.com",
    "*.tmbdirect.com", "*.tochka.com", "*.tossbank.com", "*.tossinvest.com", "*.touchbank.com",
    "*.traderepublic.com", "*.transaccionesbancolombia.com", "*.transamerica.com",
    "*.traviscu.org", "*.ubinco.com", "*.ubs.com", "*.uiccu.org", "*.ukrgasbank.com",
    "*.ukrsibbank.com", "*.umcu.org", "*.unicreditbanking.net", "*.unionbank.com",
    "*.unionbankph.com", "*.univest.net", "*.uphold.com", "*.upma.org", "*.usaa.com",
    "*.vakifbankusa.com", "*.vancity.com", "*.vanguard.com", "*.venmo.com", "*.veridiancu.org",
    "*.virginmoney.com", "*.vystarcu.org", "*.wayforpay.com", "*.wealthbar.com",
    "*.wealthfront.com", "*.wealthsimple.com", "*.webbankir.com", "*.wellsfargo.com",
    "*.westconsincu.org", "*.wideup.net", "*.wise.com", "*.wlp-acs.com", "*.wmtransfer.com",
    "*.wooppay.com", "*.wooribank.com", "*.xtb.com", "*.yesrewardz.com", "*.youneedabudget.com",
    "*.zaim.com",
];
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd core && cargo test -p tollgate-policy --test bundled && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: 5 passed; clippy and fmt clean (`#[rustfmt::skip]` keeps the packed layout).

- [ ] **Step 5: Commit**

```bash
git add core/crates/policy
git commit -m "Add the bundled passthrough list for Apple, banking and sensitive hosts"
```

---

### Task 8: Policy classification and pin learning

**Files:**
- Modify: `core/crates/policy/Cargo.toml`, `core/crates/policy/src/lib.rs`
- Create: `core/crates/policy/src/policy.rs`
- Test: `core/crates/policy/tests/policy.rs`

**Interfaces:**
- Consumes: `Config`, `HostPattern`, `bundled_passthrough()`, `log`.
- Produces (contract):
  - `pub enum Decision { Intercept, Passthrough(PassthroughReason) }`
  - `pub enum PassthroughReason { MitmDisabled, User, Bundled, LearnedPin, NotTls, Capacity, LowMemory }`
  - `pub enum RejectionKind { UnknownCa, BadCertificate, CertificateUnknown, DecryptError }`
  - `pub struct Policy` (`Send + Sync`) with `Policy::new(config: &Config, learned_pins_json: Option<&str>) -> Result<Policy, PolicyError>`, `classify(&self, host: &str, now: u64) -> Decision`, `record_client_rejection(&self, host: &str, kind: RejectionKind, now: u64) -> bool`, `learned_pins_json(&self) -> String`.
- Produces (extra): `pub const REJECTION_WINDOW_SECS: u64 = 600`, `pub const PIN_LIFETIME_SECS: u64 = 2_592_000`.
- `now` is Unix seconds from `tollgate_common::clock::unix_secs()` (see Decisions).

- [ ] **Step 1: Write the failing tests**

`core/crates/policy/tests/policy.rs`:

```rust
use tollgate_policy::{
    Config, Decision, PIN_LIFETIME_SECS, PassthroughReason, Policy, PolicyError,
    REJECTION_WINDOW_SECS, RejectionKind,
};

const T0: u64 = 1_790_000_000;

fn policy(passthrough: &[&str]) -> Policy {
    let config = Config {
        passthrough: passthrough.iter().map(|s| s.to_string()).collect(),
        ..Config::default()
    };
    Policy::new(&config, None).unwrap()
}

fn passthrough(reason: PassthroughReason) -> Decision {
    Decision::Passthrough(reason)
}

#[test]
fn ordinary_hosts_are_intercepted() {
    let p = policy(&[]);
    assert_eq!(p.classify("example.com", T0), Decision::Intercept);
    assert_eq!(p.classify("[2001:db8::1]", T0), Decision::Intercept);
}

#[test]
fn mitm_disabled_passes_everything_through() {
    let config = Config {
        mitm_enabled: false,
        passthrough: vec!["user.example".into()],
        ..Config::default()
    };
    let p = Policy::new(&config, None).unwrap();
    for host in ["example.com", "user.example", "gateway.icloud.com"] {
        assert_eq!(
            p.classify(host, T0),
            passthrough(PassthroughReason::MitmDisabled)
        );
    }
}

#[test]
fn user_patterns_come_first() {
    let p = policy(&["*.apple.com", "Bank.Example."]);
    assert_eq!(
        p.classify("www.apple.com", T0),
        passthrough(PassthroughReason::User)
    );
    assert_eq!(
        p.classify("bank.example", T0),
        passthrough(PassthroughReason::User)
    );
    assert_eq!(p.classify("www.bank.example", T0), Decision::Intercept);
    assert_eq!(
        p.classify("gateway.icloud.com", T0),
        passthrough(PassthroughReason::Bundled)
    );
}

#[test]
fn bundled_hosts_pass_through_case_and_dot_insensitively() {
    let p = policy(&[]);
    assert_eq!(
        p.classify("WWW.Chase.COM.", T0),
        passthrough(PassthroughReason::Bundled)
    );
    assert_eq!(
        p.classify("chase.com.evil.example", T0),
        Decision::Intercept
    );
}

#[test]
fn invalid_user_pattern_fails_construction() {
    let config = Config {
        passthrough: vec!["ok.example".into(), "bad pattern".into()],
        ..Config::default()
    };
    let err = Policy::new(&config, None).err().unwrap();
    assert!(
        matches!(&err, PolicyError::InvalidPattern { pattern, .. } if pattern == "bad pattern"),
        "{err:?}"
    );
}

#[test]
fn two_rejections_within_ten_minutes_learn_a_pin() {
    let p = policy(&[]);
    assert!(!p.record_client_rejection("pinned.example", RejectionKind::UnknownCa, T0));
    assert_eq!(p.classify("pinned.example", T0), Decision::Intercept);
    assert!(p.record_client_rejection(
        "Pinned.Example.",
        RejectionKind::DecryptError,
        T0 + REJECTION_WINDOW_SECS
    ));
    assert_eq!(
        p.classify("pinned.example", T0 + 601),
        passthrough(PassthroughReason::LearnedPin)
    );
    // Already a pin: further rejections do not report a new pin.
    assert!(!p.record_client_rejection("pinned.example", RejectionKind::BadCertificate, T0 + 700));
    // Pins are per host, not per domain.
    assert_eq!(
        p.classify("www.pinned.example", T0 + 700),
        Decision::Intercept
    );
}

#[test]
fn rejections_further_apart_do_not_learn() {
    let p = policy(&[]);
    assert!(!p.record_client_rejection("slow.example", RejectionKind::UnknownCa, T0));
    assert!(!p.record_client_rejection(
        "slow.example",
        RejectionKind::UnknownCa,
        T0 + REJECTION_WINDOW_SECS + 1
    ));
    // The window restarts at the second rejection.
    assert!(p.record_client_rejection(
        "slow.example",
        RejectionKind::CertificateUnknown,
        T0 + REJECTION_WINDOW_SECS + 1 + 500
    ));
}

#[test]
fn different_hosts_are_counted_separately() {
    let p = policy(&[]);
    assert!(!p.record_client_rejection("a.example", RejectionKind::UnknownCa, T0));
    assert!(!p.record_client_rejection("b.example", RejectionKind::UnknownCa, T0 + 1));
    assert_eq!(p.classify("a.example", T0 + 2), Decision::Intercept);
    assert!(!p.record_client_rejection("", RejectionKind::UnknownCa, T0 + 3));
    assert!(!p.record_client_rejection("", RejectionKind::UnknownCa, T0 + 4));
}

#[test]
fn pins_expire_after_thirty_days() {
    let p = policy(&[]);
    p.record_client_rejection("pinned.example", RejectionKind::UnknownCa, T0);
    assert!(p.record_client_rejection("pinned.example", RejectionKind::UnknownCa, T0 + 10));
    let learned_at = T0 + 10;
    assert_eq!(PIN_LIFETIME_SECS, 2_592_000);
    assert_eq!(
        p.classify("pinned.example", learned_at + PIN_LIFETIME_SECS - 1),
        passthrough(PassthroughReason::LearnedPin)
    );
    assert_eq!(
        p.classify("pinned.example", learned_at + PIN_LIFETIME_SECS),
        Decision::Intercept
    );
    // After expiry the host can be learned again.
    let later = learned_at + PIN_LIFETIME_SECS;
    assert!(!p.record_client_rejection("pinned.example", RejectionKind::UnknownCa, later));
    assert!(p.record_client_rejection("pinned.example", RejectionKind::UnknownCa, later + 1));
}

#[test]
fn user_and_bundled_rank_above_learned_pins() {
    let p = policy(&["user.example"]);
    for host in ["user.example", "gateway.icloud.com"] {
        p.record_client_rejection(host, RejectionKind::UnknownCa, T0);
        assert!(p.record_client_rejection(host, RejectionKind::UnknownCa, T0 + 1));
    }
    assert_eq!(
        p.classify("user.example", T0 + 2),
        passthrough(PassthroughReason::User)
    );
    assert_eq!(
        p.classify("gateway.icloud.com", T0 + 2),
        passthrough(PassthroughReason::Bundled)
    );
}

#[test]
fn learned_pins_round_trip_through_json() {
    let p = policy(&[]);
    assert_eq!(p.learned_pins_json(), r#"{"version":1,"pins":[]}"#);
    for host in ["b.example", "a.example"] {
        p.record_client_rejection(host, RejectionKind::UnknownCa, 100);
        p.record_client_rejection(host, RejectionKind::UnknownCa, 160);
    }
    let json = p.learned_pins_json();
    assert_eq!(
        json,
        r#"{"version":1,"pins":[{"host":"a.example","learned_at":160},{"host":"b.example","learned_at":160}]}"#
    );
    let restored = Policy::new(&Config::default(), Some(&json)).unwrap();
    assert_eq!(
        restored.classify("a.example", 200),
        passthrough(PassthroughReason::LearnedPin)
    );
    assert_eq!(
        restored.classify("B.EXAMPLE.", 200),
        passthrough(PassthroughReason::LearnedPin)
    );
    assert_eq!(
        restored.classify("a.example", 160 + PIN_LIFETIME_SECS),
        Decision::Intercept
    );
    assert_eq!(restored.learned_pins_json(), json);
}

#[test]
fn unreadable_pins_are_ignored() {
    for bad in [
        "",
        "not json",
        r#"{"version":2,"pins":[{"host":"a.example","learned_at":1}]}"#,
        r#"{"pins":[]}"#,
    ] {
        let p = Policy::new(&Config::default(), Some(bad)).unwrap();
        assert_eq!(p.classify("a.example", 2), Decision::Intercept, "{bad:?}");
        assert_eq!(
            p.learned_pins_json(),
            r#"{"version":1,"pins":[]}"#,
            "{bad:?}"
        );
    }
}

#[test]
fn expired_pins_are_dropped_when_the_next_rejection_is_recorded() {
    let json = r#"{"version":1,"pins":[{"host":"new.example","learned_at":1000},{"host":"old.example","learned_at":0}]}"#;
    let p = Policy::new(&Config::default(), Some(json)).unwrap();
    assert_eq!(p.learned_pins_json(), json);
    p.record_client_rejection(
        "other.example",
        RejectionKind::UnknownCa,
        PIN_LIFETIME_SECS + 10,
    );
    assert_eq!(
        p.learned_pins_json(),
        r#"{"version":1,"pins":[{"host":"new.example","learned_at":1000}]}"#
    );
}

#[test]
fn many_single_rejections_stay_bounded_and_do_not_learn() {
    let p = policy(&[]);
    for i in 0..5_000u64 {
        assert!(!p.record_client_rejection(
            &format!("h{i}.example"),
            RejectionKind::UnknownCa,
            T0 + i
        ));
    }
    // The most recent host is still remembered, so its second rejection learns.
    assert!(p.record_client_rejection("h4999.example", RejectionKind::UnknownCa, T0 + 5_000));
}

#[test]
fn policy_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Policy>();
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd core && cargo test -p tollgate-policy --test policy`
Expected: FAIL to compile with `` error[E0432]: unresolved imports `tollgate_policy::Decision`, ... `` naming all six new items.

- [ ] **Step 3: Implement**

`core/crates/policy/Cargo.toml`:

```toml
[package]
name = "tollgate-policy"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
publish.workspace = true

[dependencies]
log = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
```

`core/crates/policy/src/lib.rs`:

```rust
//! Which connections the proxy may intercept: the configuration shared with Swift, host
//! patterns, the bundled passthrough list and certificate pin learning.

mod bundled;
mod config;
mod pattern;
mod policy;

pub use bundled::bundled_passthrough;
pub use config::{Config, DohUpstream};
pub use pattern::HostPattern;
pub use policy::{
    Decision, PIN_LIFETIME_SECS, PassthroughReason, Policy, REJECTION_WINDOW_SECS, RejectionKind,
};

/// Errors from parsing configuration and host patterns.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("invalid host pattern {pattern:?}: {reason}")]
    InvalidPattern {
        pattern: String,
        reason: &'static str,
    },
}
```

`core/crates/policy/src/policy.rs`:

```rust
//! The interception decision and certificate pin learning.
//!
//! Every `now` argument is wall-clock Unix seconds (`tollgate_common::clock::unix_secs`),
//! because learned pins are saved and must survive a reboot.

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};

use crate::{Config, HostPattern, PolicyError, bundled_passthrough};

/// Two client rejections of the same host at most this many seconds apart make it a pin.
pub const REJECTION_WINDOW_SECS: u64 = 10 * 60;
/// A learned pin is kept for this long after it was learned.
pub const PIN_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;
/// Hosts with a single recent rejection that are remembered at once.
const MAX_RECENT_REJECTIONS: usize = 1024;
const PINS_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Intercept,
    Passthrough(PassthroughReason),
}

/// Why a connection is not intercepted. `NotTls`, `Capacity` and `LowMemory` are decided by
/// the proxy, never by [`Policy::classify`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassthroughReason {
    MitmDisabled,
    User,
    Bundled,
    LearnedPin,
    NotTls,
    Capacity,
    LowMemory,
}

/// The TLS alerts a client sends when it rejects our certificate. Each kind counts the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectionKind {
    UnknownCa,
    BadCertificate,
    CertificateUnknown,
    DecryptError,
}

/// Exact names and `*.` suffixes, matched with hash lookups on the host and its parents.
#[derive(Default)]
struct PatternSet {
    exact: HashSet<String>,
    suffix: HashSet<String>,
}

impl PatternSet {
    fn new<'a>(patterns: impl IntoIterator<Item = &'a HostPattern>) -> PatternSet {
        let mut set = PatternSet::default();
        for p in patterns {
            let target = if p.is_wildcard() {
                &mut set.suffix
            } else {
                &mut set.exact
            };
            target.insert(p.name().to_string());
        }
        set
    }

    /// `key` is a lookup key from [`lookup_key`].
    fn matches(&self, key: &str) -> bool {
        if self.exact.contains(key) {
            return true;
        }
        if self.suffix.is_empty() {
            return false;
        }
        let parents = key.match_indices('.').map(|(i, _)| &key[i + 1..]);
        std::iter::once(key)
            .chain(parents)
            .any(|s| self.suffix.contains(s))
    }
}

static BUNDLED_SET: LazyLock<PatternSet> = LazyLock::new(|| {
    let patterns: Vec<HostPattern> = bundled_passthrough()
        .iter()
        .map(|p| HostPattern::parse(p).expect("bundled patterns are valid"))
        .collect();
    PatternSet::new(&patterns)
});

/// Lowercase, one trailing dot removed, IPv6 brackets removed.
fn lookup_key(host: &str) -> String {
    let host = host.strip_suffix('.').unwrap_or(host);
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    host.to_ascii_lowercase()
}

fn pin_is_live(learned_at: u64, now: u64) -> bool {
    now.saturating_sub(learned_at) < PIN_LIFETIME_SECS
}

#[derive(Default)]
struct Learning {
    /// Host to the time it became a pin.
    pins: HashMap<String, u64>,
    /// Host to the time of its last rejection that did not make it a pin.
    recent: HashMap<String, u64>,
}

#[derive(Serialize, Deserialize)]
struct PinsFile {
    version: u32,
    pins: Vec<PinEntry>,
}

#[derive(Serialize, Deserialize)]
struct PinEntry {
    host: String,
    learned_at: u64,
}

/// Decides per host whether the proxy intercepts. `Send + Sync`; learning state sits behind
/// a mutex.
pub struct Policy {
    mitm_enabled: bool,
    user: PatternSet,
    learning: Mutex<Learning>,
}

impl Policy {
    /// Fails if a user passthrough pattern is invalid. A learned pins file that cannot be
    /// read is logged and ignored: it is a cache that rebuilds itself.
    pub fn new(config: &Config, learned_pins_json: Option<&str>) -> Result<Policy, PolicyError> {
        let user: Vec<HostPattern> = config
            .passthrough
            .iter()
            .map(|p| HostPattern::parse(p))
            .collect::<Result<_, _>>()?;
        let pins = learned_pins_json.map(parse_pins).unwrap_or_default();
        Ok(Policy {
            mitm_enabled: config.mitm_enabled,
            user: PatternSet::new(&user),
            learning: Mutex::new(Learning {
                pins,
                recent: HashMap::new(),
            }),
        })
    }

    /// Order: MITM disabled, user passthrough, bundled passthrough, learned pins, intercept.
    pub fn classify(&self, host: &str, now: u64) -> Decision {
        if !self.mitm_enabled {
            return Decision::Passthrough(PassthroughReason::MitmDisabled);
        }
        let key = lookup_key(host);
        if self.user.matches(&key) {
            return Decision::Passthrough(PassthroughReason::User);
        }
        if BUNDLED_SET.matches(&key) {
            return Decision::Passthrough(PassthroughReason::Bundled);
        }
        let learned = self.lock().pins.get(&key).copied();
        if learned.is_some_and(|at| pin_is_live(at, now)) {
            return Decision::Passthrough(PassthroughReason::LearnedPin);
        }
        Decision::Intercept
    }

    /// Returns true when this rejection made the host a learned pin.
    pub fn record_client_rejection(&self, host: &str, kind: RejectionKind, now: u64) -> bool {
        let key = lookup_key(host);
        if key.is_empty() {
            return false;
        }
        let mut learning = self.lock();
        learning.pins.retain(|_, at| pin_is_live(*at, now));
        if learning.pins.contains_key(&key) {
            return false;
        }
        match learning.recent.get(&key) {
            Some(&previous) if now.saturating_sub(previous) <= REJECTION_WINDOW_SECS => {
                learning.recent.remove(&key);
                log::info!("learned certificate pin for {key} after {kind:?}");
                learning.pins.insert(key, now);
                true
            }
            _ => {
                log::debug!("client rejected our certificate for {key}: {kind:?}");
                if learning.recent.len() >= MAX_RECENT_REJECTIONS {
                    learning
                        .recent
                        .retain(|_, at| now.saturating_sub(*at) <= REJECTION_WINDOW_SECS);
                }
                if learning.recent.len() >= MAX_RECENT_REJECTIONS {
                    let oldest = learning
                        .recent
                        .iter()
                        .min_by_key(|(_, at)| **at)
                        .map(|(host, _)| host.clone());
                    if let Some(oldest) = oldest {
                        learning.recent.remove(&oldest);
                    }
                }
                learning.recent.insert(key, now);
                false
            }
        }
    }

    /// `{"version":1,"pins":[{"host":"...","learned_at":...}]}`, sorted by host.
    pub fn learned_pins_json(&self) -> String {
        let mut pins: Vec<PinEntry> = self
            .lock()
            .pins
            .iter()
            .map(|(host, at)| PinEntry {
                host: host.clone(),
                learned_at: *at,
            })
            .collect();
        pins.sort_by(|a, b| a.host.cmp(&b.host));
        let file = PinsFile {
            version: PINS_FORMAT_VERSION,
            pins,
        };
        serde_json::to_string(&file).expect("pins hold only strings and numbers")
    }

    fn lock(&self) -> MutexGuard<'_, Learning> {
        self.learning.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn parse_pins(json: &str) -> HashMap<String, u64> {
    match serde_json::from_str::<PinsFile>(json) {
        Ok(file) if file.version == PINS_FORMAT_VERSION => file
            .pins
            .into_iter()
            .map(|p| (lookup_key(&p.host), p.learned_at))
            .filter(|(host, _)| !host.is_empty())
            .collect(),
        Ok(file) => {
            log::warn!("ignoring learned pins with format version {}", file.version);
            HashMap::new()
        }
        Err(e) => {
            log::warn!("ignoring unreadable learned pins: {e}");
            HashMap::new()
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd core && cargo test -p tollgate-policy && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: bundled 5, config 8, pattern 6, policy 15 passed; clippy and fmt clean.

- [ ] **Step 5: Commit**

```bash
git add core/Cargo.lock core/crates/policy
git commit -m "Add Policy: passthrough order and certificate pin learning"
```

---

### Task 9: tollgate-filter crate with FilterEngine

**Files:**
- Modify: `core/Cargo.toml`
- Create: `core/crates/filter/Cargo.toml`, `core/crates/filter/src/lib.rs`, `core/crates/filter/src/engine.rs`
- Test: `core/crates/filter/tests/engine.rs`

**Interfaces:**
- Consumes: `adblock` (`=0.13.3`, not `single-thread`), `memmap2`, `log`, `thiserror`; `tempfile` in tests.
- Produces (contract): `pub enum ListFormat { Adblock, Hosts }`, `pub struct ListSource<'a> { pub name: &'a str, pub text: &'a str, pub format: ListFormat }`, `pub enum Verdict { Allow, Block { rule: Option<String> } }`, `pub struct FilterEngine` (`Send + Sync`) with `from_lists(lists: &[ListSource], debug: bool) -> FilterEngine`, `serialize(&self) -> Vec<u8>`, `load(path: &Path) -> Result<FilterEngine, FilterError>` (mmap), `check(&self, url: &str, source_url: &str, request_type: &str) -> Verdict`.
- Produces (extra): `pub enum FilterError { Io { path, source }, Engine(String), .. }`, `pub fn network_rule_count(lists: &[ListSource]) -> u64`, `pub const REGEX_CLEANUP_INTERVAL: Duration` (10 s), `pub const REGEX_DISCARD_UNUSED: Duration` (30 s).

- [ ] **Step 1: Add the crate with failing tests**

`core/Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = [
    "crates/common",
    "crates/policy",
    "crates/filter",
    "crates/tollgate-ffi",
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

# Tests only.
rcgen = { version = "0.14.10", default-features = false, features = ["crypto", "ring", "pem"] }
tempfile = "3.27.0"

[profile.release]
opt-level = "s"
lto = "thin"
codegen-units = 1
debug = "line-tables-only"
```

`core/crates/filter/Cargo.toml`:

```toml
[package]
name = "tollgate-filter"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
publish.workspace = true

[dependencies]
adblock = { workspace = true }
log = { workspace = true }
memmap2 = { workspace = true }
thiserror = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
```

`core/crates/filter/src/lib.rs` (doc comment only for now):

```rust
//! Request filtering: the adblock engine for URLs seen by the proxy, the hashed DNS
//! blocklist, and compiling both from filter lists.
```

`core/crates/filter/tests/engine.rs`:

```rust
use std::io::Write;

use tollgate_filter::{
    FilterEngine, FilterError, ListFormat, ListSource, REGEX_CLEANUP_INTERVAL,
    REGEX_DISCARD_UNUSED, Verdict, network_rule_count,
};

fn adblock(text: &str) -> ListSource<'_> {
    ListSource {
        name: "test",
        text,
        format: ListFormat::Adblock,
    }
}

fn engine(rules: &str) -> FilterEngine {
    FilterEngine::from_lists(&[adblock(rules)], false)
}

fn blocked(e: &FilterEngine, url: &str, source: &str, kind: &str) -> bool {
    matches!(e.check(url, source, kind), Verdict::Block { .. })
}

#[test]
fn host_anchor_blocks_the_domain_and_subdomains() {
    let e = engine("||doubleclick.net^\n");
    assert_eq!(
        e.check(
            "https://ad.doubleclick.net/x.js",
            "https://example.com/",
            "script"
        ),
        Verdict::Block { rule: None }
    );
    assert!(blocked(
        &e,
        "https://doubleclick.net/",
        "https://example.com/",
        "image"
    ));
    assert!(!blocked(
        &e,
        "https://notdoubleclick.net/x.js",
        "https://example.com/",
        "script"
    ));
}

#[test]
fn debug_engine_names_the_rule() {
    let e = FilterEngine::from_lists(&[adblock("||doubleclick.net^\n")], true);
    assert_eq!(
        e.check(
            "https://ad.doubleclick.net/x.js",
            "https://example.com/",
            "script"
        ),
        Verdict::Block {
            rule: Some("||doubleclick.net^".into())
        }
    );
}

#[test]
fn exceptions_and_important() {
    let e = engine(
        "/ads.js\n@@||example.com/ads.js\n||ads.example.net^$important\n@@||ads.example.net^\n",
    );
    assert!(!blocked(
        &e,
        "https://example.com/ads.js",
        "https://example.com/",
        "script"
    ));
    assert!(blocked(
        &e,
        "https://other.com/ads.js",
        "https://other.com/",
        "script"
    ));
    assert!(blocked(
        &e,
        "https://ads.example.net/a.js",
        "https://news.com/",
        "script"
    ));
}

#[test]
fn third_party_uses_the_registrable_domain() {
    let e = engine("||tracker.com^$third-party\n||a.github.io^$third-party\n");
    assert!(blocked(
        &e,
        "https://tracker.com/p.gif",
        "https://news.com/",
        "image"
    ));
    assert!(!blocked(
        &e,
        "https://tracker.com/p.gif",
        "https://tracker.com/",
        "image"
    ));
    assert!(!blocked(
        &e,
        "https://cdn.tracker.com/p.gif",
        "https://www.tracker.com/",
        "image"
    ));
    // An empty source counts as third party.
    assert!(blocked(&e, "https://tracker.com/p.gif", "", "image"));
    // The public suffix list makes a.github.io and b.github.io different sites.
    assert!(blocked(
        &e,
        "https://a.github.io/x",
        "https://b.github.io/",
        "script"
    ));
}

#[test]
fn caret_is_a_separator_but_not_a_dot() {
    let e = engine("/banner/*/img^\n");
    for (url, want) in [
        ("https://example.com/banner/300x250/img/ad.gif", true),
        ("https://example.com/banner/300x250/img?x=1", true),
        ("https://example.com/banner/300x250/img", true),
        ("https://example.com/banner/a/b/img/x", true),
        ("https://example.com/banner/300x250/img.png", false),
        ("https://example.com/banner/300x250/images/x", false),
        ("https://example.com/banners/300x250/img/x", false),
    ] {
        assert_eq!(
            blocked(&e, url, "https://example.com/", "image"),
            want,
            "{url}"
        );
    }
}

#[test]
fn type_options_see_our_type_strings() {
    let e = engine(
        "||img.test^$image\n||xhr.test^$xmlhttprequest\n||frame.test^$subdocument\n||css.test^$stylesheet\n\
         ||media.test^$media\n||obj.test^$object\n||ping.test^$ping\n||font.test^$font\n",
    );
    let src = "https://site.example/";
    for (host, kind) in [
        ("img.test", "image"),
        ("xhr.test", "xmlhttprequest"),
        ("frame.test", "sub_frame"),
        ("css.test", "stylesheet"),
        ("media.test", "media"),
        ("obj.test", "object"),
        ("ping.test", "ping"),
        ("font.test", "font"),
    ] {
        let url = format!("https://{host}/a");
        assert!(blocked(&e, &url, src, kind), "{host} as {kind}");
        assert!(!blocked(&e, &url, src, "script"), "{host} as script");
    }
    // A rule without type options also matches documents.
    let e = engine("||ads.test^\n");
    assert!(blocked(&e, "https://ads.test/", "", "document"));
    assert!(blocked(&e, "https://ads.test/", "", "other"));
}

#[test]
fn hosts_lists_block_names_and_subdomains() {
    let text = "0.0.0.0 ads.example.org\n127.0.0.1 localhost\n# comment\nplain.example.net\n";
    let e = FilterEngine::from_lists(
        &[ListSource {
            name: "hosts",
            text,
            format: ListFormat::Hosts,
        }],
        false,
    );
    assert!(blocked(
        &e,
        "https://ads.example.org/x",
        "https://e.com/",
        "script"
    ));
    assert!(blocked(
        &e,
        "https://sub.ads.example.org/x",
        "https://e.com/",
        "script"
    ));
    assert!(blocked(
        &e,
        "https://plain.example.net/x",
        "https://e.com/",
        "script"
    ));
    assert!(!blocked(
        &e,
        "https://localhost/x",
        "https://e.com/",
        "script"
    ));
}

#[test]
fn cosmetic_rules_are_dropped() {
    // Same line numbers in both lists, so only the cosmetic rules differ.
    let with_cosmetic = engine("##.ad-banner\nexample.com##.sponsored\n||ads.com^\n");
    let without = engine("! one\n! two\n||ads.com^\n");
    assert_eq!(with_cosmetic.serialize(), without.serialize());
    assert!(blocked(
        &with_cosmetic,
        "https://ads.com/x",
        "https://e.com/",
        "script"
    ));
}

#[test]
fn unparseable_urls_are_allowed() {
    let e = engine("||x.com^\n");
    assert_eq!(e.check("not a url", "", "script"), Verdict::Allow);
    assert_eq!(e.check("https://", "", "script"), Verdict::Allow);
}

#[test]
fn counts_network_rules_only() {
    let text = "! comment\n[Adblock Plus 2.0]\n||a.com^\n##.ad\nexample.com##.x\n/ads.js\n@@||b.com^\n||c.com^$popup\n\n";
    assert_eq!(network_rule_count(&[adblock(text)]), 3);
    let hosts = ListSource {
        name: "hosts",
        text: "0.0.0.0 a.example\n127.0.0.1 localhost\n# c\n",
        format: ListFormat::Hosts,
    };
    assert_eq!(network_rule_count(&[adblock(text), hosts]), 4);
}

const RULES: &str = "||doubleclick.net^\n/ads.js\n@@||example.com/ads.js\n||tracker.com^$third-party\n/banner/*/img^\n";

const CASES: [(&str, &str, &str); 7] = [
    (
        "https://ad.doubleclick.net/x.js",
        "https://example.com/",
        "script",
    ),
    (
        "https://example.com/ads.js",
        "https://example.com/",
        "script",
    ),
    ("https://other.com/ads.js", "https://other.com/", "script"),
    ("https://tracker.com/p.gif", "https://news.com/", "image"),
    ("https://tracker.com/p.gif", "https://tracker.com/", "image"),
    (
        "https://example.com/banner/1/img/x",
        "https://example.com/",
        "image",
    ),
    (
        "https://example.com/fine.js",
        "https://example.com/",
        "script",
    ),
];

#[test]
fn serialized_engines_load_through_mmap() {
    for debug in [false, true] {
        let e = FilterEngine::from_lists(&[adblock(RULES)], debug);
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&e.serialize()).unwrap();
        let loaded = FilterEngine::load(file.path()).unwrap();
        for (url, source, kind) in CASES {
            assert_eq!(
                loaded.check(url, source, kind),
                e.check(url, source, kind),
                "{url} debug={debug}"
            );
        }
        let blocked_count = CASES
            .iter()
            .filter(|(u, s, k)| blocked(&loaded, u, s, k))
            .count();
        assert_eq!(blocked_count, 4);
    }
}

#[test]
fn load_rejects_bad_files() {
    let missing = std::env::temp_dir().join("tollgate-no-such-engine.dat");
    assert!(matches!(
        FilterEngine::load(&missing),
        Err(FilterError::Io { .. })
    ));

    let mut corrupt = engine("||x.com^\n").serialize();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xff;
    for bytes in [b"garbage".to_vec(), corrupt, Vec::new()] {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&bytes).unwrap();
        let err = FilterEngine::load(file.path()).err().unwrap();
        assert!(
            matches!(err, FilterError::Engine(_) | FilterError::Io { .. }),
            "{err:?}"
        );
    }
}

#[test]
fn regex_discard_policy_is_short() {
    assert_eq!(REGEX_CLEANUP_INTERVAL.as_secs(), 10);
    assert_eq!(REGEX_DISCARD_UNUSED.as_secs(), 30);
}

#[test]
fn engine_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FilterEngine>();
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd core && cargo test -p tollgate-filter --test engine`
Expected: FAIL to compile with `` error[E0432]: unresolved imports `tollgate_filter::FilterEngine`, ... `` naming every imported item, plus follow-on `E0277` errors.

- [ ] **Step 3: Implement**

`core/crates/filter/src/lib.rs`:

```rust
//! Request filtering: the adblock engine for URLs seen by the proxy, the hashed DNS
//! blocklist, and compiling both from filter lists.

mod engine;

use std::path::PathBuf;

pub use engine::{
    FilterEngine, REGEX_CLEANUP_INTERVAL, REGEX_DISCARD_UNUSED, Verdict, network_rule_count,
};

/// How a list is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListFormat {
    /// Adblock Plus, uBlock Origin and AdGuard syntax.
    Adblock,
    /// `0.0.0.0 host` lines, or one bare host per line.
    Hosts,
}

/// One filter list's text.
pub struct ListSource<'a> {
    /// Used in log messages only.
    pub name: &'a str,
    pub text: &'a str,
    pub format: ListFormat,
}

#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("engine data rejected: {0}")]
    Engine(String),
}
```

`core/crates/filter/src/engine.rs`:

```rust
//! The adblock engine that checks the URLs the proxy sees.

use std::fs::File;
use std::path::Path;
use std::time::Duration;

use adblock::Engine;
use adblock::lists::{FilterFormat, FilterSet, ParseOptions, ParsedLine, RuleTypes, parse_filter};
use adblock::regex_manager::RegexManagerDiscardPolicy;
use adblock::request::Request;

use crate::{FilterError, ListFormat, ListSource};

/// How often the engine looks for compiled regexes to discard.
pub const REGEX_CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
/// A compiled regex unused for this long is discarded (adblock's default is 180 s).
pub const REGEX_DISCARD_UNUSED: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// `rule` is the matching rule's text, only known when the engine was built with
    /// `debug = true`; engines loaded from `engine.dat` always give `None`.
    Block {
        rule: Option<String>,
    },
}

/// Network rules only, no cosmetic rules. `Send + Sync`.
pub struct FilterEngine {
    engine: Engine,
}

fn parse_options(format: ListFormat) -> ParseOptions {
    ParseOptions {
        format: match format {
            ListFormat::Adblock => FilterFormat::Standard,
            ListFormat::Hosts => FilterFormat::Hosts,
        },
        rule_types: RuleTypes::NetworkOnly,
        ..ParseOptions::default()
    }
}

impl FilterEngine {
    /// Builds an engine from rule text. `debug` keeps each rule's text so
    /// [`Verdict::Block`] can name it; it roughly doubles memory, so only the app uses it.
    pub fn from_lists(lists: &[ListSource], debug: bool) -> FilterEngine {
        let mut set = FilterSet::new(debug);
        for list in lists {
            set.add_filter_list(list.text.to_owned(), parse_options(list.format));
        }
        FilterEngine::wrap(Engine::new_with_filter_set(set))
    }

    /// The `engine.dat` bytes. Only readable by the same adblock version.
    pub fn serialize(&self) -> Vec<u8> {
        self.engine.serialize()
    }

    /// Loads `engine.dat` through a memory map, so the file's pages are clean, file-backed
    /// memory while adblock copies them into its own buffer, instead of a second heap copy.
    pub fn load(path: &Path) -> Result<FilterEngine, FilterError> {
        let io = |source| FilterError::Io {
            path: path.to_path_buf(),
            source,
        };
        let file = File::open(path).map_err(io)?;
        // SAFETY: compile() replaces engine.dat by renaming a new file over it and never
        // writes into an existing file, so the mapped bytes cannot change under us.
        let map = unsafe { memmap2::Mmap::map(&file) }.map_err(io)?;
        let mut engine = Engine::default();
        engine
            .deserialize(&map)
            .map_err(|e| FilterError::Engine(format!("{e:?}")))?;
        drop(map);
        Ok(FilterEngine::wrap(engine))
    }

    /// `request_type` is an adblock type string, see [`crate::request_type`]. A URL the
    /// engine cannot parse is allowed: filtering fails open.
    pub fn check(&self, url: &str, source_url: &str, request_type: &str) -> Verdict {
        let request = match Request::new(url, source_url, request_type, "GET") {
            Ok(request) => request,
            Err(e) => {
                log::debug!("not filtering unparseable request {url:?}: {e:?}");
                return Verdict::Allow;
            }
        };
        let result = self.engine.check_network_request(&request);
        if result.should_block() {
            Verdict::Block {
                rule: result.filter.and_then(|f| f.raw_line),
            }
        } else {
            Verdict::Allow
        }
    }

    fn wrap(engine: Engine) -> FilterEngine {
        engine.set_regex_discard_policy(RegexManagerDiscardPolicy {
            cleanup_interval: REGEX_CLEANUP_INTERVAL,
            discard_unused_time: REGEX_DISCARD_UNUSED,
        });
        FilterEngine { engine }
    }
}

/// Number of network rules adblock accepts from these lists (cosmetic rules, comments and
/// unsupported rules are not counted).
pub fn network_rule_count(lists: &[ListSource]) -> u64 {
    lists
        .iter()
        .map(|list| {
            let options = parse_options(list.format);
            list.text
                .lines()
                .filter(|line| {
                    matches!(
                        parse_filter(line, false, options),
                        Ok(ParsedLine::Network(_))
                    )
                })
                .count() as u64
        })
        .sum()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd core && cargo test -p tollgate-filter --test engine && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: 14 passed; clippy and fmt clean.

- [ ] **Step 5: Commit**

```bash
git add core/Cargo.toml core/Cargo.lock core/crates/filter
git commit -m "Add tollgate-filter with the adblock engine wrapper"
```

---

### Task 10: Request type and source URL

**Files:**
- Modify: `core/crates/filter/src/lib.rs`
- Create: `core/crates/filter/src/request_type.rs`
- Test: `core/crates/filter/tests/request_type.rs`

**Interfaces:**
- Produces (contract): `pub fn request_type(sec_fetch_dest: Option<&str>, accept: Option<&str>, path: &str) -> &'static str`.
- Produces (extra): `pub fn source_url<'a>(url: &'a str, request_type: &str, referer: Option<&'a str>, origin: Option<&'a str>) -> &'a str`.

- [ ] **Step 1: Write the failing tests**

`core/crates/filter/tests/request_type.rs`:

```rust
use adblock::request::{Request, RequestType};
use tollgate_filter::{FilterEngine, ListFormat, ListSource, Verdict, request_type, source_url};

/// Every Sec-Fetch-Dest value in the Fetch standard, plus `fencedframe`.
const FETCH_DEST: [(&str, &str); 24] = [
    ("audio", "media"),
    ("audioworklet", "script"),
    ("document", "document"),
    ("embed", "object"),
    ("empty", "xmlhttprequest"),
    ("fencedframe", "sub_frame"),
    ("font", "font"),
    ("frame", "sub_frame"),
    ("iframe", "sub_frame"),
    ("image", "image"),
    ("json", "xmlhttprequest"),
    ("manifest", "other"),
    ("object", "object"),
    ("paintworklet", "script"),
    ("report", "ping"),
    ("script", "script"),
    ("serviceworker", "script"),
    ("sharedworker", "script"),
    ("style", "stylesheet"),
    ("track", "media"),
    ("video", "media"),
    ("webidentity", "other"),
    ("worker", "script"),
    ("xslt", "other"),
];

#[test]
fn every_sec_fetch_dest_value_is_mapped() {
    for (dest, want) in FETCH_DEST {
        assert_eq!(request_type(Some(dest), None, "/x.js"), want, "{dest}");
    }
}

#[test]
fn sec_fetch_dest_ignores_case_and_whitespace_and_wins() {
    assert_eq!(request_type(Some(" Style "), None, "/"), "stylesheet");
    assert_eq!(request_type(Some("IFRAME"), None, "/"), "sub_frame");
    assert_eq!(
        request_type(Some("image"), Some("text/html"), "/a.js"),
        "image"
    );
}

#[test]
fn unknown_sec_fetch_dest_falls_back() {
    assert_eq!(
        request_type(Some("speculationrules"), Some("text/css"), "/a.js"),
        "stylesheet"
    );
    assert_eq!(
        request_type(Some("speculationrules"), None, "/a.js"),
        "script"
    );
    assert_eq!(request_type(Some(""), None, "/a.png"), "image");
}

#[test]
fn accept_uses_the_first_media_range() {
    let cases = [
        (
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "document",
        ),
        ("application/xhtml+xml", "document"),
        ("text/css,*/*;q=0.1", "stylesheet"),
        (
            "image/webp,image/avif,image/jxl,image/heic,video/*;q=0.8,image/png,*/*;q=0.5",
            "image",
        ),
        ("image/*", "image"),
        ("application/javascript", "script"),
        ("text/javascript; charset=utf-8", "script"),
        ("font/woff2;q=1.0", "font"),
        ("application/font-woff", "font"),
        ("video/mp4", "media"),
        ("audio/*", "media"),
        ("application/json, text/plain, */*", "xmlhttprequest"),
        ("application/ld+json", "xmlhttprequest"),
        ("TEXT/CSS", "stylesheet"),
    ];
    for (accept, want) in cases {
        assert_eq!(request_type(None, Some(accept), "/"), want, "{accept}");
    }
}

#[test]
fn uninformative_accept_falls_back_to_the_path() {
    assert_eq!(request_type(None, Some("*/*"), "/lib/app.js"), "script");
    assert_eq!(
        request_type(None, Some("text/plain"), "/a.css"),
        "stylesheet"
    );
    assert_eq!(request_type(None, Some(""), "/a.gif"), "image");
}

#[test]
fn path_extension_is_the_last_resort() {
    let cases = [
        ("/a/b.JS?x=1", "script"),
        ("/m.mjs", "script"),
        ("/x.css#top", "stylesheet"),
        ("/img.png", "image"),
        ("/photo.jpeg?w=100", "image"),
        ("/icon.svg", "image"),
        ("/f.woff2", "font"),
        ("/live/index.m3u8", "media"),
        ("/clip.mp4", "media"),
        ("/api/data.json", "xmlhttprequest"),
        ("/page.html", "other"),
        ("/dir.v2/file", "other"),
        ("/archive.tar.gz", "other"),
        ("/", "other"),
        ("", "other"),
        ("/noext", "other"),
        ("/a.js/", "other"),
    ];
    for (path, want) in cases {
        assert_eq!(request_type(None, None, path), want, "{path}");
    }
}

#[test]
fn adblock_recognizes_every_type_we_produce() {
    let expected = [
        ("document", RequestType::Document),
        ("sub_frame", RequestType::Subdocument),
        ("stylesheet", RequestType::Stylesheet),
        ("script", RequestType::Script),
        ("image", RequestType::Image),
        ("font", RequestType::Font),
        ("media", RequestType::Media),
        ("object", RequestType::Object),
        ("xmlhttprequest", RequestType::Xmlhttprequest),
        ("ping", RequestType::Ping),
        ("other", RequestType::Other),
    ];
    for (_, kind) in FETCH_DEST {
        assert!(
            expected.iter().any(|(s, _)| *s == kind),
            "{kind} not covered"
        );
    }
    for (kind, want) in expected {
        let request =
            Request::new("https://a.example/x", "https://b.example/", kind, "GET").unwrap();
        assert_eq!(request.request_type, want, "{kind}");
    }
}

#[test]
fn source_url_prefers_document_then_referer_then_origin() {
    let url = "https://news.example/story";
    assert_eq!(
        source_url(url, "document", Some("https://search.example/"), None),
        url
    );
    assert_eq!(
        source_url(
            url,
            "script",
            Some("https://page.example/a"),
            Some("https://origin.example")
        ),
        "https://page.example/a"
    );
    assert_eq!(
        source_url(url, "xmlhttprequest", None, Some("https://origin.example")),
        "https://origin.example"
    );
    assert_eq!(
        source_url(
            url,
            "xmlhttprequest",
            Some(""),
            Some("https://origin.example")
        ),
        "https://origin.example"
    );
    assert_eq!(source_url(url, "image", None, Some("null")), "");
    assert_eq!(source_url(url, "image", None, None), "");
}

fn engine(rules: &str) -> FilterEngine {
    FilterEngine::from_lists(
        &[ListSource {
            name: "test",
            text: rules,
            format: ListFormat::Adblock,
        }],
        false,
    )
}

fn blocked(e: &FilterEngine, url: &str, source: &str, kind: &str) -> bool {
    matches!(e.check(url, source, kind), Verdict::Block { .. })
}

#[test]
fn documents_are_their_own_source() {
    let e = engine(
        "||tracker.com^$third-party\n||cdn.example^$domain=news.com\n||ads.example^$~third-party\n",
    );
    let page = "https://tracker.com/";
    // Without a source the page itself would look third party and be blocked.
    assert!(blocked(&e, page, "", "document"));
    assert!(!blocked(
        &e,
        page,
        source_url(page, "document", None, None),
        "document"
    ));
    // $domain= only applies when the source is known.
    let script = "https://cdn.example/lib.js";
    assert!(!blocked(
        &e,
        script,
        source_url(script, "script", None, None),
        "script"
    ));
    assert!(blocked(
        &e,
        script,
        source_url(script, "script", Some("https://news.com/story"), None),
        "script"
    ));
    assert!(blocked(
        &e,
        script,
        source_url(script, "script", None, Some("https://news.com")),
        "script"
    ));
    // $~third-party needs a same-site source.
    let ad = "https://ads.example/x.js";
    assert!(!blocked(&e, ad, "", "script"));
    assert!(blocked(&e, ad, "https://www.ads.example/", "script"));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd core && cargo test -p tollgate-filter --test request_type`
Expected: FAIL to compile with `` error[E0432]: unresolved imports `tollgate_filter::request_type`, `tollgate_filter::source_url` ``.

- [ ] **Step 3: Implement**

`core/crates/filter/src/lib.rs`:

```rust
//! Request filtering: the adblock engine for URLs seen by the proxy, the hashed DNS
//! blocklist, and compiling both from filter lists.

mod engine;
mod request_type;

use std::path::PathBuf;

pub use engine::{
    FilterEngine, REGEX_CLEANUP_INTERVAL, REGEX_DISCARD_UNUSED, Verdict, network_rule_count,
};
pub use request_type::{request_type, source_url};

/// How a list is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListFormat {
    /// Adblock Plus, uBlock Origin and AdGuard syntax.
    Adblock,
    /// `0.0.0.0 host` lines, or one bare host per line.
    Hosts,
}

/// One filter list's text.
pub struct ListSource<'a> {
    /// Used in log messages only.
    pub name: &'a str,
    pub text: &'a str,
    pub format: ListFormat,
}

#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("engine data rejected: {0}")]
    Engine(String),
}
```

`core/crates/filter/src/request_type.rs`:

```rust
//! Request type and source URL for the adblock engine, from request headers.

/// `Sec-Fetch-Dest` values (Fetch standard, plus `fencedframe`) to adblock type strings.
/// adblock does not know `style`, `iframe`, `frame` or `empty` and would treat them as
/// `other`, so every value is mapped explicitly.
const FETCH_DEST: &[(&str, &str)] = &[
    ("audio", "media"),
    ("audioworklet", "script"),
    ("document", "document"),
    ("embed", "object"),
    ("empty", "xmlhttprequest"),
    ("fencedframe", "sub_frame"),
    ("font", "font"),
    ("frame", "sub_frame"),
    ("iframe", "sub_frame"),
    ("image", "image"),
    ("json", "xmlhttprequest"),
    ("manifest", "other"),
    ("object", "object"),
    ("paintworklet", "script"),
    ("report", "ping"),
    ("script", "script"),
    ("serviceworker", "script"),
    ("sharedworker", "script"),
    ("style", "stylesheet"),
    ("track", "media"),
    ("video", "media"),
    ("webidentity", "other"),
    ("worker", "script"),
    ("xslt", "other"),
];

/// Maps Sec-Fetch-Dest, then Accept, then path extension to an adblock request type string.
///
/// A `Sec-Fetch-Dest` value missing from the table (a future one) falls through to
/// `Accept`. `Accept` is judged by its first media range only, because browsers put the
/// type they want first and end with `*/*`. `path` may include a query or fragment.
pub fn request_type(
    sec_fetch_dest: Option<&str>,
    accept: Option<&str>,
    path: &str,
) -> &'static str {
    if let Some(dest) = sec_fetch_dest
        && let Some(kind) = from_fetch_dest(dest)
    {
        return kind;
    }
    if let Some(accept) = accept
        && let Some(kind) = from_accept(accept)
    {
        return kind;
    }
    from_extension(path)
}

fn from_fetch_dest(dest: &str) -> Option<&'static str> {
    let dest = dest.trim();
    FETCH_DEST
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(dest))
        .map(|(_, kind)| *kind)
}

fn from_accept(accept: &str) -> Option<&'static str> {
    let first = accept.split(',').next()?.split(';').next()?.trim();
    let first = first.to_ascii_lowercase();
    let kind = match first.as_str() {
        "text/html" | "application/xhtml+xml" => "document",
        "text/css" => "stylesheet",
        "application/javascript"
        | "text/javascript"
        | "application/ecmascript"
        | "text/ecmascript" => "script",
        "application/json" => "xmlhttprequest",
        t if t.starts_with("image/") => "image",
        t if t.starts_with("font/") || t.starts_with("application/font-") => "font",
        t if t.starts_with("video/") || t.starts_with("audio/") => "media",
        t if t.ends_with("+json") => "xmlhttprequest",
        _ => return None,
    };
    Some(kind)
}

fn from_extension(path: &str) -> &'static str {
    let path = path.split(['?', '#']).next().unwrap_or("");
    let file = path.rsplit('/').next().unwrap_or("");
    let Some((_, ext)) = file.rsplit_once('.') else {
        return "other";
    };
    match ext.to_ascii_lowercase().as_str() {
        "js" | "mjs" | "cjs" => "script",
        "css" => "stylesheet",
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "svg" | "ico" | "bmp" | "apng"
        | "heic" | "jxl" => "image",
        "woff" | "woff2" | "ttf" | "otf" | "eot" => "font",
        "mp4" | "m4v" | "webm" | "mov" | "mp3" | "m4a" | "aac" | "ogg" | "oga" | "opus" | "wav"
        | "flac" | "m3u8" | "mpd" | "m4s" => "media",
        "json" => "xmlhttprequest",
        _ => "other",
    }
}

/// The source URL adblock uses to decide first or third party.
///
/// A top-level document is its own source: with an empty source adblock treats every
/// request as third party, so `$third-party` rules would block the page itself and
/// `$domain=` rules would never apply. Other requests use `Referer`, then `Origin` (an
/// opaque `null` origin counts as missing), then the empty string.
pub fn source_url<'a>(
    url: &'a str,
    request_type: &str,
    referer: Option<&'a str>,
    origin: Option<&'a str>,
) -> &'a str {
    if request_type == "document" {
        return url;
    }
    referer
        .filter(|r| !r.is_empty())
        .or(origin.filter(|o| !o.is_empty() && *o != "null"))
        .unwrap_or("")
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd core && cargo test -p tollgate-filter --test request_type && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: 9 passed; clippy and fmt clean.

- [ ] **Step 5: Commit**

```bash
git add core/crates/filter
git commit -m "Map request headers to adblock request types and source URLs"
```

---

### Task 11: Host rule parser for the DNS blocklist

**Files:**
- Modify: `core/crates/filter/src/lib.rs`
- Create: `core/crates/filter/src/domain_rules.rs`
- Test: `core/crates/filter/tests/domain_rules.rs`

**Interfaces:**
- Consumes: `ListSource`, `ListFormat`.
- Produces (extra): `pub struct DomainRules { pub important: Vec<String>, pub allow: Vec<String>, pub block: Vec<String>, pub skipped: u64 }` (`Clone, Debug, Default, PartialEq, Eq`), `DomainRules::parse(lists: &[ListSource]) -> DomainRules`. Task 12 encodes it into `domains.bin`.

- [ ] **Step 1: Write the failing tests**

`core/crates/filter/tests/domain_rules.rs`:

```rust
use tollgate_filter::{DomainRules, ListFormat, ListSource};

fn parse(format: ListFormat, text: &str) -> DomainRules {
    DomainRules::parse(&[ListSource {
        name: "test",
        text,
        format,
    }])
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn adblock_host_rule_shapes() {
    let rules = parse(
        ListFormat::Adblock,
        "! Title: test\n\
         [Adblock Plus 2.0]\n\
         # comment\n\
         \n\
         ||doubleclick.net^\n\
         ||pipe.example^|\n\
         ||no-caret.example\n\
         .leading-dot.example^\n\
         ||Trailing.Dot.COM.^\n\
         @@||ad.10010.com^\n\
         @@||exception-pipe.example^|\n\
         ||x.example^$important\n\
         ||y.example^\n",
    );
    assert_eq!(rules.important, names(&["x.example"]));
    assert_eq!(
        rules.allow,
        names(&["ad.10010.com", "exception-pipe.example"])
    );
    assert_eq!(
        rules.block,
        names(&[
            "doubleclick.net",
            "leading-dot.example",
            "no-caret.example",
            "pipe.example",
            "trailing.dot.com",
            "y.example",
        ])
    );
    assert_eq!(rules.skipped, 0);
}

#[test]
fn non_host_rules_are_skipped() {
    let skipped = [
        "|piwik.",
        "||prefix.",
        "||*.wildcard.example^",
        "/regex-ad[0-9]+/",
        "||path.example/ads^",
        "||opt.example^$third-party",
        "||client.example^$client=1.2.3.4",
        "||dns.example^$dnstype=AAAA",
        "||empty-option.example^$",
        "||1.2.3.4^",
        "||nodot^",
        ".noncaret.example",
        "example.com##.ad",
        "plain.example.com",
        "||exämple.com^",
        "@@||path.example/x",
        "||tail.example^*",
    ];
    let rules = parse(ListFormat::Adblock, &skipped.join("\n"));
    assert_eq!(
        rules,
        DomainRules {
            skipped: skipped.len() as u64,
            ..DomainRules::default()
        }
    );
}

#[test]
fn badfilter_cancels_the_identical_rule_of_the_same_kind() {
    let rules = parse(
        ListFormat::Adblock,
        "||y.example^$badfilter\n\
         ||y.example^\n\
         ||keep.example^\n\
         @@||keep.example^$badfilter\n\
         ||imp.example^$important\n\
         ||imp.example^$important,badfilter\n\
         @@||allowed.example^\n\
         @@||allowed.example^$badfilter\n\
         .dotted.example^\n\
         ||dotted.example^$badfilter\n",
    );
    assert_eq!(rules.block, names(&["keep.example"]));
    assert!(rules.allow.is_empty());
    assert!(rules.important.is_empty());
    assert_eq!(rules.skipped, 0);
}

#[test]
fn important_exception_is_a_plain_exception() {
    let rules = parse(ListFormat::Adblock, "@@||a.example^$important\n");
    assert_eq!(rules.allow, names(&["a.example"]));
    assert!(rules.important.is_empty());
}

#[test]
fn hosts_format_edge_cases() {
    let rules = parse(
        ListFormat::Hosts,
        "\u{feff}# StevenBlack style header\n\
         127.0.0.1 localhost\n\
         127.0.0.1 localhost.localdomain\n\
         255.255.255.255 broadcasthost\n\
         ::1 localhost ip6-localhost ip6-loopback\n\
         fe80::1%lo0 localhost\n\
         ff02::2 ip6-allrouters\n\
         0.0.0.0 0.0.0.0\n\
         0.0.0.0 tracker.example # trailing comment\n\
         0.0.0.0\tTabbed.Example.\r\n\
         127.0.0.1 multi-a.example multi-b.example\n\
         bare.example.org\n\
         :: v6-any.example\n\
         0.0.0.0 bad_name!.example\n\
         0.0.0.0 1.2.3.4\n",
    );
    assert_eq!(
        rules.block,
        names(&[
            "bare.example.org",
            "multi-a.example",
            "multi-b.example",
            "tabbed.example",
            "tracker.example",
            "v6-any.example",
        ])
    );
    // localhost, localhost.localdomain, broadcasthost, the ::1 line, fe80::1%lo0,
    // ip6-allrouters, 0.0.0.0 0.0.0.0, the bad name and the address as a name.
    assert_eq!(rules.skipped, 9);
    assert!(rules.allow.is_empty());
}

#[test]
fn redundant_children_are_dropped_and_names_merge_across_lists() {
    let rules = DomainRules::parse(&[
        ListSource {
            name: "adblock",
            text: "||a.b.example.com^\n||example.com^\n||other.net^\n@@||x.allowed.org^\n@@||allowed.org^\n",
            format: ListFormat::Adblock,
        },
        ListSource {
            name: "hosts",
            text: "0.0.0.0 deep.sub.other.net\n0.0.0.0 fresh.example\n0.0.0.0 example.com\n",
            format: ListFormat::Hosts,
        },
    ]);
    assert_eq!(
        rules.block,
        names(&["example.com", "fresh.example", "other.net"])
    );
    assert_eq!(rules.allow, names(&["allowed.org"]));
}

#[test]
fn empty_input_gives_empty_rules() {
    assert_eq!(DomainRules::parse(&[]), DomainRules::default());
    assert_eq!(parse(ListFormat::Hosts, ""), DomainRules::default());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd core && cargo test -p tollgate-filter --test domain_rules`
Expected: FAIL to compile with `` error[E0432]: unresolved import `tollgate_filter::DomainRules` ``.

- [ ] **Step 3: Implement**

`core/crates/filter/src/lib.rs`:

```rust
//! Request filtering: the adblock engine for URLs seen by the proxy, the hashed DNS
//! blocklist, and compiling both from filter lists.

mod domain_rules;
mod engine;
mod request_type;

use std::path::PathBuf;

pub use domain_rules::DomainRules;
pub use engine::{
    FilterEngine, REGEX_CLEANUP_INTERVAL, REGEX_DISCARD_UNUSED, Verdict, network_rule_count,
};
pub use request_type::{request_type, source_url};

/// How a list is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListFormat {
    /// Adblock Plus, uBlock Origin and AdGuard syntax.
    Adblock,
    /// `0.0.0.0 host` lines, or one bare host per line.
    Hosts,
}

/// One filter list's text.
pub struct ListSource<'a> {
    /// Used in log messages only.
    pub name: &'a str,
    pub text: &'a str,
    pub format: ListFormat,
}

#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("engine data rejected: {0}")]
    Engine(String),
}
```

`core/crates/filter/src/domain_rules.rs`:

```rust
//! Host rules for the DNS blocklist, extracted from filter lists.

use std::collections::HashSet;

use crate::{ListFormat, ListSource};

/// Host names taken from filter lists, lowercase, without a trailing dot, sorted, unique,
/// and without names whose parent is in the same set (a lookup checks every parent, so
/// those children can never change a result).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DomainRules {
    /// `$important` blocks. They win over `allow`.
    pub important: Vec<String>,
    /// `@@` exceptions. They win over `block`.
    pub allow: Vec<String>,
    pub block: Vec<String>,
    /// Lines that are neither comments nor host rules: rules with other options, paths,
    /// wildcards, regexes, and hosts lines without a usable name.
    pub skipped: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Important,
    Allow,
    Block,
}

enum Line {
    Comment,
    Skip,
    Rule {
        kind: Kind,
        name: String,
        badfilter: bool,
    },
}

#[derive(Default)]
struct Builder {
    important: HashSet<String>,
    allow: HashSet<String>,
    block: HashSet<String>,
    badfilter: HashSet<(Kind, String)>,
    skipped: u64,
}

impl DomainRules {
    /// Adblock lists contribute `||name^`, `||name^|`, `||name` (no caret, when the name
    /// does not end in a dot), `.name^` (treated as the name and its subdomains), their
    /// `@@` forms, `$important` and `$badfilter`. Any other option, a path, a wildcard, a
    /// regex or a `|` prefix rule is skipped. Hosts lists contribute every name on
    /// `address name...` lines and bare `name` lines.
    pub fn parse(lists: &[ListSource]) -> DomainRules {
        let mut builder = Builder::default();
        for list in lists {
            let text = list.text.strip_prefix('\u{feff}').unwrap_or(list.text);
            let before = builder.skipped;
            match list.format {
                ListFormat::Adblock => text.lines().for_each(|line| builder.add_adblock_line(line)),
                ListFormat::Hosts => text.lines().for_each(|line| builder.add_hosts_line(line)),
            }
            log::info!(
                "{}: skipped {} lines for the DNS blocklist",
                list.name,
                builder.skipped - before
            );
        }
        builder.finish()
    }
}

impl Builder {
    fn add_adblock_line(&mut self, line: &str) {
        match parse_adblock_line(line) {
            Line::Comment => {}
            Line::Skip => self.skipped += 1,
            Line::Rule {
                kind,
                name,
                badfilter: true,
            } => {
                self.badfilter.insert((kind, name));
            }
            Line::Rule { kind, name, .. } => {
                let set = match kind {
                    Kind::Important => &mut self.important,
                    Kind::Allow => &mut self.allow,
                    Kind::Block => &mut self.block,
                };
                set.insert(name);
            }
        }
    }

    fn add_hosts_line(&mut self, line: &str) {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            return;
        }
        let mut fields = line.split_whitespace();
        let Some(first) = fields.next() else {
            return;
        };
        // `0.0.0.0 name`, `::1 name` and `fe80::1%lo0 name` start with an address; a line
        // without one is a bare name.
        let starts_with_address = first.parse::<std::net::IpAddr>().is_ok() || first.contains(':');
        let names = std::iter::once(first)
            .filter(|_| !starts_with_address)
            .chain(fields);
        let mut accepted = 0;
        for name in names {
            if name.eq_ignore_ascii_case("localhost.localdomain") {
                continue;
            }
            if let Some(name) = normalize_name(name) {
                self.block.insert(name);
                accepted += 1;
            }
        }
        if accepted == 0 {
            self.skipped += 1;
        }
    }

    fn finish(mut self) -> DomainRules {
        for (kind, name) in &self.badfilter {
            let set = match kind {
                Kind::Important => &mut self.important,
                Kind::Allow => &mut self.allow,
                Kind::Block => &mut self.block,
            };
            set.remove(name);
        }
        DomainRules {
            important: without_redundant_children(&self.important),
            allow: without_redundant_children(&self.allow),
            block: without_redundant_children(&self.block),
            skipped: self.skipped,
        }
    }
}

fn parse_adblock_line(line: &str) -> Line {
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') || line.starts_with('[') {
        return Line::Comment;
    }
    let (exception, rule) = match line.strip_prefix("@@") {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    let (pattern, options) = match rule.split_once('$') {
        Some((pattern, options)) => (pattern, Some(options)),
        None => (rule, None),
    };
    let mut important = false;
    let mut badfilter = false;
    for option in options.into_iter().flat_map(|o| o.split(',')) {
        match option.trim() {
            "important" => important = true,
            "badfilter" => badfilter = true,
            _ => return Line::Skip,
        }
    }
    let name = if let Some(rest) = pattern.strip_prefix("||") {
        if let Some(name) = rest.strip_suffix("^|").or_else(|| rest.strip_suffix('^')) {
            name
        } else if rest.ends_with('.') {
            // `||ads.` matches every host that starts with `ads.`: a prefix, not a host.
            return Line::Skip;
        } else {
            rest
        }
    } else if let Some(rest) = pattern.strip_prefix('.') {
        match rest.strip_suffix('^') {
            Some(name) => name,
            None => return Line::Skip,
        }
    } else {
        return Line::Skip;
    };
    let Some(name) = normalize_name(name) else {
        return Line::Skip;
    };
    // An important exception is kept as a plain exception, so an important block for
    // the same host still wins. adblock would let the exception win; no DNS list uses it.
    let kind = match (exception, important) {
        (true, _) => Kind::Allow,
        (false, true) => Kind::Important,
        (false, false) => Kind::Block,
    };
    Line::Rule {
        kind,
        name,
        badfilter,
    }
}

/// Lowercases a host name and strips one trailing dot. Rejects names that DNS never
/// asks for: no dot, empty labels, labels over 63 bytes, names over 253 bytes, characters
/// other than letters, digits, `-` and `_`, and a numeric last label (IPv4 addresses).
fn normalize_name(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.len() > 253 || !name.contains('.') {
        return None;
    }
    let mut last = "";
    for label in name.split('.') {
        let valid = !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !valid {
            return None;
        }
        last = label;
    }
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

/// Sorted names, leaving out any whose parent is also in the set.
fn without_redundant_children(names: &HashSet<String>) -> Vec<String> {
    let mut kept: Vec<String> = names
        .iter()
        .filter(|name| {
            !name
                .match_indices('.')
                .map(|(i, _)| &name[i + 1..])
                .any(|parent| names.contains(parent))
        })
        .cloned()
        .collect();
    kept.sort_unstable();
    kept
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd core && cargo test -p tollgate-filter --test domain_rules && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: 7 passed; clippy and fmt clean.

- [ ] **Step 5: Commit**

```bash
git add core/crates/filter
git commit -m "Parse host rules from adblock and hosts lists for the DNS blocklist"
```

---

### Task 12: DomainSet file format and lookups

**Files:**
- Modify: `core/crates/filter/src/lib.rs`
- Create: `core/crates/filter/src/domain_set.rs`
- Test: `core/crates/filter/tests/domain_set.rs`

**Interfaces:**
- Consumes: `DomainRules` (Task 11), `memmap2`.
- Produces (contract): `pub struct DomainSet` (`Send + Sync`, mmapped) with `build(lists: &[ListSource]) -> Vec<u8>`, `load(path: &Path) -> Result<DomainSet, FilterError>`, `from_bytes(bytes: Vec<u8>) -> Result<DomainSet, FilterError>`, `is_blocked(&self, host: &str) -> bool`, `len(&self) -> usize`.
- Produces (extra): `DomainRules::encode(&self) -> Vec<u8>`, `DomainSet::is_empty(&self) -> bool`, `pub enum DomainSetError { TooShort, BadMagic, UnsupportedVersion(u32), BadHeader, LengthMismatch { expected: u64, actual: u64 }, BadChecksum, Unsorted }`, `FilterError::DomainSet(DomainSetError)`.

- [ ] **Step 1: Write the failing tests**

`core/crates/filter/tests/domain_set.rs`:

```rust
use std::io::Write;

use tollgate_filter::{
    DomainRules, DomainSet, DomainSetError, FilterError, ListFormat, ListSource,
};

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn rules() -> DomainRules {
    DomainRules {
        important: names(&["forced.example"]),
        allow: names(&["ad.10010.com", "forced.example", "ok.tracker.example"]),
        block: names(&["10010.com", "doubleclick.net", "tracker.example"]),
        skipped: 0,
    }
}

fn set() -> DomainSet {
    DomainSet::from_bytes(rules().encode()).unwrap()
}

/// FNV-1a 64, written out here so the tests pin the hash the file format depends on.
fn fnv1a64_bytes(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn fnv1a64(s: &str) -> u64 {
    fnv1a64_bytes(s.as_bytes())
}

#[test]
fn fnv_reference_vectors() {
    assert_eq!(fnv1a64(""), 0xcbf2_9ce4_8422_2325);
    assert_eq!(fnv1a64("a"), 0xaf63_dc4c_8601_ec8c);
    assert_eq!(fnv1a64("foobar"), 0x8594_4171_f739_67e8);
}

#[test]
fn file_layout_matches_the_spec() {
    let bytes = DomainRules {
        important: names(&["c.example"]),
        allow: names(&["b.example"]),
        block: names(&["a.example", "d.example"]),
        skipped: 0,
    }
    .encode();
    assert_eq!(bytes.len(), 32 + 8 * 4);
    assert_eq!(&bytes[0..4], b"TGDS");
    assert_eq!(&bytes[4..8], &1u32.to_le_bytes());
    assert_eq!(&bytes[8..12], &2u32.to_le_bytes());
    assert_eq!(&bytes[12..16], &1u32.to_le_bytes());
    assert_eq!(&bytes[16..20], &1u32.to_le_bytes());
    assert_eq!(&bytes[20..24], &[0, 0, 0, 0]);
    assert_eq!(&bytes[24..32], &fnv1a64_bytes(&bytes[32..]).to_le_bytes());
    let mut block = [fnv1a64("a.example"), fnv1a64("d.example")];
    block.sort_unstable();
    let body: Vec<u64> = bytes[32..]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
        .collect();
    assert_eq!(
        body,
        vec![
            block[0],
            block[1],
            fnv1a64("b.example"),
            fnv1a64("c.example")
        ]
    );
}

#[test]
fn matches_the_host_and_every_parent() {
    let d = set();
    assert!(d.is_blocked("doubleclick.net"));
    assert!(d.is_blocked("ad.doubleclick.net"));
    assert!(d.is_blocked("a.b.c.ad.doubleclick.net"));
    assert!(!d.is_blocked("notdoubleclick.net"));
    assert!(!d.is_blocked("doubleclick.net.example"));
    assert!(!d.is_blocked("net"));
    assert!(!d.is_blocked(""));
    assert!(!d.is_blocked("."));
}

#[test]
fn ignores_case_and_one_trailing_dot() {
    let d = set();
    assert!(d.is_blocked("Ad.DoubleClick.NET."));
    assert!(!d.is_blocked("ad.doubleclick.net.."));
}

#[test]
fn important_then_allow_then_block() {
    let d = set();
    // Allowed child of a blocked parent.
    assert!(d.is_blocked("10010.com"));
    assert!(d.is_blocked("www.10010.com"));
    assert!(!d.is_blocked("ad.10010.com"));
    assert!(!d.is_blocked("x.ad.10010.com"));
    assert!(!d.is_blocked("ok.tracker.example"));
    assert!(d.is_blocked("tracker.example"));
    // Important wins over an exception for the same name.
    assert!(d.is_blocked("forced.example"));
    assert!(d.is_blocked("sub.forced.example"));
}

#[test]
fn len_counts_every_section() {
    let d = set();
    assert_eq!(d.len(), 7);
    assert!(!d.is_empty());
    let empty = DomainSet::from_bytes(DomainRules::default().encode()).unwrap();
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
    assert!(!empty.is_blocked("anything.example"));
}

#[test]
fn build_parses_and_encodes() {
    let bytes = DomainSet::build(&[ListSource {
        name: "dns",
        text: "||ads.example^\n@@||ok.ads.example^\n",
        format: ListFormat::Adblock,
    }]);
    let d = DomainSet::from_bytes(bytes).unwrap();
    assert!(d.is_blocked("x.ads.example"));
    assert!(!d.is_blocked("ok.ads.example"));
    assert_eq!(d.len(), 2);
}

fn error(bytes: Vec<u8>) -> DomainSetError {
    match DomainSet::from_bytes(bytes) {
        Err(FilterError::DomainSet(e)) => e,
        Err(other) => panic!("unexpected error {other:?}"),
        Ok(_) => panic!("accepted a bad file"),
    }
}

/// Rewrites the checksum after a test edits the body.
fn reseal(mut bytes: Vec<u8>) -> Vec<u8> {
    let sum = fnv1a64_bytes(&bytes[32..]);
    bytes[24..32].copy_from_slice(&sum.to_le_bytes());
    bytes
}

#[test]
fn rejects_damaged_files() {
    let good = rules().encode();
    assert_eq!(error(Vec::new()), DomainSetError::TooShort);
    assert_eq!(error(good[..31].to_vec()), DomainSetError::TooShort);

    let mut bad = good.clone();
    bad[0] = b'X';
    assert_eq!(error(bad), DomainSetError::BadMagic);

    let mut bad = good.clone();
    bad[4..8].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(error(bad), DomainSetError::UnsupportedVersion(2));

    let mut bad = good.clone();
    bad[20] = 1;
    assert_eq!(error(bad), DomainSetError::BadHeader);

    assert_eq!(
        error(good[..good.len() - 8].to_vec()),
        DomainSetError::LengthMismatch {
            expected: good.len() as u64,
            actual: good.len() as u64 - 8,
        }
    );
    let mut longer = good.clone();
    longer.push(0);
    assert!(matches!(
        error(longer),
        DomainSetError::LengthMismatch { .. }
    ));
    let mut huge = good.clone();
    huge[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(error(huge), DomainSetError::LengthMismatch { .. }));

    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert_eq!(error(bad), DomainSetError::BadChecksum);

    // Swap the first two block hashes and fix the checksum: sorted order is checked too.
    let mut bad = good.clone();
    let (first, second) = (bad[32..40].to_vec(), bad[40..48].to_vec());
    bad[32..40].copy_from_slice(&second);
    bad[40..48].copy_from_slice(&first);
    assert_eq!(error(reseal(bad)), DomainSetError::Unsorted);

    // A duplicate hash is not allowed either.
    let mut bad = good.clone();
    let first = bad[32..40].to_vec();
    bad[40..48].copy_from_slice(&first);
    assert_eq!(error(reseal(bad)), DomainSetError::Unsorted);
}

#[test]
fn load_maps_the_file() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&rules().encode()).unwrap();
    let d = DomainSet::load(file.path()).unwrap();
    assert_eq!(d.len(), 7);
    assert!(d.is_blocked("ad.doubleclick.net"));
    assert!(!d.is_blocked("ad.10010.com"));
}

#[test]
fn load_reports_missing_and_short_files() {
    let missing = std::env::temp_dir().join("tollgate-no-such-domains.bin");
    assert!(matches!(
        DomainSet::load(&missing),
        Err(FilterError::Io { .. })
    ));
    let empty = tempfile::NamedTempFile::new().unwrap();
    assert!(matches!(
        DomainSet::load(empty.path()),
        Err(FilterError::DomainSet(DomainSetError::TooShort))
    ));
    let mut garbage = tempfile::NamedTempFile::new().unwrap();
    garbage.write_all(&[0u8; 40]).unwrap();
    assert!(matches!(
        DomainSet::load(garbage.path()),
        Err(FilterError::DomainSet(DomainSetError::BadMagic))
    ));
}

#[test]
fn domain_set_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DomainSet>();
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd core && cargo test -p tollgate-filter --test domain_set`
Expected: FAIL to compile with `` error[E0432]: unresolved imports `tollgate_filter::DomainSet`, `tollgate_filter::DomainSetError` `` and `` no method named `encode` found for struct `DomainRules` ``.

- [ ] **Step 3: Implement**

`core/crates/filter/src/lib.rs`:

```rust
//! Request filtering: the adblock engine for URLs seen by the proxy, the hashed DNS
//! blocklist, and compiling both from filter lists.

mod domain_rules;
mod domain_set;
mod engine;
mod request_type;

use std::path::PathBuf;

pub use domain_rules::DomainRules;
pub use domain_set::{DomainSet, DomainSetError};
pub use engine::{
    FilterEngine, REGEX_CLEANUP_INTERVAL, REGEX_DISCARD_UNUSED, Verdict, network_rule_count,
};
pub use request_type::{request_type, source_url};

/// How a list is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListFormat {
    /// Adblock Plus, uBlock Origin and AdGuard syntax.
    Adblock,
    /// `0.0.0.0 host` lines, or one bare host per line.
    Hosts,
}

/// One filter list's text.
pub struct ListSource<'a> {
    /// Used in log messages only.
    pub name: &'a str,
    pub text: &'a str,
    pub format: ListFormat,
}

#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("engine data rejected: {0}")]
    Engine(String),
    #[error("domain set rejected: {0}")]
    DomainSet(#[from] DomainSetError),
}
```

`core/crates/filter/src/domain_set.rs`:

```rust
//! The DNS blocklist file (`domains.bin`) and lookups in it.
//!
//! Layout, all integers little-endian:
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 4 | magic `TGDS` |
//! | 4 | 4 | format version, 1 |
//! | 8 | 4 | block count |
//! | 12 | 4 | allow count |
//! | 16 | 4 | important count |
//! | 20 | 4 | reserved, 0 |
//! | 24 | 8 | FNV-1a 64 of every byte after the header |
//! | 32 | 8 each | block hashes, then allow hashes, then important hashes |
//!
//! Each hash is FNV-1a 64 of the lowercase name without a trailing dot. Each section is
//! sorted ascending with no duplicates. A false positive needs a 64-bit collision: about
//! 5e-14 per lookup with 250,000 names.

use std::fs::File;
use std::ops::Range;
use std::path::Path;

use memmap2::Mmap;

use crate::{DomainRules, FilterError, ListSource};

const MAGIC: [u8; 4] = *b"TGDS";
const VERSION: u32 = 1;
pub(crate) const HEADER_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DomainSetError {
    #[error("shorter than the 32 byte header")]
    TooShort,
    #[error("not a domain set file")]
    BadMagic,
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u32),
    #[error("reserved header field is not zero")]
    BadHeader,
    #[error("header promises {expected} bytes, file has {actual}")]
    LengthMismatch { expected: u64, actual: u64 },
    #[error("checksum mismatch")]
    BadChecksum,
    #[error("hashes are not sorted and unique")]
    Unsorted,
}

/// FNV-1a 64 over the bytes, lowercasing ASCII letters on the way.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(b.to_ascii_lowercase());
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// FNV-1a 64 of the raw bytes, for the checksum.
fn checksum(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"))
}

fn sorted_hashes(names: &[String]) -> Vec<u64> {
    let mut hashes: Vec<u64> = names.iter().map(|n| fnv1a64(n.as_bytes())).collect();
    hashes.sort_unstable();
    hashes.dedup();
    hashes
}

impl DomainRules {
    /// The `domains.bin` bytes for these rules.
    pub fn encode(&self) -> Vec<u8> {
        let sections = [
            sorted_hashes(&self.block),
            sorted_hashes(&self.allow),
            sorted_hashes(&self.important),
        ];
        let total: usize = sections.iter().map(Vec::len).sum();
        let mut out = Vec::with_capacity(HEADER_LEN + 8 * total);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        for section in &sections {
            let count = u32::try_from(section.len()).expect("fewer than 2^32 names");
            out.extend_from_slice(&count.to_le_bytes());
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        for hash in sections.iter().flatten() {
            out.extend_from_slice(&hash.to_le_bytes());
        }
        let sum = checksum(&out[HEADER_LEN..]);
        out[24..32].copy_from_slice(&sum.to_le_bytes());
        out
    }
}

enum Backing {
    Mapped(Mmap),
    Owned(Vec<u8>),
}

impl Backing {
    fn bytes(&self) -> &[u8] {
        match self {
            Backing::Mapped(map) => map,
            Backing::Owned(bytes) => bytes,
        }
    }
}

/// The hashed DNS blocklist. `Send + Sync`; lookups never allocate.
pub struct DomainSet {
    data: Backing,
    block: Range<usize>,
    allow: Range<usize>,
    important: Range<usize>,
}

impl DomainSet {
    /// Parses the lists and returns the file bytes.
    pub fn build(lists: &[ListSource]) -> Vec<u8> {
        DomainRules::parse(lists).encode()
    }

    /// Maps the file; the hashes are never copied to the heap.
    pub fn load(path: &Path) -> Result<DomainSet, FilterError> {
        let io = |source| FilterError::Io {
            path: path.to_path_buf(),
            source,
        };
        let file = File::open(path).map_err(io)?;
        let len = file.metadata().map_err(io)?.len();
        if len < HEADER_LEN as u64 {
            return Err(DomainSetError::TooShort.into());
        }
        // SAFETY: compile() replaces domains.bin by renaming a new file over it and never
        // writes into an existing file, so the mapped bytes cannot change under us.
        let map = unsafe { Mmap::map(&file) }.map_err(io)?;
        DomainSet::new(Backing::Mapped(map))
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<DomainSet, FilterError> {
        DomainSet::new(Backing::Owned(bytes))
    }

    fn new(data: Backing) -> Result<DomainSet, FilterError> {
        let bytes = data.bytes();
        if bytes.len() < HEADER_LEN {
            return Err(DomainSetError::TooShort.into());
        }
        if bytes[0..4] != MAGIC {
            return Err(DomainSetError::BadMagic.into());
        }
        let version = read_u32(bytes, 4);
        if version != VERSION {
            return Err(DomainSetError::UnsupportedVersion(version).into());
        }
        if read_u32(bytes, 20) != 0 {
            return Err(DomainSetError::BadHeader.into());
        }
        let counts =
            [read_u32(bytes, 8), read_u32(bytes, 12), read_u32(bytes, 16)].map(|c| c as usize);
        let total: u64 = counts.iter().map(|&c| c as u64).sum();
        let expected = HEADER_LEN as u64 + 8 * total;
        if bytes.len() as u64 != expected {
            return Err(DomainSetError::LengthMismatch {
                expected,
                actual: bytes.len() as u64,
            }
            .into());
        }
        let stored = u64::from_le_bytes(bytes[24..32].try_into().expect("8 bytes"));
        if checksum(&bytes[HEADER_LEN..]) != stored {
            return Err(DomainSetError::BadChecksum.into());
        }
        let block = 0..counts[0];
        let allow = block.end..block.end + counts[1];
        let important = allow.end..allow.end + counts[2];
        let set = DomainSet {
            data,
            block,
            allow,
            important,
        };
        for range in [&set.block, &set.allow, &set.important] {
            let hashes = &set.hashes()[range.clone()];
            if !hashes
                .windows(2)
                .all(|w| u64::from_le_bytes(w[0]) < u64::from_le_bytes(w[1]))
            {
                return Err(DomainSetError::Unsorted.into());
            }
        }
        Ok(set)
    }

    fn hashes(&self) -> &[[u8; 8]] {
        self.data.bytes()[HEADER_LEN..].as_chunks::<8>().0
    }

    fn contains(&self, range: &Range<usize>, hash: u64) -> bool {
        self.hashes()[range.clone()]
            .binary_search_by(|entry| u64::from_le_bytes(*entry).cmp(&hash))
            .is_ok()
    }

    /// True if an entry covers the host or one of its parents, taking important blocks
    /// first, then exceptions, then blocks. ASCII case and one trailing dot are ignored.
    pub fn is_blocked(&self, host: &str) -> bool {
        let host = host.strip_suffix('.').unwrap_or(host).as_bytes();
        // The host and each parent that still has a dot: names without a dot are never
        // stored.
        let mut hashes = [0u64; 127];
        let mut n = 0;
        let mut start = 0;
        while n < hashes.len() {
            let rest = &host[start..];
            let Some(dot) = rest.iter().position(|&b| b == b'.') else {
                break;
            };
            hashes[n] = fnv1a64(rest);
            n += 1;
            start += dot + 1;
        }
        let hashes = &hashes[..n];
        let covered = |range: &Range<usize>| {
            !range.is_empty() && hashes.iter().any(|&h| self.contains(range, h))
        };
        if covered(&self.important) {
            return true;
        }
        if covered(&self.allow) {
            return false;
        }
        covered(&self.block)
    }

    /// Number of stored hashes: blocks, exceptions and important blocks together.
    pub fn len(&self) -> usize {
        self.important.end
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd core && cargo test -p tollgate-filter --test domain_set && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: 11 passed; clippy and fmt clean.

- [ ] **Step 5: Commit**

```bash
git add core/crates/filter
git commit -m "Add the hashed, mmapped DNS blocklist file format"
```

---

### Task 13: Compiling lists into engine.dat and domains.bin

**Files:**
- Modify: `core/crates/filter/src/lib.rs`
- Create: `core/crates/filter/src/compile.rs`
- Test: `core/crates/filter/tests/compile.rs`

**Interfaces:**
- Consumes: `FilterEngine::from_lists`, `network_rule_count`, `DomainRules::parse`, `DomainRules::encode`.
- Produces (contract): `pub const ENGINE_FILE: &str = "engine.dat"`, `pub const DOMAINS_FILE: &str = "domains.bin"`, `pub struct CompileReport { pub network_rules: u64, pub domain_entries: u64, pub engine_bytes: u64, pub domains_bytes: u64 }` (`Clone, Debug`), `pub fn compile(lists: &[ListSource], dir: &Path) -> Result<CompileReport, FilterError>`.
- Produces (extra): `pub fn compile_split(engine_lists: &[ListSource], dns_lists: &[ListSource], dir: &Path) -> Result<CompileReport, FilterError>`.

- [ ] **Step 1: Write the failing tests**

`core/crates/filter/tests/compile.rs`:

```rust
use std::fs;

use tollgate_filter::{
    DOMAINS_FILE, DomainSet, ENGINE_FILE, FilterEngine, FilterError, ListFormat, ListSource,
    Verdict, compile, compile_split,
};

const EASYLIST: &str =
    "! Title: snippet\n||ads.example^\n/banner/*/img^\n##.ad\n||tracker.example^$third-party\n";
const DNS_ADBLOCK: &str = "||dns-only.example^\n@@||ok.ads.example^\n";
const HOSTS: &str = "0.0.0.0 hosts-only.example\n127.0.0.1 localhost\n";

fn lists() -> [ListSource<'static>; 2] {
    [
        ListSource {
            name: "easylist",
            text: EASYLIST,
            format: ListFormat::Adblock,
        },
        ListSource {
            name: "hosts",
            text: HOSTS,
            format: ListFormat::Hosts,
        },
    ]
}

fn file_names(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn compile_writes_both_files_and_reports_them() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("lists");
    let report = compile(&lists(), &out).unwrap();

    assert_eq!(
        file_names(&out),
        vec![DOMAINS_FILE.to_string(), ENGINE_FILE.to_string()]
    );
    assert_eq!(report.network_rules, 3);
    // ads.example (adblock list) and hosts-only.example (hosts list).
    assert_eq!(report.domain_entries, 2);
    assert_eq!(
        report.engine_bytes,
        fs::metadata(out.join(ENGINE_FILE)).unwrap().len()
    );
    assert_eq!(
        report.domains_bytes,
        fs::metadata(out.join(DOMAINS_FILE)).unwrap().len()
    );
    assert_eq!(report.domains_bytes, 32 + 8 * 2);

    let engine = FilterEngine::load(&out.join(ENGINE_FILE)).unwrap();
    assert_eq!(
        engine.check(
            "https://ads.example/a.js",
            "https://site.example/",
            "script"
        ),
        Verdict::Block { rule: None }
    );
    // Hosts lists stay out of the engine.
    assert_eq!(
        engine.check(
            "https://hosts-only.example/a.js",
            "https://site.example/",
            "script"
        ),
        Verdict::Allow
    );
    let domains = DomainSet::load(&out.join(DOMAINS_FILE)).unwrap();
    assert!(domains.is_blocked("x.ads.example"));
    assert!(domains.is_blocked("hosts-only.example"));
    // $third-party rules are not host rules.
    assert!(!domains.is_blocked("tracker.example"));
}

#[test]
fn compile_split_routes_lists() {
    let dir = tempfile::tempdir().unwrap();
    let engine_lists = [ListSource {
        name: "easylist",
        text: EASYLIST,
        format: ListFormat::Adblock,
    }];
    let dns_lists = [
        ListSource {
            name: "adguard-dns",
            text: DNS_ADBLOCK,
            format: ListFormat::Adblock,
        },
        ListSource {
            name: "hosts",
            text: HOSTS,
            format: ListFormat::Hosts,
        },
    ];
    let report = compile_split(&engine_lists, &dns_lists, dir.path()).unwrap();
    assert_eq!(report.network_rules, 3);
    assert_eq!(report.domain_entries, 3);

    let engine = FilterEngine::load(&dir.path().join(ENGINE_FILE)).unwrap();
    assert_eq!(
        engine.check(
            "https://dns-only.example/",
            "https://site.example/",
            "script"
        ),
        Verdict::Allow
    );
    let domains = DomainSet::load(&dir.path().join(DOMAINS_FILE)).unwrap();
    assert!(domains.is_blocked("dns-only.example"));
    assert!(domains.is_blocked("hosts-only.example"));
    // DNS lists alone decide the DNS blocklist.
    assert!(!domains.is_blocked("ads.example"));
}

#[test]
fn recompiling_replaces_the_files() {
    let dir = tempfile::tempdir().unwrap();
    compile(&lists(), dir.path()).unwrap();
    let old_domains = DomainSet::load(&dir.path().join(DOMAINS_FILE)).unwrap();

    let replacement = [ListSource {
        name: "new",
        text: "||new.example^\n",
        format: ListFormat::Adblock,
    }];
    let report = compile(&replacement, dir.path()).unwrap();
    assert_eq!(report.network_rules, 1);
    assert_eq!(
        file_names(dir.path()),
        vec![DOMAINS_FILE.to_string(), ENGINE_FILE.to_string()]
    );

    let domains = DomainSet::load(&dir.path().join(DOMAINS_FILE)).unwrap();
    assert!(domains.is_blocked("new.example"));
    assert!(!domains.is_blocked("ads.example"));
    // A set loaded before the rename still sees the old file.
    assert!(old_domains.is_blocked("ads.example"));
    assert!(!old_domains.is_blocked("new.example"));
}

#[test]
fn compile_reports_io_errors() {
    let dir = tempfile::tempdir().unwrap();
    let not_a_dir = dir.path().join("file");
    fs::write(&not_a_dir, b"x").unwrap();
    let err = compile(&lists(), &not_a_dir).unwrap_err();
    assert!(
        matches!(err, FilterError::Io { ref path, .. } if path == &not_a_dir),
        "{err:?}"
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd core && cargo test -p tollgate-filter --test compile`
Expected: FAIL to compile with `` error[E0432]: unresolved imports `tollgate_filter::DOMAINS_FILE`, `tollgate_filter::ENGINE_FILE`, `tollgate_filter::compile`, `tollgate_filter::compile_split` ``.

- [ ] **Step 3: Implement**

`core/crates/filter/src/lib.rs`:

```rust
//! Request filtering: the adblock engine for URLs seen by the proxy, the hashed DNS
//! blocklist, and compiling both from filter lists.

mod compile;
mod domain_rules;
mod domain_set;
mod engine;
mod request_type;

use std::path::PathBuf;

pub use compile::{CompileReport, DOMAINS_FILE, ENGINE_FILE, compile, compile_split};
pub use domain_rules::DomainRules;
pub use domain_set::{DomainSet, DomainSetError};
pub use engine::{
    FilterEngine, REGEX_CLEANUP_INTERVAL, REGEX_DISCARD_UNUSED, Verdict, network_rule_count,
};
pub use request_type::{request_type, source_url};

/// How a list is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListFormat {
    /// Adblock Plus, uBlock Origin and AdGuard syntax.
    Adblock,
    /// `0.0.0.0 host` lines, or one bare host per line.
    Hosts,
}

/// One filter list's text.
pub struct ListSource<'a> {
    /// Used in log messages only.
    pub name: &'a str,
    pub text: &'a str,
    pub format: ListFormat,
}

#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("engine data rejected: {0}")]
    Engine(String),
    #[error("domain set rejected: {0}")]
    DomainSet(#[from] DomainSetError),
}
```

`core/crates/filter/src/compile.rs`:

```rust
//! Compiling filter lists into the two files the tunnel loads.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use crate::domain_set::HEADER_LEN;
use crate::{DomainRules, FilterEngine, FilterError, ListFormat, ListSource, network_rule_count};

pub const ENGINE_FILE: &str = "engine.dat";
pub const DOMAINS_FILE: &str = "domains.bin";

#[derive(Clone, Debug)]
pub struct CompileReport {
    /// Network rules in the engine.
    pub network_rules: u64,
    /// Hashes in the DNS blocklist.
    pub domain_entries: u64,
    pub engine_bytes: u64,
    pub domains_bytes: u64,
}

/// Writes ENGINE_FILE and DOMAINS_FILE atomically into dir.
///
/// Adblock lists feed both files; hosts lists feed only the DNS blocklist. A DNS list
/// written in adblock syntax (the AdGuard DNS filter) belongs in the DNS blocklist only,
/// and would more than double the engine; pass it through [`compile_split`] instead.
pub fn compile(lists: &[ListSource], dir: &Path) -> Result<CompileReport, FilterError> {
    let engine_lists: Vec<ListSource> = lists
        .iter()
        .filter(|l| l.format == ListFormat::Adblock)
        .map(|l| ListSource {
            name: l.name,
            text: l.text,
            format: l.format,
        })
        .collect();
    compile_split(&engine_lists, lists, dir)
}

/// Builds ENGINE_FILE from `engine_lists` and DOMAINS_FILE from `dns_lists` and writes
/// both into `dir`, which is created if missing.
///
/// The engine is built without debug information. Each file is written to a temporary
/// file in `dir`, flushed to disk and renamed over the old one, so a reader sees the old
/// file or the new one, never a partial file.
pub fn compile_split(
    engine_lists: &[ListSource],
    dns_lists: &[ListSource],
    dir: &Path,
) -> Result<CompileReport, FilterError> {
    fs::create_dir_all(dir).map_err(|source| FilterError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let network_rules = network_rule_count(engine_lists);
    let engine = FilterEngine::from_lists(engine_lists, false).serialize();
    let domains = DomainRules::parse(dns_lists).encode();
    write_atomically(&dir.join(ENGINE_FILE), &engine)?;
    write_atomically(&dir.join(DOMAINS_FILE), &domains)?;
    let report = CompileReport {
        network_rules,
        domain_entries: ((domains.len() - HEADER_LEN) / 8) as u64,
        engine_bytes: engine.len() as u64,
        domains_bytes: domains.len() as u64,
    };
    log::info!("compiled filter lists: {report:?}");
    Ok(report)
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), FilterError> {
    let file_name = path
        .file_name()
        .expect("compile passes a file name")
        .to_string_lossy();
    let tmp = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    let result = File::create(&tmp)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&tmp, path));
    result.map_err(|source| {
        let _ = fs::remove_file(&tmp);
        FilterError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd core && cargo test -p tollgate-filter && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: compile 4, domain_rules 7, domain_set 11, engine 14, request_type 9 passed; clippy and fmt clean.

- [ ] **Step 5: Commit**

```bash
git add core/crates/filter
git commit -m "Compile filter lists into engine.dat and domains.bin atomically"
```

---

### Task 14: Measurement with real lists

**Files:**
- Create: `core/crates/filter/tests/measure.rs`

**Interfaces:**
- Consumes: `compile_split`, `FilterEngine::load`, `DomainSet::load`.
- Produces: an `#[ignore]` test that prints list sizes, load cost and lookup speed. It never runs in CI and needs no network: it reads lists from `TOLLGATE_LISTS_DIR`. The lists used for the numbers below were downloaded on 2026-09-25 from the EasyList, EasyPrivacy, AdGuard Mobile Ads (filter 11), AdGuard DNS filter and StevenBlack hosts URLs.

- [ ] **Step 1: Write the measurement test**

`core/crates/filter/tests/measure.rs`:

```rust
//! Sizes and timings with real filter lists. Not part of the normal test run: it needs
//! the lists on disk. Run from core/ with:
//!
//!   TOLLGATE_LISTS_DIR=/path/to/lists cargo test --release -p tollgate-filter --test measure -- --ignored --nocapture
//!
//! The directory must hold easylist.txt, easyprivacy.txt, adguard-mobile-11.txt,
//! adguard-dns-filter.txt and stevenblack-hosts.txt. Loading is measured in a fresh child
//! process, so memory freed by the compile step does not hide the load cost. Memory is
//! reported as RssAnon, the closest Linux figure to the dirty memory iOS counts.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use tollgate_filter::{
    DOMAINS_FILE, DomainSet, ENGINE_FILE, FilterEngine, ListFormat, ListSource, Verdict,
    compile_split,
};

fn rss_anon_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("RssAnon:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn report_rss(label: &str, baseline: Option<u64>) {
    if let (Some(baseline), Some(now)) = (baseline, rss_anon_kib()) {
        println!(
            "{label}: RssAnon {:+.2} MiB",
            (now as f64 - baseline as f64) / 1024.0
        );
    }
}

#[test]
#[ignore = "needs real filter lists in TOLLGATE_LISTS_DIR"]
fn measure_real_lists() {
    let dir = PathBuf::from(std::env::var("TOLLGATE_LISTS_DIR").expect("set TOLLGATE_LISTS_DIR"));
    let read = |name: &str| {
        std::fs::read_to_string(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
    };
    let easylist = read("easylist.txt");
    let easyprivacy = read("easyprivacy.txt");
    let mobile = read("adguard-mobile-11.txt");
    let adguard_dns = read("adguard-dns-filter.txt");
    let hosts = read("stevenblack-hosts.txt");
    let adblock = |name, text| ListSource {
        name,
        text,
        format: ListFormat::Adblock,
    };
    let engine_lists = [
        adblock("easylist", &easylist),
        adblock("easyprivacy", &easyprivacy),
        adblock("adguard-mobile", &mobile),
    ];
    let dns_lists = [
        adblock("adguard-dns", &adguard_dns),
        ListSource {
            name: "stevenblack",
            text: &hosts,
            format: ListFormat::Hosts,
        },
    ];

    let out = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let report = compile_split(&engine_lists, &dns_lists, out.path()).unwrap();
    println!("compile took {:?}: {report:?}", started.elapsed());
    println!(
        "{ENGINE_FILE} {:.2} MiB, {DOMAINS_FILE} {:.2} MiB",
        mib(report.engine_bytes),
        mib(report.domains_bytes)
    );

    let status = Command::new(std::env::current_exe().unwrap())
        .args(["load_compiled_lists", "--exact", "--ignored", "--nocapture"])
        .env("TOLLGATE_COMPILED_DIR", out.path())
        .status()
        .unwrap();
    assert!(status.success());
}

/// Run by measure_real_lists in a child process.
#[test]
#[ignore = "run through measure_real_lists"]
fn load_compiled_lists() {
    let Some(dir) = std::env::var_os("TOLLGATE_COMPILED_DIR") else {
        println!("load_compiled_lists only runs as part of measure_real_lists");
        return;
    };
    let dir = Path::new(&dir);
    let baseline = rss_anon_kib();

    let started = Instant::now();
    let engine = FilterEngine::load(&dir.join(ENGINE_FILE)).unwrap();
    println!("engine load took {:?}", started.elapsed());
    report_rss("after engine load", baseline);

    let started = Instant::now();
    let domains = DomainSet::load(&dir.join(DOMAINS_FILE)).unwrap();
    println!(
        "domain set load took {:?}, {} entries",
        started.elapsed(),
        domains.len()
    );
    report_rss("after domain set load", baseline);

    let requests = [
        (
            "https://securepubads.g.doubleclick.net/tag/js/gpt.js",
            "https://www.cnn.com/",
            "script",
        ),
        (
            "https://www.google-analytics.com/analytics.js",
            "https://www.bbc.com/",
            "script",
        ),
        (
            "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js",
            "https://example.com/",
            "script",
        ),
        (
            "https://connect.facebook.net/en_US/fbevents.js",
            "https://shop.example/",
            "script",
        ),
        (
            "https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js",
            "https://example.com/",
            "script",
        ),
        (
            "https://fonts.gstatic.com/s/roboto/v30/x.woff2",
            "https://example.com/",
            "font",
        ),
        (
            "https://www.wikipedia.org/",
            "https://www.wikipedia.org/",
            "document",
        ),
        (
            "https://api.github.com/repos/x/y",
            "https://github.com/",
            "xmlhttprequest",
        ),
    ];
    let n = 20_000;
    let started = Instant::now();
    let mut blocked = 0;
    for i in 0..n {
        let (url, source, kind) = requests[i % requests.len()];
        let url = format!("{url}?r={i}");
        if matches!(engine.check(&url, source, kind), Verdict::Block { .. }) {
            blocked += 1;
        }
    }
    let elapsed = started.elapsed();
    println!(
        "{n} checks in {elapsed:?} ({:.2} us each), {blocked} blocked",
        elapsed.as_secs_f64() * 1e6 / n as f64
    );

    let hosts = [
        "securepubads.g.doubleclick.net",
        "www.google.com",
        "a.b.c.d.example.com",
        "app-measurement.com",
        "graph.facebook.com",
        "x.y.z.adnxs.com",
    ];
    let n = 1_000_000;
    let started = Instant::now();
    let mut blocked = 0;
    for i in 0..n {
        if domains.is_blocked(hosts[i % hosts.len()]) {
            blocked += 1;
        }
    }
    let elapsed = started.elapsed();
    println!(
        "{n} DNS lookups in {elapsed:?} ({:.0} ns each), {blocked} blocked",
        elapsed.as_secs_f64() * 1e9 / n as f64
    );
    for host in hosts {
        println!("  {host}: blocked={}", domains.is_blocked(host));
    }
    report_rss("after the workload", baseline);
}
```

- [ ] **Step 2: Run it without lists to see it refuse**

Run: `cd core && cargo test -p tollgate-filter --test measure -- --ignored`
Expected: FAIL: `measure_real_lists` panics with `set TOLLGATE_LISTS_DIR`; `load_compiled_lists` passes because it only runs as a child of the other test.

- [ ] **Step 3: Run it with the lists**

Run: `cd core && TOLLGATE_LISTS_DIR=/path/to/lists cargo test --release -p tollgate-filter --test measure -- --ignored --nocapture`
Expected (numbers from the 2026-09-25 lists on x86_64 Linux; they drift as lists change):

```
compile took 198.446587ms: CompileReport { network_rules: 114257, domain_entries: 217012, engine_bytes: 5037901, domains_bytes: 1736128 }
engine.dat 4.80 MiB, domains.bin 1.66 MiB
engine load took 16.255824ms
after engine load: RssAnon +5.22 MiB
domain set load took 1.597429ms, 217012 entries
after domain set load: RssAnon +5.22 MiB
20000 checks in 62.542119ms (3.13 us each), 10000 blocked
1000000 DNS lookups in 149.933229ms (150 ns each), 500000 blocked
  securepubads.g.doubleclick.net: blocked=true
  www.google.com: blocked=false
  a.b.c.d.example.com: blocked=false
  app-measurement.com: blocked=true
  graph.facebook.com: blocked=false
  x.y.z.adnxs.com: blocked=true
after the workload: RssAnon +5.45 MiB
```

The engine costs about 5.2 MiB of anonymous memory after load, which is its steady state: the mmap keeps the file bytes out of the heap, so there is no second copy during load. The DNS set adds nothing to anonymous memory, because its pages stay clean and file-backed. Both fit the revised budget (engine 8 MiB, DNS blocklist 2 MiB). Linux RssAnon is a lower bound for iOS `phys_footprint`; M2 and M4 measure on the device.

- [ ] **Step 4: Commit**

```bash
git add core/crates/filter/tests/measure.rs
git commit -m "Add an ignored measurement test for real filter lists"
```

---

### Task 15: Workspace verification

**Files:** none changed.

**Interfaces:**
- Consumes: everything above. Produces: evidence that the branch is ready for review.

- [ ] **Step 1: Format, lint and test**

Run: `cd core && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: fmt and clippy clean; tests: tollgate-common 12 passed and 1 ignored, tollgate-policy 34 passed, tollgate-filter 45 passed and 2 ignored, tollgate-ffi 3 passed.

- [ ] **Step 2: No aws-lc anywhere**

Run: `cd core && cargo tree -i aws-lc-sys; cargo tree -i aws-lc-rs`
Expected: both exit with status 101 and `` error: package ID specification `aws-lc-sys` did not match any packages `` (then the same for `aws-lc-rs`).

- [ ] **Step 3: Type-check the non-test code for iOS**

On macOS with Xcode: `cd core && cargo check --workspace --target aarch64-apple-ios`.

On Linux, ring's build script needs an iOS C toolchain, so point it at a stub SDK and the host clang (`rustup target add aarch64-apple-ios` first if the target is missing):

```bash
STUB="$(mktemp -d)"
mkdir -p "$STUB/usr/include"
printf '#pragma once\n#define TARGET_OS_MAC 1\n#define TARGET_OS_IPHONE 1\n#define TARGET_OS_IOS 1\n#define TARGET_OS_OSX 0\n#define TARGET_OS_SIMULATOR 0\n#define TARGET_OS_TV 0\n#define TARGET_OS_WATCH 0\n#define TARGET_OS_VISION 0\n#define TARGET_OS_MACCATALYST 0\n' > "$STUB/usr/include/TargetConditionals.h"
printf '#pragma once\n#define assert(x) ((void)0)\n' > "$STUB/usr/include/assert.h"
printf '#pragma once\n#include <stddef.h>\nvoid *memcpy(void *, const void *, size_t);\nvoid *memset(void *, int, size_t);\nint memcmp(const void *, const void *, size_t);\nvoid *memmove(void *, const void *, size_t);\n' > "$STUB/usr/include/string.h"
(cd core && SDKROOT="$STUB" CC_aarch64_apple_ios=clang AR_aarch64_apple_ios=llvm-ar cargo check --workspace --target aarch64-apple-ios)
rm -rf "$STUB"
```

Expected: `Finished` with no errors.

- [ ] **Step 4: Bindings still generate**

Run: `tooling/scripts/build-core-ios.sh --host`
Expected: the script lists `build/bindings-host` with `tollgate_ffi.swift`, `tollgate_ffiFFI.h` and `module.modulemap`.

- [ ] **Step 5: No em-dashes**

Run: `grep -rn "$(printf '\342\200\224')" core/crates core/Cargo.toml core/tools docs/superpowers/plans/2026-09-25-m1a-common-policy-filter.md`
Expected: no output.

- [ ] **Step 6: Push the branch for review**

Run: `git push -u origin m1a-common-policy-filter`
Expected: the branch is on GitHub; the owner opens and merges the PR (PR text is drafted in the conversation first).

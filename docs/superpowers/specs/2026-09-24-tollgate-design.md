# Tollgate: design

Date: 2026-09-24
Status: approved, M0 in progress

Tollgate is a personal, sideloaded iOS ad blocker. It runs as a local packet tunnel (a
Network Extension "VPN" that never leaves the device), blocks ad and tracker domains at the
DNS layer, and intercepts HTTPS through a user-trusted root CA so URL-level filter rules
(EasyList, uBlock Origin and AdGuard syntax) apply to Safari, web views and third-party apps.

It is never published to the App Store. It is built by GitHub Actions on Apple hardware,
signed with the owner's paid Apple Developer account, and installed and debugged from a
Linux workstation.

Background research, with sources: [feasibility brief](../../research/2026-09-23-feasibility-brief.md).
The brief recommends an xtool-first build; that recommendation is superseded by the CI-first
decision below.

## Goals

- Block ads and trackers in Safari, in-app web views, and third-party app ad SDKs.
- Apply full URL rules (path, query, `$third-party`, resource type) to HTTPS traffic, not only
  hostnames.
- Keep every Apple service, and every app that pins certificates, working.
- Develop almost everything on Linux; use macOS only inside CI.

## Non-goals (for now)

- Cosmetic filtering (element hiding, scriptlets). This needs HTML response rewriting and is
  deferred until network filtering is solid.
- YouTube app ads (served in the same streams as the video; unreliable even with MITM).
- App Store or TestFlight distribution.
- Traffic from apps that bypass the system proxy (custom network stacks) beyond DNS-level
  blocking. Experiment E7 measures this gap; a userspace TCP stack is phase 2 only if it
  matters.

## Decisions

| Topic | Decision | Why |
|---|---|---|
| Build and sign | GitHub Actions, `xcode-27` Apple silicon runner (fallback `macos-26`), public repo | Free for public repos, real Xcode 27 with the iOS 27.0 SDK, native Network Extension and entitlement support, no SDK license issue |
| Project generation | XcodeGen `project.yml` | No Xcode GUI anywhere; the project file is generated in CI |
| Signing | App Store Connect API key in repo secrets, `xcodebuild -allowProvisioningUpdates -allowProvisioningDeviceRegistration`, export method `development` | Xcode creates App IDs, capabilities, App Group, device registration and profiles automatically |
| Core language | Rust | Testable on Linux, small memory footprint inside the 50 MiB extension limit, Brave's adblock engine is Rust |
| Interception | Proxy-first: `NEProxySettings` points proxy-aware clients at a local MITM proxy inside the extension; the packet path carries DNS only | Least code and memory for the MVP; netstack ingress is added later only if E7 shows a real gap |
| Filter engine | `adblock` crate (brave/adblock-rust) | Production-proven on iOS, parses ABP/uBO/AdGuard network rules |
| Device tooling | `pymobiledevice3` from a `uv` venv on Linux | Installs dev-signed apps and streams extension logs on iOS 27 without a Mac |
| License | MIT | Allows reuse of MIT references (Mudmouth, TunnelVision); avoid copying GPL code (Knot, sing-box) |

## Repository layout

```
tollgate/
  core/                        Rust workspace, developed and tested on Linux
    crates/policy/             config types, passthrough and pin-learning decisions
    crates/filter/             adblock engine wrapper, DNS domain set, list compilation
    crates/dns/                DNS-over-tunnel responder: blocking, type 65 stripping, DoH upstream
    crates/mitm/               local HTTP/HTTPS proxy: CA and leaf minting, TLS, request filtering
    crates/tollgate-ffi/       uniffi facade used by the Swift app and tunnel
    tools/devproxy/            Linux harness running dns and mitm for a desktop browser
  ios/
    project.yml                XcodeGen spec: App target and Tunnel app extension
    App/                       SwiftUI container app
    Tunnel/                    NEPacketTunnelProvider app extension
  .github/workflows/
    core.yml                   cargo fmt, clippy, test on Ubuntu
    ios.yml                    iOS build, sign, export, upload .ipa artifact
  tooling/scripts/             fetch-ipa, install, logs, device helpers
  docs/
```

## Rust core

### `policy`

- `Config` (serde JSON, shared with Swift): DoH upstreams (IP plus TLS name), filter list
  sources, user passthrough patterns, log level, feature flags (`mitm_enabled`).
- `HostPattern`: exact host or `*.suffix` wildcard; case-insensitive; trailing dot ignored.
- `Policy::classify(sni) -> Decision { Passthrough(reason) | Intercept }`. Order: user
  passthrough, bundled passthrough (Apple hosts and AdGuard HttpsExclusions snapshot), learned
  pins, otherwise intercept. `mitm_enabled = false` makes everything passthrough.
- Pin learning: `record_handshake_failure(sni, now)`. Two client-side TLS handshake failures
  for the same host within 10 minutes move it to the learned set. The learned set is
  serialized to the App Group as JSON and entries expire after 30 days.

### `filter`

- Wraps `adblock::Engine`. `FilterEngine::from_lists(lists)` builds from rule text;
  `serialize()` and `deserialize()` produce and load `engine.dat`.
- `check_request(url, source_url, request_type) -> Verdict { Allow | Block { rule } }`, plus
  `$important` and exception handling from the engine itself.
- `DomainSet`: hostname blocklist built from hosts-format and `||domain^` rules in the DNS
  lists. Matches the host and every parent label (`a.b.example.com` checks `b.example.com`
  and `example.com`). Serialized as a sorted, newline-separated file loaded into a
  `HashSet`, or a sorted vector with binary search if memory measurements require it.
- Compilation (download, parse, serialize) happens in the app process, which has far more
  memory than the extension. The extension only deserializes. Bundled snapshot lists ship in
  the app so the first launch works offline.

### `dns`

- Input: raw IPv4 or IPv6 packets from the tunnel. Only UDP port 53 to the tunnel DNS
  address (`198.18.0.1` or `fd00:7467::1`) is handled; anything else is dropped and counted.
- Parse with `etherparse` (IP and UDP) and `hickory-proto` (DNS message).
- A and AAAA for a blocked name: answer `0.0.0.0` or `::` with a 60 second TTL.
- HTTPS and SVCB (type 65 and 64): empty NOERROR answer, so clients do not learn HTTP/3 or
  ECH hints.
- Everything else: forward over DNS-over-HTTPS (RFC 8484, POST `application/dns-message`,
  HTTP/2) to upstreams reached by IP with the TLS name set explicitly, defaults Cloudflare
  `1.1.1.1` (`cloudflare-dns.com`) and Quad9 `9.9.9.9` (`dns.quad9.net`). Sockets opened by
  the extension bypass the tunnel, so upstream traffic cannot loop.
- LRU cache of 2,000 answers keyed by (name, type, class), honoring the minimum TTL, clamped
  to 10 s to 1 h.
- On upstream failure: try the next upstream, then answer SERVFAIL.
- Output: response packets with swapped addresses and ports and correct IPv4 and UDP
  checksums.

### `mitm`

- A hyper-based proxy on `127.0.0.1` with an ephemeral port, single-threaded tokio runtime.
  (Built directly on hyper, tokio-rustls, rustls with the `ring` provider, and rcgen. We may
  use `hudsucker` if it fits the memory budget and gives us the hooks we need; the decision is
  made during M1 and recorded in the plan.)
- Plain HTTP requests: filtered, then forwarded.
- `CONNECT host:port`: `Policy::classify` on the host. Passthrough copies bytes both ways
  untouched. Intercept replies `200`, peeks the ClientHello for SNI, terminates TLS with a
  leaf for that name, and serves HTTP/1.1 or HTTP/2 depending on ALPN.
- Upstream: rustls client with `webpki-roots`, ALPN `h2` and `http/1.1`, connection reuse per
  host.
- Filtering: each intercepted request becomes `filter::check_request` with the full URL,
  `Referer` or `Origin` as the source, and a request type derived from `Sec-Fetch-Dest`, then
  `Accept`, then the path extension. Blocked requests get an empty `403` (with
  `access-control-allow-origin: *` so pages do not stall on CORS errors).
- Certificate authority: ECDSA P-256 root, 10 year validity, generated once by the app and
  stored in the App Group (private key protected by file protection
  `completeUntilFirstUserAuthentication`). Leaves: ECDSA P-256, SAN only, `serverAuth` EKU,
  valid from now minus one day for 30 days. LRU cache of 128 leaves.
- Bodies stream in both directions; nothing is buffered whole. A semaphore caps concurrent
  intercepted connections at 64; above the cap new CONNECTs are passed through.
- Client handshake failures are reported to `Policy::record_handshake_failure`.

### `tollgate-ffi`

uniffi 0.32, Swift bindings generated in CI:

- `Engine::new(config_json, data_dir) -> Engine`
- `start() -> u16` (proxy port), `stop()`
- `handle_packets(packets: Vec<Vec<u8>>) -> Vec<Vec<u8>>` (DNS path)
- `reload_lists()`, `stats() -> Stats`
- `generate_ca(data_dir) -> CaInfo`, `ca_mobileconfig(data_dir) -> Vec<u8>` (app only)
- `compile_lists(sources, data_dir) -> CompileReport` (app only)
- `set_logger(callback)`; the callback forwards to `os_log` on the Swift side.

### `devproxy`

A Linux binary that runs `dns` (on a local UDP port) and `mitm` with the same config format,
and writes the CA as PEM. Firefox on the workstation, configured to use the proxy and trust
the CA, exercises the whole filtering path without a phone.

## Swift shell

### Tunnel (`NEPacketTunnelProvider`)

`startTunnel`:

1. Load `config.json` and the CA from the App Group container. The identifier comes from
   the `TollgateAppGroup` Info.plist key, which project generation fills from
   `tooling/config.env`; Swift code never hard-codes it.
2. Create the Rust `Engine`, start the proxy, get its port.
3. Apply `NEPacketTunnelNetworkSettings`:
   - remote address `127.0.0.1` (placeholder), IPv4 `198.18.0.2/32` with included route
     `198.18.0.1/32` only; IPv6 `fd00:7467::2/128` with included route `fd00:7467::1/128`
     only.
   - `NEDNSSettings(servers: ["198.18.0.1", "fd00:7467::1"])` with `matchDomains = [""]`.
   - `NEProxySettings`: HTTP and HTTPS proxy `127.0.0.1:<port>`, `matchDomains = [""]`,
     `excludeSimpleHostnames = true`, exceptions for `*.local` and captive portal hosts.
   - MTU 1500.
4. Loop `packetFlow.readPackets` into `engine.handlePackets` and write the results back.

`handleAppMessage` returns stats and a recent-events tail. Logging uses
`Logger(subsystem: "dev.tollgate.tunnel", category: ...)` at `.info` or above so
`pymobiledevice3 syslog live` shows it.

### App

- Home: VPN toggle through `NETunnelProviderManager` (creates the configuration on first use,
  with an on-demand connect rule), status, counters.
- Setup: generate the CA, serve `tollgate-ca.mobileconfig` from a short-lived local HTTP
  server and open it in Safari (iOS only installs profiles downloaded by Safari), then guide
  the user to Settings, General, About, Certificate Trust Settings. Verify trust by
  evaluating a leaf signed by the CA with `SecTrustEvaluateWithError`.
- Lists: enabled sources, last update, "update now" (download, compile through Rust, write to
  the App Group, message the tunnel to reload).
- Passthrough: bundled, learned and user entries; add and remove.
- Log: recent blocked requests and domains from a ring buffer file in the App Group.

## Data flow

- DNS: app query to `198.18.0.1` goes into the tunnel, Rust answers from cache, blocks, or
  forwards over DoH.
- HTTPS from a proxy-aware client: `CONNECT` to the local proxy, classify, then pass through
  or intercept, filter, and forward.
- HTTP/3: proxied CFNetwork traffic cannot use QUIC, and type 65 records are stripped, so
  HTTP/3 bypass is not expected. E5 checks this.

## Memory budget

The packet tunnel process has a 50 MiB hard limit (jetsam kills it above that). Target: under
35 MiB steady state.

| Component | Budget |
|---|---|
| adblock engine (EasyList, EasyPrivacy, AdGuard Mobile Ads) | 10 to 15 MiB, measured in M1 |
| DNS domain set | 3 MiB |
| proxy runtime, TLS state | 5 MiB |
| connection buffers (64 x 128 KiB worst case) | 8 MiB |
| leaf cache, DNS cache, misc | 2 MiB |

The extension logs `os_proc_available_memory()` every 30 s. Under 8 MiB available it stops
intercepting new connections (passthrough only) until memory recovers.

## Failure handling

- Engine creation fails: `startTunnel` completes with an error that the app shows.
- No compiled lists: the app compiles the bundled snapshots on first launch; the tunnel runs
  DNS-only if `engine.dat` is still missing.
- DoH upstream unreachable: next upstream, then SERVFAIL; counted in stats.
- CA missing or untrusted: the tunnel runs with `mitm_enabled = false` and the app shows the
  setup flow.
- Extension crash: the system restarts it through the on-demand rule.

## Testing

- `cargo test` per crate, run in `core.yml` on Ubuntu.
- Linux integration tests: a local TLS test server with its own CA, driven through `mitm` with
  a real HTTP client that trusts our CA (block, allow, passthrough, h2, handshake failure
  learning). `dns` tests with crafted packets and a mock upstream.
- `devproxy` with Firefox for manual end-to-end checks.
- On-device experiments as scripted checklists in `docs/experiments/`.

## Experiments (gates)

| ID | Question | Pass criterion |
|---|---|---|
| E6 | Can we install a CI-signed app from Linux onto the iOS 27.0 phone? | App launches after `pymobiledevice3 apps install`; Developer Mode toggle available |
| E1 | Does a CI-built app with a packet tunnel extension start on the phone? | `startTunnel` log line visible in `syslog live`; VPN icon shows |
| E2 | Does the Rust staticlib (with `ring`) link into the extension and run? | FFI call result logged from `startTunnel` |
| E3 | What is the extension memory limit on this phone? | Jetsam limit recorded (expected 50 MiB) |
| E4 | Do proxy settings apply even though the tunnel only routes the DNS address, and do Safari and URLSession accept our leaves? | Safari and a URLSession app send `CONNECT` to the proxy; `https://example.com` loads through MITM; a pinned app still works via passthrough. If proxy settings turn out to be route-scoped, netstack ingress moves into phase 1 |
| E5 | Does HTTP/3 get bypassed? | No UDP 443 flows observed from proxied apps |
| E7 | How much HTTPS traffic bypasses the proxy? | Measured share; decides whether netstack phase 2 is needed |

## Milestones

- M0: repository, Ubuntu CI, iOS CI producing a signed `.ipa` with an empty tunnel that links
  Rust; E6, E1, E2 pass.
- M1: Rust core complete and tested on Linux (`policy`, `filter`, `dns`, `mitm`, `ffi`,
  `devproxy`), verified with Firefox.
- M2: DNS blocking on the phone; E3.
- M3: CA setup flow and MITM in Safari, passthrough and pin learning; E4, E5.
- M4: lists and log UI, memory tuning, E7, decide on netstack phase 2.

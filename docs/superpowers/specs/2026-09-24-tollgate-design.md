# Tollgate: design

Date: 2026-09-24
Status: approved; M0 merged; M1 revisions below (2026-09-25)

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
  `1.1.1.1` (`cloudflare-dns.com`) and Quad9 `9.9.9.9` (`dns.quad9.net`), then the same two
  over IPv6 (`2606:4700:4700::1111`, `2620:fe::fe`) for IPv6-only networks with NAT64 and no
  CLAT, where a direct connect to an IPv4 literal fails. Sockets opened by the extension
  bypass the tunnel, so upstream traffic cannot loop.
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
     `excludeSimpleHostnames = true`, exceptions for loopback, the private and link-local
     IPv4 and IPv6 ranges, `*.local`, `*.lan`, `*.home.arpa`, `*.internal`,
     `*.localdomain`, `fritz.box`, `*.fritz.box`, `*.intranet`, `*.corp`, `*.private` and
     `captive.apple.com`, so local network pages never go through the extension. The
     suffix entries cover every local suffix the core's DNS treats as local
     (`LOCAL_SUFFIXES` in the dns crate) plus `*.local`; a test in the dns crate checks
     that the two lists stay in sync.
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

## Revisions after the M1 prototypes (2026-09-25)

Throwaway prototypes were built for every M1 component against the pinned crate versions,
measured on Linux, and re-run by an independent reviewer. Where this section disagrees with
the sections above, this section wins.

### Measured

| Item | Result |
|---|---|
| adblock engine, EasyList + EasyPrivacy + AdGuard Mobile Ads (114k network rules), network rules only, no debug info | `engine.dat` 4.8 MiB; 5.8 to 8 MiB resident after load; build 53 ms in the app |
| Same with debug info (keeps rule text) | 11 MiB file, 12 to 13 MiB resident: too big for the extension |
| DNS blocklist, AdGuard DNS filter + StevenBlack hosts (253k names) | `HashSet` 13 to 17 MiB (rejected); sorted 64-bit hashes 2 MiB |
| DoH: tokio runtime + one HTTP/2 connection | about 0.1 MiB heap; 10 to 25 ms per query on a warm connection |
| HTTPS proxy, 20 concurrent intercepted downloads | 52 MB with hyper defaults, 11 to 12 MB with tuned flow control |
| Leaf certificate minting (ECDSA P-256) | about 50 microseconds |

### Decisions that change the design

**Crates.** A new `tollgate-common` crate holds the continuous clock, the shared rustls
client configuration, statistics counters and the logging facade, so `dns` and `mitm` do not
depend on each other.

**filter.**
- `adblock = "=0.13.3"` with `default-features = false` and features
  `embedded-domain-resolver`, `full-regex-handling`. The default `single-thread` feature makes
  the engine `!Send`, which uniffi objects cannot hold. The version is pinned exactly because
  the app writes `engine.dat` and the extension reads it.
- Lists are compiled with network rules only and without debug info. `Verdict::Block` carries
  `rule: Option<String>`, which is `None` in the extension. The app can find the matching rule
  for its log view by re-checking the URL against a debug engine it builds on demand.
- `engine.dat` is loaded through `mmap` (`memmap2`), avoiding a transient peak of twice the
  file size.
- The regex cache discard policy is set to 10 s cleanup and 30 s unused lifetime.
- Request types come from an explicit `Sec-Fetch-Dest` table (`style` to `stylesheet`,
  `iframe`/`frame` to `sub_frame`, `empty` to `xmlhttprequest`, and so on), then `Accept`,
  then the path extension.
- Source URL: top-level document requests use their own URL; otherwise `Referer`, then
  `Origin`, then empty. An empty source counts as third party, which is adblock's behavior.

**DNS blocklist (`DomainSet`).** Names are stored as a sorted array of FNV-1a 64-bit hashes of
the lowercased name in a binary file: magic `TGDS`, format version, entry counts, the length
of the pattern section, checksum, then block hashes, allow hashes and important hashes, then
the pattern section. The extension mmaps it and binary-searches the host and each parent
label. The parser accepts `||name^`, `||name`, `.name^`, `@@||name^`, the exact-host forms
`|name^|` and `|name^` and their `@@` forms, `$important` and `$badfilter` rules and
hosts-format lines. Exceptions with a `*` in the name (the AdGuard DNS filter has about ten,
such as `@@||clk*.tradedoubler.com^|` and `@@||bcicl.*.evergage.com^|`) are kept as text in
the pattern section and parsed once at load; `*` matches any run of characters, dots
included, and a `||` pattern may match the host or a parent, a `|` pattern the host only.
Wildcard blocks, regex and prefix rules (such as `|ads.`) are skipped, and redundant children
of blocked parents are dropped. A file without a pattern section (length 0, as written before
it existed) still loads. An exact-host entry
covers the host only and is stored in the block or allow array as the hash of `|` followed by
the name, which no name produces, so the AdGuard DNS filter's `@@|cdn.example^|` unblocks that
host under a blocked `||example^` without unblocking the rest. Order of evaluation: important
block (host and parents), exact allow, allow (host and parents), exact block, block (host and
parents); a block is then lifted when a wildcard exception matches. The false positive rate is
about 5e-14 per lookup.

**dns.**
- Only UDP port 53 addressed to `198.18.0.1` or `fd00:7467::1` is handled. Everything else is
  dropped and counted; undecodable queries of at least 12 bytes get FORMERR.
- The cache stores upstream wire bytes plus the offsets of each TTL (about 0.5 MiB for 2,000
  entries) and patches id, question case and TTLs on a hit.
- The cache clock is a continuous clock that keeps counting while the device sleeps
  (`CLOCK_MONOTONIC` on Apple platforms, `CLOCK_BOOTTIME` on Linux). `Instant` stops during
  sleep on iOS.
- DoH: one shared HTTP/2 connection per upstream; each query runs in its own task on that
  connection. An attempt has a 2 s deadline on a cold connection and 1.5 s on a warm one. A
  closed connection is retried once, then the next upstream is tried, then the answer is
  SERVFAIL. An upstream whose attempt timed out or failed to connect is marked down for 30 s
  and tried only after the others (all in order when every upstream is down); when the time
  is up, one query goes to it in the background, and its answer brings it back. A network
  path change clears the marks. At most 128 queries are in flight: 96 for the DNS forwarder
  (further forwarded queries wait in its 256-job queue) and 32 for the proxy's name
  lookups (16 names at once, A and AAAA together; further names wait for a turn, and
  callers asking for a name already being looked up share that lookup).
- Responses are normalized to the requester: OPT is echoed only if the query had one, and
  answers larger than the requester's UDP size are trimmed: authority and additional records
  go first, then answer records from the end, keeping the CNAME chain and as many whole
  records of the final RRset as fit, without TC (RFC 2181 section 9). Nothing answers DNS
  over TCP on the tunnel address, so a TC reply could not be retried; it is sent only when
  not one record of the queried type fits. The cache key includes the requester's DO bit, so
  answers with DNSSEC records never reach requesters that did not ask for them.

**mitm.**
- Built directly on hyper, hyper-util, tokio-rustls, rustls (ring provider only) and rcgen, not
  `hudsucker`. hudsucker always compiles aws-lc-sys, hides client TLS failures, and would need
  its certificate authority replaced anyway.
- After `CONNECT`, the first bytes are peeked through a rewindable reader. Non-TLS traffic is
  tunneled with the peeked bytes replayed. For TLS, the host is classified from the `CONNECT`
  target and again from the SNI; either one saying passthrough tunnels the connection with
  the ClientHello replayed.
- Flow control limits are mandatory: HTTP/2 stream window 128 KiB, connection window 256 KiB,
  server send buffer 128 KiB, HTTP/1 read buffer 128 KiB.
- At most 32 intercepted client connections (about 0.35 MiB each) instead of 64. When all 32
  are taken, a new connection closes the one that has had nothing in flight the longest (at
  least 3 s) and waits up to 100 ms for its slot; without one, or when less than 8 MiB of
  memory is available, new connections pass through. Upstream
  connections are pooled per host and shared across client connections: at most 6 HTTP/1.1
  connections per host and 64 upstream connections in total. An HTTP/2 origin shares one
  connection, except that one whose stalled streams (responses whose clients stopped reading
  for 1 s) could hold half its 256 KiB window gets no new requests: the next request opens
  another connection, and the stalled one closes when its streams end. The 64-connection
  limit still bounds the windows at 16 MiB.
- At most 128 passthrough tunnels at once (two sockets and about 20 KiB each). Over the cap
  a passthrough `CONNECT` host gets `503`, and a connection passed through after its first
  bytes were read is closed. A tunnel that moves no bytes for 5 minutes is closed. The
  engine raises the soft open file limit from iOS's 256 to 2048 before opening any socket.
- Timeouts: 10 s for the first bytes and for the TLS handshake, 30 s to read request headers,
  HTTP/2 keep-alive pings, and idle connections are closed after 60 s without requests.
  Pooled upstream connections are aged with the continuous clock (tokio's clock stops during
  sleep), checked again when taken from the pool, pinged while idle (HTTP/2), and dropped all
  at once when the provider wakes or the default network path changes. A GET, HEAD or
  OPTIONS without a body that fails on a reused connection before its response starts is
  sent once more on a new connection.
- An intercepted connection is answered (`CONNECT` 200 and TLS with our leaf) before the
  upstream is dialed. When the dial for a request then fails without TLS being involved
  (the name does not resolve, the connection is refused, reset or times out), the request
  gets no response: HTTP/1.1 closes the connection and HTTP/2 resets the stream, so the
  browser shows its own error page or falls back from `https://` to `http://`, as without
  the proxy. The host is logged at info level, at most once a minute. No free upstream
  connection gets `503`; upstream TLS failures get `502` (see pin learning).
- WebSockets over intercepted HTTPS are forwarded over a dedicated HTTP/1.1 upstream
  connection.
- Passthrough tunnels and WebSocket relays outlive a wake or a path change unless their
  network is gone: on each reset (`ProxyContext::path_resets`) and 2 s later, a relay whose
  upstream socket's source address is no longer assigned to an interface (`getifaddrs`)
  closes both sockets, so the client reconnects through a new `CONNECT` on the new path.
  Pooled upstream connections that still carry requests (a server-sent events feed, a long
  poll, a download) get the same check: their socket is wrapped so it can be cut, which
  fails every request on it (HTTP/1.1 and HTTP/2 alike) instead of leaving the response
  stalled on the dead path.
- Clients using the proxy send it host names instead of looking them up, so the proxy checks
  the DNS blocklist itself (`ProxyContext::domains`, the same `DomainSet` the DNS responder
  uses, swapped together on reload): the `CONNECT` host before classification (passthrough
  hosts included), a TLS server name that differs from it, and absolute-form hosts. A block
  answers `403` (or closes the tunnel for a server name), never dials, counts in
  `dns_blocked` and is recorded as a DNS block. The allowlist applies.
- Upstream host names are looked up through `ServeOptions::resolver` (the
  `tollgate_common::resolve::Resolve` trait; the tunnel passes `tollgate_dns::HostResolver`,
  A and AAAA over the shared DoH connections with a 256-name cache), so proxied lookups are
  encrypted like the tunnel's. The first two addresses are tried for 2 s each; when the
  lookup fails, finds nothing or no address answers, `getaddrinfo` is the fallback.
- HTTP/2 requests whose authority does not match the connection's SNI get `421 Misdirected
  Request`.
- The CA certificate and key are stored as PEM; leaves are issued from the stored certificate
  (rcgen `x509-parser` feature), never from regenerated parameters.
- Pin learning: only client TLS alerts that reject our certificate (`unknown_ca`,
  `bad_certificate`, `certificate_unknown`, `decrypt_error`) count, two within 10 minutes.
  Connections that finish the handshake and close without a request are counted as a
  statistic only, until E4 shows how iOS clients actually fail. An upstream certificate the
  proxy cannot verify (webpki roots, no intermediate fetching), a server the proxy's TLS
  client shares no version or cipher suite with, or one that requires a client certificate
  makes the SNI name a learned pin at once, since it fails the same way every time; the
  request that failed gets `502`, its client connection is closed, and later connections
  are passed through for the client to handle.

**ffi.**
- Foreign traits use `#[uniffi::export(foreign)]`: `CoreLogger` (not `Logger`, which would
  shadow `os.Logger` in Swift) and `PacketSink`.
- `Engine.start(sink: PacketSink) -> UInt16`. `handle_packets` stays synchronous: it returns
  answers it can produce immediately (blocked names, cache hits, type 65 and 64, SERVFAIL when
  stopped) and queues the rest; forwarded answers arrive through `PacketSink.writePackets`.
- Every exported function on the tunnel path returns `Result` and catches panics, so a Rust
  bug becomes a Swift error instead of killing the extension. Poisoned locks are recovered.
- Swift derives each packet's protocol family from the IP version nibble when writing packets.
- `stopTunnel` always calls `engine.stop()`. The Swift `PacketSink` captures only the
  `NEPacketTunnelFlow`, never the provider, so there is no reference cycle.
- uniffi default features are off in the runtime crate; `cargo-metadata` is enabled only in
  the bindgen tool.

**CI.** A job checks the workspace with Rust 1.94, the declared minimum version.

### Revised memory budget (extension)

| Component | Budget |
|---|---|
| adblock engine | 8 MiB |
| DNS blocklist (mmapped, clean pages) | 2 MiB |
| DNS cache and DoH | 1 MiB |
| intercepted connections (32 x 0.35 MiB) | 11 MiB |
| passthrough tunnels (128 x about 20 KiB) | 2.5 MiB |
| runtime, TLS configuration, leaf cache, misc | 3 MiB |
| total for Rust | about 28 MiB, leaving room for the Swift runtime and system frameworks |

## M1 crate contracts

These signatures are the interface between the M1 plans. A plan may add private items and
extra public helpers, but must not change these.

```rust
// ---------- tollgate-common ----------
pub mod clock {
    /// Seconds from a clock that keeps counting while the device sleeps.
    pub fn now_secs() -> u64;
}
pub mod tls {
    /// rustls client configuration with the ring provider and webpki roots.
    pub fn client_config(alpn: &[&[u8]]) -> std::sync::Arc<rustls::ClientConfig>;
}
pub mod stats {
    /// Lock-free counters shared by dns, mitm and ffi.
    #[derive(Default, Debug)]
    pub struct Stats {
        pub dns_queries: AtomicU64, pub dns_blocked: AtomicU64, pub dns_cache_hits: AtomicU64,
        pub dns_forwarded: AtomicU64, pub dns_failed: AtomicU64, pub packets_dropped: AtomicU64,
        pub http_requests: AtomicU64, pub http_blocked: AtomicU64,
        pub connections_intercepted: AtomicU64, pub connections_passthrough: AtomicU64,
        pub tls_client_rejections: AtomicU64, pub tls_abandoned_after_handshake: AtomicU64,
    }
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct StatsSnapshot { /* same fields as u64 */ }
    impl Stats { pub fn snapshot(&self) -> StatsSnapshot; }
}
// Logging goes through the `log` crate facade; ffi installs a `log::Log` that forwards to
// the Swift CoreLogger, devproxy installs env_logger.

// ---------- tollgate-policy ----------
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DohUpstream { pub ip: std::net::IpAddr, pub port: u16, pub tls_name: String, pub path: String }
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub doh_upstreams: Vec<DohUpstream>,     // default: Cloudflare 1.1.1.1, Quad9 9.9.9.9,
                                             // then 2606:4700:4700::1111, 2620:fe::fe
    pub passthrough: Vec<String>,            // user host patterns
    pub mitm_enabled: bool,                  // default true
    pub max_intercepted_connections: u32,    // default 32
}
impl Default for Config;
impl Config { pub fn from_json(s: &str) -> Result<Config, PolicyError>; pub fn to_json(&self) -> String; }
pub struct HostPattern; // "example.com" (exact) or "*.example.com" (the domain and all subdomains)
impl HostPattern { pub fn parse(s: &str) -> Result<HostPattern, PolicyError>; pub fn matches(&self, host: &str) -> bool; }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision { Intercept, Passthrough(PassthroughReason) }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassthroughReason { MitmDisabled, User, Bundled, LearnedPin, NotTls, Capacity, LowMemory }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectionKind { UnknownCa, BadCertificate, CertificateUnknown, DecryptError }
pub struct Policy; // Send + Sync, interior mutability
impl Policy {
    pub fn new(config: &Config, learned_pins_json: Option<&str>) -> Result<Policy, PolicyError>;
    pub fn classify(&self, host: &str, now: u64) -> Decision;
    /// Returns true when this rejection made the host a learned pin.
    pub fn record_client_rejection(&self, host: &str, kind: RejectionKind, now: u64) -> bool;
    pub fn learned_pins_json(&self) -> String;
}
pub fn bundled_passthrough() -> &'static [&'static str]; // compiled-in patterns

// ---------- tollgate-filter ----------
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListFormat { Adblock, Hosts }
pub struct ListSource<'a> { pub name: &'a str, pub text: &'a str, pub format: ListFormat }
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict { Allow, Block { rule: Option<String> } }
pub struct FilterEngine; // Send + Sync
impl FilterEngine {
    pub fn from_lists(lists: &[ListSource], debug: bool) -> FilterEngine;
    pub fn serialize(&self) -> Vec<u8>;
    pub fn load(path: &std::path::Path) -> Result<FilterEngine, FilterError>; // mmap
    pub fn check(&self, url: &str, source_url: &str, request_type: &str) -> Verdict;
}
/// Maps Sec-Fetch-Dest, then Accept, then path extension to an adblock request type string.
pub fn request_type(sec_fetch_dest: Option<&str>, accept: Option<&str>, path: &str) -> &'static str;
pub struct DomainSet; // Send + Sync, mmapped
impl DomainSet {
    pub fn build(lists: &[ListSource]) -> Vec<u8>;                 // file bytes
    pub fn load(path: &std::path::Path) -> Result<DomainSet, FilterError>;
    pub fn from_bytes(bytes: Vec<u8>) -> Result<DomainSet, FilterError>; // tests, devproxy
    pub fn is_blocked(&self, host: &str) -> bool;
    pub fn len(&self) -> usize;
}
pub const ENGINE_FILE: &str = "engine.dat";
pub const DOMAINS_FILE: &str = "domains.bin";
#[derive(Clone, Debug)]
pub struct CompileReport { pub network_rules: u64, pub domain_entries: u64, pub engine_bytes: u64, pub domains_bytes: u64 }
/// Writes ENGINE_FILE and DOMAINS_FILE atomically into dir.
pub fn compile(lists: &[ListSource], dir: &std::path::Path) -> Result<CompileReport, FilterError>;

// ---------- tollgate-dns ----------
pub const TUNNEL_DNS_V4: std::net::Ipv4Addr; // 198.18.0.1
pub const TUNNEL_DNS_V6: std::net::Ipv6Addr; // fd00:7467::1
pub struct DnsHandler; // Send + Sync
pub enum Outcome { Reply(Vec<u8>), Forward(ForwardJob), Drop }
pub struct ForwardJob; // opaque: query wire bytes plus what is needed to build the reply packet
impl DnsHandler {
    pub fn new(blocklist: Option<std::sync::Arc<tollgate_filter::DomainSet>>, stats: std::sync::Arc<tollgate_common::stats::Stats>) -> DnsHandler;
    pub fn set_blocklist(&self, blocklist: Option<std::sync::Arc<tollgate_filter::DomainSet>>);
    /// Never blocks or awaits.
    pub fn handle_packet(&self, packet: &[u8], now: u64) -> Outcome;
    /// Builds the reply packet for a forwarded query; caches successful answers.
    pub fn complete(&self, job: ForwardJob, answer: Result<Vec<u8>, DohError>, now: u64) -> Vec<u8>;
}
pub struct DohResolver; // Clone, used on one tokio runtime
impl DohResolver {
    pub fn new(upstreams: Vec<tollgate_policy::DohUpstream>) -> DohResolver;
    pub async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>, DohError>;
}
impl ForwardJob { pub fn query(&self) -> &[u8]; }

// ---------- tollgate-mitm ----------
pub struct CertAuthority; // Send + Sync
impl CertAuthority {
    pub fn generate(common_name: &str) -> Result<CertAuthority, MitmError>;
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<CertAuthority, MitmError>;
    pub fn cert_pem(&self) -> String;
    pub fn key_pem(&self) -> String;
    pub fn cert_der(&self) -> Vec<u8>;
    /// iOS configuration profile containing only the root certificate.
    pub fn mobileconfig(&self, display_name: &str, identifier: &str) -> Vec<u8>;
}
pub struct ProxyContext {
    pub policy: std::sync::Arc<tollgate_policy::Policy>,
    pub filter: arc_swap::ArcSwapOption<tollgate_filter::FilterEngine>,
    pub ca: std::sync::Arc<CertAuthority>,
    pub stats: std::sync::Arc<tollgate_common::stats::Stats>,
    pub max_intercepted: usize,
    /// Returns available memory in bytes; `None` where unknown (Linux dev runs).
    pub available_memory: fn() -> Option<u64>,
}
/// Serves until `shutdown` resolves. Must be spawned on a current-thread tokio runtime.
pub async fn serve(listener: tokio::net::TcpListener, ctx: std::sync::Arc<ProxyContext>,
                   shutdown: impl std::future::Future<Output = ()>);

// ---------- tollgate-ffi (Swift-facing) ----------
// #[uniffi::export(foreign)] trait CoreLogger: Send + Sync { fn log(&self, level: LogLevel, target: String, message: String); }
// #[uniffi::export(foreign)] trait PacketSink: Send + Sync { fn write_packets(&self, packets: Vec<Vec<u8>>); }
// #[derive(uniffi::Object)] struct Engine;
//   #[uniffi::constructor] fn new(config_json: String, data_dir: String) -> Result<Arc<Engine>, TollgateError>
//   fn start(&self, sink: Arc<dyn PacketSink>) -> Result<u16, TollgateError>
//   fn stop(&self)
//   fn handle_packets(&self, packets: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, TollgateError>
//   fn reload_lists(&self) -> Result<(), TollgateError>
//   fn stats(&self) -> Stats            (uniffi::Record mirroring StatsSnapshot)
//   fn learned_pins_json(&self) -> String
// free functions: set_logger(Arc<dyn CoreLogger>, LogLevel), generate_ca(data_dir) -> Result<CaInfo>,
//   ca_mobileconfig(data_dir) -> Result<Vec<u8>>, compile_lists(sources: Vec<ListInput>, data_dir) -> Result<CompileReport>
```

## M3: user controls (2026-09-25)

Adds the blocked log, the allowlist, the passthrough editor, learned pin management, custom
lists and rules, and automatic list updates. Where this section disagrees with earlier
sections, this section wins.

### Behavior

- **Blocked log.** The tunnel keeps the last 500 block events in memory: DNS blocks (the
  queried name) and request blocks (host, URL truncated to 512 bytes, and the page's host).
  The app polls them while the Activity screen is visible. Nothing is written to disk.
- **Allowlist.** Host patterns (same syntax as passthrough) where Tollgate blocks nothing:
  DNS names matching a pattern are resolved normally, and a request is allowed when either
  its own host or its page's host matches. From the log, "Allow" adds `*.host`.
- **Passthrough editor.** The user edits `Config.passthrough`; entries are validated with the
  core's own pattern parser before they are saved.
- **Learned pins.** The app lists learned pins and can forget them. While the tunnel runs it
  asks the tunnel (the engine owns the pins and saves them periodically); while it is off
  the app edits `learned-pins.json` through the core.
- **Custom lists and rules.** The default lists can be switched off individually; the user
  can add list URLs of three kinds (request rules, DNS rules in adblock syntax, hosts files)
  and type their own rules, which go into both the request engine and the DNS blocklist.
  Settings live in the App Group as `lists.json`, owned by the app.
- **Automatic updates.** A background app refresh task (`dev.tollgate.lists-refresh`) runs
  about daily; the app also updates on launch and on returning to the foreground when the
  lists are more than 24 hours old. After an update the tunnel reloads the lists.
- Config changes (allowlist, passthrough) are saved to `config.json` and applied by
  restarting the tunnel.
- **Local network names.** The tunnel is the resolver for every name, and the DoH upstreams
  know nothing about the owner's LAN, so names only the network's own resolver knows are
  never sent there (`tollgate_dns::is_local_name`): single-label names, names under `lan`,
  `home.arpa`, `internal`, `localdomain`, `fritz.box`, `intranet`, `corp` and `private`, and
  the reverse zones of 10/8, 172.16/12, 192.168/16, 169.254/16, fc00::/7 and fe80::/10.
  They are never blocked. The handler returns `Outcome::Local`; the engine hands the
  question to the Swift `LocalResolver` (one lookup per question, at most 64 waiting, 5 s
  deadline), which runs `DNSServiceQueryRecord` scoped to the current physical interface
  from `NWPathMonitor(prohibitedInterfaceTypes: [.other])`, so the network's DHCP resolver
  answers, never the tunnel's. The records come back through `Engine::complete_local`;
  a failure or 2 s without an answer is SERVFAIL. Answers with records are cached for at
  most 60 s, and the cache is emptied when the interface or its gateways change
  (`Engine::set_network`). The proxy's `HostResolver` leaves these names to
  `getaddrinfo`. Names under other router domains still go to DoH and fail, and a bare
  name is sent to the router as typed, without the network's search domain.

### Contracts

```rust
// ---------- tollgate-common::events ----------
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind { Dns, Request }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockEvent { pub unix_secs: u64, pub kind: EventKind, pub host: String,
                        pub url: Option<String>, pub source_host: Option<String> }
pub struct EventLog; // Send + Sync, bounded ring buffer
impl EventLog {
    pub const CAPACITY: usize = 500;
    pub const MAX_URL_BYTES: usize = 512;
    pub fn new() -> EventLog;
    pub fn record(&self, event: BlockEvent);           // truncates url, drops oldest
    pub fn recent(&self, limit: usize) -> Vec<BlockEvent>; // newest first
    pub fn clear(&self);
}

// ---------- tollgate-policy ----------
// Config gains `pub allowlist: Vec<String>` (serde default: empty).
impl Policy {
    pub fn is_allowlisted(&self, host: &str) -> bool;
    /// Forgets learned pins (and pending rejections) for these hosts; returns how many pins.
    pub fn forget_pins(&self, hosts: &[String]) -> usize;
    /// (host, learned_at unix seconds), sorted by host.
    pub fn learned_pins(&self) -> Vec<(String, u64)>;
}

// ---------- tollgate-dns ----------
impl DnsHandler {
    pub fn set_allowlist(&self, patterns: Vec<tollgate_policy::HostPattern>);
    pub fn set_events(&self, events: Option<std::sync::Arc<tollgate_common::events::EventLog>>);
}

// ---------- tollgate-mitm ----------
// ProxyContext gains `pub events: Option<Arc<EventLog>>`. Requests are allowed when
// ctx.policy.is_allowlisted(request host) or is_allowlisted(page host); blocks are recorded.

// ---------- tollgate-ffi (Swift-facing) ----------
// #[derive(uniffi::Enum)] enum EventKind { Dns, Request }
// #[derive(uniffi::Record)] struct BlockEvent { unix_secs: u64, kind: EventKind, host: String,
//                                               url: Option<String>, source_host: Option<String> }
// #[derive(uniffi::Record)] struct LearnedPin { host: String, learned_at: u64 }
// impl Engine {
//   fn recent_events(&self, limit: u32) -> Vec<BlockEvent>
//   fn clear_events(&self)
//   fn learned_pins(&self) -> Vec<LearnedPin>
//   fn forget_pins(&self, hosts: Vec<String>) -> u32
// }
// free: validate_host_pattern(pattern: String) -> Result<(), TollgateError>
//       stored_learned_pins(data_dir: String) -> Result<Vec<LearnedPin>, TollgateError>
//       forget_stored_pins(data_dir: String, hosts: Vec<String>) -> Result<u32, TollgateError>
```

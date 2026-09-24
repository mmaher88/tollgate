# Decision brief: building an iOS 27 NEPacketTunnelProvider ad blocker (MITM) from a Linux box

Target: iPhone 15 Pro Max, iOS 27.0, USB-paired. Host: CachyOS x86_64, Ryzen 5950X, 62 GB RAM, KVM, ~65 GB free root + spare 223 GB SSD. Paid Apple Developer Program, sideload only. Date: 2026-09-23.

Legend: **[REFUTED]** = verifier refuted the agent claim; **[UNVERIFIED]** = no primary source found; **[CORRECTED]** = verifier tightened the claim.

---

## 1. Build toolchain options from Linux

| | xtool on Linux (1.20.1, 2026-09-21) | macOS VM on KVM (dockur/macos, OSX-KVM) | Remote / cloud Apple-silicon Mac | Hybrid: Rust core on Linux + thin Swift shell |
|---|---|---|---|---|
| **NE app-extension support** | Generic Foundation `.appex` (PlugIns/) supported since 1.14.0 ([PR #97](https://github.com/xtool-org/xtool/pull/97)); `NEPacketTunnelProvider` is exactly that kind. **But two code blockers today:** (1) `NetworkExtensionEntitlement` is commented out of `supportedTypes` and typed `Bool` instead of `[String]` ([EntitlementTypes.swift](https://github.com/xtool-org/xtool/blob/main/Sources/XKit/Model/Entitlements/EntitlementTypes.swift), re-checked live today), so the NETWORK_EXTENSIONS capability is never enabled on the App ID, and capability sync **deletes** any capability it doesn't recognise ([DeveloperServicesAddAppOperation.swift](https://github.com/xtool-org/xtool/blob/main/Sources/XKit/DeveloperServices/App%20IDs/DeveloperServicesAddAppOperation.swift)); (2) per-bundle entitlements are collapsed to the root app; the appex gets the app's entitlements blob ([issue #131](https://github.com/xtool-org/xtool/issues/131), open since 2025-07-14). No issue/PR/release mentions Network Extension at all **[CORRECTED: code mentions it, docs/issues don't]**. | Native Xcode support, **but** Xcode 27 "will only install and run on Apple silicon Macs" ([Xcode 27 RN](https://developer.apple.com/documentation/xcode-release-notes/xcode-27-release-notes), confirmed live). x86 VM caps at macOS Tahoe 26.x (26.7 is current, [Apple 100100](https://support.apple.com/en-us/100100)) + Xcode 26.6 (iOS 26.5 SDK, Swift 6.3, [Xcode 26.6 RN](https://developer.apple.com/documentation/xcode-release-notes/xcode-26_6-release-notes)). | Full Xcode 27 / iOS 27 SDK / Swift 6.4; NE capability is a checkbox ([thread 819032](https://developer.apple.com/forums/thread/819032)). | Core (filter engine, MITM, TLS, TCP stack, cert minting) has zero Apple dependency; the Swift shell (NE provider subclass, VPN manager UI, CA profile) still needs one of the other three columns to be signed and packaged. |
| **Signing / entitlement support** | ASC API key (paid) or Apple-ID password (private API). Registers device, dev cert, App ID (**always** rewritten to `XTL-<8hex>.your.bundle.id`), `IOS_APP_DEVELOPMENT` profile. Active mappings: App Groups, Personal VPN, Push, Multipath, WiFi-Aware, HomeKit, HealthKit, Data Protection. App Group creation only works under **password** auth (returns nil for API key) ([DeveloperServicesAssignAppGroupsOperation](https://github.com/xtool-org/xtool/blob/main/Sources/XKit/DeveloperServices/App%20IDs/Entitlements/DeveloperServicesCapability.swift)). NE mapping exists in dead code. | Xcode automatic signing; full portal support. | Same as VM, plus you can drive `xcodebuild` headless. | Inherits the chosen packaging column. |
| **iOS 27 device deploy** | Install over usbmuxd/installation_proxy (no RemoteXPC needed); no iOS 26/27 install failures reported; Xcode 27 SDK link bugs #269/#273 fixed in 1.20.1. `xtool launch` broken on iOS 17+ ([#44](https://github.com/xtool-org/xtool/issues/44)); no LLDB, DDI mounter disabled on Linux. | Xcode 26.6 debugging iOS 27.0 is **[UNVERIFIED]**: Apple lists Xcode 26.x device support as "iOS 15 or later" with no upper bound and the Xcode 27 notes' ASan item presupposes Xcode 26.5+ launches on iOS 27.0, but no explicit statement. Also needs iPhone USB passthrough into the VM; iOS 17+ CoreDevice tunneling through `usb-host` passthrough is reported flaky (re-enumeration loops), whole-controller VFIO is the robust fallback ([Silfalion guide](https://github.com/Silfalion/Iphone_docker_osx_passthrough)). | Cannot reach the USB-attached iPhone. Deliver the signed `.ipa` back to Linux and install with `pymobiledevice3 apps install` / `ideviceinstaller install` (dev profile listing the UDID). No LLDB from Linux; logs via `pymobiledevice3 syslog live`. | Rust core unit-tested natively on Linux; on-device iteration follows the packaging column. |
| **Disk / RAM cost** | Xcode 27 .xip (several GB, exact size not verified) + Darwin SDK ~7 GB (`--slim` ~3 GB) + Swift 6.4 toolchain. Fits in 65 GB. | dockur: 64 GB disk default, 4 GB RAM, 1 core; OSX-KVM: 256 GB qcow2 default; Xcode needs 45-60 GB free during install; 16 GB+ RAM sensible. Use the spare 223 GB SSD. No GPU accel; dockur says Tahoe "runs very slow for some unknown reason" ([dockur/macos](https://github.com/dockur/macos)). | Zero local. GitHub Actions macOS $0.062/min ([pricing](https://docs.github.com/en/enterprise-cloud@latest/billing/reference/actions-runner-pricing)); Scaleway M4 from EUR 0.22/h ([Scaleway](https://www.scaleway.com/en/pricing/apple-silicon/)); AWS mac2-m2.metal ~$0.878/h with 24 h minimum ([AWS FAQ](https://aws.amazon.com/ec2/instance-types/mac/faqs/)). | rustup target + Xcode SDK on disk (shared with xtool). |
| **Setup effort** | Medium: Swift 6.4 tarball (no CachyOS package on swift.org, use swiftly), usbmuxd, Xcode .xip download, `xtool setup`; **plus two source patches to xtool** and a rebuild. | High: OpenCore boot, AMD quirks (install with 1 core / <=8 GB then raise), Tahoe install, Xcode 26.6 install, USB/VFIO passthrough. | Low: rent, `git clone`, `xcodebuild -exportArchive` with development method, scp the .ipa. | Medium (cross-compile recipe in section 3), then the shell packaging. |
| **Risk** | Medium-high: the NE-appex path has **never been demonstrated** with xtool; patches are unmerged local work; Apple SDK license restricts use on non-Apple hardware ([Xcode SLA EA2002](https://www.apple.com/legal/sla/docs/xcode.pdf), sections 2.5/2.7). | High: license (macOS SLA 2B(iii): virtualization only on Apple-branded hardware, [Tahoe SLA](https://www.apple.com/legal/sla/docs/macOSTahoe.pdf)); Xcode 26.6 vs iOS 27 unverified; USB passthrough; Tahoe KVM performance. Also stuck on the iOS 26.5 SDK forever (no Xcode 27 possible). | Low technical risk; recurring cost; per-iteration latency (build remote, install local). | Low for the core; the shell inherits the packaging risk. |

### Recommendation

Build the **hybrid**: a Rust core developed and tested on Linux, plus a thin Swift shell. For packaging and signing, the primary path that honors "build this on this machine" is **xtool with two local patches**, gated by one experiment before any real code is written:

1. Patch A: uncomment `NetworkExtensionEntitlement` in `supportedTypes` and change it to `rawValue: [String]` (the WiFi-Aware mapping added in 1.18.1, [PR #240](https://github.com/xtool-org/xtool/pull/240), is the template). Patch B: plumb the per-bundle entitlement mapping through `SignerImpl.swift` -> `Zupersign.cpp` into the zsign fork's existing `list<ZSignAsset>` overload (fork already matches profiles per bundle by application-identifier suffix, [xtool-org/zsign](https://github.com/xtool-org/zsign)). Use **password auth** so App Groups get created.
2. Run experiment E1 (section 6): hello-world app + empty `NEPacketTunnelProvider` appex, `xtool dev`, confirm the tunnel starts on the iPhone. If E1 fails after a bounded effort (say 2 days), switch packaging to a **rented Apple-silicon Mac** (Scaleway M4 hourly or GitHub Actions) that signs the .ipa, and keep installing/logging from Linux. That fallback is low-risk and keeps the Rust core untouched.
3. Do **not** build the macOS KVM VM: it cannot run Xcode 27, the Xcode 26.6 + iOS 27 device combination is unverified, USB passthrough of an iOS 17+ device is the flakiest part of the whole stack, and it carries the same license issue as xtool with far more setup.

Reasoning: every Apple-side capability the app needs (packet-tunnel-provider, App Groups) is self-serve for a paid team; the only thing between this machine and a running NE appex is xtool glue code that the verifiers traced to two well-localised spots. The 50 MiB extension limit and the need for a filter engine plus TLS/TCP stack all point to Rust regardless of packaging, so the core work is not blocked on the packaging decision.

---

## 2. Base project options (ranked)

Because the core will be Rust, the Swift base only needs: the provider skeleton, packet-flow plumbing, VPN-manager/UI, CA-profile install flow, App Group sharing. Rank reflects that.

1. **juanmmm21/TunnelVision** ([repo](https://github.com/juanmmm21/TunnelVision)), MIT, Swift 6 strict concurrency, iOS 17+, XcodeGen, last commit 2026-08-29, 14 commits, 0 stars. Reuse: `NEPacketTunnelProvider` skeleton, flow table, userspace TCP reassembly, TLS termination via Network.framework, `ClientHelloScanner`, `PinnedHostMemory` (pinning fallback), documented memory strategy (mmap ring buffer, GRDB), ADRs, 1710 unit tests per README. Must add: our Rust core replaces its TCP/TLS engines (or keep them as a Swift fallback), filter engine, CA install UX. Caveats: single author, zero community, its leaf-cert minting library not inspected **[UNVERIFIED]**, rejected from App Store (Guideline 5.4, individual account; irrelevant for sideloading).
2. **zhxie/Mudmouth** ([repo](https://github.com/zhxie/Mudmouth)) MIT, iOS 15, last commit 2025-12-31, and **qtmleap/Mudmouth** SPM variant (iOS 17, swift-tools 6.1, pushed 2026-09-12). Reuse: the smallest working NEProxySettings + NIOSSL MITM + swift-certificates CA flow, and the CA profile install UX. Must add: everything else.
3. **Lojii/Knot** ([repo](https://github.com/Lojii/Knot)), GPL-3.0, 1805 stars, master frozen 2026-03-19 (activity since is on `feature/flutter-ui`, 2026-07-17). **[REFUTED]** the "working SwiftNIO ProxyServer/ProtocolRouter/MITMHandler pipeline" claim: on master the described `PacketTunnel/PacketTunnelProvider.swift` is not compiled by any target (the only iOS extension target `PacketTunnel-iOS` is an empty Xcode template stub); `ProxyServer`/`ProtocolRouter` are never instantiated; `HTTP2CaptureHandler`, `GRPCCaptureHandler`, `SOCKSProxyHandler` are dead code; the live path is the legacy `MitmService` + `ProtocolDetector` pipeline. Deployment targets: app 17.6, tunnel extension 26.2, all Swift 5 mode; no CI; Xcode 27 build unverified. Use as **read-only reference** for NIO MITM/ALPN handling; GPL-3.0 would contaminate an MIT/MPL codebase if code is copied.
4. **Filter engine: brave/adblock-rust** ([repo](https://github.com/brave/adblock-rust)), MPL-2.0, v0.13.3 (2026-08-20), pushed 2026-09-22. Parses ABP/EasyList, uBO extensions, hosts syntax, many AdGuard modifiers ($removeparam since 0.6.0; gaps: generic $removeparam, $document default, removeparam exceptions per issues #245/#247/#297). Production-proven on iOS via brave-core's `adblock-cxx` ([Cargo.toml](https://github.com/brave/brave-core/blob/master/components/brave_shields/core/common/adblock/rs/Cargo.toml)). No Swift/C FFI shipped ([adblock-rust-ffi](https://github.com/brave/adblock-rust-ffi) archived 2024-01-08): write our own via uniffi. Beats **AdguardTeam/urlfilter** (Go, GPL-3.0, v0.23.4, would need gomobile + Go runtime inside the 50 MiB extension).
5. **callmejustdodo/ShortGuard** (MIT, iOS 18.2, single-day repo 2026-03-20, contains CLAUDE.md): reference only for DNS blocking + NIOSSL MITM in one provider.
6. **SagerNet/sing-box-for-apple** (GPL-3.0, Go Libbox via gomobile, active): proven TUN stack, **no MITM anywhere in sing-box**, Go runtime memory, Xcode/gomobile build. Not a base.
7. Not usable: **Lockdown-iOS** (NEKit fork, archived upstream, Swift 4.2-era, domain blocking only), **AdguardForiOS** (DNS-only tunnel + Safari content blockers, [TunnelProvider.swift](https://github.com/AdguardTeam/AdguardForiOS/blob/version/v4.5/AdguardExtension/Tunnel/TunnelProvider.swift); note open issue #2529 "iOS 27: Filtering does not work" on its split-tunnel path), **Blokada** (WireGuard to their cloud), **NetWraith** (forwards to external Burp), **lambret-1/new-vpn** (created 2026-09-23, no license, no MITM code).

Side note from verification: Apple's new **NEURLFilter** (iOS 26+, block-only, full-URL matching via PIR, no MITM) exists ([AdGuard blog 2025-12-02](https://adguard.com/en/blog/apple-url-filter-system-wide-filtering-api.html)); it cannot do cosmetic/response modification and its availability to dev-signed apps was not researched. Worth a look if MITM proves too brittle, but it is not a substitute for the stated goal.

---

## 3. Core engine: Rust (verdict) and the cross-compilation recipe

**Verdict: Rust.** Go is disqualified for this project, not merely worse:
- `gomobile bind -target=ios` unconditionally shells out to `xcrun --sdk ... --find clang` / `--show-sdk-path` ([env.go](https://github.com/golang/mobile/blob/master/cmd/gomobile/env.go)); `GOOS=ios` requires cgo and an external Apple-style linker; no Linux-host recipe exists ([misc/ios/README](https://github.com/golang/go/blob/master/misc/ios/README)).
- Go's GC inside the 50 MiB jetsam limit has a documented history of needing runtime patches/tuning (Psiphon, WireGuard).
- The best Go TUN stacks (sing-tun/gVisor) are GPLv3 and built in Xcode.

Rust: `aarch64-apple-ios` is Tier 2 (no host tools), cross-compiled from any host given the iOS SDK ([rustc platform support](https://doc.rust-lang.org/rustc/platform-support/apple-ios.html)). rustc bundles `rust-lld` with an `ld64.lld` flavor; a verifier linked a real arm64 iOS Mach-O on this machine (rustc 1.94.0, LLD 21.1.8) with no Apple ld64 ([codegen options](https://doc.rust-lang.org/rustc/codegen-options/index.html)). **[CORRECTED]**: SDKROOT is ignored if it points at the wrong platform (e.g. MacOSX.platform), rustc tries whatever `xcrun` is on PATH on any host, and Apple targets default to a `cc` driver, so the linker must be set explicitly.

Recipe (each piece verified; the end-to-end combination is **[UNVERIFIED]** as a single documented run, so it is experiment E2):

```bash
# 0. SDK: after `xtool setup`, locate the iPhoneOS SDK inside the Darwin SDK
SDK=$(find ~/.swiftpm -type d -name 'iPhoneOS*.sdk' | head -1)   # path layout not documented; discover it
export SDKROOT="$SDK" IPHONEOS_DEPLOYMENT_TARGET=17.0

# 1. Rust target
rustup target add aarch64-apple-ios

# 2. .cargo/config.toml
# [target.aarch64-apple-ios]
# linker = "/home/mina/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
# rustflags = ["-C", "linker-flavor=ld64.lld", "-C", "link-arg=-syslibroot", "-C", "link-arg=<SDK>"]
# (alternative linker: a wrapper running `zig cc -target aarch64-ios --sysroot $SDKROOT`; cargo-zigbuild itself does NOT support iOS targets, issue #310 open)

# 3. C deps (ring / aws-lc-sys / BoringSSL): point cc-rs at clang with the iOS sysroot
export CC_aarch64_apple_ios=clang AR_aarch64_apple_ios=llvm-ar
export CFLAGS_aarch64_apple_ios="-target arm64-apple-ios17.0 -isysroot $SDKROOT"

# 4. Build a staticlib (crate-type = ["staticlib"]) and generate Swift bindings on Linux
cargo build --release --target aarch64-apple-ios
cargo run -p uniffi-bindgen-swift -- target/aarch64-apple-ios/release/libadcore.a build/swift --swift-sources --headers --modulemap
```

Crate choices (all current): `adblock` 0.13.3 (engine), `hudsucker` 0.25.0 (MITM proxy; switch its rustls features to `ring` to avoid aws-lc-rs C build, or write a leaner tokio-rustls + rcgen loop if memory is tight), `rcgen` 0.14.10 (`CertificateParams::signed_by` for CA-signed leaves), `rustls` 0.23.x with `ring` 0.17.14 (ring's CI builds aarch64-apple-ios), `smoltcp` 0.14.0 / `netstack-smoltcp` 0.2.4 (lists iOS) or `ipstack` 1.0.1 for the packet-flow TCP stack, `uniffi` 0.32.2 for Swift bindings.

Packaging gotcha **[CORRECTED]**: xtool's packer only special-cases `binaryTarget` `.framework`s; a plain `.a` linked via SwiftPM `linkerSettings` bypasses the packer entirely (good). Avoid FAT/universal static xcframeworks: xtool misdetects them as dynamic ([issue #130](https://github.com/xtool-org/xtool/issues/130), fix [PR #198](https://github.com/xtool-org/xtool/pull/198) unmerged).

License caveat: using iPhoneOS.sdk on Linux is outside the Xcode SLA (EA2002, 2026-06-08) and the xtool author says so ([Swift Forums 79803](https://forums.swift.org/t/xtool-cross-platform-xcode-replacement-build-ios-apps-on-linux-and-more/79803)); rust-lang [PR #139053](https://github.com/rust-lang/rust/pull/139053) documenting Linux cross-compilation is blocked on exactly this. Your call for a private sideloaded app.

---

## 4. iOS platform constraints to design around

- **Memory: 50 MiB for the packet tunnel process**, everything included (libraries, TLS, buffers). Apple DTS confirmed unchanged on iOS 26 (Oct 2025, [thread 73148](https://developer.apple.com/forums/thread/73148?page=2)); iOS 26.3.1 jetsam log shows `exceeded mem limit: ActiveHard 50 MB (fatal)`; for iOS 27 the only evidence is a third-party report of a tunnel peaking at 49.8 MiB on 27.0 beta **[UNVERIFIED by Apple]**. Design: stream, never buffer whole responses; cap concurrent MITM flows; keep filter lists in a zero-copy/mmap format (adblock-rust's FlatBuffers format fits); store logs in the app via App Group, not in the extension. **[CORRECTED]** the "5/6 MB before iOS 10" figure was for filter providers, not packet tunnels (those were 15 MiB).
- **CA trust**: install the root as a profile (Settings > Profile Downloaded > Install), then Settings > General > About > Certificate Trust Settings > enable full trust ([Apple 102390](https://support.apple.com/en-us/102390)). Once enabled, ATS/URLSession/WebKit accept it and apps have **no API to opt out except pinning** (DTS Aug 2025, [thread 795245](https://developer.apple.com/forums/thread/795245)). Leaf certs: SAN (CN ignored), EKU serverAuth, SHA-2, RSA >= 2048 or ECC >= 256, validity <= 825 days ([Apple 103769](https://support.apple.com/en-us/103769)); the 398-day / SC-081 47-day reductions and Apple's CT policy exempt user-added roots ([Apple 102028](https://support.apple.com/en-us/102028)). iOS 18.0-18.1 had a bug hiding installed roots in Trust Settings (fixed 18.2b4); nothing iOS 26/27-specific found. Open [mitmproxy #7932](https://github.com/mitmproxy/mitmproxy/issues/7932) (Oct 2025) reports a fully-trusted CA still rejected when traffic goes through a WireGuard tunnel: reproduce early.
- **Pinning / passthrough**: "Apple services will fail any connection that uses HTTPS Interception" ([Apple 101555](https://support.apple.com/en-us/101555)); seed an SNI passthrough list with Apple's host list (`*.apple.com`, `*.icloud.com`, `*.mzstatic.com`, `*.push.apple.com`, `mask*.icloud.com`, `gsa.apple.com`, `idmsa.apple.com`, ...) plus [AdguardTeam/HttpsExclusions](https://github.com/AdguardTeam/HttpsExclusions) (banking etc.). TunnelVision's "learn that host pins, relay untouched" pattern handles the rest.
- **QUIC / HTTP3**: drop UDP/443 at the first packet (or ICMP unreachable) so URLSession falls back to h2/h1 (DTS, [thread 682990](https://developer.apple.com/forums/thread/682990)); half-blackholed QUIC causes 6+ s stalls ([thread 771945](https://developer.apple.com/forums/thread/771945)); there is no public API to disable HTTP/3. Private Relay is bypassed while any VPN config is active ([NE docs](https://developer.apple.com/documentation/networkextension/packet-tunnel-provider)); Apple relays fall back to HTTP/2 CONNECT, so keep `mask-h2.icloud.com` in passthrough. ECH is not default-on in iOS **[low confidence, no Apple primary source]**, so SNI remains visible; strip HTTPS/SVCB RRs at the DNS layer as insurance.
- **Entitlements**: `com.apple.developer.networking.networkextension` = `[packet-tunnel-provider]` on app and appex, plus App Groups. Packet tunnel is self-serve for any paid team, no request form (DTS Mar 2026, [thread 819032](https://developer.apple.com/forums/thread/819032); [TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment) rev 2025-08-19). Free Personal Teams cannot use Network Extensions; **[CORRECTED]** App Groups *are* listed as available to free teams ([capabilities table](https://developer.apple.com/help/account/reference/supported-capabilities-ios/)), so the paid account is needed for NE only.
- **Developer Mode**: required for development-signed and (per user reports, not Apple docs) ad hoc builds; not for App Store/TestFlight ([Apple doc](https://developer.apple.com/documentation/xcode/enabling-developer-mode-on-a-device)). The Settings switch is hidden until a Mac pairs or a dev-signed app is installed; from Linux, `pymobiledevice3 amfi enable-developer-mode` only works with **no passcode** set; with a passcode use `amfi reveal-developer-mode` then toggle on-device and reboot.
- **Sideloading / distribution**: TN3134 places no supervision or App-Store-only restriction on iOS packet tunnel providers (only per-app VPN needs a managed device); the supervised-only limits hit DNS proxy and content filter providers on distribution-signed builds. [TN3120](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers) calls dropping/re-injecting packets an unsupported use: App Review policy, not a technical block. Dev profiles from xtool are `IOS_APP_DEVELOPMENT`, bundle ID prefixed `XTL-<hex>.`, App Group IDs rewritten to `group.XTL-<hex>.<id>`; hard-code neither.

---

## 5. Device tooling from Linux (iOS 27)

Works:
- **Install**: `pymobiledevice3 apps install app.ipa` (v11.17.2, 2026-09-23, confirmed live) or `ideviceinstaller install app.ipa` (1.2.0, 2025-10-30). installation_proxy is a plain lockdownd/usbmux service; no DDI, no RemoteXPC tunnel ([installation_proxy.py](https://raw.githubusercontent.com/doronz88/pymobiledevice3/master/pymobiledevice3/services/installation_proxy.py); ideviceinstaller confirmed installing on iOS 26.3 in [libimobiledevice #1744](https://github.com/libimobiledevice/libimobiledevice/issues/1744)). iOS 27.0 specifically **[UNVERIFIED]** by any report. `xtool dev` / `xtool install` use the same path.
- **Logs**: `pymobiledevice3 syslog live -pn <ExtensionExecutable> --label` or `-s <os_log subsystem>` (no tunnel/DDI). Use a unique `Logger(subsystem:category:)` per DTS ([thread 725805](https://developer.apple.com/forums/thread/725805), revised 2026-04-01); debug-level entries are not persisted, log at .info/.default. `idevicesyslog -p <name>` also works but has an open truncation bug on iOS 18.5+ ([#1667](https://github.com/libimobiledevice/libimobiledevice/issues/1667)).
- **Developer tunnel** (for `developer dvt launch`, proclist, oslog, debugserver): **[CORRECTED]** on Linux + iOS 17.4+ pymobiledevice3 now brings up an in-process userspace tunnel by **default**, no root and no flag; `--userspace` merely forces it. `sudo pymobiledevice3 lockdown start-tunnel` is the optional faster utun tunnel; `sudo pymobiledevice3 remote tunneld` is needed only for iOS 17.0-17.3.1 or when an external process (lldb) must reach the device ([ios17-tunnels guide](https://doronz88.github.io/pymobiledevice3/guides/ios17-tunnels/)). iOS 27.2 RSD-UUID breakage fixed in v11.15.5; Linux replug crash fixed (#1742); iOS 27.0 DDI `LookupImage` quirk fixed in v10.2.3.
- **DDI**: `pymobiledevice3 mounter auto-mount` (personalized image, needs internet for TSS). Also `ideviceimagemounter mount <dir>` in libimobiledevice 1.4.0.
- **Developer Mode**: `pymobiledevice3 amfi enable-developer-mode` / `idevicedevmodectl enable` (no passcode only); `reveal` otherwise.
- **Launch the container app**: `pymobiledevice3 developer dvt launch <bundle-id>`; the NE extension itself is started by the system when the VPN config activates, not by dvt.

Does not work / not available:
- `xtool launch` on iOS 17+ ([#44](https://github.com/xtool-org/xtool/issues/44)); xtool has no LLDB or DDI on Linux.
- Attaching LLDB to the **extension process** from Linux: pymobiledevice3 can start debugserver over a root tunneld, but attach-to-appex from Linux was not verified **[UNVERIFIED]**. Plan on log-driven debugging.
- Wi-Fi RSD discovery on iOS 26.x uses a dynamic port ([#1569](https://github.com/doronz88/pymobiledevice3/issues/1569), closed not-planned); USB is unaffected. iOS 27's new `remote pair-host` Wi-Fi pairing is additive.
- Whether an xtool-signed dev app also shows the "Untrusted Developer" prompt (Settings > General > VPN & Device Management) on iOS 27 **[UNVERIFIED]**; harmless if it does.
- Alternative Rust stack [jkcoxson/idevice](https://github.com/jkcoxson/idevice) (pre-0.2, breaking changes each release) covers the same ground; keep as backup.

---

## 6. Unresolved questions and the experiment that settles each

| # | Question | Experiment |
|---|---|---|
| E1 | Can patched xtool build, sign and install an app + `NEPacketTunnelProvider` appex that actually starts on iOS 27? (Blockers 1, 1b, 2; App Group under password auth.) | Fork xtool, apply patches A+B, build; `xtool new`, add an extension with `NSExtensionPointIdentifier = com.apple.networkextension.packet-tunnel`, entitlements on both bundles, `xtool dev`. On device: create `NETunnelProviderManager`, start, watch `syslog live -pn <appex>` for a first-light log line. Also confirm the portal shows NETWORK_EXTENSIONS on the `XTL-...` App ID and the appex's embedded profile contains the entitlement (`pymobiledevice3 apps` + unzip the .ipa, `codesign`-equivalent via `rcodesign print-signature-info` or zsign `-d`). |
| E2 | Does `cargo build --target aarch64-apple-ios` with the xtool-extracted SDK + `rust-lld` produce a linkable staticlib, including ring/BoringSSL C code? | The recipe in section 3 on a crate depending on `adblock`, `rustls` (ring), `rcgen`, `smoltcp`; link it into the E1 appex via SwiftPM `linkerSettings`; call one FFI function from `startTunnel`. Watch for the arm64e.x1 .tbd issue xtool 1.20.1 had to patch around in ld64.lld. |
| E3 | Is the tunnel limit 50 MiB on iOS 27.0 on this device? | In the E1 appex, allocate in 4 MiB steps and log; read the JetsamEvent log (`pymobiledevice3 crash pull` or Settings > Privacy > Analytics) for `per-process-limit`. |
| E4 | Are leaf certs from our user-installed CA accepted by Safari and a non-pinning third-party app when traffic goes through the tunnel (mitmproxy #7932)? | Mint an ECDSA P-256 root + 30-day leaves (SAN, serverAuth), install profile, enable full trust, MITM `https://example.com` inside the tunnel; test Safari, a URLSession test app, and a known pinning app (a bank) to validate passthrough. |
| E5 | Does dropping UDP/443 (silent vs ICMP unreachable) make URLSession/Safari fall back to TCP fast enough on iOS 27's modern loader? | Time page loads to an h3-enabled site (Cloudflare) under both policies; also test an ECH-enabled host to confirm SNI is visible. |
| E6 | Does plain-USB install work on iOS 27.0 with both installers, and does the Developer Mode switch appear after the first install without any Mac pairing? | `ideviceinstaller install`, then `pymobiledevice3 apps install`; check Settings > Privacy & Security for the switch; run `pymobiledevice3 amfi developer-mode-status`. |
| E7 | Is the NEProxySettings approach enough (proxy-aware clients only) or is the full userspace TCP path required for real app coverage? | With E1 tunnel: log SNI/host per flow from the packet path for 30 min of normal use; count flows that hit 443 without traversing the proxy. Decide netstack-first (TunnelVision design) vs proxy-first (Knot/Mudmouth design). |
| E8 | If E1 fails: does a cloud Mac signed `.ipa` (development method, UDID in profile) install from Linux and run the tunnel? | One-hour Scaleway/GitHub Actions job, `xcodebuild -exportArchive -exportOptionsPlist` (method development), install via pymobiledevice3. |
| E9 | Exact iPhoneOS.sdk path in xtool 1.20's SDK layout (needed for SDKROOT); Objective-C/C++ targets compiling on Linux against it. | `find` after `xtool setup`; compile one `.m` file with the swift.org clang. |
| E10 | Whether a rented Mac path or NEURLFilter changes the plan if MITM breaks too many apps in practice. | Deferred until E4/E7 data exists. |

---

## 7. Sources

- https://github.com/xtool-org/xtool/releases and /releases/tag/1.20.0, /releases/tag/1.20.1
- https://github.com/xtool-org/xtool/blob/main/Documentation/xtool.docc/Installation-Linux.md
- https://github.com/xtool-org/xtool/blob/main/Documentation/xtool.docc/Appex.md
- https://github.com/xtool-org/xtool/blob/main/Documentation/xtool.docc/Control.md
- https://github.com/xtool-org/xtool/blob/main/Documentation/xtool.docc/First-app.tutorial
- https://github.com/xtool-org/xtool/blob/main/Sources/PackLib/PackSchema.swift
- https://github.com/xtool-org/xtool/blob/main/Sources/PackLib/Packer.swift
- https://github.com/xtool-org/xtool/blob/main/Sources/PackLib/Planner.swift
- https://github.com/xtool-org/xtool/blob/main/Sources/XKit/Model/Entitlements/EntitlementTypes.swift
- https://github.com/xtool-org/xtool/blob/main/Sources/XKit/DeveloperServices/App%20IDs/DeveloperServicesAddAppOperation.swift
- https://github.com/xtool-org/xtool/blob/main/Sources/XKit/DeveloperServices/App%20IDs/Entitlements/DeveloperServicesCapability.swift
- https://github.com/xtool-org/xtool/blob/main/Sources/XKit/DeveloperServices/Profiles/DeveloperServicesFetchProfileOperation.swift
- https://github.com/xtool-org/xtool/issues/44, /issues/130, /issues/131, /issues/138, /issues/269
- https://github.com/xtool-org/xtool/pull/97, /pull/156, /pull/198, /pull/229, /pull/240
- https://github.com/xtool-org/zsign
- https://forums.swift.org/t/xtool-cross-platform-xcode-replacement-build-ios-apps-on-linux-and-more/79803
- https://github.com/nab138/crosscode
- https://github.com/erikbdev/swift-sdk-darwin
- https://developer.apple.com/documentation/xcode-release-notes/xcode-27-release-notes
- https://developer.apple.com/documentation/xcode-release-notes/xcode-26_6-release-notes
- https://developer.apple.com/support/xcode/
- https://support.apple.com/en-us/127255
- https://support.apple.com/en-us/100100
- https://developer.apple.com/forums/thread/829619
- https://github.com/dockur/macos and https://github.com/dockur/macos/issues/572
- https://hub.docker.com/r/dockurr/macos
- https://github.com/kholia/OSX-KVM and https://raw.githubusercontent.com/kholia/OSX-KVM/master/OpenCore-Boot.sh
- https://oneclick-macos-simple-kvm.notaperson535.is-a.dev/docs/guide-phone-passthrough/
- https://github.com/Silfalion/Iphone_docker_osx_passthrough
- https://github.com/orgs/quickemu-project/discussions/1372
- https://www.apple.com/legal/sla/docs/macOSTahoe.pdf
- https://www.apple.com/legal/sla/docs/xcode.pdf
- https://docs.github.com/en/enterprise-cloud@latest/billing/reference/actions-runner-pricing
- https://aws.amazon.com/ec2/instance-types/mac/faqs/
- https://www.scaleway.com/en/pricing/apple-silicon/
- https://developer.apple.com/help/app-store-connect/test-a-beta-version/testflight-overview/
- https://doc.rust-lang.org/rustc/platform-support/apple-ios.html
- https://doc.rust-lang.org/rustc/codegen-options/index.html
- https://github.com/rust-lang/rust/blob/master/compiler/rustc_codegen_ssa/src/back/apple.rs
- https://github.com/rust-lang/rust/pull/139053
- https://github.com/rust-cross/cargo-zigbuild/blob/main/README.md and /issues/310, /pull/432
- https://github.com/kubkon/zig-ios-example
- https://github.com/tpoechtrager/osxcross/blob/master/README.md
- https://docs.rs/objc2/latest/objc2/topics/cross_compiling/index.html
- https://lld.llvm.org/MachO/ld64-vs-lld.html
- https://github.com/brave/adblock-rust and https://docs.rs/adblock/latest/adblock/
- https://github.com/brave/adblock-rust-ffi
- https://github.com/brave/brave-core/blob/master/components/brave_shields/core/common/adblock/rs/Cargo.toml
- https://mozilla.github.io/uniffi-rs/latest/swift/uniffi-bindgen-swift.html
- https://github.com/omjadas/hudsucker
- https://aws.github.io/aws-lc-rs/platform_support.html
- https://github.com/briansmith/ring/blob/main/BUILDING.md
- https://docs.rs/rcgen/latest/rcgen/
- https://github.com/cavivie/netstack-smoltcp
- https://github.com/golang/mobile/blob/master/cmd/gomobile/env.go
- https://github.com/golang/go/blob/master/misc/ios/README
- https://github.com/sagernet/sing-tun
- https://github.com/elazarl/goproxy
- https://github.com/Lojii/Knot (master tree bc722ad8; /commits/master; /blob/master/LocalPackages/TunnelServices/Package.swift; /blob/master/PacketTunnel/PacketTunnelProvider.swift; /blob/master/docs/proxy-architecture.md; /blob/master/Knot.xcodeproj/project.pbxproj; /issues)
- https://github.com/juanmmm21/TunnelVision and /blob/main/docs/BUILDING.md
- https://github.com/zhxie/Mudmouth and https://github.com/qtmleap/Mudmouth
- https://github.com/callmejustdodo/ShortGuard
- https://github.com/SagerNet/sing-box-for-apple
- https://github.com/confirmedcode/Lockdown-iOS
- https://github.com/AdguardTeam/AdguardForiOS and /blob/version/v4.5/AdguardExtension/Tunnel/TunnelProvider.swift
- https://adguard.com/en/adguard-ios-pro/overview.html
- https://adguard.com/kb/adguard-for-ios/solving-problems/system-wide-filtering/
- https://adguard.com/en/blog/apple-url-filter-system-wide-filtering-api.html
- https://github.com/blokadaorg/blokada
- https://github.com/ShubhamDubeyy/NetWraith
- https://github.com/lambret-1/new-vpn
- https://github.com/ProxymanApp/atlantis
- https://github.com/apple/swift-nio-ssl, https://github.com/apple/swift-certificates, https://github.com/apple/swift-nio
- https://github.com/AdguardTeam/urlfilter
- https://github.com/heiher/hev-socks5-tunnel
- https://developer.apple.com/forums/thread/73148 (and ?page=2), /thread/106377, /thread/763586, /thread/763392
- https://github.com/SagerNet/sing-box/issues/3976
- https://support.apple.com/en-us/102390, /102400, /103769, /102028, /103214, /101555, /118254
- https://developer.apple.com/forums/thread/795245, /thread/69037, /thread/764673, /thread/682990, /thread/771945, /thread/808311, /thread/819032, /thread/776139, /thread/786255, /thread/786200, /thread/67613, /thread/725805
- https://github.com/mitmproxy/mitmproxy/issues/7932
- https://github.com/AdguardTeam/HttpsExclusions
- https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers
- https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment
- https://developer.apple.com/documentation/networkextension/packet-tunnel-provider
- https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension
- https://developer.apple.com/help/account/reference/supported-capabilities-ios/
- https://developer.apple.com/documentation/xcode/enabling-developer-mode-on-a-device
- https://github.com/WebKit/standards-positions/issues/46
- https://support.apple.com/en-gb/guide/security/sec100a75d12/web
- https://github.com/libimobiledevice/libimobiledevice/releases/tag/1.4.0 and /issues/1667, /issues/1744
- https://github.com/libimobiledevice/ideviceinstaller/releases and /issues/170, /issues/172
- https://raw.githubusercontent.com/libimobiledevice/libimobiledevice/master/tools/idevicedevmodectl.c
- https://github.com/libimobiledevice/libimobiledevice/blob/master/tools/idevicesyslog.c
- https://pypi.org/project/pymobiledevice3/
- https://doronz88.github.io/pymobiledevice3/guides/ios17-tunnels/, /guides/network-stacks/, /cli/developer/, /cli/syslog/, /cli/mounter/, /cli/apps/
- https://github.com/doronz88/pymobiledevice3/blob/master/misc/understanding_idevice_protocol_layers.md
- https://raw.githubusercontent.com/doronz88/pymobiledevice3/master/pymobiledevice3/services/installation_proxy.py
- https://github.com/doronz88/pymobiledevice3/blob/master/pymobiledevice3/services/amfi.py
- https://github.com/doronz88/pymobiledevice3/issues/796, /issues/1569, /issues/1742, /issues/1966, /pull/1738, /pull/1967
- https://newreleases.io/project/github/doronz88/pymobiledevice3/release/v10.2.3
- https://github.com/jkcoxson/idevice
- https://github.com/davesc63/GeoPort/issues/195
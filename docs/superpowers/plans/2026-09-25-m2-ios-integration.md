# M2: iOS Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The first testable Tollgate: the tunnel runs the Rust core (DNS blocking, DNS over HTTPS, HTTPS filtering through the local proxy), and the app downloads and compiles filter lists, installs the root certificate, and shows protection status and activity.

**Architecture:** The app and the tunnel share `<App Group>/core/`, the Rust core's data directory. The app writes `config.json`, compiles lists into `engine.dat` and `domains.bin` with `compileLists`, and creates the CA with `generateCa`. The tunnel creates `Engine(configJson:dataDir:)`, starts it with a `PacketSink` wrapping the packet flow, routes only the tunnel DNS addresses, and sets system proxy settings to the core's port when `engine.mitmActive()` is true. The app talks to the tunnel through `sendProviderMessage` (`stats`, `reload-lists`, `ping`, `probe-memory`).

**Tech Stack:** Swift 5 language mode with complete concurrency checking, SwiftUI, NetworkExtension, Network (`NWListener`), Security (`SecTrust`), uniffi bindings from M1d.

**Spec:** `docs/superpowers/specs/2026-09-24-tollgate-design.md` (sections "Swift shell", "Data flow", "Revisions after the M1 prototypes", "M1 crate contracts").

## Global Constraints

- No em-dashes in committed text; no `Co-Authored-By` lines.
- Identifiers only from `tooling/config.env`; Swift reads the App Group from the `TollgateAppGroup` Info.plist key.
- Logging subsystems: `dev.tollgate.tunnel`, `dev.tollgate.app`, and `dev.tollgate.core` for records forwarded from Rust.
- `stopTunnel` always calls `engine.stop()`; `FlowSink` holds only the `NEPacketTunnelFlow`.
- HTTPS filtering defaults to off in `config.json` and is only offered after the CA exists.

## Decisions

- **Proxy settings only when interception is possible.** `engine.mitmActive()` is true only with `mitm_enabled`, a CA and `engine.dat`; otherwise the tunnel sets DNS only, so a missing certificate never breaks browsing.
- **Lists are downloaded by the app at first launch** (and on "Update"), not bundled: the lists carry their own licenses and change daily. Without network at first launch the tunnel still runs, DNS-only without a blocklist.
- **Defaults:** EasyList, EasyPrivacy and AdGuard Mobile Ads into the request engine; the AdGuard DNS filter into the DNS blocklist, matching the M1a measurement that keeps the DNS filter out of `engine.dat`.
- **Profile install:** a loopback `NWListener` serves the `.mobileconfig` with `application/x-apple-aspen-config` and Safari opens it (Safari is the only way iOS accepts a profile download); a share-sheet copy is the fallback. A background task keeps the server alive for 60 s.
- **Trust check:** a throwaway leaf issued by the stored CA (`caTestLeaf`, a small M1d addition) is evaluated with `SecPolicyCreateSSL`, the same judgement Safari makes. A basic X.509 check was rejected in review: a profile-installed root passes it before full trust is enabled. The app runs the check off the main thread; the tunnel runs it on every start and falls back to DNS-only when HTTPS filtering is on but the root is not trusted.
- **HTTPS filtering safety:** the toggle can only be turned on with a trusted root and compiled lists, is forced off when trust disappears, clears learned pins when enabled, and after enabling the app makes an HTTPS request through the proxy; a certificate error turns filtering off again with an explanation.
- **Configuration freshness:** the app re-reads the VPN configuration before every change and on `NEVPNConfigurationChange`, because Settings edits it (turning the VPN off there disables Connect On Demand). The configuration is only created when the user turns protection on, so the system prompt never appears at launch.
- **Lists after start:** the core decides HTTPS filtering when the engine is created, so after a list update the app restarts a tunnel that should be filtering but is not, or that was still starting; otherwise it reloads the lists in place. Missing lists are retried when the tunnel connects and when the app returns to the foreground.
- **Before first unlock:** an on-demand start after a reboot cannot read the shared files yet. The tunnel comes up without DNS redirection and starts the core once the files are readable.
- **Always on:** starting protection enables an `NEOnDemandRuleConnect` rule so iOS reconnects after network changes and restarts; turning it off disables on-demand first.

## File map

```
ios/Shared/AppGroup.swift          + coreDirectory
ios/Shared/CoreConfig.swift        config.json (mitm_enabled)
ios/Shared/CoreLogBridge.swift     CoreLogger -> os.Logger
ios/Shared/FilterLists.swift       default list sources, compiled check
ios/Shared/TunnelCommand.swift     + stats, reload-lists
ios/Shared/TunnelStats.swift       stats JSON between tunnel and app
ios/Tunnel/PacketTunnelProvider.swift  Engine lifecycle, network settings, packet loop, FlowSink
ios/App/TunnelController.swift     on-demand start/stop, restart, stats, reload
ios/App/ListUpdater.swift          download + compileLists
ios/App/CertificateManager.swift   generateCa, profile install, trust check
ios/App/ProfileServer.swift        loopback HTTP server for the profile
ios/App/ContentView.swift          protection, setup, activity, diagnostics
ios/App/TollgateApp.swift          environment objects, Rust logger
docs/experiments/m2.md             on-device test checklist
```

### Task 1: Shared types

- [ ] Add `CoreConfig`, `CoreLogBridge`, `FilterLists`, `TunnelStats`; extend `AppGroup` and `TunnelCommand`.
- [ ] Verify: the unsigned `ios` CI compile passes.

### Task 2: Tunnel runs the engine

- [ ] Rewrite `PacketTunnelProvider`: logger, `Engine(configJson:dataDir:)`, `start(sink: FlowSink)`, network settings (IPv4 `198.18.0.2/32` routing `198.18.0.1/32`, IPv6 `fd00:7467::2/128` routing `fd00:7467::1/128`, DNS servers on both with `matchDomains = [""]`, proxy settings to `127.0.0.1:<port>` when `mitmActive()`), packet loop through `handlePackets`, `stats` and `reload-lists` messages, `engine.stop()` in `stopTunnel`.
- [ ] Verify: CI compile; on device, E8 in `docs/experiments/m2.md`.

### Task 3: App setup flow

- [ ] `TunnelController` with on-demand, restart and stats; `ListUpdater`; `CertificateManager` with `ProfileServer`; new `ContentView`.
- [ ] Verify: CI compile and signed build; on device, E9 to E12.

### Task 4: Signed build for testing

- [ ] Dispatch `ios.yml` on the branch; confirm the `Tollgate-ipa` artifact and the app icon check.

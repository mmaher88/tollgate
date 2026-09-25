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
   cat > ~/.config/tollgate/asc.env <<EOF
   ASC_KEY_ID="XXXX"
   ASC_ISSUER_ID="your-issuer-id"
   ASC_KEY_PATH="~/.config/tollgate/AuthKey_XXXX.p8"
   EOF
   tooling/asc/provision.py setup
   ```

   The tool reads `~/.config/tollgate/asc.env` for any of the three variables not set in the
   environment.

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

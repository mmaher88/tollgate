#!/usr/bin/env bash
# Builds the Rust core as a static library and generates the Swift bindings the Xcode
# project compiles against.
#
#   build-core-ios.sh          aarch64-apple-ios release build into ios/Generated (macOS CI)
#   build-core-ios.sh --host   host build, bindings only into build/bindings-host (Linux check)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CORE="$ROOT/core"
MODE="${1:-ios}"

bindgen() {
    local lib="$1" out="$2"
    rm -rf "$out"
    mkdir -p "$out/Swift" "$out/TollgateFFI"
    (cd "$CORE" && cargo run --quiet -p uniffi-bindgen-swift -- "$lib" "$out/Swift" --swift-sources)
    (cd "$CORE" && cargo run --quiet -p uniffi-bindgen-swift -- "$lib" "$out/TollgateFFI" --headers)
    # The modulemap must declare the C module name the generated Swift imports; uniffi
    # defaults it to the crate name, which does not match.
    local ffi_module
    ffi_module="$(sed -n 's/^#if canImport(\(.*\))$/\1/p' "$out/Swift/tollgate_ffi.swift" | head -n 1)"
    [ -n "$ffi_module" ] || { echo "could not find the FFI module name in tollgate_ffi.swift" >&2; exit 1; }
    (cd "$CORE" && cargo run --quiet -p uniffi-bindgen-swift -- "$lib" "$out/TollgateFFI" \
        --modulemap --module-name "$ffi_module" --modulemap-filename module.modulemap)
    grep -q "^module $ffi_module " "$out/TollgateFFI/module.modulemap"
}

case "$MODE" in
    --host)
        (cd "$CORE" && cargo build --release -p tollgate-ffi)
        bindgen "$CORE/target/release/libtollgate_ffi.a" "$ROOT/build/bindings-host"
        ls -R "$ROOT/build/bindings-host"
        ;;
    ios)
        export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-17.0}"
        TARGET=aarch64-apple-ios
        (cd "$CORE" && cargo build --release -p tollgate-ffi --target "$TARGET")
        LIB="$CORE/target/$TARGET/release/libtollgate_ffi.a"
        OUT="$ROOT/ios/Generated"
        bindgen "$LIB" "$OUT"
        mkdir -p "$OUT/lib"
        cp "$LIB" "$OUT/lib/"
        ls -R "$OUT"
        ;;
    *)
        echo "usage: $0 [--host]" >&2
        exit 2
        ;;
esac

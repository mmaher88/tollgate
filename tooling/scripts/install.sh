#!/usr/bin/env bash
# Installs the downloaded .ipa on the USB-connected iPhone.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
IPA="${1:-build/ipa/Tollgate.ipa}"
[ -f "$IPA" ] || { echo "no $IPA; run tooling/scripts/fetch-ipa.sh" >&2; exit 1; }
INFO="$(dirname "$IPA")/BUILD_INFO"
if [ -f "$INFO" ]; then
    echo "Installing:"
    cat "$INFO"
fi
tooling/scripts/device.sh apps install "$IPA"
tooling/scripts/device.sh amfi developer-mode-status || true

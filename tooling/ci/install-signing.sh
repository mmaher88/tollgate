#!/usr/bin/env bash
# Imports the development certificate into a temporary keychain and installs the
# provisioning profiles. Runs on the macOS CI runner only.
set -euo pipefail

: "${DEV_CERT_P12_BASE64:?}" "${DEV_CERT_P12_PASSWORD:?}" "${APP_PROFILE_BASE64:?}" "${TUNNEL_PROFILE_BASE64:?}" "${RUNNER_TEMP:?}"

KEYCHAIN="$RUNNER_TEMP/tollgate-signing.keychain-db"
KEYCHAIN_PASSWORD="$(uuidgen)"

echo "$DEV_CERT_P12_BASE64" | base64 --decode > "$RUNNER_TEMP/dev-cert.p12"
curl -fsSL -o "$RUNNER_TEMP/AppleWWDRCAG3.cer" https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer

security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security import "$RUNNER_TEMP/AppleWWDRCAG3.cer" -k "$KEYCHAIN" -t cert -f x509 -A || true
security import "$RUNNER_TEMP/dev-cert.p12" -k "$KEYCHAIN" -P "$DEV_CERT_P12_PASSWORD" -f pkcs12 -A \
    -T /usr/bin/codesign -T /usr/bin/security
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN" > /dev/null
# Put the temporary keychain first in the search list, keep the existing ones.
# shellcheck disable=SC2046
security list-keychains -d user -s "$KEYCHAIN" $(security list-keychains -d user | tr -d '"')
security find-identity -v -p codesigning "$KEYCHAIN"

install_profile() {
    local data="$1" tmp uuid
    tmp="$(mktemp)"
    echo "$data" | base64 --decode > "$tmp"
    uuid="$(security cms -D -i "$tmp" | plutil -extract UUID raw -o - -)"
    for dir in "$HOME/Library/MobileDevice/Provisioning Profiles" \
               "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"; do
        mkdir -p "$dir"
        cp "$tmp" "$dir/$uuid.mobileprovision"
    done
    echo "installed profile $uuid"
}
install_profile "$APP_PROFILE_BASE64"
install_profile "$TUNNEL_PROFILE_BASE64"

echo "SIGNING_KEYCHAIN=$KEYCHAIN" >> "$GITHUB_ENV"

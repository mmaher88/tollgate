#!/usr/bin/env bash
# Exports a development-signed .ipa from the archive. Expects tooling/config.env exported
# and TEAM_ID set.
set -euo pipefail

: "${TEAM_ID:?}" "${TOLLGATE_BUNDLE_ID:?}" "${TOLLGATE_TUNNEL_BUNDLE_ID:?}" \
  "${TOLLGATE_APP_PROFILE:?}" "${TOLLGATE_TUNNEL_PROFILE:?}" "${RUNNER_TEMP:?}"

ARCHIVE="${1:-build/Tollgate.xcarchive}"
EXPORT_DIR="${2:-build/export}"
PLIST="$RUNNER_TEMP/ExportOptions.plist"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>debugging</string>
    <key>signingStyle</key>
    <string>manual</string>
    <key>teamID</key>
    <string>${TEAM_ID}</string>
    <key>signingCertificate</key>
    <string>Apple Development</string>
    <key>provisioningProfiles</key>
    <dict>
        <key>${TOLLGATE_BUNDLE_ID}</key>
        <string>${TOLLGATE_APP_PROFILE}</string>
        <key>${TOLLGATE_TUNNEL_BUNDLE_ID}</key>
        <string>${TOLLGATE_TUNNEL_PROFILE}</string>
    </dict>
    <key>thinning</key>
    <string>&lt;none&gt;</string>
</dict>
</plist>
EOF

xcodebuild -exportArchive -archivePath "$ARCHIVE" -exportPath "$EXPORT_DIR" -exportOptionsPlist "$PLIST"
ls -la "$EXPORT_DIR"

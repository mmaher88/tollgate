#!/usr/bin/env bash
# Fails when the built app has no compiled app icon. A misconfigured AppIcon.icon does not
# fail the build; it silently produces an app without an icon.
set -euo pipefail

APP="${1:?usage: check-app-icon.sh path/to/Tollgate.app}"

[ -f "$APP/Assets.car" ] || { echo "error: $APP/Assets.car is missing" >&2; exit 1; }

icon_name="$(plutil -extract CFBundleIcons.CFBundlePrimaryIcon.CFBundleIconName raw -o - "$APP/Info.plist" 2>/dev/null \
    || plutil -extract CFBundleIconName raw -o - "$APP/Info.plist" 2>/dev/null || true)"
[ "$icon_name" = "AppIcon" ] || { echo "error: CFBundleIconName is '$icon_name', expected AppIcon" >&2; exit 1; }

# Flat fallback images for iOS versions before 26.
compgen -G "$APP/AppIcon60x60@2x*.png" > /dev/null || { echo "error: no AppIcon60x60@2x fallback in $APP" >&2; exit 1; }

echo "app icon ok: CFBundleIconName=$icon_name"
for f in "$APP"/Assets.car "$APP"/AppIcon*; do
    [ -e "$f" ] && echo "  ${f##*/}"
done

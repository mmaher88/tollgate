#!/usr/bin/env bash
# Owner-run: copies the signing assets from tooling/asc/out into the GitHub repo secrets.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
# shellcheck source=../config.env
source tooling/config.env
OUT=tooling/asc/out

for f in dev-cert.p12 dev-cert.password app.mobileprovision tunnel.mobileprovision team-id; do
    [ -s "$OUT/$f" ] || { echo "missing $OUT/$f; run provision.py setup first" >&2; exit 1; }
done

base64 -w0 "$OUT/dev-cert.p12" | gh secret set DEV_CERT_P12_BASE64 --repo "$TOLLGATE_REPO"
gh secret set DEV_CERT_P12_PASSWORD --repo "$TOLLGATE_REPO" < "$OUT/dev-cert.password"
base64 -w0 "$OUT/app.mobileprovision" | gh secret set APP_PROFILE_BASE64 --repo "$TOLLGATE_REPO"
base64 -w0 "$OUT/tunnel.mobileprovision" | gh secret set TUNNEL_PROFILE_BASE64 --repo "$TOLLGATE_REPO"
gh variable set TEAM_ID --repo "$TOLLGATE_REPO" --body "$(cat "$OUT/team-id")"
echo "secrets updated for $TOLLGATE_REPO"

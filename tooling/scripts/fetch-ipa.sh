#!/usr/bin/env bash
# Downloads the .ipa from the latest successful `ios` workflow run on a branch (default main).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
# shellcheck source=SCRIPTDIR/../config.env
source tooling/config.env
BRANCH="${1:-main}"
RUN_ID="$(gh run list --repo "$TOLLGATE_REPO" --workflow ios.yml --branch "$BRANCH" --status success \
    --limit 1 --json databaseId --jq '.[0].databaseId')"
[ -n "$RUN_ID" ] || { echo "no successful ios run on $BRANCH" >&2; exit 1; }
rm -rf build/ipa
gh run download "$RUN_ID" --repo "$TOLLGATE_REPO" --name Tollgate-ipa --dir build/ipa
ls -la build/ipa

#!/usr/bin/env bash
# Downloads the .ipa built by the `ios` workflow for the tip of a branch (default main).
#
#   tooling/scripts/fetch-ipa.sh [--allow-stale] [branch]
#
# Fails when the tip has no finished, successful run: start one with
#   gh workflow run ios.yml --repo <repo> --ref <branch>
# With --allow-stale (or ALLOW_STALE=1) it falls back to the newest successful run on the
# branch and says how many commits that build is behind the tip.
# The chosen run is printed and written to build/ipa/BUILD_INFO; install.sh prints it again.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
# shellcheck source=SCRIPTDIR/../config.env
source tooling/config.env

ALLOW_STALE="${ALLOW_STALE:-0}"
BRANCH=main
for arg in "$@"; do
    case "$arg" in
        --allow-stale) ALLOW_STALE=1 ;;
        -*) echo "usage: $0 [--allow-stale] [branch]" >&2; exit 2 ;;
        *) BRANCH="$arg" ;;
    esac
done

TIP="$(gh api "repos/$TOLLGATE_REPO/branches/$BRANCH" --jq .commit.sha)"
[ -n "$TIP" ] || { echo "branch $BRANCH not found on $TOLLGATE_REPO" >&2; exit 1; }

# Newest first, "|"-separated (tab would collapse the empty conclusion of a running build):
# id, headSha, status, conclusion, createdAt, event, url.
RUNS="$(gh run list --repo "$TOLLGATE_REPO" --workflow ios.yml --branch "$BRANCH" --limit 20 \
    --json databaseId,headSha,status,conclusion,createdAt,event,url \
    --jq '.[] | [.databaseId, .headSha, .status, .conclusion, .createdAt, .event, .url]
        | map(tostring) | join("|")')"

pick() { # prints the first run line matching the awk condition $1
    printf '%s\n' "$RUNS" | awk -F'|' "$1 { print; exit }"
}

RUN="$(pick "\$2 == \"$TIP\" && \$3 == \"completed\" && \$4 == \"success\"")"
if [ -z "$RUN" ]; then
    LATEST="$(pick "\$2 == \"$TIP\"")"
    if [ -z "$LATEST" ]; then
        problem="tip $TIP of $BRANCH not built; run: gh workflow run ios.yml --repo $TOLLGATE_REPO --ref $BRANCH"
    else
        IFS='|' read -r _ _ status conclusion _ _ url <<<"$LATEST"
        if [ "$status" != completed ]; then
            problem="build still running for tip $TIP ($status): $url"
        else
            problem="build failed or was cancelled for tip $TIP ($conclusion): $url"
        fi
    fi
    if [ "$ALLOW_STALE" != 1 ]; then
        echo "$problem" >&2
        echo "(--allow-stale installs the newest successful build instead)" >&2
        exit 1
    fi
    RUN="$(pick '$3 == "completed" && $4 == "success"')"
    [ -n "$RUN" ] || { echo "$problem; and no successful ios run on $BRANCH" >&2; exit 1; }
fi

IFS='|' read -r RUN_ID SHA _ _ CREATED EVENT URL <<<"$RUN"
if [ "$SHA" != "$TIP" ]; then
    BEHIND="$(gh api "repos/$TOLLGATE_REPO/compare/$SHA...$TIP" --jq .ahead_by 2>/dev/null || echo "?")"
    echo "WARNING: STALE BUILD. It is $BEHIND commits behind the tip of $BRANCH ($TIP)." >&2
    echo "WARNING: fixes after ${SHA:0:7} are not in it. $problem" >&2
fi

rm -rf build/ipa
gh run download "$RUN_ID" --repo "$TOLLGATE_REPO" --name Tollgate-ipa --dir build/ipa
{
    echo "branch:  $BRANCH"
    echo "run:     $RUN_ID"
    echo "url:     $URL"
    echo "commit:  $SHA"
    echo "event:   $EVENT"
    echo "created: $CREATED"
    [ "$SHA" = "$TIP" ] || echo "STALE:   $BEHIND commits behind $TIP"
} >build/ipa/BUILD_INFO
ls -la build/ipa
cat build/ipa/BUILD_INFO

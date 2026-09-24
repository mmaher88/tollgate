#!/usr/bin/env bash
# Streams Tollgate log lines (app and tunnel) from the phone.
#   logs.sh            both processes
#   logs.sh tunnel     tunnel only
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
case "${1:-all}" in
    tunnel) exec tooling/scripts/device.sh syslog live --label -pn TollgateTunnel ;;
    app)    exec tooling/scripts/device.sh syslog live --label -pn Tollgate ;;
    *)      exec tooling/scripts/device.sh syslog live --label -e 'dev\.tollgate\.' ;;
esac

#!/usr/bin/env bash
# Pinned pymobiledevice3, run through uv so nothing is installed globally.
set -euo pipefail
exec uvx --from 'pymobiledevice3==11.19.1' pymobiledevice3 "$@"

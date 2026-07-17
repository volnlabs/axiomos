#!/usr/bin/env bash
set -euo pipefail
exec "$(dirname "$0")/deploy/rpi5.sh" "$@"

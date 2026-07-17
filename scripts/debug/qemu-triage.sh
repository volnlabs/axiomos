#!/usr/bin/env bash
set -euo pipefail
exec "$(dirname "$0")/../qemu-debug-triage.sh" "$@"

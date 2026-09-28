#!/usr/bin/env bash
set -euo pipefail

mkdir -p /app/data/results
printf 'ready' >/tmp/botnet.ready
exec tail -f /dev/null

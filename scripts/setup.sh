#!/usr/bin/env bash
set -euo pipefail

docker --version >/dev/null || { echo "Docker is required." >&2; exit 1; }
docker compose version >/dev/null || { echo "Docker Compose plugin is required." >&2; exit 1; }
if ! id -nG "${USER}" | tr ' ' '\n' | grep -qx docker; then
  echo "You are not in the docker group. Run: sudo usermod -aG docker \$USER && newgrp docker"
fi
python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10 or newer is required.")
print(f"Python {sys.version_info.major}.{sys.version_info.minor} detected")
PY

mkdir -p data/pcap/snapshots/normal data/pcap/snapshots/attack data/features data/results ids/models
[[ -f data/results/metrics.json ]] || printf '%s\n' '{"accuracy":0,"f1":0,"fpr":0,"latency":0,"status":"not_run_yet"}' > data/results/metrics.json
[[ -f data/results/alerts.json ]] || printf '%s\n' '[]' > data/results/alerts.json
[[ -f data/results/attack_log.json ]] || printf '%s\n' '[]' > data/results/attack_log.json
chmod +x scripts/*.sh mininet/entrypoint.sh botnet/entrypoint.sh
echo "Setup complete. Run: make up"

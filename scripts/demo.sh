#!/usr/bin/env bash
# Quick end-to-end demo: start the testbed, run one automated experiment,
# then print where the result files landed. Works on any Linux box with
# Docker + the Compose plugin.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Building and starting the testbed..."
docker compose up --build -d

echo "==> Waiting for Redis to be ready..."
until docker compose exec -T redis redis-cli ping >/dev/null 2>&1; do sleep 1; done

echo "==> Dashboard is live at http://localhost:8080"
echo "==> Triggering the automated experiment (baseline -> train -> attack -> evaluate)..."
docker compose exec -T redis redis-cli set control:run_experiment 1 >/dev/null

echo "==> The pipeline runs for ~2-3 minutes. Watch progress on the dashboard."
echo "    When it finishes, result files appear in ./data/:"
echo "      topology.json  attack_log.csv  alerts.json  metrics.json  testbed_comparison.csv"
echo ""
echo "    Follow logs with:   docker compose logs -f ids orchestrator"
echo "    Stop everything:    docker compose down"

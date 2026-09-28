#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

NORMAL_WAIT_SECONDS="${CAPTURE_DURATION:-60}"
ATTACK_WAIT_SECONDS="${ATTACK_DURATION:-60}"
ATTACK_TYPE="${ATTACK_TYPE:-syn_flood}"
TARGET_IP="${TARGET_IP:-10.0.0.100}"
PACKET_RATE="${PACKET_RATE:-1000}"

mkdir -p data/pcap/snapshots/normal data/pcap/snapshots/attack data/features data/results

docker compose up -d --build

echo "Waiting for dashboard health..."
until docker compose exec -T dashboard curl -fsS http://localhost:5000/api/health >/dev/null 2>&1; do
  sleep 5
done

echo "Collecting normal traffic for ${NORMAL_WAIT_SECONDS}s..."
sleep "${NORMAL_WAIT_SECONDS}"

docker compose exec -T mininet bash -lc 'cp /app/data/pcap/*.pcap /app/data/pcap/snapshots/normal/ 2>/dev/null || true'

echo "Training IDS on normal traffic snapshot..."
docker compose exec -T ids python /app/ids/train.py --input /app/data/pcap/snapshots/normal --model /app/ids/models/if_model.pkl

echo "Launching attack ${ATTACK_TYPE} against ${TARGET_IP}..."
docker compose exec -T botnet python /app/botnet/mirai_sim.py --attack-only \
  --cidr "10.0.0.0/24" \
  >/tmp/botnet_attack.log 2>&1 &
ATTACK_PID=$!

echo "Waiting for attack window ${ATTACK_WAIT_SECONDS}s..."
sleep "${ATTACK_WAIT_SECONDS}"
wait "${ATTACK_PID}" || true

docker compose exec -T mininet bash -lc 'cp /app/data/pcap/*.pcap /app/data/pcap/snapshots/attack/ 2>/dev/null || true'

echo "Building labeled evaluation dataset..."
docker compose exec -T ids python - <<'PY'
from pathlib import Path
import pandas as pd
from feature_extractor import extract_features_from_directory, save_features

normal_dir = Path('/app/data/pcap/snapshots/normal')
attack_dir = Path('/app/data/pcap/snapshots/attack')
normal_csv = Path('/app/data/features/normal.csv')
attack_csv = Path('/app/data/features/attack.csv')
eval_csv = Path('/app/data/features/evaluation.csv')
normal_features = extract_features_from_directory(normal_dir)
attack_features = extract_features_from_directory(attack_dir)
save_features(normal_features, normal_csv, label=0)
save_features(attack_features, attack_csv, label=1)
frame = pd.concat([pd.read_csv(normal_csv), pd.read_csv(attack_csv)], ignore_index=True)
frame.to_csv(eval_csv, index=False)
print(eval_csv)
PY

echo "Evaluating IDS..."
docker compose exec -T ids python /app/ids/evaluate.py --features /app/data/features/evaluation.csv --output /app/data/results/metrics.json

echo "Generating comparison artifacts..."
docker compose exec -T dashboard python /app/evaluation/compare_testbeds.py --metrics /app/data/results/metrics.json --output-dir /app/data/results

echo "Generating final summary..."
docker compose exec -T dashboard python - <<'PY'
from pathlib import Path
import json

results_dir = Path('/app/data/results')
summary_path = results_dir / 'experiment_summary.json'
metrics = json.loads((results_dir / 'metrics.json').read_text(encoding='utf-8')) if (results_dir / 'metrics.json').exists() else {}
comparison = []
comparison_csv = results_dir / 'testbed_comparison.csv'
if comparison_csv.exists():
    comparison = comparison_csv.read_text(encoding='utf-8').splitlines()[:5]
summary = {
    'metrics': metrics,
    'comparison_preview': comparison,
}
summary_path.write_text(json.dumps(summary, indent=2), encoding='utf-8')
print(summary_path)
PY

echo "Experiment pipeline complete. Results are in data/results/."

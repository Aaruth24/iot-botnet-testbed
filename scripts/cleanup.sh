#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
docker compose down -v --remove-orphans
docker system prune -f
rm -rf data/pcap/* data/features/* data/results/*
echo "Cleaned up all containers, volumes and data"

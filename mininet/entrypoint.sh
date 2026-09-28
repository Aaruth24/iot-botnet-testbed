#!/usr/bin/env bash
set -euo pipefail

mkdir -p /app/data/pcap /app/data/results
exec python /app/mininet/topology.py --serve

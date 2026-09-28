#!/usr/bin/env bash
set -euo pipefail

mkdir -p /app/data/pcap /app/data/results
/etc/init.d/openvswitch-switch start
exec python /app/mininet/topology.py --serve

"""
Shared helpers for the Docker-based Virtual IoT Security Testbed.

IMPORTANT (scope / safety):
This project is a *defensive security research testbed*. Every component
runs inside an isolated Docker bridge network. The "attack simulator"
synthesises the NETWORK-FLOW SIGNATURES of common IoT attacks (port scan,
SYN flood, MQTT connection flood) so that an anomaly-based Intrusion
Detection System can be trained and evaluated against a known ground truth.

There is deliberately NO real exploit code, NO self-propagating malware,
NO scanning of external/real hosts, and NO credential attacks anywhere in
this repository. It reproduces *traffic statistics*, which is exactly what
IDS benchmark datasets (BoT-IoT, N-BaIoT, IoT-23, CICIoT2023) are built
from. Keep it that way.
"""

from __future__ import annotations

import json
import os
import time
import math
from typing import Any

import redis


# --------------------------------------------------------------------------
# Connection
# --------------------------------------------------------------------------
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))


def get_redis() -> "redis.Redis":
    """Return a decode-enabled Redis client (strings, not bytes)."""
    return redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True,
        socket_connect_timeout=5,
        health_check_interval=30,
    )


def wait_for_redis(r: "redis.Redis", tries: int = 60, delay: float = 1.0) -> None:
    """Block until Redis answers a PING (used during container start-up)."""
    for _ in range(tries):
        try:
            if r.ping():
                return
        except redis.exceptions.RedisError:
            pass
        time.sleep(delay)
    raise RuntimeError("Redis did not become ready in time")


# --------------------------------------------------------------------------
# Redis key / stream names (single source of truth for every service)
# --------------------------------------------------------------------------
FLOW_STREAM = "stream:flows"        # every network flow record (benign + attack)
ALERT_STREAM = "stream:alerts"      # IDS alerts
LOG_STREAM = "stream:events"        # human-readable event log for the dashboard

K_CONTROL_ATTACK = "control:attack"     # JSON: desired attack state (set by UI/orchestrator)
K_IDS_MODE = "control:ids_mode"         # "idle" | "training" | "detecting"
K_MODEL_READY = "model:ready"           # "1" once the IDS has a trained model
K_METRICS = "metrics:latest"            # JSON: live confusion-matrix + scores
K_TOPOLOGY = "state:topology"           # JSON: device inventory for the dashboard
K_EXPERIMENT = "state:experiment"       # JSON: orchestrator progress
K_COMPARISON = "state:comparison"       # JSON: testbed comparison table

ATTACK_TYPES = ["scan", "syn_flood", "mqtt_flood", "dos_udp"]


# --------------------------------------------------------------------------
# Flow record schema
# --------------------------------------------------------------------------
def make_flow(
    src: str,
    dst: str,
    dst_port: int,
    proto: str,
    packets: int,
    n_bytes: int,
    duration: float,
    device_type: str = "unknown",
    label: str = "normal",
    attack_type: str | None = None,
    src_port: int | None = None,
) -> dict[str, Any]:
    """Build one network-flow record. `label` is the ground truth used only
    for offline scoring of the IDS; the IDS itself never sees it at inference."""
    duration = max(duration, 1e-3)
    return {
        "ts": round(time.time(), 3),
        "src": src,
        "dst": dst,
        "src_port": src_port if src_port is not None else 0,
        "dst_port": int(dst_port),
        "proto": proto,
        "packets": int(packets),
        "bytes": int(n_bytes),
        "duration": round(duration, 4),
        "pkt_rate": round(packets / duration, 3),
        "byte_rate": round(n_bytes / duration, 3),
        "avg_pkt_size": round(n_bytes / max(packets, 1), 3),
        "device_type": device_type,
        "label": label,                 # ground truth: "normal" | "attack"
        "attack_type": attack_type or "",
    }


def publish_flow(r: "redis.Redis", flow: dict[str, Any], maxlen: int = 20000) -> None:
    r.xadd(FLOW_STREAM, {"data": json.dumps(flow)}, maxlen=maxlen, approximate=True)
    r.incr("stats:flows_total")
    r.incr("stats:flows_attack" if flow["label"] == "attack" else "stats:flows_normal")


def log_event(r: "redis.Redis", level: str, source: str, message: str) -> None:
    evt = {"ts": round(time.time(), 3), "level": level, "source": source, "message": message}
    r.xadd(LOG_STREAM, {"data": json.dumps(evt)}, maxlen=500, approximate=True)


# --------------------------------------------------------------------------
# Feature engineering (shared so training & inference always match)
# --------------------------------------------------------------------------
PROTO_MAP = {"TCP": 6, "UDP": 17, "ICMP": 1, "MQTT": 6}

# The IDS appends two rolling, source-based context features that it computes
# itself; these base features come straight from the flow record.
BASE_FEATURES = [
    "bytes",
    "packets",
    "duration",
    "pkt_rate",
    "byte_rate",
    "avg_pkt_size",
    "dst_port",
    "proto_num",
]
CONTEXT_FEATURES = ["distinct_dports_src", "flows_from_src"]
FEATURES = BASE_FEATURES + CONTEXT_FEATURES


def base_feature_vector(flow: dict[str, Any]) -> list[float]:
    return [
        math.log1p(flow["bytes"]),
        math.log1p(flow["packets"]),
        flow["duration"],
        math.log1p(flow["pkt_rate"]),
        math.log1p(flow["byte_rate"]),
        flow["avg_pkt_size"],
        flow["dst_port"],
        float(PROTO_MAP.get(flow["proto"], 0)),
    ]

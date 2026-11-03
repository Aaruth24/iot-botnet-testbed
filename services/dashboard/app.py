"""
Web dashboard (Flask REST API + single-page UI).

Serves a live view of the testbed: network topology, flow throughput,
IDS alerts, the confusion matrix, headline detection metrics and the
testbed comparison table. It also exposes controls to launch/stop attack
traffic, (re)train the IDS and run the full automated experiment.

All state is read from Redis, which every other service writes to, so the
dashboard holds no logic of its own beyond presentation.
"""

from __future__ import annotations

import json
import sys
import time

from flask import Flask, jsonify, render_template, request

sys.path.insert(0, "/app/common")
from testbed import (  # noqa: E402
    get_redis,
    wait_for_redis,
    log_event,
    FLOW_STREAM,
    ALERT_STREAM,
    LOG_STREAM,
    K_CONTROL_ATTACK,
    K_IDS_MODE,
    K_MODEL_READY,
    K_METRICS,
    K_EXPERIMENT,
    K_COMPARISON,
    ATTACK_TYPES,
)

app = Flask(__name__)
r = get_redis()
wait_for_redis(r)


def _recent_stream(stream: str, count: int) -> list[dict]:
    rows = r.xrevrange(stream, count=count)
    out = []
    for _, fields in rows:
        try:
            out.append(json.loads(fields["data"]))
        except (KeyError, json.JSONDecodeError):
            continue
    return out


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    return jsonify({
        "ids_mode": r.get(K_IDS_MODE) or "idle",
        "model_ready": r.get(K_MODEL_READY) == "1",
        "attack": json.loads(r.get(K_CONTROL_ATTACK) or '{"active": false}'),
        "experiment": json.loads(r.get(K_EXPERIMENT) or "{}"),
        "flows_total": int(r.get("stats:flows_total") or 0),
        "flows_normal": int(r.get("stats:flows_normal") or 0),
        "flows_attack": int(r.get("stats:flows_attack") or 0),
        "attack_types": ATTACK_TYPES,
        "server_ts": round(time.time(), 2),
    })


@app.route("/api/metrics")
def api_metrics():
    return jsonify(json.loads(r.get(K_METRICS) or "{}"))


@app.route("/api/topology")
def api_topology():
    devices = r.hgetall("inventory:devices") or {}
    nodes = [{"id": "mosquitto", "type": "broker", "ip": "10.10.0.2"}]
    edges = []
    for dev_id, meta in devices.items():
        dtype, _, ip = meta.partition("|")
        nodes.append({"id": dev_id, "type": dtype, "ip": ip})
        edges.append({"from": dev_id, "to": "mosquitto",
                      "attack": dtype == "attacker"})
    return jsonify({"nodes": nodes, "edges": edges})


@app.route("/api/flows")
def api_flows():
    return jsonify(_recent_stream(FLOW_STREAM, int(request.args.get("n", 40))))


@app.route("/api/alerts")
def api_alerts():
    return jsonify(_recent_stream(ALERT_STREAM, int(request.args.get("n", 40))))


@app.route("/api/events")
def api_events():
    return jsonify(_recent_stream(LOG_STREAM, int(request.args.get("n", 30))))


@app.route("/api/comparison")
def api_comparison():
    return jsonify(json.loads(r.get(K_COMPARISON) or "[]"))


# --------------------------------------------------------------------------
# Controls
# --------------------------------------------------------------------------
@app.route("/api/attack/start", methods=["POST"])
def api_attack_start():
    body = request.get_json(silent=True) or {}
    atype = body.get("type", "scan")
    intensity = float(body.get("intensity", 2.0))
    duration = float(body.get("duration", 0))
    r.set(K_CONTROL_ATTACK, json.dumps({
        "active": True, "type": atype, "intensity": intensity,
        "duration": duration, "started": time.time(),
    }))
    log_event(r, "attack", "dashboard", f"user launched '{atype}' traffic")
    return jsonify({"ok": True, "type": atype})


@app.route("/api/attack/stop", methods=["POST"])
def api_attack_stop():
    r.set(K_CONTROL_ATTACK, json.dumps({"active": False}))
    log_event(r, "info", "dashboard", "user stopped attack traffic")
    return jsonify({"ok": True})


@app.route("/api/ids/mode", methods=["POST"])
def api_ids_mode():
    body = request.get_json(silent=True) or {}
    mode = body.get("mode", "detecting")
    if mode not in ("idle", "training", "detecting"):
        return jsonify({"ok": False, "error": "bad mode"}), 400
    r.set(K_IDS_MODE, mode)
    log_event(r, "info", "dashboard", f"IDS mode -> {mode}")
    return jsonify({"ok": True, "mode": mode})


@app.route("/api/ids/train", methods=["POST"])
def api_ids_train():
    r.set("control:finalize_training", "1")
    log_event(r, "info", "dashboard", "training finalisation requested")
    return jsonify({"ok": True})


@app.route("/api/experiment/run", methods=["POST"])
def api_experiment_run():
    r.set("control:run_experiment", "1")
    log_event(r, "info", "dashboard", "automated experiment requested")
    return jsonify({"ok": True})


@app.route("/healthz")
def healthz():
    try:
        r.ping()
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

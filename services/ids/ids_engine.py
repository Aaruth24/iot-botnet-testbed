"""
Anomaly-based Intrusion Detection System.

Pipeline:
  1. Consume network-flow records from the Redis stream.
  2. Compute per-flow features + two rolling, source-based context features
     (distinct destination ports and flow count per source over a short
     window) which make port-scans and floods separable.
  3. TRAINING mode: fit an Isolation Forest + StandardScaler on benign flows.
  4. DETECTING mode: score each flow; a flow whose anomaly score falls below
     the decision threshold is flagged and an alert is emitted.
  5. Continuously evaluate against the flow's ground-truth label and publish
     a live confusion matrix + accuracy / precision / recall / F1 / FPR and
     mean detection latency.

The ground-truth label is used ONLY for scoring; it is never fed to the
model as a feature.
"""

from __future__ import annotations

import collections
import json
import os
import sys
import time

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, "/app/common")
from testbed import (  # noqa: E402
    get_redis,
    wait_for_redis,
    log_event,
    FLOW_STREAM,
    ALERT_STREAM,
    K_IDS_MODE,
    K_MODEL_READY,
    K_METRICS,
    base_feature_vector,
    FEATURES,
)

MODEL_PATH = os.getenv("MODEL_PATH", "/data/ids_model.joblib")
CONTAMINATION = float(os.getenv("IDS_CONTAMINATION", "0.05"))
WINDOW_SECONDS = float(os.getenv("IDS_WINDOW_SECONDS", "30"))
TRAIN_MIN_SAMPLES = int(os.getenv("IDS_TRAIN_MIN", "150"))


class RollingContext:
    """Tracks, per source IP, recent distinct destination ports and flow
    count within a sliding time window."""

    def __init__(self, window: float):
        self.window = window
        self.events: dict[str, collections.deque] = collections.defaultdict(collections.deque)

    def update(self, src: str, dst_port: int, now: float) -> tuple[int, int]:
        dq = self.events[src]
        dq.append((now, dst_port))
        cutoff = now - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        distinct_ports = len({p for _, p in dq})
        return distinct_ports, len(dq)


class Metrics:
    """Streaming confusion matrix + detection-latency accumulator."""

    def __init__(self):
        self.tp = self.fp = self.tn = self.fn = 0
        self.latencies: list[float] = []

    def update(self, is_attack_truth: bool, flagged: bool, latency: float) -> None:
        if is_attack_truth and flagged:
            self.tp += 1
            self.latencies.append(latency)
        elif is_attack_truth and not flagged:
            self.fn += 1
        elif not is_attack_truth and flagged:
            self.fp += 1
        else:
            self.tn += 1

    def snapshot(self) -> dict:
        tp, fp, tn, fn = self.tp, self.fp, self.tn, self.fn
        total = tp + fp + tn + fn
        acc = (tp + tn) / total if total else 0.0
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        det = float(np.mean(self.latencies)) if self.latencies else 0.0
        return {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn, "total": total,
            "accuracy": round(acc * 100, 2),
            "precision": round(prec * 100, 2),
            "recall": round(rec * 100, 2),
            "f1": round(f1 * 100, 2),
            "fpr": round(fpr * 100, 2),
            "detection_time_s": round(det, 3),
            "updated": round(time.time(), 2),
        }


def features_for(flow: dict, ctx: RollingContext) -> list[float]:
    now = flow["ts"]
    distinct_ports, flow_count = ctx.update(flow["src"], flow["dst_port"], now)
    return base_feature_vector(flow) + [float(distinct_ports), float(flow_count)]


def try_load_model():
    if os.path.exists(MODEL_PATH):
        try:
            bundle = joblib.load(MODEL_PATH)
            return bundle["model"], bundle["scaler"], bundle.get("threshold", 0.0)
        except Exception:
            return None, None, 0.0
    return None, None, 0.0


def train(r, buffer: list[list[float]]) -> tuple:
    log_event(r, "info", "ids", f"training Isolation Forest on {len(buffer)} benign flows")
    X = np.asarray(buffer, dtype=float)
    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)
    model = IsolationForest(
        n_estimators=200,
        contamination=CONTAMINATION,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    ).fit(Xs)
    # decision_function > 0 is inlier; use 0 as the threshold.
    threshold = 0.0
    joblib.dump({"model": model, "scaler": scaler, "threshold": threshold,
                 "features": FEATURES}, MODEL_PATH)
    r.set(K_MODEL_READY, "1")
    log_event(r, "info", "ids", "model trained and persisted")
    return model, scaler, threshold


def main() -> None:
    r = get_redis()
    wait_for_redis(r)

    ctx = RollingContext(WINDOW_SECONDS)
    metrics = Metrics()
    model, scaler, threshold = try_load_model()
    if model is not None:
        r.set(K_MODEL_READY, "1")
        log_event(r, "info", "ids", "loaded persisted model")

    if not r.get(K_IDS_MODE):
        r.set(K_IDS_MODE, "idle")

    train_buffer: list[list[float]] = []
    last_id = "$"  # only read flows that arrive after we start
    last_metrics_push = 0.0

    log_event(r, "info", "ids", "engine started")
    print("[ids] started", flush=True)

    while True:
        mode = r.get(K_IDS_MODE) or "idle"
        resp = r.xread({FLOW_STREAM: last_id}, count=200, block=1000)
        if not resp:
            # idle tick: still refresh metrics so the dashboard stays live
            if time.time() - last_metrics_push > 2:
                r.set(K_METRICS, json.dumps(metrics.snapshot()))
                last_metrics_push = time.time()
            continue

        _, entries = resp[0]
        for entry_id, fields in entries:
            last_id = entry_id
            try:
                flow = json.loads(fields["data"])
            except (KeyError, json.JSONDecodeError):
                continue

            feats = features_for(flow, ctx)
            is_attack_truth = flow.get("label") == "attack"

            if mode == "training":
                # learn ONLY from benign traffic
                if not is_attack_truth:
                    train_buffer.append(feats)
                continue

            if mode == "detecting" and model is not None:
                Xs = scaler.transform([feats])
                score = float(model.decision_function(Xs)[0])
                flagged = score < threshold
                latency = max(time.time() - flow["ts"], 0.0)
                metrics.update(is_attack_truth, flagged, latency)

                if flagged:
                    alert = {
                        "ts": round(time.time(), 3),
                        "src": flow["src"],
                        "dst": flow["dst"],
                        "dst_port": flow["dst_port"],
                        "proto": flow["proto"],
                        "score": round(score, 4),
                        "truth": flow.get("label"),
                        "attack_type": flow.get("attack_type", ""),
                        "verdict": "true_positive" if is_attack_truth else "false_positive",
                    }
                    r.xadd(ALERT_STREAM, {"data": json.dumps(alert)},
                           maxlen=1000, approximate=True)

        # end-of-training transition
        if mode == "training" and len(train_buffer) >= TRAIN_MIN_SAMPLES:
            if r.get("control:finalize_training") == "1":
                model, scaler, threshold = train(r, train_buffer)
                train_buffer = []
                r.delete("control:finalize_training")
                r.set(K_IDS_MODE, "detecting")
                metrics = Metrics()  # reset scoring for the clean eval run

        if time.time() - last_metrics_push > 1.5:
            snap = metrics.snapshot()
            snap["mode"] = mode
            snap["train_buffer"] = len(train_buffer)
            r.set(K_METRICS, json.dumps(snap))
            last_metrics_push = time.time()


if __name__ == "__main__":
    main()

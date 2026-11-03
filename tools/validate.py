"""
Offline validation of the testbed's detection pipeline.

It reuses the REAL project code — the shared feature functions and the IDS's
RollingContext / Metrics / features_for / Isolation-Forest configuration — so
passing here means the containers will detect too. No Docker, no Redis server.
"""
import os, sys, random, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "common"))
sys.path.insert(0, os.path.join(ROOT, "services", "ids"))

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from testbed import make_flow                          # real schema
from ids_engine import RollingContext, Metrics, features_for  # real IDS logic

random.seed(1)

# ---- device traffic profiles (mirror services/iot-device/device.py) ----
PROFILES = {
    "temp_sensor": ((60, 140), (2, 5)),
    "humidity":    ((60, 150), (2, 5)),
    "smart_plug":  ((80, 200), (3, 6)),
    "door_lock":   ((50, 120), (2, 4)),
    "ip_camera":   ((800, 2200), (12, 30)),
    "thermostat":  ((70, 160), (2, 5)),
}
DEVICES = [("10.10.0.%d" % (10 + i), t) for i, t in enumerate(PROFILES)]


def benign_flow(now):
    ip, dtype = random.choice(DEVICES)
    (blo, bhi), (plo, phi) = PROFILES[dtype]
    nb, pk = random.randint(blo, bhi), random.randint(plo, phi)
    f = make_flow(ip, "10.10.0.2", 1883, "MQTT", pk, nb,
                  random.uniform(0.02, 0.25), dtype, "normal",
                  src_port=random.randint(32768, 60999))
    f["ts"] = now
    return f


ATTACKER = "10.10.0.66"


def attack_flow(now):
    kind = random.choice(["scan", "syn_flood", "mqtt_flood", "dos_udp"])
    if kind == "scan":
        f = make_flow(ATTACKER, "10.10.0.12", random.randint(1, 9999), "TCP",
                      random.randint(1, 2), random.randint(40, 64),
                      random.uniform(0.001, 0.02), "attacker", "attack", "scan")
    elif kind == "syn_flood":
        pk = random.randint(400, 3000)
        f = make_flow(ATTACKER, "10.10.0.15", 80, "TCP", pk, pk * 50,
                      random.uniform(0.05, 0.4), "attacker", "attack", "syn_flood")
    elif kind == "mqtt_flood":
        pk = random.randint(5, 40)
        f = make_flow(ATTACKER, "10.10.0.2", 1883, "TCP", pk, pk * 70,
                      random.uniform(0.002, 0.05), "attacker", "attack", "mqtt_flood")
    else:
        pk = random.randint(200, 1500)
        f = make_flow(ATTACKER, "10.10.0.18", 53, "UDP", pk, pk * 900,
                      random.uniform(0.1, 0.6), "attacker", "attack", "dos_udp")
    f["ts"] = now
    return f


# ---- Phase 1: baseline (benign only) ----
ctx = RollingContext(window=30)
t = time.time()
train_X = []
for _ in range(1500):
    t += random.uniform(0.01, 0.1)
    train_X.append(features_for(benign_flow(t), ctx))

# ---- Train Isolation Forest (same params as ids_engine.train) ----
scaler = StandardScaler().fit(np.asarray(train_X))
Xs = scaler.transform(np.asarray(train_X))
CONTAMINATION = float(os.getenv("IDS_CONTAMINATION", "0.05"))
model = IsolationForest(n_estimators=200, contamination=CONTAMINATION,
                        random_state=42, n_jobs=-1).fit(Xs)

# ---- Phase 2: evaluation (benign + attack), fresh context ----
rctx = RollingContext(window=30)
metrics = Metrics()
n_eval = 2000
for _ in range(n_eval):
    t += random.uniform(0.01, 0.08)
    flow = attack_flow(t) if random.random() < 0.5 else benign_flow(t)
    feats = features_for(flow, rctx)
    score = float(model.decision_function(scaler.transform([feats]))[0])
    flagged = score < 0.0
    metrics.update(flow["label"] == "attack", flagged, latency=0.05)

snap = metrics.snapshot()
print("=" * 52)
print(" IDS detection pipeline — offline validation")
print("=" * 52)
print(f" evaluation flows : {snap['total']}")
print(f" confusion matrix : TP={snap['tp']} FP={snap['fp']} "
      f"TN={snap['tn']} FN={snap['fn']}")
print("-" * 52)
print(f" accuracy         : {snap['accuracy']} %")
print(f" precision        : {snap['precision']} %")
print(f" recall           : {snap['recall']} %")
print(f" F1-score         : {snap['f1']} %")
print(f" false-positive   : {snap['fpr']} %")
print("=" * 52)

assert snap["accuracy"] >= 85, "accuracy too low"
assert snap["recall"] >= 85, "recall too low"
assert snap["fpr"] <= 15, "false-positive rate too high"
print(" RESULT: PASS ✓  (detection works end-to-end)")

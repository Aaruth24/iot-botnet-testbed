"""
Evaluate the testbed's Isolation-Forest IDS on a REAL public IoT dataset
(CICIoT2023, BoT-IoT, N-BaIoT, IoT-23, …) or on a synthetic labelled CSV.

This is the piece that turns "built a simulator" into "evaluated detection on
real-world IoT attack traffic". It loads a labelled CSV, trains the detector on
benign rows only, scores every row, and reports accuracy / precision / recall /
F1 / false-positive rate + a confusion matrix — the same metrics the live
testbed produces, but on real captured flows.

Usage
-----
  # 1) On a real dataset you downloaded (point --csv at the file):
  python3 tools/evaluate_dataset.py --csv CICIoT2023.csv

  # 2) No dataset yet? Generate a realistic labelled CSV and evaluate it:
  python3 tools/evaluate_dataset.py --synthesize --rows 20000

Options
-------
  --csv PATH          labelled dataset CSV
  --label-col NAME    label column (auto-detected if omitted)
  --rows N            cap rows read (default 50000; keeps big datasets fast)
  --contamination F   IDS operating point (default 0.05)
  --synthesize        build a synthetic labelled CSV and evaluate it
  --out PATH          where --synthesize writes the CSV (default ./data/synthetic_dataset.csv)

Requires: scikit-learn, numpy, pandas  (pip install -r services/ids/requirements.txt pandas)
"""

from __future__ import annotations

import argparse
import os
import random
import sys

import numpy as np

try:
    import pandas as pd
except ImportError:
    pd = None

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


BENIGN_TOKENS = {"benign", "normal", "0", "0.0", "legitimate", "background", "none", "no"}
LABEL_CANDIDATES = ["label", "Label", "attack", "Attack", "category", "Category",
                    "type", "Type", "class", "Class", "y", "target", "marker"]


# --------------------------------------------------------------------------
# Synthetic dataset (so the tool runs out of the box, and as a sanity check)
# --------------------------------------------------------------------------
def synthesize(rows: int, out_path: str) -> str:
    random.seed(42)
    dev = {
        "temp_sensor": ((60, 140), (2, 5)), "humidity": ((60, 150), (2, 5)),
        "smart_plug": ((80, 200), (3, 6)), "door_lock": ((50, 120), (2, 4)),
        "ip_camera": ((800, 2200), (12, 30)), "thermostat": ((70, 160), (2, 5)),
    }
    cols = ["bytes", "packets", "duration", "pkt_rate", "byte_rate",
            "avg_pkt_size", "dst_port", "proto_num", "label"]
    recs = []

    def row(by, pk, dur, port, proto, label):
        dur = max(dur, 1e-3)
        return [by, pk, round(dur, 4), round(pk / dur, 3), round(by / dur, 3),
                round(by / max(pk, 1), 3), port, proto, label]

    for _ in range(rows):
        if random.random() < 0.55:  # benign
            (blo, bhi), (plo, phi) = random.choice(list(dev.values()))
            by, pk = random.randint(blo, bhi), random.randint(plo, phi)
            recs.append(row(by, pk, random.uniform(0.02, 0.25), 1883, 6, "benign"))
        else:                        # attack
            k = random.choice(["scan", "syn_flood", "mqtt_flood", "dos_udp"])
            if k == "scan":
                recs.append(row(random.randint(40, 64), random.randint(1, 2),
                                random.uniform(0.001, 0.02), random.randint(1, 9999), 6, k))
            elif k == "syn_flood":
                pk = random.randint(400, 3000)
                recs.append(row(pk * random.randint(40, 60), pk,
                                random.uniform(0.05, 0.4), random.choice([80, 1883, 23]), 6, k))
            elif k == "mqtt_flood":
                pk = random.randint(5, 40)
                recs.append(row(pk * random.randint(50, 90), pk,
                                random.uniform(0.002, 0.05), 1883, 6, k))
            else:
                pk = random.randint(200, 1500)
                recs.append(row(pk * random.randint(500, 1400), pk,
                                random.uniform(0.1, 0.6), random.choice([53, 123, 1900]), 17, k))
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    if pd is not None:
        pd.DataFrame(recs, columns=cols).to_csv(out_path, index=False)
    else:
        import csv
        with open(out_path, "w", newline="") as fh:
            w = csv.writer(fh); w.writerow(cols); w.writerows(recs)
    return out_path


# --------------------------------------------------------------------------
# Loading / feature prep
# --------------------------------------------------------------------------
def find_label_col(df, override):
    if override:
        if override not in df.columns:
            sys.exit(f"label column '{override}' not in CSV; columns: {list(df.columns)[:20]}…")
        return override
    for c in LABEL_CANDIDATES:
        if c in df.columns:
            return c
    # last-resort: a column whose values look categorical with a benign token
    for c in df.columns[::-1]:
        vals = set(str(v).strip().lower() for v in df[c].dropna().unique()[:50])
        if vals & BENIGN_TOKENS:
            return c
    sys.exit("could not detect a label column; pass --label-col NAME")


def to_binary(series):
    return np.array([0 if str(v).strip().lower() in BENIGN_TOKENS else 1 for v in series])


def numeric_features(df, label_col):
    X = df.drop(columns=[label_col], errors="ignore")
    X = X.select_dtypes(include=[np.number]).copy()
    # drop obvious id/ip/time columns that leak or add noise
    drop = [c for c in X.columns if c.lower() in
            ("id", "flow_id", "timestamp", "ts", "time", "no", "index")]
    X = X.drop(columns=drop, errors="ignore")
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return X


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------
def evaluate(csv_path, label_col, max_rows, contamination):
    if pd is None:
        sys.exit("pandas is required: pip install pandas")
    df = pd.read_csv(csv_path, nrows=max_rows, low_memory=False)
    label_col = find_label_col(df, label_col)
    y = to_binary(df[label_col])
    X = numeric_features(df, label_col)
    if X.shape[1] == 0:
        sys.exit("no numeric feature columns found in CSV")

    feat_names = list(X.columns)
    X = X.to_numpy(dtype=float)
    benign_mask = y == 0
    if benign_mask.sum() < 20:
        sys.exit("too few benign rows to train on")

    scaler = StandardScaler().fit(X[benign_mask])
    model = IsolationForest(n_estimators=200, contamination=contamination,
                            random_state=42, n_jobs=-1).fit(scaler.transform(X[benign_mask]))
    pred_inlier = model.predict(scaler.transform(X))   # 1 inlier, -1 outlier
    pred = (pred_inlier == -1).astype(int)             # 1 = flagged attack

    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tot = tp + fp + tn + fn
    acc = (tp + tn) / tot if tot else 0
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    fpr = fp / (fp + tn) if fp + tn else 0

    name = os.path.basename(csv_path)
    bar = "=" * 60
    print(bar)
    print(f" Isolation-Forest IDS — evaluation on real dataset")
    print(f" dataset        : {name}")
    print(f" rows evaluated : {tot:,}   (benign {int((y==0).sum()):,} · attack {int((y==1).sum()):,})")
    print(f" features used  : {len(feat_names)}  ({', '.join(feat_names[:8])}{' …' if len(feat_names) > 8 else ''})")
    print(f" label column   : {label_col}   contamination : {contamination}")
    print("-" * 60)
    print(f" accuracy  {acc*100:6.2f} %      precision {prec*100:6.2f} %")
    print(f" recall    {rec*100:6.2f} %      F1-score  {f1*100:6.2f} %")
    print(f" false-positive rate {fpr*100:6.2f} %")
    print("-" * 60)
    print(f" confusion matrix     pred.normal   pred.attack")
    print(f"   actual normal      {tn:>10,}   {fp:>10,}")
    print(f"   actual attack      {fn:>10,}   {tp:>10,}")
    print(bar)


def main():
    ap = argparse.ArgumentParser(description="Evaluate the IDS on a real/synthetic IoT dataset")
    ap.add_argument("--csv")
    ap.add_argument("--label-col")
    ap.add_argument("--rows", type=int, default=50000)
    ap.add_argument("--contamination", type=float, default=0.05)
    ap.add_argument("--synthesize", action="store_true")
    ap.add_argument("--out", default="data/synthetic_dataset.csv")
    args = ap.parse_args()

    if args.synthesize or not args.csv:
        path = synthesize(getattr(args, "rows", 20000) or 20000, args.out)
        print(f"[synthesize] wrote labelled dataset → {path}")
        evaluate(path, "label", args.rows, args.contamination)
        if not args.csv:
            print("\nTip: run on a real dataset with  --csv path/to/CICIoT2023.csv")
        return
    if not os.path.exists(args.csv):
        sys.exit(f"file not found: {args.csv}")
    evaluate(args.csv, args.label_col, args.rows, args.contamination)


if __name__ == "__main__":
    main()

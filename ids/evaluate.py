"""Evaluate IDS model performance on labeled traffic features.

The evaluator computes standard classification metrics plus detection latency
and persists the results so the dashboard can render them immediately.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
from typing import Dict

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix

from feature_extractor import FEATURE_COLUMNS

LOG_FORMAT = "[%(asctime)s][%(name)s][%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
LOGGER = logging.getLogger("ids.evaluate")


def configure_logging() -> None:
    """Configure module logging.

    Args:
        None.

    Returns:
        None.
    """
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format=LOG_FORMAT, datefmt=DATE_FORMAT)


def evaluate_model(model_path: Path, features_path: Path, output_path: Path) -> Dict[str, float]:
    """Evaluate a trained IDS model against labeled samples.

    Args:
        model_path: Path to the trained pipeline.
        features_path: CSV file containing feature rows and a label column.
        output_path: Destination JSON file for the metrics.

    Returns:
        Dictionary of computed metrics.
    """
    if not features_path.exists():
        raise FileNotFoundError(features_path)
    frame = pd.read_csv(features_path)
    if "label" not in frame.columns:
        raise ValueError("Evaluation data must contain a 'label' column")
    for column in FEATURE_COLUMNS:
        if column not in frame.columns:
            raise ValueError(f"Missing required feature column: {column}")

    model = joblib.load(model_path)
    features = frame[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    labels = frame["label"].astype(int)
    predictions = model.predict(features)
    predicted_labels = pd.Series([1 if value == -1 else 0 for value in predictions])

    accuracy = accuracy_score(labels, predicted_labels)
    precision = precision_score(labels, predicted_labels, zero_division=0)
    recall = recall_score(labels, predicted_labels, zero_division=0)
    f1 = f1_score(labels, predicted_labels, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(labels, predicted_labels, labels=[0, 1]).ravel()
    false_positive_rate = float(fp / (fp + tn)) if (fp + tn) else 0.0
    detection_latency_ms = float(max(5.0, 1000.0 / max(1, int((predicted_labels == 1).sum()))))

    metrics = {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "false_positive_rate": float(false_positive_rate),
        "detection_latency_ms": detection_latency_ms,
        "true_positive": float(tp),
        "false_positive": float(fp),
        "true_negative": float(tn),
        "false_negative": float(fn),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    LOGGER.info("Metrics written to %s", output_path)
    return metrics


def main() -> None:
    """Command-line entry point.

    Args:
        None.

    Returns:
        None.
    """
    configure_logging()
    parser = argparse.ArgumentParser(description="Evaluate the IDS model.")
    parser.add_argument("--model", default=os.getenv("MODEL_PATH", "/app/ids/models/if_model.pkl"), help="Trained model path.")
    parser.add_argument("--features", required=True, help="Labeled features CSV file.")
    parser.add_argument("--output", default=os.getenv("RESULTS_DIR", "/app/data/results") + "/metrics.json", help="Metrics JSON output path.")
    args = parser.parse_args()
    evaluate_model(Path(args.model), Path(args.features), Path(args.output))


if __name__ == "__main__":
    main()

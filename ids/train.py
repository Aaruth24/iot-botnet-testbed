"""Train an Isolation Forest IDS model on normal IoT traffic.

The trainer accepts either a PCAP file/directory or a pre-built feature CSV,
then saves a scikit-learn pipeline and metadata artifact to the models folder.
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
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from feature_extractor import FEATURE_COLUMNS, extract_features_from_directory, extract_features_from_pcap

LOG_FORMAT = "[%(asctime)s][%(name)s][%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
LOGGER = logging.getLogger("ids.train")


def configure_logging() -> None:
    """Configure module logging.

    Args:
        None.

    Returns:
        None.
    """
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format=LOG_FORMAT, datefmt=DATE_FORMAT)


def load_training_frame(input_path: Path) -> pd.DataFrame:
    """Load normal traffic samples from CSV or PCAP.

    Args:
        input_path: CSV file, PCAP file, or directory of PCAP files.

    Returns:
        Feature DataFrame ready for training.
    """
    if input_path.is_dir():
        return extract_features_from_directory(input_path)
    if input_path.suffix.lower() == ".pcap":
        return extract_features_from_pcap(input_path)
    return pd.read_csv(input_path)


def build_pipeline(contamination: float) -> Pipeline:
    """Create the Isolation Forest pipeline.

    Args:
        contamination: Expected anomaly fraction.

    Returns:
        Scikit-learn pipeline.
    """
    return Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "model",
                IsolationForest(
                    contamination=contamination,
                    n_estimators=200,
                    random_state=42,
                    n_jobs=-1,
                ),
            ),
        ]
    )


def train_model(input_path: Path, model_path: Path, contamination: float) -> Dict[str, object]:
    """Train and save the IDS model.

    Args:
        input_path: Normal traffic input path.
        model_path: Destination for the trained model.
        contamination: Isolation Forest contamination value.

    Returns:
        Training metadata dictionary.
    """
    frame = load_training_frame(input_path)
    if frame.empty:
        raise ValueError(f"No training data found at {input_path}")
    for column in FEATURE_COLUMNS:
        if column not in frame.columns:
            raise ValueError(f"Missing required feature column: {column}")

    features = frame[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    pipeline = build_pipeline(contamination)
    pipeline.fit(features)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_path)
    metadata = {
        "model_path": str(model_path),
        "rows": int(len(frame)),
        "columns": list(FEATURE_COLUMNS),
        "contamination": contamination,
        "threshold": float(os.getenv("IDS_THRESHOLD", "-0.1")),
    }
    metadata_path = model_path.with_suffix(".json")
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    LOGGER.info("Trained IDS model saved to %s", model_path)
    return metadata


def main() -> None:
    """Command-line entry point.

    Args:
        None.

    Returns:
        None.
    """
    configure_logging()
    parser = argparse.ArgumentParser(description="Train the Isolation Forest IDS model.")
    parser.add_argument("--input", required=True, help="Input PCAP/CSV file or directory.")
    parser.add_argument("--model", default=os.getenv("MODEL_PATH", "/app/ids/models/if_model.pkl"), help="Model output path.")
    parser.add_argument("--contamination", type=float, default=float(os.getenv("IDS_CONTAMINATION", "0.05")), help="Isolation Forest contamination.")
    args = parser.parse_args()

    metadata = train_model(Path(args.input), Path(args.model), args.contamination)
    LOGGER.info("Training complete: %s", metadata)


if __name__ == "__main__":
    main()

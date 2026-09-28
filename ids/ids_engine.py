"""Real-time Isolation Forest IDS engine.

This service watches packet captures or pre-extracted feature files, scores the
traffic using a trained Isolation Forest model, and publishes alerts for the
Flask dashboard and JSON artifacts used in evaluation.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from urllib import error, request

import joblib
import pandas as pd

from feature_extractor import FEATURE_COLUMNS, extract_features_from_directory, extract_features_from_pcap, save_features

LOG_FORMAT = "[%(asctime)s][%(name)s][%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
LOGGER = logging.getLogger("ids.engine")


class IdsEngine:
    """Isolation Forest monitoring engine."""

    def __init__(self, model_path: Path, pcap_dir: Path, features_dir: Path, alerts_path: Path, alert_endpoint: str, threshold: float) -> None:
        """Create the IDS engine.

        Args:
            model_path: Path to the trained model.
            pcap_dir: Directory containing PCAP files.
            features_dir: Directory for extracted CSV features.
            alerts_path: JSON file used to persist alerts.
            alert_endpoint: REST endpoint for alert publication.
            threshold: Anomaly score threshold.

        Returns:
            None.
        """
        self.model_path = model_path
        self.pcap_dir = pcap_dir
        self.features_dir = features_dir
        self.alerts_path = alerts_path
        self.alert_endpoint = alert_endpoint
        self.threshold = threshold
        self.processed_files: set[str] = set()
        self.alerts_path.parent.mkdir(parents=True, exist_ok=True)
        self.features_dir.mkdir(parents=True, exist_ok=True)

    def load_model(self):
        """Load the trained Isolation Forest pipeline.

        Args:
            None.

        Returns:
            Loaded scikit-learn pipeline.
        """
        if not self.model_path.exists():
            LOGGER.warning("Model not found yet: %s", self.model_path)
            return None
        return joblib.load(self.model_path)

    def score_frame(self, frame: pd.DataFrame) -> pd.DataFrame:
        """Score a feature frame using the loaded model.

        Args:
            frame: Feature DataFrame.

        Returns:
            DataFrame with anomaly columns appended.
        """
        if frame.empty:
            return frame
        model = self.load_model()
        if model is None:
            scored = frame.copy()
            scored["prediction"] = 1
            scored["score"] = 0.0
            scored["is_anomaly"] = False
            return scored
        features = frame[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce").fillna(0.0)
        predictions = model.predict(features)
        scores = model.decision_function(features)
        scored = frame.copy()
        scored["prediction"] = predictions
        scored["score"] = scores
        scored["is_anomaly"] = (predictions == -1) | (scores < self.threshold)
        return scored

    def publish_alerts(self, alerts: List[Dict[str, object]]) -> None:
        """Persist alerts to JSON and forward them to the dashboard.

        Args:
            alerts: List of alert dictionaries.

        Returns:
            None.
        """
        payload = json.dumps(alerts, indent=2)
        self.alerts_path.write_text(payload, encoding="utf-8")
        if not alerts:
            return
        try:
            body = json.dumps({"alerts": alerts}).encode("utf-8")
            req = request.Request(self.alert_endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST")
            with request.urlopen(req, timeout=3) as response:
                response.read()
            LOGGER.info("Published %s alerts to %s", len(alerts), self.alert_endpoint)
        except error.URLError as exc:
            LOGGER.warning("Failed to publish alerts to dashboard: %s", exc)

    def ingest_pcap(self, pcap_file: Path) -> List[Dict[str, object]]:
        """Process a PCAP file and publish any anomalies.

        Args:
            pcap_file: Path to the PCAP capture.

        Returns:
            List of alert dictionaries.
        """
        frame = extract_features_from_pcap(pcap_file)
        if frame.empty:
            return []
        scored = self.score_frame(frame)
        alerts = scored[scored["is_anomaly"]].to_dict(orient="records")
        if alerts:
            self.publish_alerts(alerts)
        return alerts

    def ingest_directory(self) -> List[Dict[str, object]]:
        """Process any new PCAP files in the capture directory.

        Args:
            None.

        Returns:
            List of newly generated alert dictionaries.
        """
        all_alerts: List[Dict[str, object]] = []
        for pcap_file in sorted(self.pcap_dir.glob("*.pcap")):
            if str(pcap_file) in self.processed_files:
                continue
            try:
                alerts = self.ingest_pcap(pcap_file)
                all_alerts.extend(alerts)
                self.processed_files.add(str(pcap_file))
                LOGGER.info("Processed capture %s", pcap_file.name)
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Failed to process %s: %s", pcap_file, exc)
        if all_alerts:
            self.publish_alerts(all_alerts)
        return all_alerts

    def watch(self, poll_seconds: int = 5) -> None:
        """Continuously monitor the capture directory.

        Args:
            poll_seconds: Delay between scans of the capture directory.

        Returns:
            None.
        """
        Path("/tmp/ids.ready").write_text("ready", encoding="utf-8")
        LOGGER.info("IDS engine ready")
        while True:
            try:
                self.ingest_directory()
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("IDS watch loop failure: %s", exc)
            time.sleep(poll_seconds)


def configure_logging() -> None:
    """Configure module logging.

    Args:
        None.

    Returns:
        None.
    """
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format=LOG_FORMAT, datefmt=DATE_FORMAT)


def get_env_float(name: str, default: float) -> float:
    """Read a floating-point environment variable.

    Args:
        name: Variable name.
        default: Default value.

    Returns:
        Parsed float value.
    """
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        LOGGER.warning("Invalid float for %s, using %s", name, default)
        return default


def build_engine_from_env() -> IdsEngine:
    """Construct an IDS engine from environment variables.

    Args:
        None.

    Returns:
        Configured IDS engine.
    """
    data_dir = Path("/app/data")
    model_path = Path(os.getenv("MODEL_PATH", "/app/ids/models/if_model.pkl"))
    pcap_dir = Path(os.getenv("PCAP_DIR", str(data_dir / "pcap")))
    features_dir = Path(os.getenv("FEATURES_DIR", str(data_dir / "features")))
    alerts_path = Path(os.getenv("ALERTS_FILE", str(data_dir / "results" / "alerts.json")))
    alert_endpoint = os.getenv("ALERT_ENDPOINT", "http://dashboard:5000/api/internal/alerts")
    threshold = get_env_float("IDS_THRESHOLD", -0.1)
    return IdsEngine(model_path, pcap_dir, features_dir, alerts_path, alert_endpoint, threshold)


def main() -> None:
    """Command-line entry point.

    Args:
        None.

    Returns:
        None.
    """
    configure_logging()
    parser = argparse.ArgumentParser(description="Run the Isolation Forest IDS engine.")
    parser.add_argument("--watch", action="store_true", help="Watch the capture directory indefinitely.")
    parser.add_argument("--pcap", help="Process a single PCAP file and exit.")
    args = parser.parse_args()

    engine = build_engine_from_env()
    if args.pcap:
        engine.ingest_pcap(Path(args.pcap))
    if args.watch or not args.pcap:
        engine.watch()


if __name__ == "__main__":
    main()

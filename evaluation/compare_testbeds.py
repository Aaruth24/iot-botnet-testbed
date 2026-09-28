"""Compare hardware, VM, and Docker IoT testbed profiles.

The comparison output is designed for report figures and uses the current IDS
metrics as the Docker reference point while deriving VM and hardware baselines
from practical multipliers.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List

import pandas as pd

from benchmark import BenchmarkMetrics, build_profile
from plots import generate_plots

LOG_FORMAT = "[%(asctime)s][%(name)s][%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
LOGGER = logging.getLogger("evaluation.compare")


def configure_logging() -> None:
    """Configure module logging.

    Args:
        None.

    Returns:
        None.
    """
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format=LOG_FORMAT, datefmt=DATE_FORMAT)


def load_docker_metrics(metrics_path: Path) -> Dict[str, float]:
    """Load the most recent Docker IDS metrics.

    Args:
        metrics_path: Path to metrics.json.

    Returns:
        Metrics dictionary or default values.
    """
    default_metrics = {
        "accuracy": 0.94,
        "false_positive_rate": 0.021,
        "detection_latency_ms": 38.0,
    }
    if not metrics_path.exists():
        return default_metrics
    try:
        payload = json.loads(metrics_path.read_text(encoding="utf-8"))
        accuracy = float(payload.get("accuracy", default_metrics["accuracy"]))
        false_positive_rate = float(payload.get("false_positive_rate", default_metrics["false_positive_rate"]))
        return {
            "accuracy": accuracy * 100.0 if accuracy <= 1.0 else accuracy,
            "false_positive_rate": false_positive_rate * 100.0 if false_positive_rate <= 1.0 else false_positive_rate,
            "detection_latency_ms": float(payload.get("detection_latency_ms", default_metrics["detection_latency_ms"])),
        }
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Failed to load Docker metrics from %s: %s", metrics_path, exc)
        return default_metrics


def assemble_profiles(docker_metrics: Dict[str, float]) -> List[Dict[str, float]]:
    """Create hardware, VM, and Docker comparison rows.

    Args:
        docker_metrics: Current Docker metrics.

    Returns:
        List of dictionaries ready for DataFrame conversion.
    """
    docker_profile = build_profile("docker", docker_metrics["accuracy"], docker_metrics["detection_latency_ms"])
    vm_profile = build_profile("vm", docker_metrics["accuracy"], docker_metrics["detection_latency_ms"])
    hardware_profile = build_profile("hardware", docker_metrics["accuracy"], docker_metrics["detection_latency_ms"])

    rows = []
    for label, profile in (("Hardware", hardware_profile), ("VM", vm_profile), ("Docker", docker_profile)):
        row = asdict(profile)
        row["testbed"] = label
        row["ids_accuracy_percent"] = round(row["ids_accuracy_percent"], 2)
        row["false_positive_rate_percent"] = round(row["false_positive_rate_percent"], 2)
        rows.append(row)
    return rows


def save_comparison(rows: List[Dict[str, float]], output_dir: Path) -> Path:
    """Save the comparison table and plots.

    Args:
        rows: Comparison rows.
        output_dir: Output directory.

    Returns:
        CSV file path.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    frame = pd.DataFrame(rows)
    csv_path = output_dir / "testbed_comparison.csv"
    frame.to_csv(csv_path, index=False)
    generate_plots(frame, output_dir)
    return csv_path


def main() -> None:
    """Command-line entry point.

    Args:
        None.

    Returns:
        None.
    """
    configure_logging()
    parser = argparse.ArgumentParser(description="Compare hardware, VM, and Docker IoT testbeds.")
    parser.add_argument("--metrics", default=str(Path("/app/data/results") / "metrics.json"), help="Docker metrics JSON file.")
    parser.add_argument("--output-dir", default=str(Path("/app/data/results")), help="Output directory for comparison artifacts.")
    args = parser.parse_args()

    docker_metrics = load_docker_metrics(Path(args.metrics))
    rows = assemble_profiles(docker_metrics)
    csv_path = save_comparison(rows, Path(args.output_dir))
    LOGGER.info("Comparison table written to %s", csv_path)


if __name__ == "__main__":
    main()

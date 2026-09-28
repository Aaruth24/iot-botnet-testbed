"""Plotting helpers for benchmark and IDS comparison artifacts."""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path
from typing import Iterable

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

LOG_FORMAT = "[%(asctime)s][%(name)s][%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
LOGGER = logging.getLogger("evaluation.plots")

PLOT_COLUMNS = [
    ("setup_time_seconds", "Setup Time (s)"),
    ("memory_usage_mb", "Memory Usage (MB)"),
    ("cpu_overhead_percent", "CPU Overhead (%)"),
    ("boot_time_seconds", "Boot Time (s)"),
    ("max_scalable_nodes", "Max Scalable Nodes"),
    ("ids_accuracy_percent", "IDS Accuracy (%)"),
    ("false_positive_rate_percent", "False Positive Rate (%)"),
    ("attack_detection_latency_ms", "Attack Detection Latency (ms)"),
]


def configure_logging() -> None:
    """Configure module logging.

    Args:
        None.

    Returns:
        None.
    """
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format=LOG_FORMAT, datefmt=DATE_FORMAT)


def generate_plots(frame: pd.DataFrame, output_dir: Path) -> None:
    """Generate comparison plots for all benchmark metrics.

    Args:
        frame: Comparison DataFrame.
        output_dir: Directory where PNG charts will be written.

    Returns:
        None.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    for column, title in PLOT_COLUMNS:
        if column not in frame.columns:
            continue
        plt.figure(figsize=(8, 4.5))
        plt.bar(frame["testbed"], frame[column], color=["#b45309", "#64748b", "#0f766e"])
        plt.title(title)
        plt.ylabel(title)
        plt.tight_layout()
        output_path = output_dir / f"{column}.png"
        plt.savefig(output_path, dpi=180)
        plt.close()
        LOGGER.info("Wrote plot %s", output_path)


def main() -> None:
    """Command-line entry point.

    Args:
        None.

    Returns:
        None.
    """
    configure_logging()
    parser = argparse.ArgumentParser(description="Generate plots from a comparison CSV file.")
    parser.add_argument("--input", default=str(Path("/app/data/results") / "testbed_comparison.csv"), help="Comparison CSV path.")
    parser.add_argument("--output-dir", default=str(Path("/app/data/results")), help="Output directory.")
    args = parser.parse_args()
    frame = pd.read_csv(args.input)
    generate_plots(frame, Path(args.output_dir))


if __name__ == "__main__":
    main()

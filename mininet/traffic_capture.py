"""Packet capture helpers for the Mininet IoT testbed.

The capture utilities are intentionally simple so they can be used both from the
persistent Mininet service and from ad-hoc evaluation runs.
"""

from __future__ import annotations

import argparse
import logging
import os
import time
from pathlib import Path
from typing import Iterable, List

from scapy.all import Packet, sniff, wrpcap

LOG_FORMAT = "[%(asctime)s][%(name)s][%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
LOGGER = logging.getLogger("mininet.capture")


def configure_logging() -> None:
    """Configure module logging.

    Args:
        None.

    Returns:
        None.
    """
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format=LOG_FORMAT, datefmt=DATE_FORMAT)


def capture_interface_to_pcap(interface: str, output_file: Path, duration: int) -> Path:
    """Capture packets from an interface and write them to a PCAP file.

    Args:
        interface: Network interface to capture from.
        output_file: Destination PCAP file.
        duration: Capture duration in seconds.

    Returns:
        The path to the generated PCAP file.
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)
    LOGGER.info("Capturing %s for %ss into %s", interface, duration, output_file)
    packets = sniff(iface=interface, timeout=duration)
    wrpcap(str(output_file), packets)
    return output_file


def capture_interfaces_to_directory(interfaces: Iterable[str], output_dir: Path, duration: int) -> List[Path]:
    """Capture from multiple interfaces.

    Args:
        interfaces: Interfaces to capture from.
        output_dir: Directory that will store per-interface PCAP files.
        duration: Capture duration in seconds.

    Returns:
        List of written PCAP file paths.
    """
    output_files: List[Path] = []
    for interface in interfaces:
        output_file = output_dir / f"{interface.replace('/', '_')}.pcap"
        capture_interface_to_pcap(interface, output_file, duration)
        output_files.append(output_file)
    return output_files


def main() -> None:
    """Command-line entry point.

    Args:
        None.

    Returns:
        None.
    """
    parser = argparse.ArgumentParser(description="Capture packets to a PCAP file using Scapy.")
    parser.add_argument("--interface", default="any", help="Interface to sniff.")
    parser.add_argument("--output", required=True, help="Output PCAP file path.")
    parser.add_argument("--duration", type=int, default=60, help="Capture duration in seconds.")
    args = parser.parse_args()
    configure_logging()
    capture_interface_to_pcap(args.interface, Path(args.output), args.duration)
    LOGGER.info("Capture complete")


if __name__ == "__main__":
    main()

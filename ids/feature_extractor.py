"""Feature extraction utilities for the Isolation Forest IDS.

The extractor reads PCAP files or Redis queue messages and converts network
traffic into fixed-width flow features suitable for anomaly detection.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

import pandas as pd
from scapy.all import IP, TCP, UDP, rdpcap

LOG_FORMAT = "[%(asctime)s][%(name)s][%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
LOGGER = logging.getLogger("ids.features")
FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "avg_packet_size",
    "flow_duration",
    "src_port",
    "dst_port",
    "protocol",
    "inter_arrival_time",
    "syn_flag_ratio",
    "urg_flag_ratio",
]


@dataclass
class FlowSummary:
    """Aggregated statistics for a single network flow.

    Args:
        packet_count: Number of packets in the flow.
        byte_count: Total payload size in bytes.
        avg_packet_size: Average packet size in bytes.
        flow_duration: Duration of the flow in seconds.
        src_port: Source transport port.
        dst_port: Destination transport port.
        protocol: Transport protocol number.
        inter_arrival_time: Mean inter-arrival time in seconds.
        syn_flag_ratio: Fraction of packets with SYN set.
        urg_flag_ratio: Fraction of packets with URG set.

    Returns:
        None.
    """

    packet_count: int
    byte_count: int
    avg_packet_size: float
    flow_duration: float
    src_port: int
    dst_port: int
    protocol: int
    inter_arrival_time: float
    syn_flag_ratio: float
    urg_flag_ratio: float


def configure_logging() -> None:
    """Configure module logging.

    Args:
        None.

    Returns:
        None.
    """
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format=LOG_FORMAT, datefmt=DATE_FORMAT)


def _packet_key(packet: object) -> Tuple[str, str, int, int, int]:
    """Build a stable 5-tuple for packet grouping.

    Args:
        packet: Scapy packet.

    Returns:
        Flow key tuple.
    """
    if IP not in packet:
        return ("0.0.0.0", "0.0.0.0", 0, 0, 0)
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = int(packet[IP].proto)
    src_port = 0
    dst_port = 0
    if TCP in packet:
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif UDP in packet:
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
    return (src_ip, dst_ip, src_port, dst_port, protocol)


def _summarize_flow(packets: Sequence[object]) -> FlowSummary:
    """Convert packets from one flow into feature values.

    Args:
        packets: Packets belonging to a single flow.

    Returns:
        Aggregated flow summary.
    """
    packet_count = len(packets)
    byte_count = sum(len(packet) for packet in packets)
    timestamps = [float(getattr(packet, "time", 0.0)) for packet in packets]
    durations = max(timestamps) - min(timestamps) if packet_count > 1 else 0.0
    inter_arrivals = [timestamps[index] - timestamps[index - 1] for index in range(1, len(timestamps))]
    avg_inter_arrival = sum(inter_arrivals) / len(inter_arrivals) if inter_arrivals else 0.0
    avg_packet_size = float(byte_count / packet_count) if packet_count else 0.0
    tcp_packets = [packet for packet in packets if TCP in packet]
    syn_count = sum(1 for packet in tcp_packets if int(packet[TCP].flags) & 0x02)
    urg_count = sum(1 for packet in tcp_packets if int(packet[TCP].flags) & 0x20)
    first_packet = packets[0]
    if TCP in first_packet:
        src_port = int(first_packet[TCP].sport)
        dst_port = int(first_packet[TCP].dport)
        protocol = 6
    elif UDP in first_packet:
        src_port = int(first_packet[UDP].sport)
        dst_port = int(first_packet[UDP].dport)
        protocol = 17
    elif IP in first_packet:
        src_port = 0
        dst_port = 0
        protocol = int(first_packet[IP].proto)
    else:
        src_port = 0
        dst_port = 0
        protocol = 0
    syn_flag_ratio = float(syn_count / packet_count) if packet_count else 0.0
    urg_flag_ratio = float(urg_count / packet_count) if packet_count else 0.0
    return FlowSummary(
        packet_count=packet_count,
        byte_count=byte_count,
        avg_packet_size=avg_packet_size,
        flow_duration=float(durations),
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        inter_arrival_time=float(avg_inter_arrival),
        syn_flag_ratio=syn_flag_ratio,
        urg_flag_ratio=urg_flag_ratio,
    )


def extract_features_from_packets(packets: Sequence[object]) -> pd.DataFrame:
    """Convert a packet sequence into a feature table.

    Args:
        packets: Sequence of Scapy packets.

    Returns:
        DataFrame with one row per flow.
    """
    grouped: Dict[Tuple[str, str, int, int, int], List[object]] = defaultdict(list)
    for packet in packets:
        grouped[_packet_key(packet)].append(packet)
    rows = [asdict(_summarize_flow(flow_packets)) for flow_packets in grouped.values() if flow_packets]
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)


def extract_features_from_pcap(pcap_path: Path) -> pd.DataFrame:
    """Extract flow features from a PCAP file.

    Args:
        pcap_path: Path to a PCAP file.

    Returns:
        Feature DataFrame.
    """
    packets = rdpcap(str(pcap_path))
    return extract_features_from_packets(packets)


def extract_features_from_pcaps(pcap_paths: Iterable[Path]) -> pd.DataFrame:
    """Extract features from multiple PCAP files.

    Args:
        pcap_paths: Iterable of PCAP files.

    Returns:
        Combined feature DataFrame.
    """
    frames = [extract_features_from_pcap(path) for path in pcap_paths if path.exists()]
    if not frames:
        return pd.DataFrame(columns=FEATURE_COLUMNS)
    return pd.concat(frames, ignore_index=True)


def extract_features_from_directory(pcap_dir: Path) -> pd.DataFrame:
    """Extract features from all PCAP files in a directory.

    Args:
        pcap_dir: Directory containing PCAP files.

    Returns:
        Combined feature DataFrame.
    """
    return extract_features_from_pcaps(sorted(pcap_dir.glob("*.pcap")))


def save_features(features: pd.DataFrame, output_path: Path, label: int | None = None) -> Path:
    """Save a feature table to CSV.

    Args:
        features: Feature DataFrame.
        output_path: Destination CSV file.
        label: Optional label to attach to all rows.

    Returns:
        Path to the written CSV file.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    frame = features.copy()
    if label is not None:
        frame["label"] = label
    frame.to_csv(output_path, index=False)
    return output_path


def main() -> None:
    """Command-line entry point.

    Args:
        None.

    Returns:
        None.
    """
    configure_logging()
    parser = argparse.ArgumentParser(description="Extract IDS features from PCAP files.")
    parser.add_argument("--input", required=True, help="Input PCAP file or directory.")
    parser.add_argument("--output", required=True, help="Output CSV file.")
    parser.add_argument("--label", type=int, default=None, help="Optional label to apply to all rows.")
    args = parser.parse_args()

    input_path = Path(args.input)
    if input_path.is_dir():
        features = extract_features_from_directory(input_path)
    else:
        features = extract_features_from_pcap(input_path)
    save_features(features, Path(args.output), args.label)
    LOGGER.info("Extracted %s feature rows into %s", len(features), args.output)


if __name__ == "__main__":
    main()

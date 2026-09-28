"""Mininet-based virtual IoT topology and traffic generation service.

This module creates a star topology with constrained IoT hosts, a command and
control server, and persistent packet captures so the IDS can train and evaluate
on real traffic traces inside Docker.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.topo import Topo

from traffic_capture import capture_interface_to_pcap

LOG_FORMAT = "[%(asctime)s][%(name)s][%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
LOGGER = logging.getLogger("mininet.topology")


class IoTStarTopology(Topo):
    """Custom star topology for a virtual IoT testbed.

    Args:
        node_count: Number of IoT hosts to attach to the switch.

    Returns:
        None.
    """

    def build(self, node_count: int = 10) -> None:
        """Build the topology graph.

        Args:
            node_count: Number of IoT nodes to create.

        Returns:
            None.
        """
        switch = self.addSwitch("s1")
        for index in range(1, node_count + 1):
            host = self.addHost(f"h{index}", ip=f"10.0.0.{index}/24")
            self.addLink(host, switch, bw=10, delay="5ms")
        c2_server = self.addHost("c2", ip="10.0.0.254/24")
        self.addLink(c2_server, switch, bw=10, delay="5ms")


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
        name: Environment variable name.
        default: Default value when the variable is missing or invalid.

    Returns:
        Parsed integer value.
    """
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        LOGGER.warning("Invalid integer for %s, using %s", name, default)
        return default


def get_path(name: str, default: str) -> Path:
    """Read a path from the environment.

    Args:
        name: Environment variable name.
        default: Default path to use when missing.

    Returns:
        Resolved path object.
    """
    return Path(os.getenv(name, default)).resolve()


def ensure_directories(paths: Iterable[Path]) -> None:
    """Create output directories when needed.

    Args:
        paths: Paths to create.

    Returns:
        None.
    """
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)


def export_topology_json(net: Mininet, output_file: Path) -> Dict[str, object]:
    """Export the current Mininet topology to JSON.

    Args:
        net: Active Mininet instance.
        output_file: JSON destination path.

    Returns:
        Topology dictionary that was written to disk.
    """
    hosts = []
    for host in net.hosts:
        hosts.append(
            {
                "name": host.name,
                "ip": host.IP(),
                "mac": host.MAC(),
                "interfaces": [intf.name for intf in host.intfList()],
            }
        )

    links = []
    for link in net.links:
        links.append(
            {
                "node1": link.intf1.node.name,
                "node2": link.intf2.node.name,
            }
        )

    topology = {
        "network_size": len([host for host in net.hosts if host.name.startswith("h")]),
        "switches": [switch.name for switch in net.switches],
        "hosts": hosts,
        "links": links,
        "timestamp": time.time(),
    }
    output_file.write_text(json.dumps(topology, indent=2), encoding="utf-8")
    return topology


def start_packet_captures(net: Mininet, pcap_dir: Path) -> List[subprocess.Popen[str]]:
    """Start tcpdump captures inside each Mininet host namespace.

    Args:
        net: Active Mininet instance.
        pcap_dir: Directory where packet captures will be stored.

    Returns:
        List of tcpdump subprocess handles.
    """
    captures: List[subprocess.Popen[str]] = []
    for host in net.hosts:
        pcap_file = pcap_dir / f"{host.name}.pcap"
        command = f"tcpdump -U -i any -w {pcap_file} >/tmp/{host.name}_tcpdump.log 2>&1"
        capture = host.popen(["bash", "-lc", command])
        captures.append(capture)
        LOGGER.info("Started capture for %s -> %s", host.name, pcap_file)
    return captures


def stop_packet_captures(captures: Iterable[subprocess.Popen[str]]) -> None:
    """Terminate all tcpdump capture processes.

    Args:
        captures: Iterable of subprocess handles.

    Returns:
        None.
    """
    for capture in captures:
        try:
            capture.terminate()
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Failed to terminate capture cleanly: %s", exc)


def generate_normal_traffic(net: Mininet, interval_seconds: int) -> None:
    """Generate benign traffic between IoT nodes and the C2 host.

    Args:
        net: Active Mininet instance.
        interval_seconds: Delay between traffic bursts.

    Returns:
        None.
    """
    c2_host = net.get("c2")
    while True:
        for host in net.hosts:
            if host.name == "c2":
                continue
            host.cmd(f"ping -c 1 -W 1 {c2_host.IP()}")
            host.cmd(f"ping -c 1 -W 1 {host.IP()}")
        time.sleep(interval_seconds)


def build_network(node_count: int) -> Mininet:
    """Create and start the Mininet network.

    Args:
        node_count: Number of IoT hosts to create.

    Returns:
        Started Mininet network.
    """
    topo = IoTStarTopology(node_count=node_count)
    net = Mininet(
        topo=topo,
        controller=Controller,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True,
        cleanup=True,
    )
    net.start()
    return net


def serve_topology() -> None:
    """Run the persistent Mininet service.

    Args:
        None.

    Returns:
        None.
    """
    configure_logging()
    node_count = get_env_int("NETWORK_SIZE", 10)
    capture_duration = get_env_int("CAPTURE_DURATION", 120)
    capture_interval = max(5, min(15, capture_duration // 4 or 5))
    data_dir = Path("/app/data")
    pcap_dir = get_path("PCAP_DIR", str(data_dir / "pcap"))
    results_dir = get_path("RESULTS_DIR", str(data_dir / "results"))
    topology_file = get_path("TOPOLOGY_FILE", str(results_dir / "topology.json"))
    ensure_directories([pcap_dir, results_dir])

    net = build_network(node_count)
    export_topology_json(net, topology_file)
    Path("/tmp/mininet.ready").write_text("ready", encoding="utf-8")
    LOGGER.info("Topology exported to %s", topology_file)

    captures = start_packet_captures(net, pcap_dir)
    traffic_thread = threading.Thread(
        target=generate_normal_traffic,
        args=(net, capture_interval),
        daemon=True,
    )
    traffic_thread.start()

    stop_event = threading.Event()

    def handle_signal(_signum: int, _frame: object) -> None:
        """Request a graceful shutdown.

        Args:
            _signum: Signal number.
            _frame: Current stack frame.

        Returns:
            None.
        """
        stop_event.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        while not stop_event.is_set():
            time.sleep(1)
    finally:
        stop_packet_captures(captures)
        net.stop()
        LOGGER.info("Mininet topology stopped")


def main() -> None:
    """Command-line entry point.

    Args:
        None.

    Returns:
        None.
    """
    parser = argparse.ArgumentParser(description="Start the virtual IoT Mininet topology.")
    parser.add_argument("--serve", action="store_true", help="Run the topology as a persistent service.")
    args = parser.parse_args()
    if args.serve:
        serve_topology()
    else:
        LOGGER.info("Nothing to do without --serve; use the service entrypoint.")


if __name__ == "__main__":
    main()

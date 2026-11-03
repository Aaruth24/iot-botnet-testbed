"""
Attack-TRAFFIC generator for IDS evaluation.

This service reproduces the *network-flow signatures* of well-known IoT
attack phases so that the anomaly-based IDS can be trained and scored
against a labelled ground truth. It is a statistical traffic synthesiser,
confined to the testbed's internal Redis stream.

It does NOT:
  - run real exploits or contain any CVE payloads,
  - scan, connect to, or attack any real/external host,
  - brute-force real credentials or self-propagate.

Each generated flow is explicitly labelled label="attack" with its
attack_type, which is used only for offline evaluation of detector quality.

Supported signatures (all drawn from public IDS literature):
  - scan        : horizontal port scan — one source, many destination ports,
                  tiny payloads, very short flows (high fan-out).
  - syn_flood   : TCP SYN flood — enormous packet rate to a single port,
                  minimal bytes per packet.
  - mqtt_flood  : connection flood against the MQTT broker (tcp/1883).
  - dos_udp     : UDP volumetric flood — large byte rate, one destination.
"""

from __future__ import annotations

import json
import os
import random
import time

import sys

sys.path.insert(0, "/app/common")
from testbed import (  # noqa: E402
    get_redis,
    wait_for_redis,
    make_flow,
    publish_flow,
    log_event,
    K_CONTROL_ATTACK,
    ATTACK_TYPES,
)

ATTACKER_IP = os.getenv("ATTACKER_IP", "10.10.0.66")
TARGET_SUBNET = os.getenv("TARGET_SUBNET", "10.10.0")
BROKER_IP = os.getenv("BROKER_IP", "10.10.0.2")


def _targets(n: int = 20) -> list[str]:
    return [f"{TARGET_SUBNET}.{i}" for i in range(2, 2 + n)]


def gen_scan(r) -> None:
    """Horizontal/vertical scan: one src hits many ports across many hosts."""
    victim = random.choice(_targets())
    for port in random.sample(range(1, 10000), random.randint(40, 120)):
        flow = make_flow(
            src=ATTACKER_IP, dst=victim, dst_port=port, proto="TCP",
            packets=random.randint(1, 2), n_bytes=random.randint(40, 64),
            duration=random.uniform(0.001, 0.02),
            device_type="attacker", label="attack", attack_type="scan",
            src_port=random.randint(40000, 60000),
        )
        publish_flow(r, flow)


def gen_syn_flood(r) -> None:
    """SYN flood: massive packet rate, tiny packets, single victim/port."""
    victim = random.choice(_targets())
    for _ in range(random.randint(30, 80)):
        packets = random.randint(400, 3000)
        flow = make_flow(
            src=ATTACKER_IP, dst=victim, dst_port=random.choice([80, 1883, 8080, 23]),
            proto="TCP", packets=packets, n_bytes=packets * random.randint(40, 60),
            duration=random.uniform(0.05, 0.4),
            device_type="attacker", label="attack", attack_type="syn_flood",
            src_port=random.randint(1024, 65000),
        )
        publish_flow(r, flow)


def gen_mqtt_flood(r) -> None:
    """Connection flood against the broker: many short TCP/1883 flows."""
    for _ in range(random.randint(60, 150)):
        packets = random.randint(5, 40)
        flow = make_flow(
            src=ATTACKER_IP, dst=BROKER_IP, dst_port=1883, proto="TCP",
            packets=packets, n_bytes=packets * random.randint(50, 90),
            duration=random.uniform(0.002, 0.05),
            device_type="attacker", label="attack", attack_type="mqtt_flood",
            src_port=random.randint(1024, 65000),
        )
        publish_flow(r, flow)


def gen_dos_udp(r) -> None:
    """UDP volumetric flood: high byte rate to a single victim."""
    victim = random.choice(_targets())
    for _ in range(random.randint(25, 70)):
        packets = random.randint(200, 1500)
        flow = make_flow(
            src=ATTACKER_IP, dst=victim, dst_port=random.choice([53, 123, 19, 1900]),
            proto="UDP", packets=packets, n_bytes=packets * random.randint(500, 1400),
            duration=random.uniform(0.1, 0.6),
            device_type="attacker", label="attack", attack_type="dos_udp",
            src_port=random.randint(1024, 65000),
        )
        publish_flow(r, flow)


GENERATORS = {
    "scan": gen_scan,
    "syn_flood": gen_syn_flood,
    "mqtt_flood": gen_mqtt_flood,
    "dos_udp": gen_dos_udp,
}


def read_control(r) -> dict:
    raw = r.get(K_CONTROL_ATTACK)
    if not raw:
        return {"active": False}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"active": False}


def main() -> None:
    r = get_redis()
    wait_for_redis(r)
    r.hset("inventory:devices", "attacker-01", f"attacker|{ATTACKER_IP}")
    log_event(r, "info", "attack-sim", "ready (idle)")
    print("[attack-sim] ready; waiting for control commands", flush=True)

    announced = None
    while True:
        ctrl = read_control(r)
        if ctrl.get("active"):
            atype = ctrl.get("type", "scan")
            if atype == "mixed":
                atype = random.choice(ATTACK_TYPES)
            if atype not in GENERATORS:
                atype = "scan"
            intensity = float(ctrl.get("intensity", 1.0))

            if announced != ctrl.get("type"):
                log_event(r, "attack", "attack-sim", f"launching '{ctrl.get('type')}' traffic")
                announced = ctrl.get("type")

            bursts = max(1, int(round(intensity)))
            for _ in range(bursts):
                GENERATORS[atype](r)

            # auto-stop after the requested duration
            started = ctrl.get("started", 0)
            duration = ctrl.get("duration", 0)
            if duration and started and (time.time() - started) > duration:
                r.set(K_CONTROL_ATTACK, json.dumps({"active": False}))
                log_event(r, "info", "attack-sim", "attack window elapsed; stopping")
                announced = None
            time.sleep(random.uniform(0.4, 0.9))
        else:
            announced = None
            time.sleep(1.0)


if __name__ == "__main__":
    main()

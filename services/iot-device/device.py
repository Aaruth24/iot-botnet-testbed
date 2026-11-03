"""
Simulated IoT device.

Each container of this image impersonates one IoT device type. It does two
real, observable things:

  1. Publishes realistic telemetry to the Mosquitto MQTT broker
     (genuine IoT protocol traffic on tcp/1883).
  2. Emits a corresponding network-FLOW RECORD to Redis so the IDS has a
     uniform, reproducible stream of benign traffic to learn from.

Traffic profiles differ per device type (a camera is chattier than a door
sensor), which gives the Isolation Forest a realistic "normal" baseline.
"""

from __future__ import annotations

import os
import random
import socket
import sys
import time

import paho.mqtt.client as mqtt

sys.path.insert(0, "/app/common")
from testbed import get_redis, wait_for_redis, make_flow, publish_flow, log_event  # noqa: E402

DEVICE_TYPE = os.getenv("DEVICE_TYPE", "sensor")
DEVICE_ID = os.getenv("DEVICE_ID", socket.gethostname())
MQTT_HOST = os.getenv("MQTT_HOST", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))

# per-type behaviour: publish interval (s), payload byte range, packets/flow
PROFILES = {
    "temp_sensor":  {"interval": (4.0, 7.0),  "bytes": (60, 140),   "packets": (2, 5),   "topic": "iot/sensors/temperature"},
    "humidity":     {"interval": (5.0, 9.0),  "bytes": (60, 150),   "packets": (2, 5),   "topic": "iot/sensors/humidity"},
    "smart_plug":   {"interval": (3.0, 6.0),  "bytes": (80, 200),   "packets": (3, 6),   "topic": "iot/actuators/plug"},
    "door_lock":    {"interval": (8.0, 15.0), "bytes": (50, 120),   "packets": (2, 4),   "topic": "iot/security/door"},
    "ip_camera":    {"interval": (1.0, 2.5),  "bytes": (800, 2200), "packets": (12, 30), "topic": "iot/camera/stream"},
    "thermostat":   {"interval": (6.0, 10.0), "bytes": (70, 160),   "packets": (2, 5),   "topic": "iot/actuators/thermostat"},
}
PROFILE = PROFILES.get(DEVICE_TYPE, PROFILES["temp_sensor"])


def local_ip() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "10.10.0.0"


def reading(device_type: str) -> str:
    if device_type in ("temp_sensor", "thermostat"):
        return f'{{"device":"{DEVICE_ID}","temp_c":{round(random.uniform(18, 31), 2)}}}'
    if device_type == "humidity":
        return f'{{"device":"{DEVICE_ID}","rh":{round(random.uniform(30, 70), 1)}}}'
    if device_type == "smart_plug":
        return f'{{"device":"{DEVICE_ID}","watts":{round(random.uniform(5, 1800), 1)},"on":{random.choice(["true","false"])}}}'
    if device_type == "door_lock":
        return f'{{"device":"{DEVICE_ID}","state":"{random.choice(["locked","unlocked"])}"}}'
    if device_type == "ip_camera":
        return f'{{"device":"{DEVICE_ID}","frame":{random.randint(1, 99999)},"motion":{random.choice(["true","false"])}}}'
    return f'{{"device":"{DEVICE_ID}","value":{round(random.uniform(0, 100), 2)}}}'


def main() -> None:
    r = get_redis()
    wait_for_redis(r)
    ip = local_ip()
    broker_ip = ""
    try:
        broker_ip = socket.gethostbyname(MQTT_HOST)
    except Exception:
        broker_ip = "10.10.0.2"

    client = mqtt.Client(client_id=DEVICE_ID, clean_session=True)
    connected = False
    for attempt in range(30):
        try:
            client.connect(MQTT_HOST, MQTT_PORT, keepalive=30)
            client.loop_start()
            connected = True
            break
        except Exception as exc:  # broker may still be booting
            print(f"[{DEVICE_ID}] broker not ready ({exc}); retry {attempt}", flush=True)
            time.sleep(2)
    if not connected:
        print(f"[{DEVICE_ID}] could not reach broker; emitting flow records only", flush=True)

    # register this device in the topology inventory
    r.hset("inventory:devices", DEVICE_ID, f"{DEVICE_TYPE}|{ip}")
    log_event(r, "info", DEVICE_ID, f"{DEVICE_TYPE} online at {ip}")
    print(f"[{DEVICE_ID}] {DEVICE_TYPE} publishing to {MQTT_HOST}:{MQTT_PORT}", flush=True)

    while True:
        payload = reading(DEVICE_TYPE)
        n_bytes = max(len(payload), random.randint(*PROFILE["bytes"]))
        packets = random.randint(*PROFILE["packets"])
        # small jitter makes the flow duration realistic
        duration = random.uniform(0.02, 0.25)

        if connected:
            try:
                client.publish(PROFILE["topic"], payload, qos=0)
            except Exception as exc:
                print(f"[{DEVICE_ID}] publish failed: {exc}", flush=True)

        flow = make_flow(
            src=ip,
            dst=broker_ip,
            dst_port=MQTT_PORT,
            proto="MQTT",
            packets=packets,
            n_bytes=n_bytes,
            duration=duration,
            device_type=DEVICE_TYPE,
            label="normal",
            src_port=random.randint(32768, 60999),
        )
        publish_flow(r, flow)

        time.sleep(random.uniform(*PROFILE["interval"]))


if __name__ == "__main__":
    main()

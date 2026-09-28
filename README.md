# Docker-Based Virtual IoT Testbed for Botnet Attack Simulation and Intrusion Detection System Evaluation

## Linux Quick Start

### Prerequisites

- Ubuntu 20.04+, Debian 11+, or another modern Linux distribution
- Docker Engine 24+ and the Docker Compose plugin
- Make and Git

### One-time setup

```bash
git clone <your-repo-url>
cd iot-botnet-testbed
make setup
```

If Docker socket permissions fail, run `sudo usermod -aG docker $USER` and then `newgrp docker`.

### Run everything

```bash
make up
make dashboard
```

The dashboard is available at `http://localhost:5000`. Run `make run` to execute the capture, training, attack, and evaluation pipeline. Stop the stack with `make down`.

### Offline demo

Open [dashboard/static/index.html](dashboard/static/index.html) directly in a browser. The dashboard falls back to local demo data and its Launch Attack control runs a complete animated simulation without Docker.

A Docker-based virtual IoT security lab for simulating Mirai-style botnet attacks and evaluating an Isolation Forest intrusion detection system against multiple testbed styles.

## Project Objectives

- Build a scalable IoT testbed using Docker and Mininet.
- Simulate Mirai-like attack behavior with scan, infect, report, and attack stages.
- Train and evaluate an Isolation Forest IDS on captured traffic features.
- Compare Docker-based, VM-based, and hardware-based testbed characteristics.
- Visualize topology, attacks, alerts, and metrics through a Flask dashboard.

## System Overview

The system is split into four services:

- `mininet` creates the virtual IoT network and captures traffic.
- `botnet` runs the Mirai simulation and attack modules.
- `ids` extracts flow features, trains the Isolation Forest model, and watches for anomalies.
- `dashboard` exposes REST endpoints and a self-contained live UI.

Supporting services include `influxdb` for metrics storage and `mosquitto` for MQTT-based IoT simulation.

For a deeper design breakdown, see [docs/architecture.md](docs/architecture.md).

## Prerequisites

- Docker Engine or Docker Desktop with Compose support
- Python 3.10+ if you plan to run scripts outside Docker
- Linux or WSL2 for reliable Mininet support

## Repository Layout

- [docker-compose.yml](docker-compose.yml)
- [requirements.txt](requirements.txt)
- [mininet/topology.py](mininet/topology.py)
- [botnet/mirai_sim.py](botnet/mirai_sim.py)
- [ids/ids_engine.py](ids/ids_engine.py)
- [dashboard/app.py](dashboard/app.py)
- [evaluation/compare_testbeds.py](evaluation/compare_testbeds.py)
- [scripts/run_experiment.sh](scripts/run_experiment.sh)
- [docs/setup_guide.md](docs/setup_guide.md)

## Setup

1. Review `.env` and adjust `NETWORK_SIZE`, `TARGET_IP`, `ATTACK_TYPE`, and `PACKET_RATE` if needed.
2. Build the containers:

```bash
docker compose build
```

3. Start the full stack:

```bash
docker compose up -d
```

4. Confirm the dashboard is healthy:

```bash
curl http://localhost:5000/api/health
```

## Running on Linux

### Prerequisites

- Docker Engine 24+ (not Docker Desktop)
- Docker Compose plugin (`sudo apt install docker-compose-plugin`)
- Git

### Quick start

```bash
git clone <your-repo>
cd iot-botnet-testbed
make setup
make up
make run
# Dashboard opens at http://localhost:5000
```

If you get permission errors on the Docker socket:

```bash
sudo usermod -aG docker $USER
newgrp docker
```

## Run the Full Experiment

Use the scripted pipeline to run the complete capture, training, attack, and evaluation flow:

```bash
bash scripts/run_experiment.sh
```

The script performs these steps:

1. Starts the Docker stack.
2. Waits for the dashboard to become healthy.
3. Collects normal traffic.
4. Trains the Isolation Forest IDS.
5. Launches the Mirai attack simulation.
6. Generates labeled evaluation data.
7. Computes IDS metrics and comparison artifacts.
8. Produces a summary file in `data/results/`.

## View the Dashboard

Open the dashboard in a browser at:

```text
http://localhost:5000
```

The dashboard shows:

- Live topology graph
- Attack event feed
- IDS metrics cards
- Alert stream
- Docker vs VM vs Hardware comparison chart

## Expected Results

After a successful run, you should find artifacts like:

- `data/results/topology.json`
- `data/results/attack_log.csv`
- `data/results/alerts.json`
- `data/results/metrics.json`
- `data/results/testbed_comparison.csv`
- `data/results/*.png` comparison plots

Expected behavior:

- Docker should show the fastest startup and the lowest resource overhead.
- VM-based setups should be more expensive than Docker but easier to isolate.
- Hardware-based setups should remain the least scalable and slowest to provision.
- IDS accuracy should improve after training on clean normal traffic captures.

## Screenshots

Add screenshots of the dashboard, topology graph, attack feed, and comparison plots from `data/results/` or your final report folder.

## Troubleshooting

- If Mininet fails to start, verify that you are using Linux or WSL2 and that Docker is running in privileged mode for the `mininet` service.
- If the IDS has no model yet, run the training step first or let `scripts/run_experiment.sh` create one automatically.
- If raw packet sending fails, confirm that the container has network permissions and that you are running the attack from inside Docker.
- If the dashboard is blank, check `docker compose logs dashboard` and confirm that `data/results/topology.json` and `data/results/metrics.json` exist.
- If PCAP files are empty, give the Mininet service enough time to generate normal traffic before training.

## References

- Mirai botnet paper: Antonakakis et al., "Understanding the Mirai Botnet", USENIX Security 2017.
- Isolation Forest paper: Liu, Ting, and Zhou, "Isolation Forest", ICDM 2008.
- N-BaIoT dataset: Meidan et al., "N-BaIoT: Network-based Detection of IoT Botnet Attacks Using Deep Autoencoders".
- CIC-IoT dataset family for IoT traffic benchmarking and comparison.

## Notes

This repository is designed to be a complete final-year project scaffold. You can extend it with your own dataset, tune the Isolation Forest threshold, and replace the default benchmark profiles with real hardware and VM measurements.

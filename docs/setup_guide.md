# Setup Guide

## Prerequisites
- Docker Desktop or Docker Engine with Compose support
- Python 3.10+ if you want to run scripts locally outside Docker
- Linux or WSL2 is strongly recommended for Mininet

## Initial Setup
1. Open the project root in VS Code.
2. Review `.env` and adjust values such as `NETWORK_SIZE`, `TARGET_IP`, and `PACKET_RATE`.
3. Build the services:

```bash
docker compose build
```

4. Start the stack:

```bash
docker compose up -d
```

## Run the Full Experiment
Use the scripted pipeline:

```bash
bash scripts/run_experiment.sh
```

The script will:
- start the Docker stack,
- wait for the dashboard to become healthy,
- capture normal traffic,
- train the Isolation Forest IDS,
- launch the Mirai simulation attack,
- evaluate the IDS,
- generate comparison plots and summary files.

## View the Dashboard
Open the dashboard at:

```text
http://localhost:5000
```

## Shutdown
Stop all services and remove named volumes when needed:

```bash
bash scripts/cleanup.sh
```

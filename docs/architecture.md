# Architecture

The project is organized as a Docker-based IoT testbed with four main layers.

## 1. Network Emulation
The `mininet` service creates a star topology with constrained IoT hosts and a command-and-control node. It produces PCAP captures and exports topology metadata as JSON.

## 2. Botnet Simulation
The `botnet` service implements a Mirai-style lifecycle:
- scan the network range,
- simulate infection using default credentials,
- report infected nodes,
- launch SYN, UDP, or HTTP flood attacks.

## 3. IDS Layer
The `ids` service extracts flow features from PCAPs, trains an Isolation Forest on normal traffic, and watches for anomalies in real time. Alerts are stored as JSON and published to the dashboard.

## 4. Dashboard and Evaluation
The `dashboard` service exposes REST endpoints and a real-time React UI. The `evaluation` scripts generate comparison tables and plots for hardware, VM, and Docker-based testbeds.

## Data Flow
1. Mininet generates traffic and writes PCAP files.
2. IDS converts PCAPs into flow features.
3. Isolation Forest scores the flow features and emits alerts.
4. The dashboard reads alerts, topology, attack logs, and metrics.
5. Evaluation scripts compare the resulting metrics across testbed types.

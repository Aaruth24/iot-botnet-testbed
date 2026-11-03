# Docker-Based Virtual IoT Security Testbed
### Botnet-traffic simulation & anomaly-based Intrusion Detection System (IDS) evaluation

A fully containerised, reproducible research testbed that builds a virtual IoT
network, generates both **benign** and **attack** network traffic, detects
anomalies with an **Isolation-Forest IDS**, and visualises everything on a
**live web dashboard** — all with a single `docker compose up`.

> **Scope & ethics.** This is a *defensive security research* project. Every
> component runs inside an **isolated internal Docker network**. The attack
> component is a **traffic-pattern generator**: it synthesises the
> *network-flow signatures* of common IoT attacks (scan, SYN flood, MQTT
> flood, UDP flood) so an IDS can be trained and scored against a known ground
> truth. There is **no real exploit code, no self-propagating malware, no
> scanning of real/external hosts, and no credential attacks** anywhere in
> this repository — the same principle behind public IDS datasets such as
> BoT-IoT, N-BaIoT, IoT-23 and CICIoT2023.

---

## 1. Why this is an upgrade over the original project

| Area | Original project | This version |
|---|---|---|
| Orchestration | Mininet + manual steps | **Pure Docker Compose** — one command, runs on any Linux box |
| Devices | Few / static | **6 device types** with distinct, realistic traffic profiles |
| Message bus | — | **Redis streams** decouple every service (clean, scalable) |
| IDS features | Raw per-flow | Per-flow **+ rolling source-context features** (catches scans/floods) |
| IDS lifecycle | Train once | **Live training / detecting modes**, model persisted to disk |
| Dashboard | Static Flask page | **Live SPA**: topology, throughput chart, confusion matrix, alerts, event log, controls |
| Experiments | Manual | **One-click automated pipeline** → writes all result files |
| Reproducibility | OS-dependent | **Container-isolated & deterministic** (seeded model) |
| Metrics | Reported | **Computed live** from a streaming confusion matrix |

Everything from the paper is preserved (MQTT/Mosquitto, Mirai-style attack
*phases*, Isolation Forest, metric storage, Flask dashboard, testbed
comparison) — just made to actually run, cross-platform, with better tooling.

---

## 2. Architecture

```
                         ┌──────────────────────────────────────────┐
                         │          internal Docker network          │
                         │               10.10.0.0/24                 │
  Browser  ── :8080 ──▶  │  ┌───────────┐     MQTT      ┌───────────┐ │
                         │  │ dashboard │                │ mosquitto │ │
                         │  └─────┬─────┘                └─────▲─────┘ │
                         │        │ reads                      │ pub   │
                         │        ▼                      ┌──────┴─────┐ │
                         │  ┌───────────┐   flow stream  │ 6 × IoT    │ │
                         │  │   redis    │◀───────────────│ devices    │ │
                         │  │  (streams) │                └────────────┘ │
                         │  └─────▲──┬───┘                ┌────────────┐ │
                         │  flows │  │ control            │ attack-sim │ │
                         │        │  └───────────────────▶│ (synthetic)│ │
                         │  ┌─────┴──────┐                └────────────┘ │
                         │  │    ids     │  Isolation Forest             │
                         │  │ (sklearn)  │  → alerts + metrics           │
                         │  └────────────┘                               │
                         │  ┌──────────────┐  runs the full experiment   │
                         │  │ orchestrator │  → writes ./data/*          │
                         │  └──────────────┘                             │
                         └──────────────────────────────────────────────┘
```

**Services**

- **redis** – message bus + shared state (flow stream, alerts, metrics, control).
- **mosquitto** – real MQTT broker (tcp/1883) the devices publish to.
- **dev-*** (×6) – simulated IoT devices (temp, humidity, plug, door lock, IP camera, thermostat). Each publishes MQTT telemetry and emits a flow record.
- **attack-sim** – synthetic attack-traffic generator (scan / syn_flood / mqtt_flood / dos_udp).
- **ids** – Isolation-Forest engine: feature extraction, training, scoring, live metrics.
- **orchestrator** – automated experiment pipeline and report writer.
- **dashboard** – Flask REST API + single-page live web UI.

---

## 3. Requirements

- Linux (also works on macOS / Windows with Docker Desktop)
- **Docker Engine 20.10+** and the **Docker Compose plugin** (`docker compose`)

Check:
```bash
docker --version
docker compose version
```

---

## 4. Quick start

### Option A — full Dockerized testbed (Linux)
```bash
cd iot-security-testbed
./run-linux.sh           # checks Docker, builds, starts everything
# or:  docker compose up --build -d
```
`run-linux.sh` verifies Docker is installed and running and prints the exact
install commands for Ubuntu/Debian, Fedora and Arch if anything is missing.

### Option B — offline demo (no Docker, no internet)
For a presentation/viva, open the self-contained page in any browser:
```bash
xdg-open demo/testbed-demo.html
```
It runs the entire testbed as a live in-browser simulation — see `demo/README.md`.

### Then

Open the dashboard:

```
http://localhost:8080
```

Then either click **▶ Run full experiment** in the UI, or:

```bash
./scripts/demo.sh
```

Shut down:

```bash
docker compose down          # keep data
docker compose down -v       # also wipe redis volume
```

### Handy `make` shortcuts
```bash
make up           # build + start everything
make experiment   # trigger the automated pipeline
make attack       # fire a 30s port-scan for a quick demo
make stop         # stop attack traffic
make logs         # follow all logs
make reports      # list result files
make down         # stop
```

---

## 5. Using the dashboard

- **KPI row** – live accuracy, precision, recall, F1, false-positive rate, detection time.
- **Controls** – run the full experiment, launch/stop specific attacks, switch the IDS between *training* and *detecting*.
- **Virtual IoT network** – topology of devices, broker and attacker.
- **Flow throughput** – benign vs attack flows per second.
- **Confusion matrix** – live TP / FP / TN / FN.
- **IDS alerts** – each flagged flow, marked true-positive or false-positive.
- **Live network flows** – raw flow feed.
- **Testbed comparison** – Docker (measured) vs VM / hardware (reference).
- **Event log** – what every service is doing.

### Manual flow (without the one-click pipeline)
1. **Train IDS** → collects benign traffic, fits the model, switches to detecting.
2. **Launch traffic** (pick a signature) → watch alerts + the confusion matrix fill in.
3. **Stop** when done.

---

## 6. The automated experiment pipeline

`orchestrator` reproduces the paper's methodology end-to-end:

1. **Baseline** – collect benign IoT traffic (default 40 s).
2. **Train** – fit the Isolation Forest + scaler on benign flows; persist to `/data/ids_model.joblib`.
3. **Attack** – replay each attack signature while benign traffic continues.
4. **Evaluate** – the IDS scores every flow against ground truth (default 20 s window).
5. **Report** – write result files to `./data/`:

| File | Contents |
|---|---|
| `topology.json` | nodes & edges of the virtual network |
| `attack_log.csv` | every alert with verdict |
| `alerts.json` | full alert objects |
| `metrics.json` | final confusion matrix + scores |
| `testbed_comparison.csv` | Docker vs VM vs hardware |

Timings are configurable via `.env` (copy `.env.example`).

---

## 7. How detection works

Each flow becomes a feature vector:

- **Base (per-flow):** bytes, packets, duration, packet rate, byte rate, average packet size, destination port, protocol.
- **Context (rolling, per source IP over a 30 s window):** distinct destination ports, flow count.

The context features are what make **port scans** (many distinct ports from one
source) and **floods** (huge flow counts / packet rates) clearly separable from
a steady IoT baseline. An **Isolation Forest** (200 trees, seeded) is fitted on
benign traffic only; at inference a flow whose anomaly score drops below the
decision boundary is flagged. Ground-truth labels drive a **streaming confusion
matrix** for accuracy / precision / recall / F1 / FPR and mean detection
latency — exactly the metrics in the paper.

---

### Reproduce the detection result without Docker

A self-contained validator drives the **real** feature-extraction and
Isolation-Forest code against simulated benign + attack flows:

```bash
pip install -r services/ids/requirements.txt
python3 tools/validate.py
```

Typical output (seeded, deterministic):

```
 accuracy   90.9 %   precision 93.7 %   recall 87.9 %
 F1-score   90.7 %   false-positive 6.1 %
```

> **Operating point / honesty note.** The false-positive rate tracks the
> `IDS_CONTAMINATION` hyperparameter (Isolation Forest sets its decision
> threshold from it). Lower it (e.g. `0.03`) for fewer false alarms at some
> cost to recall; raise it for higher recall. Report the numbers **your own
> run** produces — don't copy the abstract's target figures. Change it live
> with `IDS_CONTAMINATION=0.03 docker compose up -d ids`.

### Evaluate on a REAL public dataset (the key credibility upgrade)

Run the *same* Isolation-Forest IDS on real labelled IoT traffic — CICIoT2023,
BoT-IoT, N-BaIoT or IoT-23 — and report those numbers next to the live testbed:

```bash
pip install -r services/ids/requirements.txt pandas

# point it at a real dataset CSV you downloaded:
python3 tools/evaluate_dataset.py --csv CICIoT2023.csv

# no dataset yet? it generates a labelled CSV and evaluates it out of the box:
python3 tools/evaluate_dataset.py --synthesize --rows 20000
```

It auto-detects the label column, trains on benign rows only, scores everything,
and prints accuracy / precision / recall / F1 / FPR + a confusion matrix. This
turns the project from "a simulator" into "a testbed **and** a detector evaluated
on real-world attack data".

### What the live demo adds (`demo/testbed-demo.html`)

The browser demo now also computes, live from the IDS scores:
- a **ROC curve + AUC**,
- **per-attack detection rates** (scan / SYN / MQTT / UDP),
- a **Proposed (Isolation Forest) vs Baseline (volume threshold)** comparison —
  the baseline is the weak "existing system", so you can *show* why the proposed
  detector is better instead of just claiming it.

---

## 8. Mapping to the paper

| Paper component | Where it lives |
|---|---|
| Docker virtual network | `docker-compose.yml` (`iotnet` 10.10.0.0/24) |
| MQTT / Mosquitto | `mosquitto/` + `services/iot-device/` |
| Mirai-style phases (scan/infect/report/attack) | `services/attack-sim/simulator.py` (flow signatures) |
| Isolation-Forest IDS | `services/ids/ids_engine.py` |
| Metric storage | Redis (`metrics:latest`) + `./data/metrics.json` |
| Flask dashboard | `services/dashboard/` |
| Automated pipeline | `services/orchestrator/pipeline.py` |
| Testbed comparison | `./data/testbed_comparison.csv` |

> The VM and hardware rows in the comparison are **reference figures from the
> literature** for context; the Docker row is **measured live** from your run.
> Report your own measured numbers in the paper.

---

## 9. Project layout

```
iot-security-testbed/
├── docker-compose.yml        # orchestrates all services
├── Makefile                  # convenience targets
├── .env.example              # tunable experiment timings
├── mosquitto/mosquitto.conf  # MQTT broker config
├── common/testbed.py         # shared schema + Redis + feature helpers
├── services/
│   ├── iot-device/           # simulated IoT devices (MQTT publishers)
│   ├── attack-sim/           # synthetic attack-traffic generator
│   ├── ids/                  # Isolation-Forest IDS engine
│   ├── orchestrator/         # automated experiment pipeline
│   └── dashboard/            # Flask API + live web UI
├── scripts/demo.sh           # one-shot end-to-end demo
└── data/                     # generated result files (gitignored)
```

---

## 10. Troubleshooting

- **Port 8080 busy** → change `"8080:8080"` to e.g. `"8090:8080"` in `docker-compose.yml`.
- **First build is slow** → `scikit-learn`/`numpy` compile once; later builds are cached.
- **Metrics stay at 0** → the IDS must be in *detecting* mode with a trained model; use **Run full experiment** or the **Train IDS** button first.
- **Reset everything** → `docker compose down -v && docker compose up --build -d`.

---

## 11. Extending it (ideas for the viva / future work)

- Add a supervised model (Random Forest / XGBoost) and compare with the unsupervised IDS.
- Replay a public dataset (BoT-IoT, CICIoT2023) through the same pipeline.
- Add InfluxDB + Grafana for long-term metric storage.
- Scale the device swarm with `docker compose up --scale dev-temp=20`.
- Add SDN (Open vSwitch / Ryu) for programmable mitigation of detected attacks.
```

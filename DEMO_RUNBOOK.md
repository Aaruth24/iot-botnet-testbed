# Demo Runbook — one page to hold during the viva

**Project:** Docker-Based Virtual IoT Security Testbed · botnet-traffic simulation + Isolation-Forest IDS
**Live demo:** `demo/testbed-demo.html` (offline, no Docker/Wi-Fi needed) · **Repo:** this repository

---

## Before you present (10 min)
- [ ] Open `demo/testbed-demo.html` once — confirm it runs (`xdg-open demo/testbed-demo.html`).
- [ ] Open 3 windows: **the demo page**, **the GitHub repo**, **a terminal** in the project folder.
- [ ] (Optional, for real Docker) run `docker compose up --build -d` **beforehand** — never build live.

## Demo order

**1 · It's a real system — GitHub repo (30s)**
Scroll the folders: `services/` (iot-device, attack-sim, ids, orchestrator, dashboard), `docker-compose.yml`, `tools/`.
> "The whole testbed is containerized — 8 services orchestrated with Docker Compose."

**2 · Live demo — the showpiece (3–4 min)**
Open `demo/testbed-demo.html` → point to the topology + green benign flows → click **▶ Run full experiment**.
> "It collects normal traffic, trains the Isolation-Forest IDS, injects four botnet attacks, then evaluates."

Then point to: **KPIs** · **ROC curve + AUC** · **per-attack detection** · **Proposed vs Baseline** table.
> "My detector catches ~100% of attacks; the baseline 'existing system' misses about half — measured live, not hard-coded."

**3 · Real-data capable (1 min)** — in the terminal:
```bash
python3 tools/evaluate_dataset.py --synthesize --rows 20000     # or --csv CICIoT2023.csv
```
> "The same IDS runs on real public datasets like CICIoT2023 / BoT-IoT."

**4 · (Optional) real Docker system** — if pre-built, open `http://localhost:8080` and show the same dashboard from actual containers.

## The honesty line (say it plainly)
> "The browser page is a faithful **simulation** for presentation — same features, same detector. The real experiments run in the Docker containers and on real datasets, both in the repo."

## If something breaks
- Wi-Fi dies → the offline demo still works (everything is inside the one file).
- Docker misbehaves → skip it; the demo + `python3 tools/validate.py` + `demo/screenshot.png` cover you.

## Know your numbers (from a live run — yours will vary slightly)
| Metric | Proposed (Isolation Forest) | Baseline (existing) |
|---|---|---|
| Accuracy | ~98% | ~65% |
| Recall | ~100% | ~53% |
| F1-score | ~98% | ~65% |
| False-positive rate | ~5–7% | ~9% |
| ROC AUC | ~0.9 | — |

**If asked "why isn't the false-positive rate a fixed 3.2%?"** → *"It's a real detector; the FPR tracks the `IDS_CONTAMINATION` operating point. I report my measured run, not a fixed number."*
**If asked "is this real malware?"** → *"No — it synthesizes attack-traffic signatures in an isolated network, like the BoT-IoT / CICIoT2023 datasets. No exploits, no propagation."*

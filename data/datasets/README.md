# Dataset Instructions

Use this folder to place benchmark or training datasets for the IoT botnet testbed.

Recommended sources:
- N-BaIoT dataset for botnet traffic patterns.
- CIC-IoT 2023 or CIC-IDS-style IoT traffic traces for normal and attack flows.

Suggested workflow:
1. Download the raw dataset from the original source.
2. Extract or convert the traffic to PCAP or CSV flow features.
3. Separate normal traffic for `ids/train.py`.
4. Label attack traffic with `1` and normal traffic with `0` for `ids/evaluate.py`.
5. Store any processed artifacts under `data/features/` or `data/results/`.

Keep the raw source files out of version control if they are large.

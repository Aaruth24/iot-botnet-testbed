# Offline presentation demo

`testbed-demo.html` is a **single, self-contained web page** that runs the whole
testbed as a live simulation — IoT devices, botnet attacks, the Isolation-Forest
IDS, confusion matrix and metrics — with **no Docker, no server and no internet**
(Chart.js is vendored inside the file).

Perfect for a viva/presentation where projector Wi-Fi is unreliable.

## Run it (Linux)
```bash
xdg-open demo/testbed-demo.html      # or: firefox demo/testbed-demo.html
```
Just double-clicking the file in a file manager also works.

## Present with it
1. It opens already alive — point to the **Virtual IoT network** and **Live flows**.
2. Click **▶ Run full experiment** — watch baseline → train → attack → evaluate,
   the attack spike on the chart, alerts filling, and the confusion matrix + KPIs populate.
3. Try a manual **Port scan** → **Launch traffic**, then **Stop**.

`screenshot.png` is a reference capture of a completed run.

> This page is a faithful *simulation* of the Dockerized system (same features,
> same operating point). The real experiments run in the containers via
> `docker compose up` / `./run-linux.sh`.

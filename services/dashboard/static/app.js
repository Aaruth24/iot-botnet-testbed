/* Dashboard client: polls the REST API and renders the live view. */
"use strict";

const $ = (id) => document.getElementById(id);
const api = (p, opt) => fetch(p, opt).then((r) => r.json());

/* ---------- throughput chart ---------- */
const tctx = $("throughput").getContext("2d");
const throughput = new Chart(tctx, {
  type: "line",
  data: {
    labels: [],
    datasets: [
      { label: "normal", data: [], borderColor: "#4da3ff", backgroundColor: "#4da3ff22", tension: .35, fill: true, pointRadius: 0 },
      { label: "attack", data: [], borderColor: "#ff6b6b", backgroundColor: "#ff6b6b22", tension: .35, fill: true, pointRadius: 0 },
    ],
  },
  options: {
    animation: false, responsive: true,
    scales: {
      x: { ticks: { color: "#8a99b3", maxTicksLimit: 6 }, grid: { color: "#243049" } },
      y: { ticks: { color: "#8a99b3" }, grid: { color: "#243049" }, beginAtZero: true },
    },
    plugins: { legend: { labels: { color: "#e6edf7", boxWidth: 12 } } },
  },
});
let lastNormal = 0, lastAttack = 0;

/* ---------- topology canvas ---------- */
const topo = $("topo");
const tg = topo.getContext("2d");
function sizeTopo() { topo.width = topo.clientWidth; }
window.addEventListener("resize", sizeTopo);
sizeTopo();

function drawTopology(data) {
  const W = topo.width, H = topo.height;
  tg.clearRect(0, 0, W, H);
  const broker = data.nodes.find((n) => n.type === "broker") || { id: "broker" };
  const bx = W / 2, by = H / 2;
  const others = data.nodes.filter((n) => n.type !== "broker");
  const R = Math.min(W, H) * 0.38;

  // edges
  others.forEach((n, i) => {
    const a = (i / Math.max(others.length, 1)) * Math.PI * 2 - Math.PI / 2;
    const x = bx + R * Math.cos(a), y = by + R * Math.sin(a);
    tg.beginPath();
    tg.moveTo(bx, by); tg.lineTo(x, y);
    tg.strokeStyle = n.type === "attacker" ? "#ff6b6b" : "#243049";
    tg.lineWidth = n.type === "attacker" ? 2 : 1;
    tg.stroke();
  });
  // nodes
  others.forEach((n, i) => {
    const a = (i / Math.max(others.length, 1)) * Math.PI * 2 - Math.PI / 2;
    const x = bx + R * Math.cos(a), y = by + R * Math.sin(a);
    node(x, y, n.type === "attacker" ? "#ff6b6b" : "#3ddc97", n.id.slice(0, 10));
  });
  node(bx, by, "#4da3ff", broker.id, 14);
}
function node(x, y, color, label, rad = 9) {
  tg.beginPath(); tg.arc(x, y, rad, 0, Math.PI * 2);
  tg.fillStyle = color; tg.shadowColor = color; tg.shadowBlur = 12; tg.fill(); tg.shadowBlur = 0;
  tg.fillStyle = "#e6edf7"; tg.font = "10px sans-serif"; tg.textAlign = "center";
  tg.fillText(label, x, y + rad + 12);
}

/* ---------- renderers ---------- */
function setMetrics(m) {
  const f = (v) => (v == null ? "—" : v + "%");
  $("k-acc").textContent = f(m.accuracy);
  $("k-prec").textContent = f(m.precision);
  $("k-rec").textContent = f(m.recall);
  $("k-f1").textContent = f(m.f1);
  $("k-fpr").textContent = f(m.fpr);
  $("k-det").textContent = m.detection_time_s != null ? m.detection_time_s + "s" : "—";
  $("cm-tn").textContent = m.tn ?? 0;
  $("cm-fp").textContent = m.fp ?? 0;
  $("cm-fn").textContent = m.fn ?? 0;
  $("cm-tp").textContent = m.tp ?? 0;
  $("cm-mode").textContent = "mode: " + (m.mode || "—") +
    (m.train_buffer ? ` · training samples: ${m.train_buffer}` : "");
}

function setStatus(s) {
  const ids = $("pill-ids");
  ids.textContent = "IDS: " + s.ids_mode;
  ids.className = "pill " + (s.ids_mode === "detecting" ? "on" : s.ids_mode === "training" ? "warn" : "");
  const model = $("pill-model");
  model.textContent = "model: " + (s.model_ready ? "ready" : "untrained");
  model.className = "pill " + (s.model_ready ? "on" : "warn");
  const atk = $("pill-attack");
  const active = s.attack && s.attack.active;
  atk.textContent = "attack: " + (active ? s.attack.type : "idle");
  atk.className = "pill " + (active ? "hot" : "");
  $("flow-counts").textContent =
    `flows: ${s.flows_total}  ·  normal ${s.flows_normal}  ·  attack ${s.flows_attack}`;

  const exp = s.experiment || {};
  const wrap = $("exp-wrap");
  if (exp.stage && (exp.running || exp.pct === 100)) {
    wrap.hidden = false;
    $("exp-stage").textContent = exp.stage;
    $("exp-note").textContent = exp.note || "";
    $("exp-bar").style.width = (exp.pct || 0) + "%";
    if (exp.pct === 100 && !exp.running) setTimeout(() => { wrap.hidden = true; }, 6000);
  }
}

function feedRow(parent, cls, left, right, tagClass) {
  const div = document.createElement("div");
  div.className = "row " + cls;
  div.innerHTML = `<span>${left}</span><span class="tag ${tagClass || ""}">${right}</span>`;
  parent.appendChild(div);
}

function renderAlerts(list) {
  const box = $("alerts"); box.innerHTML = "";
  $("alert-count").textContent = list.length;
  list.forEach((a) => {
    const cls = a.verdict === "true_positive" ? "tp" : "fp";
    const tag = a.verdict === "true_positive" ? "red" : "amber";
    feedRow(box, cls,
      `${a.src} → ${a.dst}:${a.dst_port} <b>${a.attack_type || a.proto}</b>`,
      `${a.verdict === "true_positive" ? "DETECTED" : "FALSE+"} (${a.score})`, tag);
  });
}

function renderFlows(list) {
  const box = $("flows"); box.innerHTML = "";
  list.forEach((f) => {
    feedRow(box, f.label,
      `${f.src} → ${f.dst}:${f.dst_port} ${f.proto} · ${f.packets}pkt ${f.bytes}B`,
      f.label === "attack" ? (f.attack_type || "attack") : f.device_type,
      f.label === "attack" ? "red" : "green");
  });
}

function renderEvents(list) {
  const box = $("events"); box.innerHTML = "";
  list.forEach((e) => {
    const d = document.createElement("div");
    d.className = "row lvl-" + e.level;
    const t = new Date(e.ts * 1000).toLocaleTimeString();
    d.innerHTML = `<span>[${t}] <b>${e.source}</b> ${e.message}</span>`;
    box.appendChild(d);
  });
}

function renderComparison(rows) {
  const t = $("cmp");
  if (!rows.length) { t.innerHTML = "<tr><td class='sub'>Run an experiment to populate.</td></tr>"; return; }
  const cols = ["testbed", "accuracy", "precision", "recall", "f1", "fpr", "detection_time_s", "startup_s", "isolation", "reproducible"];
  const head = cols.map((c) => `<th>${c.replace(/_/g, " ")}</th>`).join("");
  let html = `<tr>${head}</tr>`;
  rows.forEach((r) => {
    const me = r.testbed.includes("this work") ? "me" : "";
    html += `<tr class="${me}">` + cols.map((c) => `<td>${r[c] ?? "—"}</td>`).join("") + "</tr>";
  });
  t.innerHTML = html;
}

/* ---------- polling ---------- */
async function tick() {
  try {
    const [status, metrics, alerts, flows, events] = await Promise.all([
      api("/api/status"), api("/api/metrics"),
      api("/api/alerts?n=40"), api("/api/flows?n=40"), api("/api/events?n=25"),
    ]);
    setStatus(status); setMetrics(metrics);
    renderAlerts(alerts); renderFlows(flows); renderEvents(events);

    // throughput deltas
    const n = status.flows_normal - lastNormal;
    const a = status.flows_attack - lastAttack;
    lastNormal = status.flows_normal; lastAttack = status.flows_attack;
    const label = new Date().toLocaleTimeString().slice(0, 8);
    const L = throughput.data.labels;
    L.push(label); throughput.data.datasets[0].data.push(Math.max(n, 0));
    throughput.data.datasets[1].data.push(Math.max(a, 0));
    if (L.length > 30) { L.shift(); throughput.data.datasets.forEach((d) => d.data.shift()); }
    throughput.update();
  } catch (e) { /* transient during container boot */ }
}

async function slowTick() {
  try {
    drawTopology(await api("/api/topology"));
    renderComparison(await api("/api/comparison"));
  } catch (e) {}
}

/* ---------- controls ---------- */
$("atk-int").addEventListener("input", (e) => { $("atk-int-val").textContent = e.target.value; });
$("btn-atk-start").onclick = () => api("/api/attack/start", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ type: $("atk-type").value, intensity: +$("atk-int").value }),
});
$("btn-atk-stop").onclick = () => api("/api/attack/stop", { method: "POST" });
$("btn-train").onclick = async () => {
  await api("/api/ids/mode", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode: "training" }) });
  setTimeout(() => api("/api/ids/train", { method: "POST" }), 500);
};
$("btn-detect").onclick = () => api("/api/ids/mode", {
  method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode: "detecting" }),
});
$("btn-exp").onclick = () => { api("/api/experiment/run", { method: "POST" }); $("exp-wrap").hidden = false; };

tick(); slowTick();
setInterval(tick, 1500);
setInterval(slowTick, 5000);

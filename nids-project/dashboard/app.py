#!/usr/bin/env python3
"""
NIDS Live Dashboard
Reads Suricata's eve.json and renders a real-time monitoring UI.
Self-contained: only requires Flask.
"""
import json
import os
import threading
import time
from collections import Counter, deque
from datetime import datetime

from flask import Flask, jsonify, render_template_string, request

EVE_LOG = "/var/log/suricata/eve.json"
MAX_ALERTS = 500
app = Flask(__name__)

# In-memory store
alerts = deque(maxlen=MAX_ALERTS)
stats = {
    "total": 0,
    "by_severity": Counter(),      # {1: n, 2: n, 3: n}
    "by_proto": Counter(),
    "by_src": Counter(),
    "by_signature": Counter(),
    "started_at": datetime.now().isoformat(timespec="seconds"),
}


def tail_eve():
    """Continuously tail Suricata's eve.json and ingest alerts."""
    while not os.path.exists(EVE_LOG):
        print(f"[wait] {EVE_LOG} not found yet...", flush=True)
        time.sleep(2)

    with open(EVE_LOG, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event_type") != "alert":
                continue

            a = ev.get("alert", {})
            record = {
                "timestamp": ev.get("timestamp", ""),
                "time": ev.get("timestamp", "")[:19].replace("T", " "),
                "src_ip": ev.get("src_ip", "?"),
                "src_port": ev.get("src_port", ""),
                "dst_ip": ev.get("dest_ip", "?"),
                "dst_port": ev.get("dest_port", ""),
                "proto": ev.get("proto", "?"),
                "signature": a.get("signature", "Unknown"),
                "signature_id": a.get("signature_id", 0),
                "category": a.get("category", ""),
                "severity": a.get("severity", 3),
                "action": a.get("action", "allowed"),
            }
            alerts.append(record)

            stats["total"] += 1
            stats["by_severity"][record["severity"]] += 1
            stats["by_proto"][record["proto"]] += 1
            stats["by_src"][record["src_ip"]] += 1
            stats["by_signature"][record["signature"]] += 1


PAGE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NIDS Dashboard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root{
    --bg:#0b1220; --panel:#131c2e; --panel-2:#1a2540; --border:#243352;
    --text:#e6edf7; --muted:#8aa0c0; --accent:#3b82f6;
    --sev1:#ef4444; --sev2:#f59e0b; --sev3:#10b981;
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
       background:var(--bg);color:var(--text);font-size:14px}
  header{display:flex;align-items:center;justify-content:space-between;
         padding:16px 24px;background:var(--panel);border-bottom:1px solid var(--border)}
  header h1{margin:0;font-size:18px;font-weight:600;letter-spacing:.3px}
  header h1 span{color:var(--accent)}
  .status{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px}
  .dot{width:8px;height:8px;border-radius:50%;background:#10b981;
       box-shadow:0 0 8px #10b981;animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
  main{padding:20px 24px;display:grid;gap:18px}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:10px;
        padding:16px 18px}
  .card .label{color:var(--muted);font-size:12px;text-transform:uppercase;
               letter-spacing:.6px;margin-bottom:8px}
  .card .value{font-size:28px;font-weight:700}
  .card.sev1 .value{color:var(--sev1)}
  .card.sev2 .value{color:var(--sev2)}
  .card.sev3 .value{color:var(--sev3)}
  .grid-2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
  @media(max-width:900px){.grid-2{grid-template-columns:1fr}}
  .panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;
         padding:16px 18px}
  .panel h2{margin:0 0 12px;font-size:14px;font-weight:600;color:var(--muted);
            text-transform:uppercase;letter-spacing:.6px}
  .chart-wrap{position:relative;height:240px}
  .filters{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .filters input,.filters select{background:var(--panel-2);border:1px solid var(--border);
        color:var(--text);padding:8px 12px;border-radius:6px;font-size:13px;outline:none}
  .filters input:focus,.filters select:focus{border-color:var(--accent)}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{position:sticky;top:0;background:var(--panel-2);color:var(--muted);
     text-align:left;padding:10px 12px;font-weight:600;font-size:12px;
     text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border)}
  td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}
  tr:hover td{background:var(--panel-2)}
  .sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;
       font-weight:600;text-transform:uppercase}
  .sev-1{background:rgba(239,68,68,.15);color:var(--sev1);border:1px solid rgba(239,68,68,.3)}
  .sev-2{background:rgba(245,158,11,.15);color:var(--sev2);border:1px solid rgba(245,158,11,.3)}
  .sev-3{background:rgba(16,185,129,.15);color:var(--sev3);border:1px solid rgba(16,185,129,.3)}
  .mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:var(--muted)}
  .scroll{max-height:520px;overflow-y:auto;border-radius:8px}
  .scroll::-webkit-scrollbar{width:8px}
  .scroll::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
  .empty{text-align:center;padding:40px;color:var(--muted)}
  .toplist{list-style:none;margin:0;padding:0}
  .toplist li{display:flex;justify-content:space-between;padding:7px 0;
              border-bottom:1px solid var(--border);font-size:13px}
  .toplist li:last-child{border:0}
  .toplist .count{color:var(--accent);font-weight:600}
  .bar{height:6px;background:var(--panel-2);border-radius:3px;margin-top:6px;overflow:hidden}
  .bar > i{display:block;height:100%;background:var(--accent)}
</style>
</head>
<body>
<header>
  <h1>NIDS <span>Live Dashboard</span></h1>
  <div class="status"><span class="dot"></span><span id="status">Monitoring</span>
    <span id="clock" class="mono" style="margin-left:14px"></span></div>
</header>

<main>
  <!-- KPI cards -->
  <div class="cards">
    <div class="card"><div class="label">Total Alerts</div><div class="value" id="kpi-total">0</div></div>
    <div class="card sev1"><div class="label">High Severity</div><div class="value" id="kpi-high">0</div></div>
    <div class="card sev2"><div class="label">Medium</div><div class="value" id="kpi-med">0</div></div>
    <div class="card sev3"><div class="label">Low</div><div class="value" id="kpi-low">0</div></div>
    <div class="card"><div class="label">Unique Sources</div><div class="value" id="kpi-srcs">0</div></div>
    <div class="card"><div class="label">Signatures Hit</div><div class="value" id="kpi-sigs">0</div></div>
  </div>

  <!-- Charts -->
  <div class="grid-2">
    <div class="panel">
      <h2>Severity Breakdown</h2>
      <div class="chart-wrap"><canvas id="sevChart"></canvas></div>
    </div>
    <div class="panel">
      <h2>Protocol Distribution</h2>
      <div class="chart-wrap"><canvas id="protoChart"></canvas></div>
    </div>
  </div>

  <!-- Top lists -->
  <div class="grid-2">
    <div class="panel">
      <h2>Top Source IPs</h2>
      <ul class="toplist" id="top-srcs"><li class="empty">No data yet</li></ul>
    </div>
    <div class="panel">
      <h2>Top Signatures</h2>
      <ul class="toplist" id="top-sigs"><li class="empty">No data yet</li></ul>
    </div>
  </div>

  <!-- Alerts table -->
  <div class="panel">
    <h2>Recent Alerts</h2>
    <div class="filters" style="margin-bottom:12px">
      <input id="q" placeholder="Search signature, IP, port..." style="min-width:280px">
      <select id="sev-filter">
        <option value="">All severities</option>
        <option value="1">High only</option>
        <option value="2">Medium only</option>
        <option value="3">Low only</option>
      </select>
      <select id="proto-filter">
        <option value="">All protocols</option>
        <option>TCP</option><option>UDP</option><option>ICMP</option>
      </select>
      <span class="mono" id="count-label" style="margin-left:auto"></span>
    </div>
    <div class="scroll">
      <table>
        <thead><tr>
          <th>Time</th><th>Severity</th><th>Source</th><th>Destination</th>
          <th>Proto</th><th>Signature</th><th>Category</th>
        </tr></thead>
        <tbody id="rows">
          <tr><td colspan="7" class="empty">Waiting for alerts...</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</main>

<script>
// ---------- Charts ----------
const sevChart = new Chart(document.getElementById('sevChart'), {
  type: 'doughnut',
  data: {
    labels: ['High', 'Medium', 'Low'],
    datasets: [{
      data: [0,0,0],
      backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
      borderColor: '#131c2e', borderWidth: 3
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { labels: { color: '#e6edf7', padding: 16 } } }
  }
});

const protoChart = new Chart(document.getElementById('protoChart'), {
  type: 'bar',
  data: {
    labels: [],
    datasets: [{
      label: 'Packets',
      data: [],
      backgroundColor: '#3b82f6',
      borderRadius: 6
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#8aa0c0' }, grid: { display: false } },
      y: { ticks: { color: '#8aa0c0' }, grid: { color: '#243352' }, beginAtZero: true }
    }
  }
});

// ---------- Helpers ----------
function sevLabel(s){ return s===1?'High':s===2?'Medium':'Low'; }
function sevClass(s){ return `sev sev-${s}`; }

async function refresh(){
  try {
    const r = await fetch('/api/alerts');
    const d = await r.json();

    // KPIs
    document.getElementById('kpi-total').textContent = d.kpi.total;
    document.getElementById('kpi-high').textContent  = d.kpi.by_severity['1'] || 0;
    document.getElementById('kpi-med').textContent   = d.kpi.by_severity['2'] || 0;
    document.getElementById('kpi-low').textContent   = d.kpi.by_severity['3'] || 0;
    document.getElementById('kpi-srcs').textContent  = d.kpi.unique_sources;
    document.getElementById('kpi-sigs').textContent  = d.kpi.unique_signatures;

    // Severity chart
    sevChart.data.datasets[0].data = [
      d.kpi.by_severity['1'] || 0,
      d.kpi.by_severity['2'] || 0,
      d.kpi.by_severity['3'] || 0
    ];
    sevChart.update('none');

    // Proto chart
    protoChart.data.labels = Object.keys(d.kpi.by_proto);
    protoChart.data.datasets[0].data = Object.values(d.kpi.by_proto);
    protoChart.update('none');

    // Top sources
    const srcUl = document.getElementById('top-srcs');
    srcUl.innerHTML = d.top_sources.length
      ? d.top_sources.map(([ip, n]) => {
          const pct = Math.min(100, n * 100 / (d.top_sources[0][1] || 1));
          return `<li><span class="mono">${ip}</span>
                  <span class="count">${n}</span></li>
                  <div class="bar"><i style="width:${pct}%"></i></div>`;
        }).join('')
      : '<li class="empty">No data yet</li>';

    // Top signatures
    const sigUl = document.getElementById('top-sigs');
    sigUl.innerHTML = d.top_signatures.length
      ? d.top_signatures.map(([sig, n]) =>
          `<li><span>${escapeHtml(sig)}</span>
           <span class="count">${n}</span></li>`).join('')
      : '<li class="empty">No data yet</li>';

    // Alerts table (client-side filtering)
    renderTable(d.alerts);

  } catch (e) {
    document.getElementById('status').textContent = 'Disconnected';
    console.error(e);
  }
}

function escapeHtml(s){
  return (s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

let ALL_ALERTS = [];

function renderTable(alerts){
  ALL_ALERTS = alerts;
  const q   = document.getElementById('q').value.toLowerCase();
  const sev = document.getElementById('sev-filter').value;
  const pr  = document.getElementById('proto-filter').value;

  const filtered = alerts.filter(a => {
    if (sev && String(a.severity) !== sev) return false;
    if (pr && a.proto !== pr) return false;
    if (q) {
      const hay = `${a.signature} ${a.src_ip} ${a.dst_ip} ${a.src_port} ${a.dst_port} ${a.category}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  document.getElementById('count-label').textContent =
    `${filtered.length} / ${alerts.length} alerts`;

  const tbody = document.getElementById('rows');
  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty">No matching alerts</td></tr>';
    return;
  }
  tbody.innerHTML = filtered.map(a => `
    <tr>
      <td class="mono">${a.time}</td>
      <td><span class="${sevClass(a.severity)}">${sevLabel(a.severity)}</span></td>
      <td class="mono">${a.src_ip}${a.src_port?':'+a.src_port:''}</td>
      <td class="mono">${a.dst_ip}${a.dst_port?':'+a.dst_port:''}</td>
      <td>${a.proto}</td>
      <td>${escapeHtml(a.signature)}</td>
      <td class="mono">${escapeHtml(a.category || '—')}</td>
    </tr>`).join('');
}

// Wire up filters
['q','sev-filter','proto-filter'].forEach(id => {
  document.getElementById(id).addEventListener('input', () => renderTable(ALL_ALERTS));
  document.getElementById(id).addEventListener('change', () => renderTable(ALL_ALERTS));
});

// Clock
setInterval(() => {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}, 1000);

// Poll
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/api/alerts")
def api_alerts():
    # Prepare data for JSON serialization
    kpi = {
        "total": stats["total"],
        "by_severity": {str(k): v for k, v in stats["by_severity"].items()},
        "by_proto": dict(stats["by_proto"].most_common(6)),
        "unique_sources": len(stats["by_src"]),
        "unique_signatures": len(stats["by_signature"]),
    }
    top_sources = stats["by_src"].most_common(8)
    top_signatures = stats["by_signature"].most_common(8)

    return jsonify({
        "kpi": kpi,
        "top_sources": top_sources,
        "top_signatures": top_signatures,
        "alerts": list(alerts)[::-1][:200],
    })


if __name__ == "__main__":
    print(">>> NIDS Dashboard starting...", flush=True)
    print(f">>> Reading alerts from: {EVE_LOG}", flush=True)
    print(">>> Open http://localhost:5000 in your browser", flush=True)

    threading.Thread(target=tail_eve, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
ENDOFFILE

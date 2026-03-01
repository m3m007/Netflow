#!/usr/bin/env python3
"""
flow_server.py — Minimal HTTP server for the network flow monitor.

Serves on 0.0.0.0:7000 (reaches Tailscale clients automatically).
Two endpoints:
  GET /           → HTML5 dashboard (this file contains it inline)
  GET /api/flows  → reads ./ndpi_state/flows.json and proxies it

No third-party dependencies. Python 3.6+ stdlib only.

Usage:
  python3 flow_server.py [--port 7000] [--data ./ndpi_state/flows.json]
"""

import http.server
import json
import os
import sys
import argparse
from pathlib import Path
from datetime import datetime

# ── defaults ─────────────────────────────────────────────────────────────────

DEFAULT_PORT      = 7000
DEFAULT_DATA_FILE = "./ndpi_state/flows.json"

# ─────────────────────────────────────────────────────────────────────────────
# HTML dashboard — everything runs in the browser; server just provides data.
# ─────────────────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Flow Monitor</title>
<style>
  :root {
    --bg:      #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border:  #30363d;
    --text:    #e6edf3; --muted: #8b949e;
    --green:   #3fb950; --yellow: #d29922; --red: #f85149;
    --blue:    #58a6ff; --purple: #bc8cff;
    --risk-bg: #3d1a1a; --unsafe-bg: #2d1f00; --enc-bg: #0d1f36;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font: 13px/1.5 'Courier New', monospace; }

  /* ── header ── */
  header { background: var(--bg2); border-bottom: 1px solid var(--border);
           padding: 12px 20px; display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
  header h1 { font-size: 16px; color: var(--blue); letter-spacing: 1px; white-space: nowrap; }
  #status { font-size: 11px; color: var(--muted); margin-left: auto; white-space: nowrap; }
  #status.ok  { color: var(--green); }
  #status.err { color: var(--red); }

  /* ── summary cards ── */
  #summary { display: flex; gap: 12px; padding: 14px 20px; flex-wrap: wrap;
             border-bottom: 1px solid var(--border); background: var(--bg2); }
  .card { background: var(--bg3); border: 1px solid var(--border); border-radius: 6px;
          padding: 10px 18px; min-width: 130px; }
  .card .val { font-size: 22px; font-weight: bold; color: var(--blue); line-height: 1.2; }
  .card .lbl { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }
  .card.risk  .val { color: var(--red); }
  .card.enc   .val { color: var(--purple); }
  .card.proto .val { font-size: 14px; color: var(--green); }

  /* ── toolbar ── */
  #toolbar { padding: 10px 20px; display: flex; gap: 10px; align-items: center;
             flex-wrap: wrap; background: var(--bg); border-bottom: 1px solid var(--border); }
  #filter { background: var(--bg3); border: 1px solid var(--border); color: var(--text);
            padding: 5px 10px; border-radius: 4px; width: 280px; font: inherit; }
  #filter::placeholder { color: var(--muted); }
  #count { font-size: 11px; color: var(--muted); }
  label { font-size: 11px; color: var(--muted); display: flex; align-items: center; gap: 4px; cursor: pointer; }

  /* ── table ── */
  #wrap { overflow-x: auto; max-height: calc(100vh - 210px); overflow-y: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  thead { position: sticky; top: 0; z-index: 10; }
  th { background: var(--bg3); border-bottom: 2px solid var(--border);
       padding: 7px 10px; text-align: left; white-space: nowrap;
       cursor: pointer; user-select: none; color: var(--muted);
       font-weight: normal; letter-spacing: .5px; }
  th:hover { color: var(--text); }
  th.asc::after  { content: " ▲"; color: var(--blue); }
  th.desc::after { content: " ▼"; color: var(--blue); }
  td { padding: 5px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  tr:hover td { background: var(--bg3); }

  /* row colour classes — applied to <tr> */
  tr.risk   td { background: var(--risk-bg); }
  tr.unsafe td { background: var(--unsafe-bg); }
  tr.enc    td:last-child { color: var(--purple); }

  /* column-specific colours */
  .col-risk  { color: var(--red);    font-weight: bold; }
  .col-enc   { color: var(--purple); }
  .col-safe  { color: var(--green); }
  .col-bytes { color: var(--muted); }
  .col-l4    { color: var(--yellow); }
  .col-l7    { color: var(--blue); }
  .ip        { font-family: inherit; }
  .no-data   { text-align: center; padding: 60px; color: var(--muted); }
</style>
</head>
<body>

<header>
  <h1>⬡ NETWORK FLOW MONITOR</h1>
  <span id="status">connecting…</span>
</header>

<div id="summary">
  <div class="card">       <div class="val" id="s-total">—</div><div class="lbl">Total Flows</div></div>
  <div class="card risk">  <div class="val" id="s-risk"> —</div><div class="lbl">Risky Flows</div></div>
  <div class="card enc">   <div class="val" id="s-enc">  —</div><div class="lbl">Encrypted</div></div>
  <div class="card proto"> <div class="val" id="s-top">  —</div><div class="lbl">Top L7 Proto</div></div>
  <div class="card">       <div class="val" id="s-bytes"> —</div><div class="lbl">Total Traffic</div></div>
</div>

<div id="toolbar">
  <input id="filter" placeholder="Filter (IP, port, protocol, category…)" oninput="render()">
  <label><input type="checkbox" id="chk-risk" onchange="render()"> Risky only</label>
  <label><input type="checkbox" id="chk-enc"  onchange="render()"> Encrypted only</label>
  <span id="count"></span>
</div>

<div id="wrap">
  <table>
    <thead>
      <tr id="hdr">
        <th data-k="proto"          >L4</th>
        <th data-k="src"            >Source</th>
        <th data-k="dst"            >Destination</th>
        <th data-k="ndpi.proto"     >L7 Protocol</th>
        <th data-k="ndpi.category"  >Category</th>
        <th data-k="ndpi.breed"     >Breed</th>
        <th data-k="_bytes"  class="r">Bytes ↕</th>
        <th data-k="_pkts"   class="r">Pkts</th>
        <th data-k="_risk"          >Risk</th>
      </tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>
</div>

<script>
"use strict";

let flows    = [];
let sortKey  = '_bytes';
let sortDir  = -1;          // -1 = descending (most traffic first)
let timer;

// ── fetch + refresh ───────────────────────────────────────────────────────────

async function fetchFlows() {
  const st = document.getElementById('status');
  try {
    const r = await fetch('/api/flows');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    flows = await r.json();
    // Attach synthetic fields used for sorting / display
    for (const f of flows) {
      f._bytes = (f.ndpi.cli2srv_bytes || 0) + (f.ndpi.srv2cli_bytes || 0);
      f._pkts  = (f.ndpi.cli2srv_pkts  || 0) + (f.ndpi.srv2cli_pkts  || 0);
      f._risk  = f.ndpi.flow_risk && Object.keys(f.ndpi.flow_risk).length > 0;
      f.src    = `${f.src_ip}:${f.src_port || '—'}`;
      f.dst    = `${f.dest_ip}:${f.dst_port || '—'}`;
    }
    computeSummary();
    render();
    const now = new Date().toLocaleTimeString();
    st.textContent = `↻ ${now} — ${flows.length} flows`;
    st.className = 'ok';
  } catch(e) {
    st.textContent = `✗ ${e.message}`;
    st.className = 'err';
  }
}

// ── summary bar ───────────────────────────────────────────────────────────────

function computeSummary() {
  let risky = 0, enc = 0, totalBytes = 0;
  const protoCounts = {};
  for (const f of flows) {
    if (f._risk)              risky++;
    if (f.ndpi.encrypted)     enc++;
    totalBytes += f._bytes;
    const p = f.ndpi.proto || f.proto;
    protoCounts[p] = (protoCounts[p] || 0) + 1;
  }
  const topProto = Object.entries(protoCounts).sort((a,b) => b[1]-a[1])[0];
  document.getElementById('s-total').textContent = flows.length;
  document.getElementById('s-risk' ).textContent = risky;
  document.getElementById('s-enc'  ).textContent = enc + (flows.length ? ` (${Math.round(enc*100/flows.length)}%)` : '');
  document.getElementById('s-top'  ).textContent = topProto ? topProto[0] : '—';
  document.getElementById('s-bytes').textContent = fmtBytes(totalBytes);
}

// ── render table ─────────────────────────────────────────────────────────────

function render() {
  const q    = document.getElementById('filter').value.toLowerCase();
  const onlyRisk = document.getElementById('chk-risk').checked;
  const onlyEnc  = document.getElementById('chk-enc' ).checked;

  let rows = flows.filter(f => {
    if (onlyRisk && !f._risk)          return false;
    if (onlyEnc  && !f.ndpi.encrypted) return false;
    if (!q) return true;
    return (f.src_ip + f.dest_ip + f.proto + f.src_port + f.dst_port +
            (f.ndpi.proto||'') + (f.ndpi.category||'') + (f.ndpi.breed||''))
           .toLowerCase().includes(q);
  });

  rows.sort((a, b) => {
    const av = get(a, sortKey), bv = get(b, sortKey);
    if (av < bv) return  sortDir;
    if (av > bv) return -sortDir;
    return 0;
  });

  document.getElementById('count').textContent = `${rows.length} / ${flows.length} flows`;

  if (!rows.length) {
    document.getElementById('tbody').innerHTML =
      '<tr><td colspan="9" class="no-data">No flows match the current filter.</td></tr>';
    return;
  }

  const parts = rows.map(f => {
    const riskClass   = f._risk ? 'risk' : (f.ndpi.breed === 'Unsafe' ? 'unsafe' : '');
    const breedColour = breedClass(f.ndpi.breed);
    const riskText    = f._risk
      ? Object.values(f.ndpi.flow_risk).map(r => r.risk).join(', ')
      : '';

    return `<tr class="${riskClass}">
      <td class="col-l4">${esc(f.proto)}</td>
      <td class="ip">${esc(f.src)}</td>
      <td class="ip">${esc(f.dst)}</td>
      <td class="col-l7">${esc(f.ndpi.proto||'?')}</td>
      <td>${esc(f.ndpi.category||'')}</td>
      <td class="${breedColour}">${esc(f.ndpi.breed||'')}</td>
      <td class="col-bytes" style="text-align:right">${fmtBytes(f._bytes)}</td>
      <td class="col-bytes" style="text-align:right">${f._pkts}</td>
      <td class="${f._risk ? 'col-risk' : ''}">${f._risk ? '⚠ '+esc(riskText) : f.ndpi.encrypted ? '<span class="col-enc">🔒</span>' : ''}</td>
    </tr>`;
  });

  document.getElementById('tbody').innerHTML = parts.join('');
}

// ── utilities ─────────────────────────────────────────────────────────────────

function get(obj, key) {
  if (key.includes('.')) {
    const [a, b] = key.split('.');
    return (obj[a] || {})[b] || '';
  }
  return obj[key] ?? '';
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B','KB','MB','GB','TB'];
  let i = 0;
  while (n >= 1024 && i < u.length-1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + ' ' + u[i];
}

function breedClass(breed) {
  switch (breed) {
    case 'Safe':        return 'col-safe';
    case 'Unsafe':
    case 'Dangerous':   return 'col-risk';
    case 'Acceptable':
    case 'Fun':         return 'col-l7';
    default:            return '';
  }
}

// ── sortable headers ─────────────────────────────────────────────────────────

document.getElementById('hdr').addEventListener('click', e => {
  const th = e.target.closest('th');
  if (!th) return;
  const k = th.dataset.k;
  if (!k) return;
  if (sortKey === k) { sortDir *= -1; }
  else { sortKey = k; sortDir = -1; }
  document.querySelectorAll('th').forEach(t => t.className = '');
  th.className = sortDir === -1 ? 'desc' : 'asc';
  render();
});

// ── auto-refresh every 5 s ───────────────────────────────────────────────────

fetchFlows();
setInterval(fetchFlows, 5000);
</script>
</body>
</html>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Request handler
# ─────────────────────────────────────────────────────────────────────────────

class Handler(http.server.BaseHTTPRequestHandler):
    data_file: str = DEFAULT_DATA_FILE

    def log_message(self, fmt, *args):
        # Suppress per-request logs to keep output clean; errors still go out
        if args and str(args[1]) not in ('200', '304'):
            super().log_message(fmt, *args)

    def do_GET(self):
        if self.path in ('/', '/index.html'):
            self._send(200, 'text/html; charset=utf-8', HTML.encode())

        elif self.path == '/api/flows':
            try:
                with open(self.data_file, 'rb') as fh:
                    body = fh.read()
                self._send(200, 'application/json', body)
            except FileNotFoundError:
                # Return empty array so the browser shows "0 flows" cleanly
                self._send(200, 'application/json', b'[]')
            except Exception as e:
                self._send(500, 'text/plain', str(e).encode())

        else:
            self._send(404, 'text/plain', b'Not found')

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        # Allow browser to cache the dashboard HTML but never cache flow data
        if '/api/' in self.path:
            self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description='Flow Monitor web server')
    p.add_argument('--port', type=int,  default=DEFAULT_PORT,      metavar='N')
    p.add_argument('--data', type=str,  default=DEFAULT_DATA_FILE,  metavar='PATH')
    args = p.parse_args()

    Handler.data_file = args.data

    # ThreadingHTTPServer handles each request in its own thread — prevents one
    # slow browser connection from stalling others, while keeping overhead tiny
    # (typically only 1-2 threads active at once at this traffic level).
    server = http.server.ThreadingHTTPServer(('0.0.0.0', args.port), Handler)

    print(f"Flow Monitor  http://0.0.0.0:{args.port}/")
    print(f"Data file:    {args.data}")
    print(f"Started:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Ctrl-C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == '__main__':
    main()

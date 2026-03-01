#!/usr/bin/env python3
"""
flow_server.py — Minimal HTTP server for the network flow monitor.

Serves on 0.0.0.0:7000 (reachable on Tailscale automatically).
Endpoints:
  GET /              → HTML5 dashboard (embedded inline)
  GET /api/flows     → reads flows.json, returns it as-is
  GET /favicon.ico   → served from ./html/ if present, else inline SVG fallback
  GET /<anything>    → served from ./html/<anything> if the file exists

Static files:
  Place any static asset in the ./html/ directory and it will be served
  automatically.  For example:
    ./html/favicon.ico   — overrides the inline SVG fallback
    ./html/favicon.png   — add <link> in the HTML if you prefer PNG

No third-party dependencies. Python 3.6+ stdlib only.

Usage:
  python3 flow_server.py [--port 7000] [--data ./ndpi_state/flows.json]
                         [--html ./html]
"""

import http.server
import mimetypes
import os
import argparse
from datetime import datetime
from pathlib import Path

DEFAULT_PORT      = 7000
DEFAULT_DATA_FILE = "./ndpi_state/flows.json"
DEFAULT_HTML_DIR  = "./html"

# MIME types for files served from ./html/ — extends Python's built-in map
EXTRA_MIME = {
    ".ico":   "image/x-icon",
    ".png":   "image/png",
    ".svg":   "image/svg+xml",
    ".webp":  "image/webp",
    ".woff2": "font/woff2",
    ".js":    "application/javascript",
    ".css":   "text/css",
    ".txt":   "text/plain; charset=utf-8",
}

# ─────────────────────────────────────────────────────────────────────────────
# Tiny SVG favicon — served at /favicon.ico as image/svg+xml.
# No file needed on disk; silences the browser 404.
# ─────────────────────────────────────────────────────────────────────────────

FAVICON_SVG = b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect width="32" height="32" rx="6" fill="#0d1117"/>
  <circle cx="16" cy="16" r="9" fill="none" stroke="#58a6ff" stroke-width="2.5"/>
  <circle cx="16" cy="16" r="3" fill="#58a6ff"/>
  <line x1="16" y1="4"  x2="16" y2="10" stroke="#58a6ff" stroke-width="2"/>
  <line x1="16" y1="22" x2="16" y2="28" stroke="#58a6ff" stroke-width="2"/>
  <line x1="4"  y1="16" x2="10" y2="16" stroke="#58a6ff" stroke-width="2"/>
  <line x1="22" y1="16" x2="28" y2="16" stroke="#58a6ff" stroke-width="2"/>
</svg>"""

# ─────────────────────────────────────────────────────────────────────────────
# HTML5 dashboard
# ─────────────────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Flow Monitor</title>
<link rel="icon" type="image/svg+xml" href="/favicon.ico">
<style>
  :root {
    --bg:      #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border:  #30363d;
    --text:    #e6edf3; --muted: #8b949e;
    --green:   #3fb950; --yellow: #d29922; --red: #f85149;
    --blue:    #58a6ff; --purple: #bc8cff; --orange: #ffa657;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text);
         font: 13px/1.5 'Courier New', monospace; }

  /* header */
  header { background: var(--bg2); border-bottom: 1px solid var(--border);
           padding: 10px 18px; display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
  header h1 { font-size: 15px; color: var(--blue); letter-spacing: 1px; white-space: nowrap; }
  #status { font-size: 11px; color: var(--muted); margin-left: auto; white-space: nowrap; }
  #status.ok  { color: var(--green); }
  #status.err { color: var(--red); }

  /* summary cards */
  #summary { display: flex; gap: 10px; padding: 12px 18px; flex-wrap: wrap;
             border-bottom: 1px solid var(--border); background: var(--bg2); }
  .card { background: var(--bg3); border: 1px solid var(--border); border-radius: 6px;
          padding: 8px 16px; min-width: 120px; }
  .card .val { font-size: 20px; font-weight: bold; color: var(--blue); line-height: 1.3; }
  .card .lbl { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .8px; }
  .card.risk  .val { color: var(--red); }
  .card.enc   .val { color: var(--purple); }
  .card.proto .val { font-size: 13px; color: var(--green); }
  .card.window .val { font-size: 13px; color: var(--orange); }

  /* risk legend banner */
  #legend { background: #161b22; border-bottom: 1px solid var(--border);
            padding: 6px 18px; font-size: 11px; color: var(--muted);
            display: flex; gap: 18px; flex-wrap: wrap; align-items: center; }
  #legend b { color: var(--text); }
  #legend .note { color: #6e7681; font-style: italic; }
  #legend-toggle { cursor: pointer; color: var(--blue); user-select: none; white-space: nowrap; }

  /* toolbar */
  #toolbar { padding: 8px 18px; display: flex; gap: 10px; align-items: center;
             flex-wrap: wrap; background: var(--bg); border-bottom: 1px solid var(--border); }
  #filter { background: var(--bg3); border: 1px solid var(--border); color: var(--text);
            padding: 5px 10px; border-radius: 4px; width: 260px; font: inherit; }
  #filter::placeholder { color: var(--muted); }
  #count { font-size: 11px; color: var(--muted); margin-left: auto; }
  label { font-size: 11px; color: var(--muted); display: flex; align-items: center; gap: 4px; cursor: pointer; }
  select { background: var(--bg3); border: 1px solid var(--border); color: var(--text);
           padding: 4px 8px; border-radius: 4px; font: inherit; font-size: 11px; cursor: pointer; }

  /* table */
  #wrap { overflow-x: auto; max-height: calc(100vh - 230px); overflow-y: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 11.5px; }
  thead { position: sticky; top: 0; z-index: 10; }
  th { background: var(--bg3); border-bottom: 2px solid var(--border);
       padding: 6px 9px; text-align: left; white-space: nowrap;
       cursor: pointer; user-select: none; color: var(--muted);
       font-weight: normal; letter-spacing: .4px; font-size: 11px; }
  th:hover { color: var(--text); }
  th.asc::after  { content: " ▲"; color: var(--blue); }
  th.desc::after { content: " ▼"; color: var(--blue); }
  td { padding: 4px 9px; border-bottom: 1px solid #1c2128; white-space: nowrap;
       max-width: 260px; overflow: hidden; text-overflow: ellipsis; }
  tr:hover td { background: var(--bg3); }

  /* row classes */
  tr.risk-hi  > td:first-child { border-left: 3px solid var(--red); }
  tr.risk-lo  > td:first-child { border-left: 3px solid var(--yellow); }
  tr.risk-hi  { background: #200d0d; }

  /* cell colours */
  .c-l4     { color: var(--yellow); font-size: 10px; }
  .c-l7     { color: var(--blue); }
  .c-safe   { color: var(--green); }
  .c-unsafe { color: var(--red); }
  .c-ok     { color: var(--muted); }
  .c-bytes  { color: #adbac7; text-align: right; }
  .c-risk   { color: var(--red); font-size: 10px; white-space: normal;
              line-height: 1.3; max-width: 200px; }
  .c-enc    { color: var(--purple); }
  .c-ip     { color: var(--text); font-size: 11px; }
  .c-port   { color: var(--muted); }
  .no-data  { text-align: center; padding: 60px; color: var(--muted); }
  .no-bytes { color: #444c56; font-style: italic; }

  /* proto badge */
  .badge { display: inline-block; padding: 1px 5px; border-radius: 3px;
           font-size: 10px; background: #21262d; border: 1px solid var(--border); }
  .badge.tcp  { border-color: #1f6feb; }
  .badge.udp  { border-color: #388bfd44; }
  .badge.icmp { border-color: #30363d; }
</style>
</head>
<body>

<header>
  <h1>⬡ NETWORK FLOW MONITOR</h1>
  <span id="status">connecting…</span>
</header>

<div id="summary">
  <div class="card">        <div class="val" id="s-total"> —</div><div class="lbl">Total Flows</div></div>
  <div class="card risk">   <div class="val" id="s-risk">  —</div><div class="lbl">Risky</div></div>
  <div class="card">        <div class="val" id="s-scan">  —</div><div class="lbl">Scan / Probe</div></div>
  <div class="card enc">    <div class="val" id="s-enc">   —</div><div class="lbl">Encrypted</div></div>
  <div class="card proto">  <div class="val" id="s-top">   —</div><div class="lbl">Top L7 Proto</div></div>
  <div class="card window"> <div class="val" id="s-cats">  —</div><div class="lbl">Categories</div></div>
</div>

<div id="legend">
  <span id="legend-toggle" onclick="toggleLegend()">▶ Risk legend</span>
  <span id="legend-body" style="display:none; display:flex; gap:18px; flex-wrap:wrap;">
    <span><b style="color:var(--red)">Malicious Fingerprint</b> — TCP SYN matched known scanner (Shodan/Censys/botnet). Normal on public IPs.</span>
    <span><b style="color:var(--yellow)">Unidirectional</b> — packet sent, no reply (or vice versa). Normal for port scans hitting closed ports.</span>
    <span><b>Known Proto on Non-Std Port</b> — e.g. TLS on port 8443. Usually legitimate.</span>
    <span class="note">On internet-facing hosts, most warnings are background internet noise, not compromise.</span>
  </span>
</div>

<div id="toolbar">
  <input id="filter" placeholder="Filter IP, port, protocol, category…" oninput="render()">
  <select id="sel-cat" onchange="render()"><option value="">All categories</option></select>
  <select id="sel-l7"  onchange="render()"><option value="">All L7 protos</option></select>
  <label><input type="checkbox" id="chk-risk" onchange="render()"> Risky only</label>
  <label><input type="checkbox" id="chk-enc"  onchange="render()"> Encrypted</label>
  <span id="count"></span>
</div>

<div id="wrap">
  <table>
    <thead><tr id="hdr">
      <th data-k="proto">L4</th>
      <th data-k="src_ip">Source IP</th>
      <th data-k="src_port" style="text-align:right">Sport</th>
      <th data-k="dst_arrow" style="text-align:center">→</th>
      <th data-k="dest_ip">Dest IP</th>
      <th data-k="dst_port" style="text-align:right">Dport</th>
      <th data-k="ndpi.proto">L7</th>
      <th data-k="ndpi.category">Category</th>
      <th data-k="ndpi.breed">Breed</th>
      <th data-k="ndpi.encrypted" style="text-align:center">Enc</th>
      <th data-k="_bytes" style="text-align:right">Bytes ↕</th>
      <th data-k="_pkts"  style="text-align:right">Pkts</th>
      <th data-k="_riskscore" style="text-align:right">Score</th>
      <th data-k="_risktext">Risk</th>
    </tr></thead>
    <tbody id="tbody"></tbody>
  </table>
</div>

<script>
"use strict";

let flows   = [];
let sortKey = '_riskscore';
let sortDir = -1;

// ── fetch ─────────────────────────────────────────────────────────────────────

async function fetchFlows() {
  const st = document.getElementById('status');
  try {
    const r = await fetch('/api/flows');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const raw = await r.json();

    // Attach synthetic helper fields
    flows = raw.map(f => {
      const nd = f.ndpi || {};
      const risk = nd.flow_risk && typeof nd.flow_risk === 'object'
                   ? Object.values(nd.flow_risk) : [];
      const riskNames = risk.map(r => r.risk || '').filter(Boolean);
      const maxSev = risk.reduce((m, r) => {
        const s = (r.severity||'').toLowerCase();
        if (s === 'high')   return Math.max(m, 3);
        if (s === 'medium') return Math.max(m, 2);
        if (s === 'low')    return Math.max(m, 1);
        return m;
      }, 0);
      return {
        ...f,
        _bytes:     (nd.cli2srv_bytes||0) + (nd.srv2cli_bytes||0),
        _pkts:      (nd.cli2srv_pkts||0)  + (nd.srv2cli_pkts||0),
        _riskscore: nd.ndpi_risk_score || 0,
        _risknames: riskNames,
        _risktext:  riskNames.join(' · '),
        _severity:  maxSev,       // 0=none 1=low 2=med 3=high
        _hasrisk:   riskNames.length > 0,
      };
    });

    populateDropdowns();
    computeSummary();
    render();

    const now = new Date().toLocaleTimeString();
    st.textContent = `↻ ${now} · ${flows.length} flows`;
    st.className = 'ok';
  } catch(e) {
    st.textContent = `✗ ${e.message}`;
    st.className = 'err';
  }
}

// ── dropdowns ─────────────────────────────────────────────────────────────────

function populateDropdowns() {
  const cats = [...new Set(flows.map(f => f.ndpi?.category).filter(Boolean))].sort();
  const l7s  = [...new Set(flows.map(f => f.ndpi?.proto).filter(Boolean))].sort();

  function repop(id, vals) {
    const sel = document.getElementById(id);
    const cur = sel.value;
    sel.innerHTML = `<option value="">All ${id==='sel-cat'?'categories':'L7 protos'}</option>`
      + vals.map(v => `<option${v===cur?' selected':''}>${esc(v)}</option>`).join('');
  }
  repop('sel-cat', cats);
  repop('sel-l7',  l7s);
}

// ── summary ───────────────────────────────────────────────────────────────────

function computeSummary() {
  let risky = 0, scans = 0, enc = 0;
  const protoCounts = {}, catSet = new Set();
  for (const f of flows) {
    if (f._hasrisk)         risky++;
    if (f._risknames.some(r => r.toLowerCase().includes('fingerprint') ||
                               r.toLowerCase().includes('unidirectional'))) scans++;
    if (f.ndpi?.encrypted)  enc++;
    const p = f.ndpi?.proto || f.proto;
    if (p) protoCounts[p] = (protoCounts[p]||0)+1;
    if (f.ndpi?.category) catSet.add(f.ndpi.category);
  }
  const top = Object.entries(protoCounts).sort((a,b)=>b[1]-a[1])[0];
  document.getElementById('s-total').textContent = flows.length;
  document.getElementById('s-risk' ).textContent = risky;
  document.getElementById('s-scan' ).textContent = scans;
  document.getElementById('s-enc'  ).textContent = enc + (flows.length
    ? ` (${Math.round(enc*100/flows.length)}%)` : '');
  document.getElementById('s-top'  ).textContent = top
    ? `${top[0]} ×${top[1]}` : '—';
  document.getElementById('s-cats' ).textContent = [...catSet].join(', ') || '—';
}

// ── render ────────────────────────────────────────────────────────────────────

function render() {
  const q       = document.getElementById('filter').value.toLowerCase();
  const cat     = document.getElementById('sel-cat').value;
  const l7      = document.getElementById('sel-l7').value;
  const onlyRisk = document.getElementById('chk-risk').checked;
  const onlyEnc  = document.getElementById('chk-enc').checked;

  let rows = flows.filter(f => {
    if (onlyRisk && !f._hasrisk)         return false;
    if (onlyEnc  && !f.ndpi?.encrypted)  return false;
    if (cat && f.ndpi?.category !== cat) return false;
    if (l7  && f.ndpi?.proto   !== l7)  return false;
    if (!q) return true;
    return (f.src_ip + ' ' + f.dest_ip + ' ' + f.proto + ' ' +
            f.src_port + ' ' + f.dst_port + ' ' +
            (f.ndpi?.proto||'') + ' ' + (f.ndpi?.category||'') + ' ' +
            (f.ndpi?.breed||'') + ' ' + f._risktext)
           .toLowerCase().includes(q);
  });

  rows.sort((a,b) => {
    let av = get(a, sortKey), bv = get(b, sortKey);
    if (typeof av === 'string') av = av.toLowerCase();
    if (typeof bv === 'string') bv = bv.toLowerCase();
    return av < bv ?  sortDir :
           av > bv ? -sortDir : 0;
  });

  document.getElementById('count').textContent =
    `${rows.length} / ${flows.length} flows`;

  if (!rows.length) {
    document.getElementById('tbody').innerHTML =
      '<tr><td colspan="14" class="no-data">No flows match.</td></tr>';
    return;
  }

  const html = rows.map(f => {
    const nd = f.ndpi || {};
    const rowCls = f._severity >= 3 ? 'risk-hi' :
                   f._severity >= 1 ? 'risk-lo' : '';

    const proto = f.proto||'';
    const pbadge = `<span class="badge ${proto.toLowerCase()}">${esc(proto)}</span>`;

    const bytesCell = f._bytes > 0
      ? `<span class="c-bytes">${fmtBytes(f._bytes)}</span>`
      : `<span class="no-bytes">n/a</span>`;
    const pktsCell  = f._pkts  > 0
      ? `<span class="c-bytes">${f._pkts}</span>`
      : `<span class="no-bytes">—</span>`;

    const breedCls = nd.breed === 'Safe'      ? 'c-safe'   :
                     nd.breed === 'Unsafe' ||
                     nd.breed === 'Dangerous'  ? 'c-unsafe' : 'c-ok';

    const encCell = nd.encrypted
      ? '<span class="c-enc" title="Encrypted">🔒</span>' : '';

    const scoreCell = f._riskscore > 0
      ? `<span class="c-unsafe">${f._riskscore}</span>` : '';

    const riskCell = f._hasrisk
      ? `<span class="c-risk" title="${esc(f._risktext)}">${esc(f._risktext)}</span>`
      : '';

    return `<tr class="${rowCls}">
      <td>${pbadge}</td>
      <td class="c-ip">${esc(f.src_ip||'')}</td>
      <td class="c-port" style="text-align:right">${f.src_port||'—'}</td>
      <td style="text-align:center;color:var(--border)">→</td>
      <td class="c-ip">${esc(f.dest_ip||'')}</td>
      <td class="c-port" style="text-align:right">${f.dst_port||'—'}</td>
      <td class="c-l7">${esc(nd.proto||'?')}</td>
      <td>${esc(nd.category||'')}</td>
      <td class="${breedCls}">${esc(nd.breed||'')}</td>
      <td style="text-align:center">${encCell}</td>
      <td style="text-align:right">${bytesCell}</td>
      <td style="text-align:right">${pktsCell}</td>
      <td style="text-align:right">${scoreCell}</td>
      <td>${riskCell}</td>
    </tr>`;
  });

  document.getElementById('tbody').innerHTML = html.join('');
}

// ── sortable headers ──────────────────────────────────────────────────────────

document.getElementById('hdr').addEventListener('click', e => {
  const th = e.target.closest('th[data-k]');
  if (!th || th.dataset.k === 'dst_arrow') return;
  const k = th.dataset.k;
  if (sortKey === k) sortDir *= -1;
  else { sortKey = k; sortDir = -1; }
  document.querySelectorAll('th').forEach(t => t.className = '');
  th.className = sortDir === -1 ? 'desc' : 'asc';
  render();
});

// ── legend toggle ─────────────────────────────────────────────────────────────

function toggleLegend() {
  const b = document.getElementById('legend-body');
  const t = document.getElementById('legend-toggle');
  const show = b.style.display === 'none';
  b.style.display = show ? 'flex' : 'none';
  t.textContent = (show ? '▼' : '▶') + ' Risk legend';
}

// ── utilities ─────────────────────────────────────────────────────────────────

function get(obj, key) {
  if (key.startsWith('ndpi.')) return (obj.ndpi||{})[key.slice(5)] ?? '';
  return obj[key] ?? '';
}

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B','KB','MB','GB'];
  let i = 0;
  while (n >= 1024 && i < u.length-1) { n/=1024; i++; }
  return (i ? n.toFixed(1) : n) + '\u202f' + u[i];
}

// ── boot ──────────────────────────────────────────────────────────────────────

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
    html_dir:  str = DEFAULT_HTML_DIR

    def log_message(self, fmt, *args):
        # Only log non-200 responses to keep output clean
        if args and str(args[1]) not in ('200', '304'):
            super().log_message(fmt, *args)

    def do_GET(self):
        if self.path in ('/', '/index.html'):
            self._send(200, 'text/html; charset=utf-8', HTML.encode())

        elif self.path == '/api/flows':
            try:
                with open(self.data_file, 'rb') as fh:
                    body = fh.read()
                self._send(200, 'application/json', body,
                           extra_headers=[('Cache-Control', 'no-store')])
            except FileNotFoundError:
                self._send(200, 'application/json', b'[]',
                           extra_headers=[('Cache-Control', 'no-store')])
            except Exception as e:
                self._send(500, 'text/plain', str(e).encode())

        else:
            # Try to serve from ./html/ static directory.
            # Path traversal is prevented by resolving against html_dir and
            # checking the result still starts with that directory.
            served = self._try_static(self.path)
            if not served:
                # Last resort: for /favicon.ico serve the inline SVG fallback
                # so the browser never gets a 404 even without an html/ folder.
                if self.path == '/favicon.ico':
                    self._send(200, 'image/svg+xml', FAVICON_SVG)
                else:
                    self._send(404, 'text/plain', b'Not found')

    def _try_static(self, url_path):
        """Serve url_path from html_dir. Returns True if served, False if not found."""
        # Strip query string and decode percent-encoding
        clean = url_path.split('?')[0]
        try:
            clean = clean.encode('ascii').decode('unicode_escape')
        except Exception:
            return False

        # Resolve to an absolute path and guard against traversal
        base    = Path(self.html_dir).resolve()
        target  = (base / clean.lstrip('/')).resolve()
        if not str(target).startswith(str(base)):
            self._send(403, 'text/plain', b'Forbidden')
            return True  # handled (with error)

        if not target.is_file():
            return False

        ext      = target.suffix.lower()
        ctype    = EXTRA_MIME.get(ext) or mimetypes.guess_type(str(target))[0] or 'application/octet-stream'
        try:
            body = target.read_bytes()
            self._send(200, ctype, body)
            return True
        except OSError:
            return False

    def _send(self, code, ctype, body, extra_headers=None):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description='Flow Monitor web server')
    p.add_argument('--port', type=int, default=DEFAULT_PORT,      metavar='N')
    p.add_argument('--data', type=str, default=DEFAULT_DATA_FILE,  metavar='PATH')
    p.add_argument('--html', type=str, default=DEFAULT_HTML_DIR,   metavar='DIR',
                   help='Directory to serve static files from (default: ./html)')
    args = p.parse_args()

    Handler.data_file = args.data
    Handler.html_dir  = args.html

    # Create the html directory if it doesn't exist so the server starts cleanly
    # even before the user has put any files there.
    Path(args.html).mkdir(parents=True, exist_ok=True)

    server = http.server.ThreadingHTTPServer(('0.0.0.0', args.port), Handler)

    print(f"Flow Monitor  http://0.0.0.0:{args.port}/")
    print(f"Data file:    {args.data}")
    print(f"Static files: {args.html}/  (drop favicon.ico etc. here)")
    print(f"Started:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Ctrl-C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()

if __name__ == '__main__':
    main()

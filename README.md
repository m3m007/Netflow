# ndpi-flow-monitor

A lightweight network flow monitor built on [nDPI](https://github.com/ntop/nDPI)'s `ndpiReader`.
A Rust daemon captures and stores flows; a Python web server serves a live HTML5 dashboard.

```
ndpiReader ──NDJSON──► flow_monitor (Rust)
                             │
                    sled DB (./ndpi_db)
                             │
                    flows.json (./ndpi_state/)   ◄── atomic rename every 5 s
                             │
                    flow_server.py (Python)
                             │
                    browser  http://tailnet-host:7000/
```

---

## Features

- **Deep packet inspection** via nDPI — identifies 300+ application protocols (TLS, QUIC, STUN, HTTP/2, DNS-over-HTTPS, …)
- **Risk flagging** — surfaces flows carrying nDPI risk events (Malicious Fingerprint, Unidirectional Traffic, Known Proto on Non-Std Port, …)
- **Cross-window deduplication** — flow records are deduplicated across 15-second capture windows so the same reconnecting host doesn't generate noise
- **Live web dashboard** — sortable, filterable table with per-flow byte counts, protocol labels, breed classification and risk indicators; auto-refreshes every 5 seconds
- **Zero lock contention** — the web server never touches the sled database; the Rust process exports an atomically-replaced JSON snapshot for the browser to consume
- **BPF pre-filtering** — reduce DPI CPU load with a kernel-level filter before packets reach nDPI
- **Tailscale-ready** — server binds `0.0.0.0:7000`; reachable on any Tailscale address automatically
- **No browser dependencies** — pure HTML5 + vanilla JS; no npm, no bundler, no CDN calls

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  flow_monitor  (runs as root for pcap)               │
│                                                      │
│  ndpiReader ──stdout──► parser_task                  │
│                              │                       │
│                         dedup_task  (LRU 50k flows)  │
│                              │                       │
│                      sled_flush_task  ──► ./ndpi_db  │
│                                                      │
│                      json_export_task ──► flows.json │
│                        (every 5 s, atomic rename)    │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  flow_server.py  (runs as any user)                  │
│                                                      │
│  GET /            ──► embedded HTML5 dashboard       │
│  GET /api/flows   ──► reads flows.json (read-only)   │
└─────────────────────────────────────────────────────┘
```

---

## Requirements

### System

| Requirement | Notes |
|---|---|
| Linux (x86\_64 or ARM64) | Tested on Kernel 6.18.13 (Arch) |
| `ndpiReader` ≥ 4.x | Must be on `$PATH`; see install below |
| `libpcap` | Usually already present; needed by ndpiReader |
| Rust ≥ 1.70 | Install via `rustup` |
| Python ≥ 3.6 | Stdlib only — no pip packages needed |
| Root / `CAP_NET_RAW` | Required for live packet capture |

### Rust crate dependencies (handled automatically by Cargo)

| Crate | Version | Purpose |
|---|---|---|
| `tokio` | 1 (full) | Async runtime |
| `sled` | 0.34 | Embedded key-value store |
| `indexmap` | 2 | Ordered map for LRU dedup |
| `serde` + `serde_json` | 1 | JSON serialisation |
| `thiserror` | 1 | Error types |
| `chrono` | 0.4 | Timestamped debug filenames |

---

## Installing ndpiReader

### Debian / Ubuntu — from ntop packages (recommended, stays up to date)

```bash
# Add the ntop repository
wget -qO - https://packages.ntop.org/apt/ntop.key | sudo apt-key add -
echo "deb https://packages.ntop.org/apt/$(lsb_release -cs)/ $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/ntop.list

sudo apt-get update
sudo apt-get install -y ndpi libndpi-dev libndpi-bin
```

### Debian / Ubuntu — from distribution packages (older version, simpler)

```bash
sudo apt-get install -y libndpi-bin
```

> ⚠️ Distribution packages may be nDPI 4.x.  The JSON field layout is the same
> but some optional fields (e.g. `tcp_fingerprint`) may be absent.  This is safe —
> absent fields default to empty/zero.

### Build from source (for nDPI 5.x features)

```bash
sudo apt-get install -y build-essential libpcap-dev libssl-dev \
                        automake autoconf libtool pkg-config git

git clone https://github.com/ntop/nDPI.git
cd nDPI
./autogen.sh
./configure
make -j$(nproc)
sudo make install
sudo ldconfig
```

### Verify

```bash
ndpiReader --help          # should print usage
which ndpiReader           # should print a path
```

---

## Building flow_monitor (Rust)

### Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### Clone and build

```bash
git clone https://github.com/m3m007/Netflow.git
cd ndpi-flow-monitor

cargo build --release
```

The binary is at `target/release/flow_monitor`.

First build downloads and compiles all crate dependencies — expect 1–3 minutes.
Subsequent builds are incremental and take a few seconds.

### Verify the binary

```bash
./target/release/flow_monitor --help    # prints nothing useful yet, but confirms it runs
```

---

## Running

Both processes must be started.  They are independent — the web server can be
restarted without touching the Rust daemon, and vice versa.

### 1. Start the flow monitor (requires root)

```bash
# Minimal — capture on eth0
sudo ./target/release/flow_monitor -i eth0

# With a BPF filter to reduce noise (highly recommended on busy links)
sudo ./target/release/flow_monitor -i eth0 -f "not port 22 and not arp"

# Specify a different interface
sudo ./target/release/flow_monitor -i ens3

# Show every flow immediately as it arrives (instead of batching per second)
sudo ./target/release/flow_monitor -i eth0 --continuous
```

On startup you will see:

```
STDOUT STREAMING MODE  (-k /dev/stdout -q)
JSON export → ./ndpi_state/flows.json (every 5s)
Capture on eth0 (15s window)
```

ndpiReader is respawned automatically every 15 seconds.
Stop with **Ctrl-C** — the shutdown is clean and all buffered flows are flushed.

### 2. Start the web server (any user)

In a separate terminal, from the same directory:

```bash
python3 flow_server.py
```

Then open localhost:7000 or **http://\<your-tailnet-hostname\>:7000/** in a browser.

```bash
# Custom port or data file path
python3 flow_server.py --port 8080 --data /var/run/ndpi/flows.json
```

---

## File layout at runtime

```
ndpi-flow-monitor/
├── target/release/flow_monitor   # compiled binary
├── flow_server.py                # web server
│
├── ndpi_db/                      # sled database (created automatically)
│   ├── db.lock                   # ← exclusive OS lock; do NOT open from another process
│   └── ...
│
└── ndpi_state/
    └── flows.json                # JSON snapshot for the web server (atomic rename)
```

> **Important:** `ndpi_db/` is locked exclusively by `flow_monitor` while it runs.
> Never point another sled instance or database tool at it while the daemon is running.
> `flows.json` is safe to read at any time — it is always a complete, valid JSON file.

---

## Configuration reference

Settings are accepted as CLI flags **or** environment variables.
CLI flags take precedence over environment variables.

| CLI flag | Environment variable | Default | Description |
|---|---|---|---|
| `-i eth0` | `FLOW_INTERFACE=eth0` | `eth0` | Network interface to capture on |
| `-f "not arp"` | `FLOW_BPF_FILTER="not arp"` | *(none)* | BPF pre-filter expression |
| `--export-path P` | `FLOW_EXPORT_PATH=P` | `./ndpi_state/flows.json` | Where to write the JSON snapshot |
| `--continuous` | `FLOW_CONTINUOUS_OUTPUT=1` | off | Print every flow to terminal immediately |
| `--no-output` | `FLOW_NO_OUTPUT=1` | off | Suppress all terminal flow output |
| `--debug-files` | `FLOW_DEBUG_FILES=1` | off | Write raw NDJSON files instead of streaming |
| `--debug-dir D` | `FLOW_DEBUG_DIR=D` | `./ndpi_debug` | Directory for debug NDJSON files |

### Web server options

| Flag | Default | Description |
|---|---|---|
| `--port N` | `7000` | TCP port to listen on |
| `--data PATH` | `./ndpi_state/flows.json` | Path to the JSON snapshot file |

---

## Debug mode

If you are getting JSON parse errors or seeing unexpected data, `--debug-files`
writes one raw NDJSON file per 15-second window and keeps them on disk:

```bash
sudo ./target/release/flow_monitor -i eth0 --debug-files
```

Files appear in `./ndpi_debug/` as `ndpi_YYYYMMDD_HHMMSS.json`.
Inspect a single flow record:

```bash
head -1 ndpi_debug/ndpi_20250117_143022.json | python3 -m json.tool
```

This lets you verify field names directly against your installed ndpiReader version,
which can vary depending on build flags and configure options.

---

## BPF filter examples

A good BPF filter dramatically reduces CPU load on busy links by dropping
uninteresting packets before they reach nDPI's DPI engine.

```bash
# Drop SSH, mDNS and ARP — usually safe to ignore for flow analysis
-f "not port 22 and not port 5353 and not arp"

# Focus only on traffic to/from a specific host
-f "host 10.0.0.50"

# Only analyse TCP traffic
-f "tcp"

# Ignore ICMP entirely
-f "not icmp and not icmp6"
```

BPF filter syntax is the same as `tcpdump`.

---

## Running as a systemd service

### flow_monitor.service

```ini
[Unit]
Description=ndpi Flow Monitor
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ndpi-flow-monitor
ExecStart=/opt/ndpi-flow-monitor/target/release/flow_monitor -i eth0 -f "not port 22 and not arp" --no-output
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### flow_server.service

```ini
[Unit]
Description=ndpi Flow Monitor Web Server
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/ndpi-flow-monitor
ExecStart=/usr/bin/python3 /opt/ndpi-flow-monitor/flow_server.py --port 7000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp flow_monitor.service flow_server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now flow_monitor flow_server

# Check status
sudo systemctl status flow_monitor
sudo systemctl status flow_server

# Follow logs
sudo journalctl -u flow_monitor -f
```

---

## Troubleshooting

### `ndpiReader: command not found`
Install ndpiReader (see [Installing ndpiReader](#installing-ndpireader)) and make sure it is on `$PATH`.
If you built from source: `sudo make install` or add the build directory to `PATH`.

### `Permission denied` / `Operation not permitted`
The flow monitor must run as root or with `CAP_NET_RAW`:
```bash
sudo ./target/release/flow_monitor -i eth0
# or
sudo setcap cap_net_raw+eip target/release/flow_monitor
./target/release/flow_monitor -i eth0
```

### `No such device` for the interface
Find your interface name with `ip link show` or `ifconfig -a`.
Common names: `eth0`, `ens3`, `enp3s0`, `wlan0`, `tailscale0`.

### `flows.json` is empty or missing
The file is written every 5 seconds after the first flow arrives.
Wait one capture window (15 seconds) after starting the monitor.
Check the monitor's terminal output for parse errors.

### JSON parse errors in the terminal
Run with `--debug-files` and inspect the raw output (see [Debug mode](#debug-mode)).
The most common cause is a field-name difference between nDPI builds.

### Dashboard shows stale data / stops updating
Check that `flow_monitor` is still running — the web server only reads the file,
it cannot detect if the producer has stopped.
`flow_server.py` will always serve the last successfully written snapshot.

### Flows not appearing for certain protocols
Add `-f` to restrict to interesting traffic, or check that nDPI has the protocol
in its library: `ndpiReader -i lo -s 2 --debug-files` and inspect what fields appear.

---

## Notes on nDPI versions

The JSON field layout was verified against nDPI 4.x and 5.x.
Key quirks to be aware of if you are debugging a different build:

- The destination address field is `"dest_ip"`, **not** `"dst_ip"` — this is
  asymmetric with `"dst_port"` and differs from many other tools' conventions.
- All nDPI classification fields (`proto`, `breed`, `category`, `flow_risk`, …)
  are nested inside a `"ndpi"` sub-object, not at the top level.
- Byte and packet counters (`cli2srv_bytes`, etc.) are only present if your
  ndpiReader was compiled with `--enable-flow-stats` or equivalent.
- `tcp_fingerprint` is a nDPI 5.x field and will be absent in 4.x output.

---

## License

MIT

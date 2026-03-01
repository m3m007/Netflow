// ═════════════════════════════════════════════════════════════════════════════
// Cargo.toml dependencies:
//
//   [dependencies]
//   tokio      = { version = "1", features = ["full"] }
//   sled       = "0.34"
//   indexmap   = "2"
//   thiserror  = "1"
//   serde      = { version = "1", features = ["derive"] }
//   serde_json = "1"
//   chrono     = { version = "0.4", features = ["clock"] }
//
// ═════════════════════════════════════════════════════════════════════════════
// INVOCATION MODES
//
// ── Default: stdout streaming ─────────────────────────────────────────────────
//
//   ndpiReader -i eth0 -s <N> -k /dev/stdout -K json -q [-f <BPF>]
//
//   On Linux /dev/stdout is valid for fopen(), so ndpi_flow2json writes each
//   completed flow as a JSON line directly into our pipe.  We consume it
//   concurrently, so the pipe never fills and ndpiReader never blocks.
//
//   WHY -q IS MANDATORY:
//     Without -q, ndpiReader emits a startup banner and per-thread stats to
//     stdout even when -k is active.  Those lines are not JSON and trigger
//     parse errors.  -q suppresses all non-flow output to stdout.
//
//   WHY -s IS MANDATORY:
//     Without a capture window ndpiReader runs forever.  If the pipe ever
//     fills (reader stalls), ndpiReader's fwrite() blocks and it stops
//     reacting to signals — the hang observed in testing.  -s N guarantees a
//     clean exit, immediately restarted by our loop.
//
// ── Debug: file mode (--debug-files) ─────────────────────────────────────────
//
//   ndpiReader -i eth0 -s <N> -k ./ndpi_debug/ndpi_<ts>.json -K json -q
//
//   We wait for the process to exit (file fully flushed), then parse.
//   The file is kept on disk for inspection with `python3 -m json.tool`.
//   Enable: --debug-files  or  FLOW_DEBUG_FILES=1
//
// ── Useful ndpiReader flags ────────────────────────────────────────────────────
//
//   -i <iface>   Network interface (required)
//   -s <N>       Exit cleanly after N seconds (REQUIRED for our loop)
//   -k <path>    NDJSON output path; /dev/stdout for streaming mode
//   -K json      Enable ndpi_flow2json serialiser
//   -q           Quiet: suppress banner + stats (REQUIRED in streaming mode)
//   -f <BPF>     Pre-filter traffic before DPI (huge CPU saving on busy links;
//                e.g. "not port 22", "not arp", "host 10.0.0.1")
//   -t           Dissect GTP/TZSP tunnels (mobile / VPN environments)
//
// ═════════════════════════════════════════════════════════════════════════════
// SLED LOCKING — WHY THE WEB SERVER MUST NOT OPEN THE DB DIRECTLY
//
//   sled 0.34 places an exclusive OS-level lock on the DB directory
//   (./ndpi_db/db.lock) for the entire lifetime of this process.  Any second
//   process that calls sled::open() on the same path will get an immediate
//   error.  Opening it read-only is not an option; sled has no read-only mode.
//
//   The solution used here is a background json_export_task that periodically
//   snapshots the entire flow table to a plain JSON file, written atomically
//   via rename(2).  The web server reads only that file — no DB access, no
//   lock contention, never reads a partial write.
//
// ═════════════════════════════════════════════════════════════════════════════
// JSON FIELD LAYOUT — verified from actual ndpiReader 5.x sample output
//
//   Top-level:
//     "src_ip"          string   Source IP (IPv4 or IPv6)
//     "dest_ip"         string   Destination IP  ← "dest_ip", NOT "dst_ip"
//     "src_port"        u32      Source port (absent for ICMP → defaults to 0)
//     "dst_port"        u32      Dest port   (absent for ICMP → defaults to 0)
//     "ip"              u32      IP version: 4 or 6
//     "proto"           string   L4: "TCP", "UDP", "ICMPV6", …
//     "tcp_fingerprint" string   Optional JA4/TCP fingerprint
//
//   Nested under "ndpi":
//     "proto"           string   L7 name: "STUN", "TLS", "HTTP", …
//     "proto_id"        string   Numeric protocol id as string, e.g. "78"
//     "proto_by_ip"     string   Protocol guessed from IP
//     "encrypted"       u32      1 = flow is encrypted
//     "breed"           string   "Acceptable", "Safe", "Unsafe", "Fun", …
//     "category_id"     u32      nDPI category numeric id
//     "category"        string   nDPI category name
//     "confidence"      object   {"<num>": "<method>"} — kept as raw JSON
//     "flow_risk"       object   Optional risk entries  — kept as raw JSON
//     "ndpi_risk_score" u32      Aggregate risk score
//     "first_seen"      u64      Epoch ms (build-dependent)
//     "last_seen"       u64      Epoch ms (build-dependent)
//     "cli2srv_bytes"   u64      (build-dependent)
//     "srv2cli_bytes"   u64      (build-dependent)
//     "cli2srv_pkts"    u64      (build-dependent)
//     "srv2cli_pkts"    u64      (build-dependent)
//
// ═════════════════════════════════════════════════════════════════════════════

use std::{
    collections::{hash_map::DefaultHasher, VecDeque},
    env,
    hash::{Hash, Hasher},
    path::PathBuf,
    process::Stdio,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use chrono::Local;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use sled::Db;
use thiserror::Error;
use tokio::{
    fs,
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    signal,
    sync::mpsc::{self, Sender},
    task,
    time::{interval, sleep},
};

// ─────────────────────────────────────────────────────────────────────────────
// Capture window in seconds
// ─────────────────────────────────────────────────────────────────────────────

const CAPTURE_WINDOW_SECS: u32 = 15;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
enum AppError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),
}

// ─────────────────────────────────────────────────────────────────────────────
// NdpiInfo — nested "ndpi" sub-object in ndpiReader's JSON
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct NdpiInfo {
    #[serde(default)] proto:           String,
    #[serde(default)] proto_id:        String,
    #[serde(default)] proto_by_ip:     String,
    #[serde(default)] encrypted:       u32,
    #[serde(default)] breed:           String,
    #[serde(default)] category_id:     u32,
    #[serde(default)] category:        String,
    /// {"<id>": "<method>"} — raw JSON; keys are numeric strings
    #[serde(default)] confidence:      serde_json::Value,
    /// Raw JSON — new risk types never break parsing
    #[serde(default)] flow_risk:       serde_json::Value,
    #[serde(default)] ndpi_risk_score: u32,

    // Optional counters — present only in some ndpiReader builds
    #[serde(default)] first_seen:    u64,
    #[serde(default)] last_seen:     u64,
    #[serde(default)] cli2srv_bytes: u64,
    #[serde(default)] srv2cli_bytes: u64,
    #[serde(default)] cli2srv_pkts:  u64,
    #[serde(default)] srv2cli_pkts:  u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// FlowRecord — top-level fields match actual ndpiReader 5.x NDJSON
//
//   Field naming quirk in ndpiReader:
//     "dest_ip"  — destination address (NOT "dst_ip")
//     "dst_port" — destination port    (asymmetric with dest_ip, but correct)
//
//   src_port / dst_port are #[serde(default)] because ICMP/ICMPv6 flows omit
//   them entirely; they default to 0 rather than causing a parse failure.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct FlowRecord {
    src_ip:  String,
    dest_ip: String,
    #[serde(default)] src_port: u32,
    #[serde(default)] dst_port: u32,
    #[serde(default)] ip:       u32,   // 4 or 6
    proto:   String,                   // L4: "TCP", "UDP", "ICMPV6", …
    #[serde(default)] tcp_fingerprint: String,
    #[serde(default)] ndpi: NdpiInfo,
}

impl FlowRecord {
    #[inline] fn total_bytes(&self) -> u64 { self.ndpi.cli2srv_bytes + self.ndpi.srv2cli_bytes }
    #[inline] fn total_pkts (&self) -> u64 { self.ndpi.cli2srv_pkts  + self.ndpi.srv2cli_pkts  }

    #[inline]
    fn has_risk(&self) -> bool {
        matches!(&self.ndpi.flow_risk, serde_json::Value::Object(m) if !m.is_empty())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FlowKey — 5-tuple hash
//
// Deduplication note: ndpiReader emits each flow once at completion (FIN/RST
// for TCP; idle timeout for UDP/ICMP).  Within a single capture window,
// duplicates are impossible.  The dedup map's value is cross-window: if
// ndpiReader restarts quickly after a crash and re-emits a flow, we avoid
// writing a duplicate to sled.  Reconnections on the same 5-tuple always pass
// through because their byte counts differ, making PartialEq return false.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey(u64);

fn flow_key(flow: &FlowRecord) -> FlowKey {
    let mut h = DefaultHasher::new();
    flow.src_ip.hash(&mut h);
    flow.src_port.hash(&mut h);
    flow.dest_ip.hash(&mut h);  // "dest_ip" — correct field name
    flow.dst_port.hash(&mut h);
    flow.proto.hash(&mut h);    // L4 at top level
    FlowKey(h.finish())
}

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Config {
    interface:         String,
    bpf_filter:        Option<String>,
    continuous_output: bool,
    no_output:         bool,
    debug_files:       bool,
    debug_dir:         PathBuf,
    /// Path where the JSON snapshot is written for the web server.
    /// Parent directory is created automatically.
    export_path:       PathBuf,
}

impl Config {
    fn from_env_or_args() -> Self {
        let mut interface         = String::from("eth0");
        let mut bpf_filter        = None::<String>;
        let mut continuous_output = false;
        let mut no_output         = false;
        let mut debug_files       = false;
        let mut debug_dir         = PathBuf::from("./ndpi_debug");
        let mut export_path       = PathBuf::from("./ndpi_state/flows.json");

        if let Ok(v) = env::var("FLOW_INTERFACE")         { interface     = v; }
        if let Ok(v) = env::var("FLOW_BPF_FILTER")        { bpf_filter    = Some(v); }
        if let Ok(v) = env::var("FLOW_DEBUG_DIR")         { debug_dir     = PathBuf::from(v); }
        if let Ok(v) = env::var("FLOW_EXPORT_PATH")       { export_path   = PathBuf::from(v); }
        if let Ok(v) = env::var("FLOW_DEBUG_FILES") {
            debug_files = matches!(v.to_lowercase().as_str(), "1" | "true");
        }
        if let Ok(v) = env::var("FLOW_CONTINUOUS_OUTPUT") {
            continuous_output = matches!(v.to_lowercase().as_str(), "1" | "true");
        }
        if let Ok(v) = env::var("FLOW_NO_OUTPUT") {
            no_output = matches!(v.to_lowercase().as_str(), "1" | "true");
        }

        let args: Vec<String> = env::args().collect();
        let mut iter = args.iter().skip(1);
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--continuous"        => continuous_output = true,
                "--no-output"         => no_output         = true,
                "--debug-files"       => debug_files       = true,
                "-i" | "--interface"  => { if let Some(v) = iter.next() { interface    = v.clone(); } }
                "-f" | "--bpf"        => { if let Some(v) = iter.next() { bpf_filter   = Some(v.clone()); } }
                "--debug-dir"         => { if let Some(v) = iter.next() { debug_dir    = PathBuf::from(v); } }
                "--export-path"       => { if let Some(v) = iter.next() { export_path  = PathBuf::from(v); } }
                _ => {}
            }
        }

        Self { interface, bpf_filter, continuous_output, no_output,
               debug_files, debug_dir, export_path }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ndpiReader argument builder
//
// -q is always included to prevent ndpiReader from emitting its startup banner
// and per-thread stats to stdout, which would inject non-JSON lines into our
// stream and cause parse errors in streaming mode.
// ─────────────────────────────────────────────────────────────────────────────

fn ndpi_args(config: &Config, window_str: &str, k_path: &str) -> Vec<String> {
    let mut args = vec![
        "-i".into(), config.interface.clone(),
        "-s".into(), window_str.into(),
        "-k".into(), k_path.into(),
        "-K".into(), "json".into(),
        "-q".into(),
    ];
    if let Some(ref f) = config.bpf_filter {
        args.push("-f".into());
        args.push(f.clone());
    }
    args
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: timestamped debug file path
// ─────────────────────────────────────────────────────────────────────────────

fn debug_file_path(config: &Config) -> PathBuf {
    let ts = Local::now().format("%Y%m%d_%H%M%S");
    config.debug_dir.join(format!("ndpi_{ts}.json"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: pretty-print one flow to terminal
// ─────────────────────────────────────────────────────────────────────────────

fn print_flow(flow: &FlowRecord) {
    let risk = if flow.has_risk() { "⚠ " } else { "  " };
    println!(
        "{risk}{:<8} {:>39}:{:<5} -> {:>39}:{:<5}  {:>10}B  {:>6}pkts  L7={} [{}]",
        flow.proto, flow.src_ip, flow.src_port,
        flow.dest_ip, flow.dst_port,
        flow.total_bytes(), flow.total_pkts(),
        flow.ndpi.proto, flow.ndpi.category,
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Task: JSON export for the web server
//
// Runs every EXPORT_INTERVAL_SECS.  Reads the entire sled flow tree in a
// spawn_blocking call (sled is sync), serialises to JSON, and writes
// atomically using rename(2):
//
//   write  →  ./ndpi_state/flows.json.tmp
//   rename →  ./ndpi_state/flows.json
//
// rename(2) is atomic on Linux on the same filesystem, so the web server
// never reads a partial file.  The web server needs no DB access and is
// completely free of sled's exclusive directory lock.
// ─────────────────────────────────────────────────────────────────────────────

const EXPORT_INTERVAL_SECS: u64 = 5;

async fn json_export_task(tree: sled::Tree, export_path: PathBuf) {
    let tmp_path = export_path.with_extension("json.tmp");
    let mut tick = interval(Duration::from_secs(EXPORT_INTERVAL_SECS));
    tick.tick().await; // discard the immediate first tick

    loop {
        tick.tick().await;

        // Collect all flows from sled on a blocking thread
        let t = tree.clone();
        let result = task::spawn_blocking(move || -> Result<Vec<u8>, String> {
            let flows: Vec<serde_json::Value> = t
                .iter()
                .filter_map(|r| r.ok())
                .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
                .collect();
            serde_json::to_vec(&flows).map_err(|e| e.to_string())
        })
        .await;

        let json_bytes = match result {
            Ok(Ok(b))  => b,
            Ok(Err(e)) => { eprintln!("Export serialise error: {e}"); continue; }
            Err(e)     => { eprintln!("Export task panicked: {e}");   continue; }
        };

        // Atomic write: .tmp → final path
        match fs::write(&tmp_path, &json_bytes).await {
            Err(e) => { eprintln!("Export write error: {e}"); continue; }
            Ok(()) => {}
        }
        if let Err(e) = fs::rename(&tmp_path, &export_path).await {
            eprintln!("Export rename error: {e}");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Parse NDJSON lines from any AsyncRead (stdout pipe or debug file)
// ─────────────────────────────────────────────────────────────────────────────

async fn parse_ndjson(
    reader:     impl tokio::io::AsyncRead + Unpin,
    tx_dedup:   &Sender<FlowRecord>,
    tx_metrics: &Sender<FlowRecord>,
) -> Result<usize, AppError> {
    let mut lines = BufReader::new(reader).lines();
    let mut count = 0usize;

    while let Some(line) = lines.next_line().await.map_err(AppError::Io)? {
        let line = line.trim().to_owned();
        if line.is_empty() { continue; }

        match serde_json::from_str::<FlowRecord>(&line) {
            Ok(flow) => {
                count += 1;
                let _ = tx_metrics.try_send(flow.clone()); // lossy, never stalls pipeline
                if tx_dedup.send(flow).await.is_err() {
                    eprintln!("Dedup channel closed; stopping parse.");
                    break;
                }
            }
            Err(e) => {
                // Field-name mismatches show up here; with -q these should be very rare
                eprintln!("JSON parse error: {e}\n  line: {line}");
            }
        }
    }
    Ok(count)
}

// ─────────────────────────────────────────────────────────────────────────────
// Task: deduplicator + LRU eviction
// ─────────────────────────────────────────────────────────────────────────────

async fn dedup_task(
    mut rx:    tokio::sync::mpsc::Receiver<FlowRecord>,
    tx:        Sender<FlowRecord>,
    max_flows: usize,
    max_age:   Duration,
) {
    let mut map: IndexMap<FlowKey, (FlowRecord, Instant)> = IndexMap::new();
    let mut age_tick = interval(Duration::from_secs(30));
    age_tick.tick().await;

    loop {
        tokio::select! {
            biased;

            maybe_flow = rx.recv() => {
                let flow = match maybe_flow { Some(f) => f, None => break };

                let key = flow_key(&flow);
                let now = Instant::now();

                let changed = map.get(&key)
                    .map(|(prev, _)| prev != &flow)
                    .unwrap_or(true);

                if changed {
                    if tx.send(flow.clone()).await.is_err() { break; }
                }

                map.shift_remove(&key);
                map.insert(key, (flow, now));

                while map.len() > max_flows {
                    map.shift_remove_index(0);
                }
            }

            _ = age_tick.tick() => {
                let now = Instant::now();
                // checked_duration_since avoids panic on monotonic clock step
                map.retain(|_, (_, ts)| {
                    now.checked_duration_since(*ts)
                       .map(|age| age <= max_age)
                       .unwrap_or(true)
                });
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Task: sled persistence
// ─────────────────────────────────────────────────────────────────────────────

const SLED_BATCH_SIZE: usize = 256;

async fn sled_flush_task(
    tree:   sled::Tree,
    mut rx: tokio::sync::mpsc::Receiver<FlowRecord>,
) {
    let mut buf: Vec<FlowRecord> = Vec::with_capacity(SLED_BATCH_SIZE);
    let mut flush_tick = interval(Duration::from_millis(500));
    flush_tick.tick().await;

    loop {
        tokio::select! {
            biased;

            maybe_flow = rx.recv() => {
                match maybe_flow {
                    Some(f) => {
                        buf.push(f);
                        if buf.len() >= SLED_BATCH_SIZE {
                            do_sled_flush(&tree, &mut buf).await;
                        }
                    }
                    None => {
                        if !buf.is_empty() { do_sled_flush(&tree, &mut buf).await; }
                        break;
                    }
                }
            }

            _ = flush_tick.tick() => {
                if !buf.is_empty() { do_sled_flush(&tree, &mut buf).await; }
            }
        }
    }
}

async fn do_sled_flush(tree: &sled::Tree, buf: &mut Vec<FlowRecord>) {
    let records: Vec<FlowRecord> = buf.drain(..).collect();
    let t = tree.clone();

    let result = task::spawn_blocking(move || {
        let mut batch = sled::Batch::default();
        for flow in &records {
            let key = flow_key(flow).0.to_be_bytes();
            match serde_json::to_vec(flow) {
                Ok(val) => batch.insert(&key[..], val),
                Err(e)  => eprintln!("Serialise error: {e}"),
            }
        }
        t.apply_batch(&batch)
    }).await;

    match result {
        Ok(Ok(()))  => {}
        Ok(Err(e))  => eprintln!("Sled write error: {e}"),
        Err(e)      => eprintln!("Sled flush task panicked: {e}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Task: terminal metrics / display
// ─────────────────────────────────────────────────────────────────────────────

const RING_SIZE: usize = 20;

async fn metrics_task(
    mut rx: tokio::sync::mpsc::Receiver<FlowRecord>,
    config: Arc<Config>,
) {
    let mut ring: VecDeque<FlowRecord> = VecDeque::with_capacity(RING_SIZE + 1);
    let mut tick = interval(Duration::from_secs(1));
    tick.tick().await;

    loop {
        tokio::select! {
            maybe_flow = rx.recv() => {
                match maybe_flow {
                    Some(flow) => {
                        if !config.no_output && config.continuous_output {
                            print_flow(&flow);
                        }
                        ring.push_back(flow);
                        if ring.len() > RING_SIZE { ring.pop_front(); }
                    }
                    None => break,
                }
            }

            _ = tick.tick() => {
                if config.no_output || config.continuous_output || ring.is_empty() {
                    ring.clear();
                    continue;
                }
                println!("─── {} flow(s) ───", ring.len());
                for flow in ring.drain(..) { print_flow(&flow); }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let config = Arc::new(Config::from_env_or_args());
    let db: Db = sled::open("./ndpi_db")?;
    let tree   = db.open_tree("flows")?;

    // ── Create output directories ────────────────────────────────────────────
    if config.debug_files {
        fs::create_dir_all(&config.debug_dir).await?;
        eprintln!("DEBUG FILE MODE: captures → {}", config.debug_dir.display());
    } else {
        eprintln!("STDOUT STREAMING MODE  (-k /dev/stdout -q)");
    }
    if let Some(ref f) = config.bpf_filter { eprintln!("BPF filter: {f}"); }

    if let Some(parent) = config.export_path.parent() {
        fs::create_dir_all(parent).await?;
    }
    eprintln!("JSON export → {} (every {EXPORT_INTERVAL_SECS}s)", config.export_path.display());

    // ── Shutdown flag — see comment in capture loop ──────────────────────────
    let shutting_down = Arc::new(AtomicBool::new(false));

    // ── Pipeline channels — created once, shared across all restart cycles ───
    let (tx_dedup,   rx_dedup)   = mpsc::channel::<FlowRecord>(4_096);
    let (tx_batch,   rx_batch)   = mpsc::channel::<FlowRecord>(4_096);
    let (tx_metrics, rx_metrics) = mpsc::channel::<FlowRecord>(4_096);

    // ── Long-lived background tasks ──────────────────────────────────────────
    let dedup_h   = tokio::spawn(dedup_task(
        rx_dedup, tx_batch, 50_000, Duration::from_secs(120),
    ));
    let sled_h    = tokio::spawn(sled_flush_task(tree.clone(), rx_batch));
    let metrics_h = tokio::spawn(metrics_task(rx_metrics, config.clone()));
    // Export task: no channel — reads sled directly on its own timer
    let export_h  = tokio::spawn(json_export_task(tree.clone(), config.export_path.clone()));

    // ── Capture / restart loop ───────────────────────────────────────────────
    'capture: loop {
        let window_str = CAPTURE_WINDOW_SECS.to_string();
        let sd         = Arc::clone(&shutting_down);

        let restart = if config.debug_files {
            // ── DEBUG FILE MODE ──────────────────────────────────────────────
            let path   = debug_file_path(&config);
            let path_s = path.to_string_lossy().into_owned();
            eprintln!("Capture → {} ({}s window)", path.display(), CAPTURE_WINDOW_SECS);

            let mut child = Command::new("ndpiReader")
                .args(ndpi_args(&config, &window_str, &path_s))
                .kill_on_drop(true)
                .spawn()?;

            let restart = tokio::select! {
                _ = signal::ctrl_c() => {
                    sd.store(true, Ordering::SeqCst);
                    eprintln!("Ctrl-C – shutting down.");
                    let _ = child.kill().await;
                    false
                }
                result = child.wait() => {
                    // Check flag first: ndpiReader may have received the same
                    // SIGINT from the terminal and exited before our ctrl_c()
                    // future was polled.  Without this check we would restart.
                    if sd.load(Ordering::SeqCst) { false } else {
                        eprintln!("ndpiReader: {}",
                            result.map(|s| s.to_string())
                                  .unwrap_or_else(|e| e.to_string()));
                        true
                    }
                }
            };

            if restart && path.exists() {
                match fs::File::open(&path).await {
                    Ok(file) => match parse_ndjson(file, &tx_dedup, &tx_metrics).await {
                        Ok(n)  => eprintln!("Parsed {n} flows from {}", path.display()),
                        Err(e) => eprintln!("Parse error: {e}"),
                    },
                    Err(e) => eprintln!("Cannot open {}: {e}", path.display()),
                }
                eprintln!("Debug file retained: {}", path.display());
            }

            restart

        } else {
            // ── STDOUT STREAMING MODE ────────────────────────────────────────
            eprintln!("Capture on {} ({}s window)", config.interface, CAPTURE_WINDOW_SECS);

            let mut child = Command::new("ndpiReader")
                .args(ndpi_args(&config, &window_str, "/dev/stdout"))
                .stdout(Stdio::piped())   // capture NDJSON flow stream
                .stderr(Stdio::inherit()) // ndpiReader stats → terminal
                .kill_on_drop(true)
                .spawn()?;

            let stdout = child.stdout.take().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "no stdout from ndpiReader")
            })?;

            // Parser runs concurrently: drains pipe continuously so it never
            // fills and ndpiReader never blocks in fwrite().
            let tx_d = tx_dedup.clone();
            let tx_m = tx_metrics.clone();
            let parse_h = tokio::spawn(async move {
                parse_ndjson(stdout, &tx_d, &tx_m).await
            });

            let restart = tokio::select! {
                _ = signal::ctrl_c() => {
                    sd.store(true, Ordering::SeqCst);
                    eprintln!("Ctrl-C – shutting down.");
                    let _ = child.kill().await;
                    false
                }
                result = child.wait() => {
                    if sd.load(Ordering::SeqCst) { false } else {
                        eprintln!("ndpiReader: {}",
                            result.map(|s| s.to_string())
                                  .unwrap_or_else(|e| e.to_string()));
                        true
                    }
                }
            };

            // Always drain — flushes lines buffered in the pipe on kill too
            match parse_h.await {
                Ok(Ok(n))  => eprintln!("Parsed {n} flows this window."),
                Ok(Err(e)) => eprintln!("Parse error: {e}"),
                Err(e)     => eprintln!("Parse task panicked: {e}"),
            }

            restart
        };

        if !restart { break 'capture; }

        tokio::select! {
            _ = signal::ctrl_c() => {
                eprintln!("Ctrl-C during restart pause – exiting.");
                break 'capture;
            }
            _ = sleep(Duration::from_millis(200)) => {}
        }
    }

    // ── Shutdown cascade ─────────────────────────────────────────────────────
    //
    // Drop the two senders main owns.  Cascade:
    //   drop(tx_dedup)   → dedup_task exits → drops tx_batch
    //                    → sled_flush_task exits
    //   drop(tx_metrics) → metrics_task exits
    //
    // export_h has no channel; abort it directly.
    //
    drop(tx_dedup);
    drop(tx_metrics);
    export_h.abort();

    if let Err(e) = dedup_h.await   { eprintln!("Dedup task panicked: {e}");   }
    if let Err(e) = sled_h.await    { eprintln!("Sled task panicked: {e}");    }
    if let Err(e) = metrics_h.await { eprintln!("Metrics task panicked: {e}"); }

    Ok(())
}

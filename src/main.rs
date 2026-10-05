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
//   Top-level fields (always present or default if missing):
//     "src_ip"              string   Source IP (IPv4 or IPv6)
//     "dest_ip"             string   Destination IP  ← "dest_ip", NOT "dst_ip"
//     "src_port"            u32      Source port (absent for ICMP → defaults to 0)
//     "dst_port"            u32      Dest port   (absent for ICMP → defaults to 0)
//     "ip"                  u32      IP version: 4 or 6
//     "proto"               string   L4: "TCP", "UDP", "ICMPV6", …
//     "tcp_fingerprint"     string   Optional TCP fingerprint (protocol-dependent)
//     "ndpi_fingerprint"    string   NEW — nDPI app-level fingerprint hash
//     "server_hostname"     string   NEW — TLS/QUIC ClientHello SNI (top level, not in ndpi{})
//
//   Top-level sub-objects (present only with -F flag):
//     "detection_completed" u32      1 = nDPI finished classification
//     "check_extra_packets" u32      1 = nDPI may need more packets
//     "flow_id"             u64      nDPI's internal flow identifier
//     "first_seen"          f64      Unix epoch seconds (float)
//     "last_seen"           f64      Unix epoch seconds (float)
//     "duration"            f64      Flow duration in seconds (float)
//     "vlan_id"             u32      VLAN tag (0 if not tagged)
//     "bidirectional"       u32      0 = unidirectional (no response), 1 = bidirectional
//
//   Transfer stats (nested "xfer", only with -F):
//     "src2dst_packets"     u64      Packets: src → dest
//     "src2dst_bytes"       u64      Bytes: src → dest
//     "src2dst_goodput_bytes" u64    Payload bytes (TCP MSS adjusted)
//     "dst2src_packets"     u64      Packets: dest → src
//     "dst2src_bytes"       u64      Bytes: dest → src
//     "dst2src_goodput_bytes" u64    Payload bytes
//     "data_ratio"          f32      Ratio: upload vs download
//     "data_ratio_str"      string   Direction label: "Upload"/"Download"/"Mixed"
//
//   IAT stats (nested "iat", only with -F — inter-arrival times in ms):
//     "flow_min"            u64      Flow min IAT
//     "flow_avg"            f64      Flow avg IAT
//     "flow_max"            u64      Flow max IAT
//     "flow_stddev"         f64      Flow stddev
//     "c_to_s_min" / "c_to_s_avg" / "c_to_s_max" / "c_to_s_stddev" — client→server
//     "s_to_c_min" / "s_to_c_avg" / "s_to_c_max" / "s_to_c_stddev" — server→client
//
//   Packet length stats (nested "pktlen", only with -F):
//     "c_to_s_min"          u32      Client→server min packet length
//     "c_to_s_avg"          f64      Client→server avg packet length
//     "c_to_s_max"          u32      Client→server max packet length
//     "c_to_s_stddev"       f64      Client→server stddev
//     "s_to_c_min" / "s_to_c_avg" / "s_to_c_max" / "s_to_c_stddev" — server→client
//
//   Packet length histograms (nested "plen_bins", only with -F):
//     "raw"                 string   Comma-separated 48 bucket counts (original size distribution)
//     "normalized"          string   Comma-separated 48 bucket counts (per-packet normalized)
//
//   Nested under "ndpi" (classification & metadata):
//     "proto"               string   L7 name: "STUN", "TLS", "HTTP", …
//     "proto_id"            string   Numeric protocol id as string, e.g. "78"
//     "proto_by_ip"         string   Protocol guessed from IP reputation
//     "proto_by_ip_id"      u32      IP reputation database ID (e.g., 126 for Google)
//     "encrypted"           u32      1 = flow is encrypted
//     "breed"               string   "Acceptable", "Safe", "Unsafe", "Fun", …
//     "category_id"         u32      nDPI category numeric id
//     "category"            string   nDPI category name
//     "confidence"          object   {"<num>": "<method>"} — kept as raw JSON
//     "flow_risk"           object   Optional risk entries — kept as raw JSON
//     "ndpi_risk_score"     u32      Aggregate risk score
//     "hostname"            string   Extracted hostname from DNS/HTTP (NOT TLS ClientHello)
//     "domainame"           string   nDPI typo — intentional field name ("domainame", not "domain")
//
//   TLS sub-object (nested "ndpi.tls", if TLS detected and handshake seen):
//     "version"             string   e.g. "TLSv1.2", "TLSv1.3"
//     "ja3"                 string   Client JA3 fingerprint (absent if no full handshake)
//     "ja3s"                string   Server JA3 fingerprint
//     "ja4"                 string   Client JA4 fingerprint (empty if absent)
//     "cipher"              string   Negotiated cipher name
//     "unsafe_cipher"       u32      1 if cipher is weak
//     "server_names"        string   TLS certificate SubjectAltNames (SANs)
//     "issuer_dn"           string   Certificate Issuer DN (verify exact key name)
//     "subject_dn"          string   Certificate Subject DN (verify exact key name)
//     "alpn"                string   ALPN protocol selected (e.g., "h2", "h3")
//
//   DNS sub-object (nested "ndpi.dns", if DNS detected):
//     "num_queries"         u32      Number of DNS queries in flow
//     "num_answers"         u32      Number of DNS responses
//     "reply_code"          u32      DNS RCODE (0 = NOERROR, 3 = NXDOMAIN, etc.)
//     "query_type"          u32      DNS RRtype (1 = A, 28 = AAAA, etc.)
//     "rsp_type"            u32      Response RRtype (0 = NODATA/NOERROR, etc.)
//     "rsp_addr"            array    [{"ip":"140.82.121.3","ttl":47"}, …] — parse on demand
//
//   STUN sub-object (nested "ndpi.stun", if STUN detected):
//     "mapped_address"      string   STUN-mapped public address
//     "multimedia_flow_types" string Flow type flags (RTP/RTCP/etc.)
//
//   HTTP sub-object (nested "ndpi.http", if HTTP detected):
//     (schema varies by request type; empty object {} for scanner traffic)
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

// ── ndpi.tls sub-object ───────────────────────────────────────────────────────
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct TlsInfo {
    #[serde(default)] version:        String,
    #[serde(default)] ja3:            String,  // client — absent if handshake not seen
    #[serde(default)] ja3s:           String,  // server
    #[serde(default)] ja4:            String,  // client JA4 — empty string when absent
    #[serde(default)] cipher:         String,
    #[serde(default)] unsafe_cipher:  u32,
    // Present only on flows with complete handshake in capture window:
    #[serde(default)] server_names:   String,  // cert SANs — verify key name on next capture
    #[serde(default)] issuer_dn:      String,  // verify exact key name (may be "issuerDN")
    #[serde(default)] subject_dn:     String,  // verify exact key name (may be "subjectDN")
    #[serde(default)] alpn:           String,
}

// ── ndpi.dns sub-object ───────────────────────────────────────────────────────
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct DnsInfo {
    #[serde(default)] num_queries: u32,
    #[serde(default)] num_answers: u32,
    #[serde(default)] reply_code:  u32,
    #[serde(default)] query_type:  u32,
    #[serde(default)] rsp_type:    u32,
    // Format: "140.82.121.3,ttl=47" — parse ip/ttl in enrichment, not here
    // Empty vec when rsp_type:0 (NODATA — AAAA query for IPv4-only host)
    #[serde(default)] rsp_addr:    Vec<String>,
}

// ── ndpi.stun sub-object ──────────────────────────────────────────────────────
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct StunInfo {
    #[serde(default)] mapped_address:        String,
    #[serde(default)] multimedia_flow_types: String,
}

// ── xfer top-level sub-object (only with -F) ─────────────────────────────────
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct XferStats {
    #[serde(default)] data_ratio:            f32,
    #[serde(default)] data_ratio_str:        String,  // "Upload"/"Download"/"Mixed"
    #[serde(default)] src2dst_packets:       u64,
    #[serde(default)] src2dst_bytes:         u64,
    #[serde(default)] src2dst_goodput_bytes: u64,
    #[serde(default)] dst2src_packets:       u64,
    #[serde(default)] dst2src_bytes:         u64,
    #[serde(default)] dst2src_goodput_bytes: u64,
}

// ── iat top-level sub-object (only with -F) ───────────────────────────────────
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct IatStats {
    #[serde(default)] flow_min:      u64,
    #[serde(default)] flow_avg:      f64,
    #[serde(default)] flow_max:      u64,
    #[serde(default)] flow_stddev:   f64,
    #[serde(default)] c_to_s_min:    u64,
    #[serde(default)] c_to_s_avg:    f64,
    #[serde(default)] c_to_s_max:    u64,
    #[serde(default)] c_to_s_stddev: f64,
    #[serde(default)] s_to_c_min:    u64,
    #[serde(default)] s_to_c_avg:    f64,
    #[serde(default)] s_to_c_max:    u64,
    #[serde(default)] s_to_c_stddev: f64,
}

// ── pktlen top-level sub-object (only with -F) ────────────────────────────────
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct PktlenStats {
    #[serde(default)] c_to_s_min:    u32,
    #[serde(default)] c_to_s_avg:    f64,
    #[serde(default)] c_to_s_max:    u32,
    #[serde(default)] c_to_s_stddev: f64,
    #[serde(default)] s_to_c_min:    u32,
    #[serde(default)] s_to_c_avg:    f64,
    #[serde(default)] s_to_c_max:    u32,
    #[serde(default)] s_to_c_stddev: f64,
}

// ── plen_bins top-level sub-object (only with -F) ────────────────────────────
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct PlenBins {
    // 48-bucket packet-size histograms as comma-separated strings
    // Parse on demand with: entry.split(',').map(|s| s.parse::<u32>())
    #[serde(default)] raw:        String,
    #[serde(default)] normalized: String,
}

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
    #[serde(default)] proto_id:        String,   // "5.203" or "91" — dotted, keep as String
    #[serde(default)] proto_by_ip:     String,
    #[serde(default)] proto_by_ip_id:  u32,
    #[serde(default)] encrypted:       u32,
    #[serde(default)] breed:           String,
    #[serde(default)] category_id:     u32,
    #[serde(default)] category:        String,
    #[serde(default)] confidence:      serde_json::Value,
    #[serde(default)] flow_risk:       serde_json::Value,
    #[serde(default)] ndpi_risk_score: u32,
    // Hostname fields — inside ndpi{}, from DNS/HTTP (NOT from TLS ClientHello)
    #[serde(default)] hostname:        String,
    #[serde(default)] domainame:       String,   // intentional nDPI typo
    // Protocol-specific sub-objects
    #[serde(default)] tls:  Option<TlsInfo>,
    #[serde(default)] dns:  Option<DnsInfo>,
    #[serde(default)] stun: Option<StunInfo>,
    #[serde(default)] http: serde_json::Value,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct FlowRecord {
    // ── Always present ────────────────────────────────────────────────────────
    src_ip:   String,
    dest_ip:  String,
    #[serde(default)] src_port: u32,
    #[serde(default)] dst_port: u32,
    #[serde(default)] ip:       u32,
    proto:    String,

    // ── Fingerprints — top level, protocol-dependent ──────────────────────────
    #[serde(default)] tcp_fingerprint:  String,
    #[serde(default)] ndpi_fingerprint: String,  // NEW — nDPI app fingerprint hash

    // ── TLS ClientHello hostname — TOP LEVEL, not inside ndpi{} ──────────────
    // Populated when nDPI sees the full TLS/QUIC handshake in the capture window
    #[serde(default)] server_hostname:  String,  // NEW — was wrongly omitted

    // ── nDPI classification ───────────────────────────────────────────────────
    #[serde(default)] ndpi: NdpiInfo,

    // ── Flow metadata — top level, only present with -F ───────────────────────
    #[serde(default)] detection_completed: u32,
    #[serde(default)] check_extra_packets: u32,
    #[serde(default)] flow_id:             u64,
    #[serde(default)] first_seen:          f64,  // Unix epoch as float (e.g. 1772467064.389)
    #[serde(default)] last_seen:           f64,
    #[serde(default)] duration:            f64,  // seconds as float
    #[serde(default)] vlan_id:             u32,
    #[serde(default)] bidirectional:       u32,  // 0 or 1 — key field for noise classifier

    // ── Transfer statistics — top level, only with -F ─────────────────────────
    #[serde(default)] xfer:      XferStats,
    #[serde(default)] iat:       IatStats,
    #[serde(default)] pktlen:    PktlenStats,
    #[serde(default)] plen_bins: PlenBins,
}

impl FlowRecord {
    // Bytes are now in the top-level xfer object, not inside ndpi
    #[inline] fn total_bytes(&self) -> u64 {
        self.xfer.src2dst_bytes + self.xfer.dst2src_bytes
    }
    #[inline] fn total_pkts(&self) -> u64 {
        self.xfer.src2dst_packets + self.xfer.dst2src_packets
    }

    #[inline]
    fn has_risk(&self) -> bool {
        matches!(&self.ndpi.flow_risk, serde_json::Value::Object(m) if !m.is_empty())
    }

    // NEW — replaces the srv2cli_bytes == 0 heuristic used in noise classification
    // bidirectional:0 means nDPI only saw traffic in one direction (no response)
    #[inline]
    fn is_unidirectional(&self) -> bool {
        self.bidirectional == 0
    }

    // NEW — effective hostname: prefer TLS ClientHello SNI, fall back to DNS/HTTP hostname
    #[inline]
    fn effective_hostname(&self) -> &str {
        if !self.server_hostname.is_empty() {
            &self.server_hostname
        } else {
            &self.ndpi.hostname
        }
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
// Sled key layout — v2 (big-endian first_seen + 5-tuple hash)
//
//   v1 (original): 8 bytes = flow_key().0.to_be_bytes()
//                  → unordered by time; a retention scan had to read and
//                    deserialise EVERY record. Unbounded growth.
//   v2 (current):  16 bytes = [0..8]  first_seen as unix seconds, u64 BE
//                            [8..16] flow_key().0, u64 BE
//
// Big-endian integers sort correctly under sled's byte-lexicographic ordering,
// so `tree.scan_prefix()` over an 8-byte timestamp bound walks exactly the
// records seen in that instant window. That is what makes nightly retention a
// cheap ranged read instead of a full-tree deserialise.
//
// MIGRATION (documented for existing databases, per brief):
//   Old v1 keys are still present and readable. The daemon recognises both
//   layouts on read (`split_sled_key`), so flows.json stays complete across
//   the switch without any offline step. Two things happen automatically:
//     1. New writes always use v2.
//     2. The first retention pass with --retain-days > 0 treats a legacy v1 key
//        as "unknown age": it reads the record, re-keys it to v2 using the
//        stored first_seen, and leaves it in place if not yet expired. So the
//        tree converges to v2 within one retention cycle, and genuinely expired
//        v1 records are archived and removed like any other.
//   No data is ever dropped without first being written to a cold shard.
// ─────────────────────────────────────────────────────────────────────────────

const SLED_KEY_V2_LEN: usize = 16;
const SLED_KEY_V1_LEN: usize = 8;

/// Timestamp half of a v2 key (unix seconds, big-endian).
fn key_ts_be(secs: u64) -> [u8; 8] {
    secs.to_be_bytes()
}

/// Build a v2 sled key from a record's first_seen and its 5-tuple hash.
fn sled_key_v2(flow: &FlowRecord) -> [u8; SLED_KEY_V2_LEN] {
    let ts = flow.first_seen.max(0.0) as u64;
    let mut k = [0u8; SLED_KEY_V2_LEN];
    k[..8].copy_from_slice(&ts.to_be_bytes());
    k[8..].copy_from_slice(&flow_key(flow).0.to_be_bytes());
    k
}

/// Split a raw sled key into (Option<first_seen_secs>, hash).
/// `None` timestamp means a legacy v1 key whose age is unknown until decoded.
fn split_sled_key(key: &[u8]) -> Option<(Option<u64>, u64)> {
    if key.len() == SLED_KEY_V2_LEN {
        let ts = u64::from_be_bytes(key[..8].try_into().ok()?);
        let hash = u64::from_be_bytes(key[8..].try_into().ok()?);
        Some((Some(ts), hash))
    } else if key.len() == SLED_KEY_V1_LEN {
        let hash = u64::from_be_bytes(key.try_into().ok()?);
        Some((None, hash))
    } else {
        None
    }
}

/// Read the timestamp actually used for retention out of a stored key,
/// preferring the record's own first_seen when present (authoritative).
fn effective_first_seen(key: &[u8], flow: &FlowRecord) -> Option<u64> {
    match split_sled_key(key) {
        Some((Some(_), _)) if flow.first_seen > 0.0 => Some(flow.first_seen as u64),
        Some((Some(ts), _)) => Some(ts),
        Some((None, _)) if flow.first_seen > 0.0 => Some(flow.first_seen as u64),
        // v1 key AND no usable timestamp: nothing sane to expire on.
        _ => None,
    }
}

/// Pure retention selector — decides which entries expire. Deliberately takes
/// plain values (no sled, no clock) so it is unit-testable with fake timestamps
/// (acceptance gate 3/4: `cargo test` must not need root or ndpiReader).
///
/// Returns `(expired_index, needs_rekey)` for every input entry:
///   expired   → archive to a cold shard, then remove from sled
///   needs_rekey → keep, but rewrite under a v2 key (legacy v1 record)
fn select_expired(entries: &[(Vec<u8>, u64)], cutoff: u64) -> (Vec<usize>, Vec<usize>) {
    let mut expired = Vec::new();
    let mut rekey = Vec::new();
    for (i, (key, seen)) in entries.iter().enumerate() {
        match split_sled_key(key) {
            None => {}
            Some((Some(_), _)) => {
                if *seen != 0 && *seen < cutoff {
                    expired.push(i);
                }
            }
            Some((None, _)) => {
                // Legacy v1: caller supplied the decoded first_seen in `seen`.
                // A zero here means "timestamp unknown" → never expire, but do
                // re-key so the next pass can decide properly.
                if *seen == 0 {
                    rekey.push(i);
                } else if *seen < cutoff {
                    expired.push(i);
                } else {
                    rekey.push(i);
                }
            }
        }
    }
    (expired, rekey)
}

/// Cold-shard filename for a given unix timestamp: cold/flows-YYYY-MM-DD.ndjson.zst
/// (UTC date derived from `secs`; `offset_hours` lets tests pin the timezone.)
fn cold_shard_name(secs: u64, offset_hours: i64) -> String {
    use chrono::{FixedOffset, TimeZone, Utc};
    let dt = Utc
        .timestamp_opt(secs as i64, 0)
        .single()
        .unwrap_or_else(Utc::now);
    let local = dt.with_timezone(
        &FixedOffset::east_opt((offset_hours * 3600) as i32)
            .unwrap_or(FixedOffset::east_opt(0).unwrap()),
    );
    format!("flows-{}.ndjson.zst", local.format("%Y-%m-%d"))
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
    /// Hot-storage retention window in days. 0 disables the retention task
    /// entirely (records then accumulate in sled as before).
    retain_days:       u64,
    /// Directory for zstd-compressed NDJSON cold shards.
    cold_dir:          PathBuf,
    /// How often the retention pass runs (nightly-friendly default; it is a
    /// cheap ranged scan, so running it often costs almost nothing and keeps
    /// the hot tree inside its window even if the daemon restarts a lot).
    retain_interval_secs: u64,
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
        let mut retain_days: u64  = 7;
        let mut cold_dir          = PathBuf::from("./cold");
        let mut retain_interval_secs: u64 = RETENTION_INTERVAL_SECS_DEFAULT;

        if let Ok(v) = env::var("FLOW_INTERFACE")         { interface     = v; }
        if let Ok(v) = env::var("FLOW_BPF_FILTER")        { bpf_filter    = Some(v); }
        if let Ok(v) = env::var("FLOW_DEBUG_DIR")         { debug_dir     = PathBuf::from(v); }
        if let Ok(v) = env::var("FLOW_EXPORT_PATH")       { export_path   = PathBuf::from(v); }
        if let Ok(v) = env::var("FLOW_RETAIN_DAYS") {
            retain_days = v.parse().unwrap_or(retain_days);
        }
        if let Ok(v) = env::var("FLOW_COLD_DIR")          { cold_dir = PathBuf::from(v); }
        if let Ok(v) = env::var("FLOW_RETAIN_INTERVAL") {
            retain_interval_secs = v.parse().unwrap_or(retain_interval_secs);
        }
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
                "--retain-days"       => {
                    if let Some(v) = iter.next() {
                        retain_days = v.parse().unwrap_or_else(|_| {
                            eprintln!("--retain-days expects a non-negative integer, got '{v}'; keeping default");
                            retain_days
                        });
                    }
                }
                "--cold-dir"          => { if let Some(v) = iter.next() { cold_dir = PathBuf::from(v); } }
                "--retain-interval"   => {
                    if let Some(v) = iter.next() {
                        retain_interval_secs = v.parse().unwrap_or(retain_interval_secs);
                    }
                }
                _ => {}
            }
        }

        // Clamp absurd intervals — a retention pass that never runs is the same
        // bug as one that spins the whole tree every second.
        if retain_interval_secs < 60 { retain_interval_secs = 60; }

        Self { interface, bpf_filter, continuous_output, no_output,
               debug_files, debug_dir, export_path,
               retain_days, cold_dir, retain_interval_secs }
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
        "-F".into(),   // NEW — enables xfer/iat/pktlen/plen_bins + timestamps
        // Enable DNS hostname→IP cache (populates server_hostname in JSON)
        "--cfg=dpi.address_cache_size,5000".into(),
        // Enable JA4r (server response fingerprint, disabled by default)
        "--cfg=tls,metadata.ja4r_fingerprint,1".into(),
        // Enable DNS subclassification (adds detail to dns{} sub-object)
        "--cfg=dns,subclassification,1".into(),
        // Enable hostname format validation (helps flag DGA names)
        "--cfg=NULL,hostname_dns_check,1".into(),
        // Enable SSH client/server metadata
        "--cfg=ssh,metadata.ssh_data,1".into(),
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
    let host = flow.effective_hostname();
    let host_str = if host.is_empty() {
        String::new()
    } else {
        format!(" ({})", host)
    };
    let dir = if flow.bidirectional == 1 { "↔" } else { "→" };
    println!(
        "{risk}{:<8} {:>39}:{:<5} {dir} {:>39}:{:<5}  {:>8}B  {:>5}pkts  {:.1}s  L7={}{host_str}  [{}]",
        flow.proto,
        flow.src_ip,   flow.src_port,
        flow.dest_ip,  flow.dst_port,
        flow.total_bytes(),
        flow.total_pkts(),
        flow.duration,
        flow.ndpi.proto,
        flow.ndpi.category,
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
const RETENTION_INTERVAL_SECS_DEFAULT: u64 = 3600;

async fn json_export_task(tree: sled::Tree, export_path: PathBuf) {
    let tmp_path = export_path.with_extension("json.tmp");
    let mut tick = interval(Duration::from_secs(EXPORT_INTERVAL_SECS));
    tick.tick().await; // discard the immediate first tick

    loop {
        tick.tick().await;

        // Collect all flows from sled on a blocking thread.
        // Values are decoded rather than keys, so a legacy v1 key still exports
        // correctly — flows.json must never silently lose records mid-migration.
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

        // ndpiReader emits some plain-text lines to stdout even with -q:
        //   • "Successfully set BPF filter to '...'"  — one per window start
        //   • Any other status/warning lines
        // Silently skip anything that isn't a JSON object.  This avoids a
        // noisy parse error on every single capture window restart.
        if !line.starts_with('{') {
            eprintln!("Skipping non-JSON line: {line}");
            continue;
        }

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
                // Genuine field-name mismatches — log for debugging
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
            // v2 key: big-endian first_seen + 5-tuple hash (see layout note).
            // A record with no timestamp (first_seen == 0, e.g. ndpiReader run
            // without -F) still gets a stable key, it just sorts at the start of
            // the range and is handled by the "unknown age" branch in retention.
            match serde_json::to_vec(flow) {
                Ok(val) => batch.insert(&sled_key_v2(flow)[..], val),
                Err(e)  => eprintln!("Serialise error: {e}"),
            }
        }
        t.apply_batch(batch)
    }).await;

    match result {
        Ok(Ok(()))  => {}
        Ok(Err(e))  => eprintln!("Sled write error: {e}"),
        Err(e)      => eprintln!("Sled flush task panicked: {e}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Task: hot/cold storage split (retention)
//
// The tree used to be insert-only, so ./ndpi_db grew forever. This task moves
// records older than `retain_days` out of sled into date-partitioned cold
// shards, then removes them from the hot tree.
//
//   cold/flows-YYYY-MM-DD.ndjson.zst   — one NDJSON line per FlowRecord,
//                                         compressed with the zstd CLI
//
// Compression is delegated to the external `zstd` binary via Command rather
// than a Rust crate, keeping Cargo.toml unchanged (brief: "box has zstd CLI;
// keep Cargo.toml minimal"). If zstd is missing the pass aborts WITHOUT
// deleting anything — losing data because a compressor went away is not an
// acceptable failure mode.
//
// Ordering guarantee: append + flush + successful zstd compression happens
// BEFORE the sled removal. A crash mid-pass leaves records in both places
// (harmless duplicate in a shard) rather than in neither.
//
// Runs every config.retain_interval_secs (default hourly); a nightly cron-style
// invocation is equally fine since the work is idempotent.
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of one retention pass — returned by the pure-ish core so tests and
/// callers can inspect it without reading stderr.
#[derive(Debug, Default, Clone, PartialEq)]
struct RetentionReport {
    scanned: usize,
    expired: usize,
    rekeyed: usize,
    /// Records kept because their age could not be established at all.
    undated: usize,
    shards: Vec<PathBuf>,
}

fn retention_cutoff(now_secs: u64, retain_days: u64) -> u64 {
    // Saturating: retain_days * 86_400 overflows u64 for absurd values, and a
    // saturating cutoff of 0 simply means "nothing expires", which is correct.
    let window = retain_days.saturating_mul(86_400);
    now_secs.saturating_sub(window)
}

/// Read an existing cold shard back into NDJSON lines.
///
/// Returns `Err` when the shard is unreadable or not valid UTF-8 — callers must
/// treat that as "this shard is corrupt" and preserve rather than overwrite it.
fn read_cold_shard(path: &std::path::Path) -> Result<Vec<String>, String> {
    use std::process::Command as StdCommand;
    let out = StdCommand::new("zstd")
        .args(["-dc", "-q"])
        .arg(path)
        .output()
        .map_err(|e| format!("cannot run zstd to read {}: {e}", path.display()))?;
    if !out.status.success() {
        return Err(format!("zstd -dc failed on {} (exit {})", path.display(), out.status));
    }
    let text = std::str::from_utf8(&out.stdout)
        .map_err(|e| format!("{} is not valid UTF-8: {e}", path.display()))?;
    Ok(text.lines().filter(|l| !l.is_empty()).map(|l| l.to_string()).collect())
}

/// Write `lines` (NDJSON) into cold/<shard> compressed via the zstd CLI.
/// Returns the final path on success. Uses a temp file + rename so distill.py
/// never observes a half-written shard.
///
/// REOPEN IS A MERGE, NOT AN OVERWRITE: shards are named after each record's own
/// `first_seen` UTC day, and a retention pass runs hourly, so one day's records
/// expire across ~24 consecutive passes. POSIX `rename` overwrites atomically, so
/// writing only the new batch would silently discard every earlier line of that
/// day — and those records were already removed from sled, so they would be gone
/// for good. Hence: decompress what is there, keep its order, append the incoming
/// lines that are not already present, then compress the union.
///
/// Duplicates *within* `lines` are preserved (a v2 record and its legacy v1 copy
/// serialise identically and must both land), but a line already archived in a
/// previous pass is not written twice — that makes a retry whose sled removal
/// never landed idempotent instead of growing the shard forever.
fn write_cold_shard(cold_dir: &PathBuf, shard_name: &str, lines: &[String]) -> Result<PathBuf, String> {
    use std::collections::HashSet;
    use std::io::Write;
    use std::process::{Command as StdCommand, Stdio as PStdio};

    std::fs::create_dir_all(cold_dir).map_err(|e| format!("mkdir {}: {e}", cold_dir.display()))?;

    let final_path = cold_dir.join(shard_name);
    let tmp_path   = cold_dir.join(format!("{shard_name}.tmp"));

    // Merge with whatever this shard already holds. `PathBuf` derefs to `Path`
    // here, so `.exists()` resolves without an explicit reborrow.
    let mut existing_lines: Vec<String> = Vec::new();
    if final_path.exists() {
        match read_cold_shard(&final_path) {
            Ok(l) => existing_lines = l,
            Err(e) => {
                // Never delete data we cannot read: move the bad shard aside under
                // a name distill.py ignores, then start that day fresh.
                let secs = chrono::Utc::now().timestamp().max(0);
                let quarantine =
                    cold_dir.join(format!("{shard_name}.corrupt-{secs}"));
                match std::fs::rename(&final_path, &quarantine) {
                    Ok(_) => eprintln!(
                        "Retention: {e} — preserved unreadable shard as {}",
                        quarantine.display()
                    ),
                    Err(re) => eprintln!(
                        "Retention: {e} — could NOT quarantine {} ({re}); rewriting it",
                        final_path.display()
                    ),
                }
                existing_lines = Vec::new();
            }
        }
    }
    let seen: HashSet<&str> = existing_lines.iter().map(|s| s.as_str()).collect();

    let mut merged: Vec<&str> = Vec::with_capacity(existing_lines.len() + lines.len());
    for line in &existing_lines {
        merged.push(line.as_str());
    }
    for line in lines {
        if seen.contains(line.as_str()) {
            continue;
        }
        merged.push(line.as_str());
    }

    // zstd reads stdin, writes the archive given by -o. Level 9 is a good
    // ratio/speed trade-off for NDJSON and is the CLI's `-9` (NOT the libzstd
    // `--compress=` form — that string is rejected by the binary).
    let mut child = StdCommand::new("zstd")
        .args(["-q", "-f", "-9", "-o"])
        .arg(&tmp_path)
        .stdin(PStdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run zstd (install it or set FLOW_COLD_DIR elsewhere): {e}"))?;

    {
        let stdin = child.stdin.as_mut().ok_or("no stdin for zstd")?;
        for line in &merged {
            stdin.write_all(line.as_bytes()).map_err(|e| format!("zstd pipe write: {e}"))?;
            stdin.write_all(b"\n").map_err(|e| format!("zstd pipe write: {e}"))?;
        }
        stdin.flush().ok();
    }

    let status = child.wait().map_err(|e| format!("waiting on zstd: {e}"))?;
    if !status.success() {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(format!("zstd exited with {status}"));
    }
    std::fs::rename(&tmp_path, &final_path).map_err(|e| format!("rename shard: {e}"))?;
    Ok(final_path)
}

/// Core of one retention pass, split out from the async wrapper so it can be
/// exercised against a real (tempdir) sled tree without ndpiReader or root.
fn run_retention_pass(tree: &sled::Tree, config: &Config, now_secs: u64) -> Result<RetentionReport, String> {
    if config.retain_days == 0 {
        return Ok(RetentionReport::default());
    }
    let cutoff = retention_cutoff(now_secs, config.retain_days);
    let mut rep = RetentionReport::default();

    // Phase 1 — ranged read. Everything under a v2 key smaller than
    // cutoff.to_be_bytes() is expired by construction; we still iterate the
    // whole tree once because legacy v1 keys sort interleaved and need to be
    // inspected (and re-keyed) too.
    let mut expired_lines: Vec<String> = Vec::new();
    let mut expired_keys: Vec<Vec<u8>> = Vec::new();
    let mut rekeys: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new(); // old,new,val

    for entry in tree.iter() {
        let (k, v) = match entry { Ok(kv) => kv, Err(_) => continue };
        rep.scanned += 1;
        let key: Vec<u8> = k.to_vec();

        let flow: FlowRecord = match serde_json::from_slice(&v) {
            Ok(f) => f,
            Err(_) => continue, // unreadable value: leave it alone, don't destroy it
        };

        match split_sled_key(&key) {
            None => continue, // not a key we understand — never touch it
            Some((ts, hash)) => {
                // Age to judge: for v2 keys the stored timestamp (record body
                // wins when present); for legacy v1 keys the decoded first_seen,
                // or 0 meaning "undatable".
                let seen = match ts {
                    Some(_) => effective_first_seen(&key, &flow).unwrap_or(0),
                    None => if flow.first_seen > 0.0 { flow.first_seen as u64 } else { 0 },
                };
                let (expired, rekey) = select_expired(&[(key.clone(), seen)], cutoff);

                if !expired.is_empty() {
                    expired_keys.push(key);
                    if let Ok(s) = serde_json::to_string(&flow) {
                        expired_lines.push(s);
                    }
                    rep.expired += 1;
                } else if !rekey.is_empty() {
                    // Legacy v1 survivor (or an undated record being stamped now):
                    // rewrite under a v2 key so later passes are ranged scans.
                    let stamp = if seen != 0 { seen } else { now_secs };
                    if seen == 0 {
                        rep.undated += 1;
                    }
                    let mut nk = [0u8; SLED_KEY_V2_LEN];
                    nk[..8].copy_from_slice(&key_ts_be(stamp));
                    nk[8..].copy_from_slice(&hash.to_be_bytes());
                    rekeys.push((key, nk.to_vec(), v.to_vec()));
                    rep.rekeyed += 1;
                }
            }
        }
    }

    if expired_lines.is_empty() && rekeys.is_empty() {
        return Ok(rep);
    }

    // Phase 2 — archive first, delete second. Shard name is per-day; when
    // expiring across several days we group lines by their own date.
    if !expired_lines.is_empty() {
        let mut grouped: IndexMap<String, Vec<String>> = IndexMap::new();
        for (line, key) in expired_lines.iter().zip(expired_keys.iter()) {
            let seen = split_sled_key(key).and_then(|(ts, _)| ts).unwrap_or(0);
            // For legacy keys the ts lives in the record; recover from JSON.
            let day = match seen {
                0 => serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .and_then(|j| j.get("first_seen").and_then(|v| v.as_f64()))
                    .map(|f| cold_shard_name(f.max(0.0) as u64, 0))
                    .unwrap_or_else(|| cold_shard_name(cutoff, 0)),
                s => cold_shard_name(s, 0),
            };
            grouped.entry(day).or_default().push(line.clone());
        }
        for (shard, lines) in grouped {
            match write_cold_shard(&config.cold_dir, &shard, &lines) {
                Ok(p) => rep.shards.push(p),
                Err(e) => {
                    // Do NOT remove anything: the hot tree keeps these flows.
                    eprintln!("Retention aborted archive: {e}");
                    return Err(e);
                }
            }
        }
        // All shards written successfully → safe to drop from hot storage.
        let mut batch = sled::Batch::default();
        for key in &expired_keys {
            batch.remove(&key[..]);
        }
        tree.apply_batch(batch).map_err(|e| format!("sled remove: {e}"))?;
    }

    // Phase 3 — migrate surviving legacy keys to v2 (insert new, remove old).
    if !rekeys.is_empty() {
        let mut batch = sled::Batch::default();
        for (old, new, val) in &rekeys {
            batch.insert(&new[..], val.clone());
            batch.remove(&old[..]);
        }
        tree.apply_batch(batch).map_err(|e| format!("sled rekey: {e}"))?;
    }

    if !rep.shards.is_empty() {
        // sled's own flush thread persists the batch; nothing to checkpoint here.
        rep.shards.sort();
    }
    Ok(rep)
}

async fn retention_task(tree: sled::Tree, config: Arc<Config>) {
    let mut tick = interval(Duration::from_secs(config.retain_interval_secs));
    // First pass shortly after start (not immediately): lets the pipeline warm
    // up, then converges legacy keys to v2 within seconds of boot.
    sleep(Duration::from_secs(5)).await;

    loop {
        let t = tree.clone();
        let c = config.clone();
        let result = task::spawn_blocking(move || {
            let now = chrono::Utc::now().timestamp().max(0) as u64;
            run_retention_pass(&t, &c, now)
        })
        .await;

        match result {
            Err(e) => eprintln!("Retention task panicked: {e}"),
            Ok(Err(e)) => eprintln!("Retention pass failed: {e}"),
            Ok(Ok(rep)) => {
                if rep.expired > 0 || rep.rekeyed > 0 {
                    eprintln!(
                        "Retention: scanned {} flow(s), archived {} → {} shard(s), re-keyed {} legacy record(s){}",
                        rep.scanned,
                        rep.expired,
                        rep.shards.len(),
                        rep.rekeyed,
                        if rep.undated > 0 {
                            format!(", {} undated stamped with now", rep.undated)
                        } else { String::new() },
                    );
                }
            }
        }

        tick.tick().await;
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

    // ── Retention / cold-archive setup ───────────────────────────────────────
    if config.retain_days > 0 {
        fs::create_dir_all(&config.cold_dir).await?;
        eprintln!(
            "Retention: hot window {} day(s), expired flows → {}/flows-YYYY-MM-DD.ndjson.zst (pass every {}s)",
            config.retain_days, config.cold_dir.display(), config.retain_interval_secs
        );
    } else {
        eprintln!("Retention: DISABLED (--retain-days 0) — ./ndpi_db grows unbounded");
    }

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
    // Retention task: only when a hot window is configured. Reads/writes the
    // same tree (same process, so sled's exclusive lock is not an issue).
    let retain_h = if config.retain_days > 0 {
        Some(tokio::spawn(retention_task(tree.clone(), config.clone())))
    } else {
        None
    };

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
    if let Some(h) = retain_h {
        h.abort();
    }

    if let Err(e) = dedup_h.await   { eprintln!("Dedup task panicked: {e}");   }
    if let Err(e) = sled_h.await    { eprintln!("Sled task panicked: {e}");    }
    if let Err(e) = metrics_h.await { eprintln!("Metrics task panicked: {e}"); }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — pure logic only (acceptance gate 3/4).
//
// No network, no root, no ndpiReader, no capture path. The retention test uses
// a real sled tree in a throwaway directory (sled is already a dependency),
// created and removed by the test itself; `cargo test` never touches ./ndpi_db.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(src_ip: &str, src_port: u32, dest_ip: &str, dst_port: u32, proto: &str) -> FlowRecord {
        FlowRecord {
            src_ip: src_ip.into(),
            dest_ip: dest_ip.into(),
            src_port,
            dst_port,
            ip: 4,
            proto: proto.into(),
            first_seen: 1_700_000_000.5,
            ..Default::default()
        }
    }

    /// Test-only Config with retention knobs overridable; paths rooted at `dir`.
    fn test_config(dir: &std::path::Path, retain_days: u64) -> Config {
        Config {
            interface: "lo".into(),
            bpf_filter: None,
            continuous_output: false,
            no_output: false,
            debug_files: false,
            debug_dir: dir.join("debug"),
            export_path: dir.join("flows.json"),
            retain_days,
            cold_dir: dir.join("cold"),
            retain_interval_secs: 3600,
        }
    }

    /// Throwaway directory for a sled test (never ./ndpi_db).
    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("fm_{tag}_{}_{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("cold")).unwrap();
        dir
    }

    // ── flow-key dedup ───────────────────────────────────────────────────────

    #[test]
    fn key_is_stable_for_same_5_tuple() {
        let a = flow("10.0.0.1", 5000, "93.184.216.34", 443, "TCP");
        let b = flow("10.0.0.1", 5000, "93.184.216.34", 443, "TCP");
        assert_eq!(flow_key(&a), flow_key(&b));
    }

    #[test]
    fn key_differs_when_any_tuple_member_changes() {
        let base = flow("10.0.0.1", 5000, "93.184.216.34", 443, "TCP");
        for other in [
            flow("10.0.0.2", 5000, "93.184.216.34", 443, "TCP"),  // src_ip
            flow("10.0.0.1", 5001, "93.184.216.34", 443, "TCP"),  // src_port
            flow("10.0.0.1", 5000, "93.184.216.35", 443, "TCP"),  // dest_ip
            flow("10.0.0.1", 5000, "93.184.216.34",  80, "TCP"),  // dst_port
            flow("10.0.0.1", 5000, "93.184.216.34", 443, "UDP"),  // proto
        ] {
            assert_ne!(flow_key(&base), flow_key(&other));
        }
    }

    #[test]
    fn key_ignores_byte_counts() {
        // A reconnect on the same 5-tuple must collide with the original key so
        // the dedup LRU replaces rather than accumulating entries.
        let mut a = flow("10.0.0.1", 5000, "93.184.216.34", 443, "TCP");
        let mut b = a.clone();
        a.xfer.src2dst_bytes = 100;
        b.xfer.src2dst_bytes = 9_000_000;
        assert_eq!(flow_key(&a), flow_key(&b));
        assert_ne!(a, b);
    }

    #[test]
    fn direction_is_not_swapped_into_the_same_key() {
        let fwd = flow("10.0.0.1", 5000, "93.184.216.34", 443, "TCP");
        let rev = flow("93.184.216.34", 443, "10.0.0.1", 5000, "TCP");
        assert_ne!(flow_key(&fwd), flow_key(&rev));
    }

    // ── key layout v1/v2 + migration helpers ─────────────────────────────────

    #[test]
    fn v2_key_roundtrips_timestamp_and_hash() {
        let f = flow("10.0.0.1", 5000, "1.1.1.1", 443, "TCP");
        let k = sled_key_v2(&f);
        assert_eq!(k.len(), SLED_KEY_V2_LEN);
        let (ts, hash) = split_sled_key(&k).unwrap();
        assert_eq!(ts, Some(f.first_seen as u64));
        assert_eq!(hash, flow_key(&f).0);
    }

    #[test]
    fn v2_keys_sort_lexicographically_by_time() {
        // This ordering property is what lets retention use a ranged scan.
        let mut old = flow("10.0.0.1", 1, "1.1.1.1", 2, "TCP");
        let mut new = flow("10.0.0.9", 1, "1.1.1.1", 2, "TCP");
        old.first_seen = 1_600_000_000.0;
        new.first_seen = 1_700_000_000.0;
        assert!(sled_key_v2(&old)[..] < sled_key_v2(&new)[..]);
    }

    #[test]
    fn v1_legacy_key_is_detected_as_undated() {
        let legacy = 42u64.to_be_bytes();
        let (ts, hash) = split_sled_key(&legacy).unwrap();
        assert_eq!(ts, None);
        assert_eq!(hash, 42);
    }

    #[test]
    fn bogus_key_length_is_rejected() {
        assert!(split_sled_key(&[0u8; 7]).is_none());
        assert!(split_sled_key(&[0u8; 9]).is_none());
        assert!(split_sled_key(&[0u8; 12]).is_none());
    }

    #[test]
    fn effective_first_seen_prefers_record_body() {
        let mut f = flow("10.0.0.1", 5000, "1.1.1.1", 443, "TCP");
        f.first_seen = 1_500_000_000.0;
        let mut k = [0u8; SLED_KEY_V2_LEN];
        k[..8].copy_from_slice(&1_600_000_000u64.to_be_bytes());
        k[8..].copy_from_slice(&flow_key(&f).0.to_be_bytes());
        assert_eq!(effective_first_seen(&k, &f), Some(1_500_000_000));
    }

    // ── retention selector (pure function, fake timestamps) ──────────────────

    fn v2(secs: u64) -> Vec<u8> {
        let mut k = secs.to_be_bytes().to_vec();
        k.extend_from_slice(&secs.wrapping_mul(7).to_be_bytes()); // filler hash half
        k
    }

    #[test]
    fn cutoff_is_days_back_from_now() {
        assert_eq!(retention_cutoff(1_000_000, 7), 1_000_000 - 7 * 86_400);
        assert_eq!(retention_cutoff(100, 7), 0, "window larger than clock → nothing expires");
        // Absurd retain_days must saturate, not overflow or panic.
        assert_eq!(retention_cutoff(100, u64::MAX), 0);
    }

    #[test]
    fn selector_expires_only_records_past_the_cutoff() {
        let cutoff = 1_700_000_000u64;
        let entries = vec![
            (v2(cutoff - 1), cutoff - 1), // expired (strictly older)
            (v2(cutoff),     cutoff),     // kept (boundary is inclusive)
            (v2(cutoff + 5), cutoff + 5), // kept
            (v2(1),          1),          // expired
        ];
        let (expired, rekey) = select_expired(&entries, cutoff);
        assert_eq!(expired, vec![0, 3]);
        assert!(rekey.is_empty());
    }

    #[test]
    fn selector_migrates_live_legacy_keys_without_dropping_them() {
        let cutoff = 1_700_000_000u64;
        let legacy_hot  = 7u64.to_be_bytes().to_vec();
        let legacy_cold = 8u64.to_be_bytes().to_vec();
        let entries = vec![
            (legacy_hot.clone(), cutoff + 10),  // v1 key, dated recent → re-key, keep
            (legacy_cold, cutoff - 10),         // v1 key, dated old    → expire
            (legacy_hot, 0),                    // v1 key, undatable    → re-key, keep
        ];
        let (expired, rekey) = select_expired(&entries, cutoff);
        assert_eq!(expired, vec![1]);
        assert_eq!(rekey, vec![0, 2]);
    }

    #[test]
    fn selector_zero_timestamp_on_v2_never_expires() {
        // A v2 key with ts 0 means "no timestamp at write time". Expiring it
        // would silently archive brand-new flows, so it must be left alone.
        let entries = vec![(v2(0), 0u64)];
        let (expired, rekey) = select_expired(&entries, 1_700_000_000);
        assert!(expired.is_empty());
        assert!(rekey.is_empty());
    }

    #[test]
    fn cold_shard_name_is_utc_date_partitioned() {
        // 2023-11-14T22:13:20Z
        assert_eq!(cold_shard_name(1_700_000_000, 0), "flows-2023-11-14.ndjson.zst");
        // Same instant at UTC+9 rolls to the next day.
        assert_eq!(cold_shard_name(1_700_000_000, 9), "flows-2023-11-15.ndjson.zst");
    }

    // ── retention pass against a real (throwaway) sled tree ──────────────────

    #[test]
    fn retention_pass_archives_expired_then_removes_from_sled() {
        let dir  = scratch_dir("retain");
        let cold = dir.join("cold");

        let now: u64 = 1_700_000_000;
        let db = sled::open(&dir).unwrap();
        let tree = db.open_tree("flows").unwrap();

        // one expired v2 record, one fresh v2 record, one legacy v1 record
        let mut old_flow = flow("10.0.0.1", 1111, "203.0.113.9", 443, "TCP");
        old_flow.first_seen = (now - 30 * 86_400) as f64;
        tree.insert(&sled_key_v2(&old_flow)[..], serde_json::to_vec(&old_flow).unwrap()).unwrap();

        let mut fresh_flow = flow("10.0.0.2", 2222, "203.0.113.10", 443, "TCP");
        fresh_flow.first_seen = (now - 60) as f64;
        tree.insert(&sled_key_v2(&fresh_flow)[..], serde_json::to_vec(&fresh_flow).unwrap()).unwrap();

        // Legacy v1 key holding a copy of the OLD flow → expires via its body ts.
        let legacy_val = serde_json::to_vec(&old_flow).unwrap();
        tree.insert(&99u64.to_be_bytes()[..], legacy_val).unwrap();

        let config = test_config(&dir, 7);
        let rep = run_retention_pass(&tree, &config, now).expect("pass ok");

        assert_eq!(rep.expired, 2, "both old records archived");
        assert_eq!(rep.scanned, 3);
        assert_eq!(rep.shards.len(), 1);
        assert_eq!(rep.shards[0], cold.join("flows-2023-10-15.ndjson.zst"));
        assert!(rep.shards[0].exists(), "cold shard written before removal");

        // Hot tree keeps exactly the fresh flow.
        let remaining: Vec<Vec<u8>> = tree.iter().map(|r| r.unwrap().0.to_vec()).collect();
        assert_eq!(remaining.len(), 1, "expired keys removed from sled");
        assert_eq!(split_sled_key(&remaining[0]).unwrap().0, Some(fresh_flow.first_seen as u64));

        // Shard decompresses to NDJSON containing the expired flow's 5-tuple.
        let out = std::process::Command::new("zstd")
            .args(["-dc", rep.shards[0].to_str().unwrap()])
            .output()
            .expect("zstd -dc");
        let text = String::from_utf8_lossy(&out.stdout);
        assert_eq!(text.trim().lines().count(), 2, "two archived lines");
        assert!(text.contains("\"dest_ip\":\"203.0.113.9\""));
        assert!(text.contains("\"src_ip\":\"10.0.0.1\""));

        // The shard must be readable by distill.py's contract: one complete JSON
        // object per line, no trailing partial line, valid UTF-8.
        for (i, line) in text.lines().enumerate() {
            let parsed: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("shard line {i} is not valid JSON: {e}"));
            assert!(parsed.is_object(), "shard line {i} is not a JSON object");
            assert!(parsed.get("first_seen").is_some(), "shard line {i} lost first_seen");
        }

        drop(db);
        // Keep the produced shard when explicitly asked, so an external step
        // (distill.py) can consume real Rust output in the pipeline proof.
        if env::var("FM_KEEP_SHARDS").is_ok() {
            let keep = std::path::PathBuf::from(env::var("FM_KEEP_SHARDS").unwrap());
            std::fs::create_dir_all(&keep).unwrap();
            for shard in &rep.shards {
                std::fs::copy(shard, keep.join(shard.file_name().unwrap())).unwrap();
            }
            eprintln!("kept shards in {}", keep.display());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_pass_converts_legacy_keys_to_v2_in_place() {
        let dir = scratch_dir("rekey");
        let now: u64 = 1_700_000_000;
        let db = sled::open(&dir).unwrap();
        let tree = db.open_tree("flows").unwrap();

        let mut f = flow("10.0.0.5", 5000, "203.0.113.50", 53, "UDP");
        f.first_seen = (now - 3600) as f64; // well inside a 7-day window
        let hash = flow_key(&f).0;
        tree.insert(&hash.to_be_bytes()[..], serde_json::to_vec(&f).unwrap()).unwrap();

        let config = test_config(&dir, 7);
        let rep = run_retention_pass(&tree, &config, now).unwrap();
        assert_eq!(rep.expired, 0, "recent flow must survive");
        assert_eq!(rep.rekeyed, 1, "legacy key migrated to v2");
        assert!(dir.join("cold").join("flows-2023-11-14.ndjson.zst").parent().unwrap().exists());

        let keys: Vec<Vec<u8>> = tree.iter().map(|r| r.unwrap().0.to_vec()).collect();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].len(), SLED_KEY_V2_LEN, "record now lives under a v2 key");
        assert_eq!(split_sled_key(&keys[0]).unwrap().0, Some(f.first_seen as u64));
        // Value survived the move intact.
        let (_, v) = tree.iter().next().unwrap().unwrap();
        let back: FlowRecord = serde_json::from_slice(&v).unwrap();
        assert_eq!(back, f);

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_pass_leaves_a_converged_tree_untouched() {
        // After one pass everything is v2 and in-window, so a second pass must be
        // a genuine no-op: that is what makes running it hourly safe.
        let dir = scratch_dir("noop");
        let now: u64 = 1_700_000_000;
        let db = sled::open(&dir).unwrap();
        let tree = db.open_tree("flows").unwrap();

        for i in 0..5u32 {
            let mut f = flow("10.0.0.1", 4000 + i, "203.0.113.1", 443, "TCP");
            f.first_seen = (now - 60 * i as u64) as f64;
            tree.insert(&sled_key_v2(&f)[..], serde_json::to_vec(&f).unwrap()).unwrap();
        }
        let config = test_config(&dir, 7);

        let first = run_retention_pass(&tree, &config, now).unwrap();
        assert_eq!(first.expired, 0);
        assert_eq!(first.rekeyed, 0, "already v2 → nothing to migrate");

        let before: Vec<Vec<u8>> = tree.iter().map(|r| r.unwrap().0.to_vec()).collect();
        let second = run_retention_pass(&tree, &config, now).unwrap();
        let after: Vec<Vec<u8>> = tree.iter().map(|r| r.unwrap().0.to_vec()).collect();
        assert_eq!(second.scanned, 5);
        assert_eq!(second.expired, 0);
        assert!(second.shards.is_empty());
        assert_eq!(before, after, "keys changed on a no-op pass");
        assert_eq!(std::fs::read_dir(dir.join("cold")).unwrap().count(), 0,
                   "no shard should be produced when nothing expired");

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_pass_handles_a_mixed_v1_and_v2_tree() {
        // The real mid-migration state: some keys already v2, some still legacy.
        let dir = scratch_dir("mixed");
        let now: u64 = 1_700_000_000;
        let db = sled::open(&dir).unwrap();
        let tree = db.open_tree("flows").unwrap();

        // v2 recent — survives untouched.
        let mut a = flow("10.0.0.1", 1000, "203.0.113.1", 443, "TCP");
        a.first_seen = (now - 100) as f64;
        tree.insert(&sled_key_v2(&a)[..], serde_json::to_vec(&a).unwrap()).unwrap();

        // v2 old — expires.
        let mut b = flow("10.0.0.2", 2000, "203.0.113.2", 443, "TCP");
        b.first_seen = (now - 40 * 86_400) as f64;
        tree.insert(&sled_key_v2(&b)[..], serde_json::to_vec(&b).unwrap()).unwrap();

        // v1 old — expires via its body timestamp.
        let mut c = flow("10.0.0.3", 3000, "203.0.113.3", 443, "TCP");
        c.first_seen = (now - 40 * 86_400) as f64;
        tree.insert(&flow_key(&c).0.to_be_bytes()[..], serde_json::to_vec(&c).unwrap()).unwrap();

        // v1 recent — re-keyed to v2, kept.
        let mut d = flow("10.0.0.4", 4000, "203.0.113.4", 443, "TCP");
        d.first_seen = (now - 200) as f64;
        tree.insert(&flow_key(&d).0.to_be_bytes()[..], serde_json::to_vec(&d).unwrap()).unwrap();

        // v1 with no timestamp at all — stamped with `now`, kept.
        let mut e = flow("10.0.0.5", 5000, "203.0.113.5", 443, "TCP");
        e.first_seen = 0.0;
        tree.insert(&flow_key(&e).0.to_be_bytes()[..], serde_json::to_vec(&e).unwrap()).unwrap();

        let config = test_config(&dir, 7);
        let rep = run_retention_pass(&tree, &config, now).unwrap();

        assert_eq!(rep.scanned, 5);
        assert_eq!(rep.expired, 2, "b (v2 old) and c (v1 old) expire");
        assert_eq!(rep.rekeyed, 2, "d and e migrate to v2");
        assert_eq!(rep.undated, 1, "e had no timestamp anywhere");

        let survivors: Vec<(Option<u64>, Vec<u8>)> = tree.iter()
            .map(|r| { let (k, _) = r.unwrap(); (split_sled_key(&k).unwrap().0, k.to_vec()) })
            .collect();
        assert_eq!(survivors.len(), 3, "a, d, e remain");
        assert!(survivors.iter().all(|(ts, k)| k.len() == SLED_KEY_V2_LEN && ts.is_some()),
                "every survivor is keyed v2 after one pass");

        // The undated record got stamped with `now`, putting it inside the window.
        assert!(survivors.iter().any(|(ts, _)| *ts == Some(now)),
                "undated v1 record was not stamped with now");

        // Expired records land in one day-shard (b and c share a date).
        assert_eq!(rep.shards.len(), 1);
        let out = std::process::Command::new("zstd")
            .args(["-dc", rep.shards[0].to_str().unwrap()]).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert_eq!(text.trim().lines().count(), 2);
        assert!(text.contains("\"src_ip\":\"10.0.0.2\""));
        assert!(text.contains("\"src_ip\":\"10.0.0.3\""));

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── cold-shard reopen must MERGE, never overwrite (F1) ───────────────────

    /// Decompress a shard into its NDJSON lines.
    fn shard_lines(path: &std::path::Path) -> Vec<String> {
        let out = std::process::Command::new("zstd")
            .args(["-dc", "-q"])
            .arg(path)
            .output()
            .expect("zstd -dc");
        assert!(out.status.success(), "shard {} unreadable", path.display());
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect()
    }

    #[test]
    fn cold_shard_reopen_merges_without_data_loss() {
        // The F1 proof. Two records on the SAME UTC day expire across two hourly
        // passes because the cutoff advances ~1h each pass. Before the merge fix
        // the second pass overwrote the shard and the first record was lost for
        // good (it had already left sled).
        let dir  = scratch_dir("reopen");
        let cold = dir.join("cold");

        let now1: u64 = 1_698_006_800; // 2023-10-22 20:33:20 UTC
        let db = sled::open(&dir).unwrap();
        let tree = db.open_tree("flows").unwrap();

        // r1: first_seen 2023-10-15 20:00 → expires in pass 1 (cutoff 20:33:20).
        let mut r1 = flow("10.0.0.1", 1001, "203.0.113.1", 443, "TCP");
        r1.first_seen = 1_697_400_000.0;
        let k1 = sled_key_v2(&r1);
        tree.insert(&k1[..], serde_json::to_vec(&r1).unwrap()).unwrap();

        // r2: same UTC day, 21:00 → survives pass 1, expires in pass 2.
        let mut r2 = flow("10.0.0.2", 1002, "203.0.113.2", 443, "TCP");
        r2.first_seen = 1_697_403_600.0;
        let k2 = sled_key_v2(&r2);
        tree.insert(&k2[..], serde_json::to_vec(&r2).unwrap()).unwrap();

        let config = test_config(&dir, 7);

        let rep1 = run_retention_pass(&tree, &config, now1).expect("pass 1");
        assert_eq!(rep1.expired, 1, "only r1 is past cutoff 1_697_402_000");
        let shard = cold.join("flows-2023-10-15.ndjson.zst");
        assert!(shard.exists(), "pass 1 created the day shard");
        assert_eq!(shard_lines(&shard).len(), 1, "pass 1 archived one line");

        let now2: u64 = 1_698_010_400; // 21:33:20 → cutoff 1_697_405_600
        let rep2 = run_retention_pass(&tree, &config, now2).expect("pass 2");
        assert_eq!(rep2.expired, 1, "r2 expires into the SAME shard");

        let lines = shard_lines(&shard);
        assert_eq!(lines.len(), 2, "reopen merged instead of clobbering");
        assert!(lines.iter().any(|l| l.contains("\"src_ip\":\"10.0.0.1\"")), "r1 kept");
        assert!(lines.iter().any(|l| l.contains("\"src_ip\":\"10.0.0.2\"")), "r2 kept");
        for line in &lines {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("archived line is valid JSON");
            assert!(parsed.get("first_seen").is_some());
        }

        // Both records are gone from the hot tree.
        let remaining: Vec<Vec<u8>> = tree.iter().map(|r| r.unwrap().0.to_vec()).collect();
        assert!(remaining.is_empty(), "both expired keys removed from sled");

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_pass_rearchiving_same_line_does_not_grow_shard() {
        // Retry safety: if a pass archives a record but its sled removal never
        // lands, the next pass re-archives the identical line. The shard must not
        // grow, or an operator retrying a failed pass would duplicate history.
        let dir  = scratch_dir("rearchive");
        let cold = dir.join("cold");

        let now: u64 = 1_700_000_000;
        let db = sled::open(&dir).unwrap();
        let tree = db.open_tree("flows").unwrap();

        let mut old = flow("10.0.0.7", 7000, "203.0.113.7", 443, "TCP");
        old.first_seen = (now - 30 * 86_400) as f64;
        let key = sled_key_v2(&old);
        let val = serde_json::to_vec(&old).unwrap();
        tree.insert(&key[..], val.clone()).unwrap();

        let config = test_config(&dir, 7);
        let rep1 = run_retention_pass(&tree, &config, now).unwrap();
        assert_eq!(rep1.expired, 1);
        let shard = cold.join("flows-2023-10-15.ndjson.zst");
        let after_first = shard_lines(&shard).len();
        assert_eq!(after_first, 1);

        // Simulate the partial failure: put the exact record back and re-run with
        // the same `now` (same cutoff).
        tree.insert(&key[..], val).unwrap();
        let rep2 = run_retention_pass(&tree, &config, now).unwrap();
        assert_eq!(rep2.expired, 1, "the replayed record expires again");

        let after_second = shard_lines(&shard);
        assert_eq!(after_second.len(), after_first, "re-archive did not grow the shard");
        assert!(after_second[0].contains("10.0.0.7"));

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_existing_shard_is_preserved_and_replaced() {
        // A truncated/garbage shard must never be silently overwritten: the bad
        // bytes move aside to a `.corrupt-*` name that distill.py ignores, and a
        // fresh valid shard takes its place.
        let dir  = scratch_dir("corrupt");
        let cold = dir.join("cold");

        let now: u64 = 1_700_000_000;
        let db = sled::open(&dir).unwrap();
        let tree = db.open_tree("flows").unwrap();

        let shard = cold.join("flows-2023-10-15.ndjson.zst");
        std::fs::write(&shard, b"not-zstd-data").unwrap();

        let mut old = flow("10.0.0.9", 9000, "203.0.113.9", 443, "TCP");
        old.first_seen = (now - 30 * 86_400) as f64;
        tree.insert(&sled_key_v2(&old)[..], serde_json::to_vec(&old).unwrap()).unwrap();

        let config = test_config(&dir, 7);
        let rep = run_retention_pass(&tree, &config, now).expect("pass survives a corrupt shard");
        assert_eq!(rep.expired, 1);

        // (a) the live shard is now valid and holds the expected record.
        let lines = shard_lines(&shard);
        assert_eq!(lines.len(), 1, "fresh shard written over the corrupt one");
        assert!(lines[0].contains("\"src_ip\":\"10.0.0.9\""));

        // (b) the garbage was preserved, not deleted.
        let quarantined: Vec<std::path::PathBuf> = std::fs::read_dir(&cold)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.file_name().unwrap().to_string_lossy().contains(".corrupt"))
            .collect();
        assert_eq!(quarantined.len(), 1, "corrupt shard moved aside, not destroyed");
        assert_eq!(std::fs::read(&quarantined[0]).unwrap(), b"not-zstd-data");

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retain_days_zero_disables_the_pass() {
        let dir = scratch_dir("off");
        let db = sled::open(&dir).unwrap();
        let tree = db.open_tree("flows").unwrap();
        tree.insert(&sled_key_v2(&flow("1.1.1.1", 1, "2.2.2.2", 2, "TCP"))[..], b"{}".to_vec()).unwrap();

        let config = test_config(&dir, 0);
        let rep = run_retention_pass(&tree, &config, 1_700_000_000).unwrap();
        assert_eq!(rep, RetentionReport::default(), "disabled retention does nothing");
        assert_eq!(tree.iter().count(), 1, "nothing removed");

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── ndjson parsing (regression guard for field-name drift) ───────────────

    #[test]
    fn parses_sample_ndjson_line_with_dest_ip_quirk() {
        let line = r#"{"src_ip":"10.0.0.7","dest_ip":"8.8.8.8","src_port":4000,"dst_port":53,
            "ip":4,"proto":"UDP","first_seen":1700000000.25,"last_seen":1700000000.9,
            "duration":0.65,"bidirectional":1,"ndpi":{"proto":"DNS","encrypted":0,
            "flow_risk":{"0":{"risk":"Known TCP issues","severity":"low"}}},
            "xfer":{"src2dst_bytes":60,"dst2src_bytes":120,"src2dst_packets":1,"dst2src_packets":1}}"#;
        let f: FlowRecord = serde_json::from_str(line).unwrap();
        assert_eq!(f.dest_ip, "8.8.8.8");
        assert_eq!(f.src_ip, "10.0.0.7");
        assert_eq!(f.first_seen, 1700000000.25);
        assert_eq!(f.total_bytes(), 180);
        assert!(f.has_risk());
        assert!(!f.is_unidirectional());
        assert_eq!(sled_key_v2(&f)[..8], 1700000000u64.to_be_bytes());
    }

    #[test]
    fn icmp_flow_without_ports_defaults_to_zero() {
        let line = r#"{"src_ip":"10.0.0.8","dest_ip":"10.0.0.9","ip":4,"proto":"ICMP"}"#;
        let f: FlowRecord = serde_json::from_str(line).unwrap();
        assert_eq!((f.src_port, f.dst_port, f.first_seen), (0, 0, 0.0));
        // Undated record: v2 key still builds, retention treats age as unknown.
        assert_eq!(&sled_key_v2(&f)[..8], 0u64.to_be_bytes());
    }

    #[test]
    fn unknown_ndpi_fields_do_not_break_parsing() {
        let line = r#"{"src_ip":"a","dest_ip":"b","proto":"TCP","brand_new_field":123,
            "ndpi":{"proto":"TLS","invented":true}}"#;
        let f: FlowRecord = serde_json::from_str(line).unwrap();
        assert_eq!(f.ndpi.proto, "TLS");
    }

    #[test]
    fn effective_hostname_prefers_tls_sni() {
        let mut f = flow("10.0.0.1", 1, "1.1.1.1", 2, "TCP");
        f.ndpi.hostname = "dns-name.example".into();
        assert_eq!(f.effective_hostname(), "dns-name.example");
        f.server_hostname = "sni.example".into();
        assert_eq!(f.effective_hostname(), "sni.example");
    }

    // ── ndpiReader argv must NOT change semantics (brief constraint) ─────────

    #[test]
    fn ndpi_args_keep_required_argv_shape() {
        let c = Config {
            interface: "eth0".into(),
            bpf_filter: Some("not port 22".into()),
            continuous_output: false,
            no_output: false,
            debug_files: false,
            debug_dir: PathBuf::from("./ndpi_debug"),
            export_path: PathBuf::from("./ndpi_state/flows.json"),
            retain_days: 7,
            cold_dir: PathBuf::from("./cold"),
            retain_interval_secs: 3600,
        };
        let a = ndpi_args(&c, "15", "/dev/stdout");
        assert_eq!(a[0], "-i");
        assert_eq!(a[1], "eth0");
        assert_eq!(a[2], "-s");
        assert_eq!(a[3], "15");
        assert_eq!(a[4], "-k");
        assert_eq!(a[5], "/dev/stdout");
        assert!(a.contains(&"-q".to_string()), "-q is mandatory in streaming mode");
        assert!(a.contains(&"-F".to_string()), "-F feeds first_seen needed by retention");
        let i = a.iter().position(|x| x == "-f").unwrap();
        assert_eq!(a[i + 1], "not port 22");
    }
}

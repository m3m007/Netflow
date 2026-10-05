#!/usr/bin/env python3
"""
distill.py — cold-shard distiller (Task 2). Reads the zstd NDJSON shards written
by flow_monitor's retention task and rolls them up into `summary.sqlite`.

This SQLite file is the ONLY thing the agent (Hermes) is meant to query later:
small, machine-readable, deterministic. No LLM anywhere in this path.

SCHEMA (contract — keep in sync with anything that reads summary.sqlite)
════════════════════════════════════════════════════════════════════════
meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)
    schema_version   integer, currently "1"
    distilled_at     ISO-8601 UTC of the most recent successful ingest
    last_shard       filename of the newest shard already ingested
    shard_count      number of shards ingested so far
    geo_available    "1"/"0" — whether GeoLite2 lookups were usable at distill time

daily_summary(
    date             TEXT PRIMARY KEY,   -- YYYY-MM-DD (UTC)
    total_flows      INTEGER NOT NULL,
    bytes_out        INTEGER NOT NULL,   -- sum(src2dst_bytes)
    bytes_in         INTEGER NOT NULL,   -- sum(dst2src_bytes)
    distinct_dests   INTEGER NOT NULL,   -- unique dest_ip seen that day
    alerts           INTEGER NOT NULL,   -- flows classified alert/suspicious
    top_talkers_json     TEXT NOT NULL DEFAULT '[]',  -- [{"ip","bytes"}] top 10
    top_countries_json   TEXT NOT NULL DEFAULT '[]'   -- [{"iso","flows"}] top 10
)

dest_rollup(
    dest_ip      TEXT PRIMARY KEY,
    iso          TEXT,                   -- country_iso2 from GeoLite2-City (NULL if no geo)
    asn_org      TEXT,                   -- org name from GeoLite2-ASN (NULL if no geo)
    asn          INTEGER,                -- real ASN number (whitelist matches on THIS)
    first_seen   REAL NOT NULL,          -- unix seconds
    last_seen    REAL NOT NULL,
    flows        INTEGER NOT NULL,
    bytes        INTEGER NOT NULL,
    alert_count  INTEGER NOT NULL
)

Idempotency
═══════════════
* ingest() aggregates the WHOLE shard set it was given before writing anything:
  daily_summary rows are replaced per date and dest_rollup rows are replaced with
  lifetime totals summed across every day. So applying the same shard set twice
  yields byte-identical tables, and a dest seen on three days sums to three.
* first_seen/last_seen still widen monotonically (MIN/MAX) because they are
  genuinely cumulative and must survive seeing an older shard after a newer one.
* To extend history incrementally, pass ALL shards each run (cheap — they are
  day-sized) or use --rebuild. Passing only a subset recomputes only that subset's
  dates; dest totals then reflect just those dates.
* Shards are assigned to exactly one date (their own filename).

Usage
═══════
  python3 distill.py                          # ingest ./cold/* into ./ndpi_state/summary.sqlite
  python3 distill.py --cold ./cold --db /tmp/summary.sqlite
  python3 distill.py --rebuild                # drop and rebuild from all shards
  python3 distill.py --shard cold/flows-2026-10-04.ndjson.zst   # single shard
  python3 distill.py --dry-run                # aggregate + report, write nothing

Shards are decompressed by piping through the external `zstd -dc` binary (the
same tool that wrote them); stdlib-only means no python-zstandard dependency.
"""

import argparse
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_COLD_DIR = "./cold"
DEFAULT_DB       = "./ndpi_state/summary.sqlite"
SCHEMA_VERSION   = 1
SHARD_RE = re.compile(r"^flows-(\d{4})-(\d{2})-(\d{2})\.ndjson(?:\.zst)?$")
TOP_N            = 10

# Verdicts counted as "alerts" in rollups. Mirrors flow_server.py's classifier
# severity ladder without importing its HTTP machinery (kept deterministic and
# dependency-free; see classify() below).
ALERT_VERDICTS = ("alert", "suspicious", "threat")


# ─────────────────────────────────────────────────────────────────────────────
# Shard discovery + reading
# ─────────────────────────────────────────────────────────────────────────────

def shard_date(name: str):
    """Return 'YYYY-MM-DD' from a shard filename, or None if it isn't one.

    Accepts both compressed (.ndjson.zst) and plain (.ndjson) shards so a
    hand-dropped archive still gets distilled. The date must be real, not merely
    shaped right: flows-2026-13-45.ndjson.zst would otherwise create a day row
    that no query can ever range-match. A trailing .tmp is rejected too (that is
    an in-flight write, not a shard).
    """
    m = SHARD_RE.match(Path(name).name)
    if not m:
        return None
    year, month, day = (int(g) for g in m.groups())
    try:
        datetime(year, month, day)
    except ValueError:
        return None
    return f"{year:04d}-{month:02d}-{day:02d}"


def find_shards(cold_dir: Path):
    """All shard paths in cold_dir, sorted oldest-first by their date."""
    if not cold_dir.is_dir():
        return []
    out = []
    for p in sorted(cold_dir.iterdir()):
        d = shard_date(p.name)
        if d and p.is_file():
            out.append((d, p))
    out.sort(key=lambda t: (t[0], t[1].name))
    return out


def iter_shard_lines(path: Path):
    """Yield decoded lines from one shard, streaming through `zstd -dc`.

    Plain .ndjson files are read directly. Never loads a whole shard into RAM.
    """
    if path.suffix == ".zst":
        proc = subprocess.Popen(
            ["zstd", "-dc", "-q", str(path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            assert proc.stdout is not None
            for raw in proc.stdout:
                yield raw
            proc.stdout.close()
            rc = proc.wait()
            if rc != 0:
                err = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
                raise RuntimeError(f"zstd -dc {path} exited {rc}: {err.strip()}")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            if proc.stderr:
                proc.stderr.close()
    else:
        with open(path, "rb") as fh:
            yield from fh


def parse_flow_line(raw: bytes):
    """Decode one NDJSON line into a dict, or None if unusable."""
    try:
        text = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    if not text or not text.startswith("{"):
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


# ─────────────────────────────────────────────────────────────────────────────
# Deterministic classification (no network, no LLM)
# ─────────────────────────────────────────────────────────────────────────────

HIGH_SIGNAL_RISKS = {
    "malware_host_contacted", "blacklisted_ip", "dns_suspicious_traffic",
    "http_suspicious_header", "suspicious_dga_domain", "data_exfiltration",
    "malicious_ja3", "malicious_sha1_certificate",
}
NOISE_RISKS = {
    "tcp_issues", "unidirectional_traffic", "malicious_fingerprint",
    "known_proto_on_non_std_port", "tls_selfsigned_certificate",
}


def risk_names(flow: dict) -> list:
    nd = flow.get("ndpi") or {}
    fr = nd.get("flow_risk")
    if not isinstance(fr, dict):
        return []
    names = []
    for v in fr.values():
        if isinstance(v, dict):
            name = v.get("risk") or ""
            if name:
                names.append(name.lower().replace(" ", "_"))
    return names


def classify(flow: dict, trusted_asns=None) -> str:
    """Coarse verdict used only to count `alerts` in rollups.

    Deliberately simpler than flow_server.py's classifier — this is a
    historical tally, not the live dashboard decision. A destination whose real
    ASN is whitelisted is never alerted (that's the Task 1 win: numbers, not
    org-name fragments).
    """
    names = risk_names(flow)
    if any(n in HIGH_SIGNAL_RISKS for n in names):
        return "alert"
    if trusted_asns:
        asn = (flow.get("_asn") or {}).get("asn") if isinstance(flow.get("_asn"), dict) else None
        if asn and asn in trusted_asns:
            return "noise"
    score = (flow.get("ndpi") or {}).get("ndpi_risk_score") or 0
    if score >= 50 or (names and not all(n in NOISE_RISKS for n in names)):
        return "alert"
    if score >= 10:
        return "suspicious"
    return "safe"


# ─────────────────────────────────────────────────────────────────────────────
# Geo enrichment (optional — degrades to NULL columns when mmdb absent)
# ─────────────────────────────────────────────────────────────────────────────

def open_geo(mmdb_dir: str):
    """Best-effort GeoIP lookup helper, or None. Never raises (brief: degrade).

    Uses flow_server's GeoReader (ctypes → libmaxminddb) when that module is
    importable; if neither the databases nor libmaxminddb exist, callers get
    None and the geo columns stay NULL.
    """
    try:
        import flow_server
    except Exception:
        return None
    try:
        reader = flow_server.GeoReader(mmdb_dir=mmdb_dir)
    except Exception:
        return None
    return reader if reader.available else None


# ─────────────────────────────────────────────────────────────────────────────
# Aggregation
# ─────────────────────────────────────────────────────────────────────────────

def _day_of(ts: float) -> str:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d")
    except (ValueError, OSError, OverflowError, TypeError):
        return ""


def _new_day_bucket():
    """Per-day accumulator used by both aggregate_shard() and ingest()."""
    return defaultdict(lambda: {
        "total_flows": 0, "bytes_out": 0, "bytes_in": 0,
        "dests": set(), "alerts": 0,
        "talkers": defaultdict(int), "countries": defaultdict(int),
    })


def _merge_day(target: dict, src: dict) -> None:
    """Fold one shard's day bucket into the running aggregate for that day."""
    target["total_flows"] += src["total_flows"]
    target["bytes_out"]   += src["bytes_out"]
    target["bytes_in"]    += src["bytes_in"]
    target["dests"] |= src["dests"]
    target["alerts"] += src["alerts"]
    for k, v in src["talkers"].items():
        target["talkers"][k] += v
    for k, v in src["countries"].items():
        target["countries"][k] += v


def aggregate_shard(path, shard_day: str, geo=None, trusted_asns=None):
    """Read one shard → (per-day buckets, dest rollup rows, bad_line_count)."""
    path = Path(path)
    daily = _new_day_bucket()
    dests = {}
    bad_lines = 0

    for raw in iter_shard_lines(path):
        f = parse_flow_line(raw)
        if f is None:
            bad_lines += 1
            continue

        first = f.get("first_seen") or f.get("last_seen") or 0.0
        try:
            first = float(first)
        except (TypeError, ValueError):
            first = 0.0
        day = _day_of(first) or shard_day

        xfer = f.get("xfer") or {}
        b_out = int(xfer.get("src2dst_bytes") or 0)
        b_in  = int(xfer.get("dst2src_bytes") or 0)
        dest_ip = f.get("dest_ip") or ""
        verdict = classify(f, trusted_asns)

        d = daily[day]
        d["total_flows"] += 1
        d["bytes_out"]   += b_out
        d["bytes_in"]    += b_in
        if dest_ip:
            d["dests"].add(dest_ip)
        if verdict in ALERT_VERDICTS:
            d["alerts"] += 1
        src = f.get("src_ip") or ""
        if src:
            d["talkers"][src] += b_out + b_in

        iso = asn_org = None
        asn_no = None
        # Prefer enrichment already stamped on the record (flows.json carries
        # country_iso/asn_org/asn at export time); fall back to a live lookup.
        geo_f = f.get("_geo") if isinstance(f.get("_geo"), dict) else {}
        iso     = geo_f.get("country_iso")
        asn_org = geo_f.get("asn_org")
        asn_no  = geo_f.get("asn")
        if geo is not None and dest_ip and (not iso or not asn_no):
            try:
                g = geo.city(dest_ip) or {}
                a = geo.asn(dest_ip) or {}
                iso     = iso or g.get("country_iso")
                asn_org = asn_org or a.get("asn_org")
                asn_no  = asn_no or a.get("asn")
            except Exception:
                pass
        if iso:
            d["countries"][iso] += 1

        if dest_ip:
            last = first
            try:
                last = float(f.get("last_seen") or first)
            except (TypeError, ValueError):
                pass
            cur = dests.get(dest_ip)
            if cur is None:
                dests[dest_ip] = {
                    "dest_ip": dest_ip, "iso": iso, "asn_org": asn_org, "asn": asn_no,
                    "first_seen": first, "last_seen": last,
                    "flows": 1, "bytes": b_out + b_in,
                    "alert_count": 1 if verdict in ALERT_VERDICTS else 0,
                }
            else:
                cur["flows"]  += 1
                cur["bytes"]  += b_out + b_in
                cur["alert_count"] += 1 if verdict in ALERT_VERDICTS else 0
                cur["first_seen"] = min(cur["first_seen"], first)
                cur["last_seen"]  = max(cur["last_seen"], last)
                cur["iso"]      = cur["iso"] or iso
                cur["asn_org"]  = cur["asn_org"] or asn_org
                cur["asn"]      = cur["asn"] or asn_no

    return daily, dests, bad_lines


# ─────────────────────────────────────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────────────────────────────────────

DDL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS daily_summary (
    date               TEXT PRIMARY KEY,
    total_flows        INTEGER NOT NULL DEFAULT 0,
    bytes_out          INTEGER NOT NULL DEFAULT 0,
    bytes_in           INTEGER NOT NULL DEFAULT 0,
    distinct_dests     INTEGER NOT NULL DEFAULT 0,
    alerts             INTEGER NOT NULL DEFAULT 0,
    top_talkers_json   TEXT NOT NULL DEFAULT '[]',
    top_countries_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS dest_rollup (
    dest_ip     TEXT PRIMARY KEY,
    iso         TEXT,
    asn_org     TEXT,
    asn         INTEGER,
    first_seen  REAL NOT NULL DEFAULT 0,
    last_seen   REAL NOT NULL DEFAULT 0,
    flows       INTEGER NOT NULL DEFAULT 0,
    bytes       INTEGER NOT NULL DEFAULT 0,
    alert_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_daily_date      ON daily_summary(date);
CREATE INDEX IF NOT EXISTS idx_dest_alerts     ON dest_rollup(alert_count);
CREATE INDEX IF NOT EXISTS idx_dest_last_seen  ON dest_rollup(last_seen);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(DDL)
    return conn


def get_meta(conn: sqlite3.Connection, key: str, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_meta(conn: sqlite3.Connection, key: str, value) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )


def write_daily(conn: sqlite3.Connection, day: str, agg: dict) -> None:
    """Replace (not add to) a day's row — makes re-ingest idempotent."""
    talkers = sorted(agg["talkers"].items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_N]
    countries = sorted(agg["countries"].items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_N]
    conn.execute(
        """INSERT INTO daily_summary(date, total_flows, bytes_out, bytes_in,
                                     distinct_dests, alerts,
                                     top_talkers_json, top_countries_json)
           VALUES(?,?,?,?,?,?,?,?)
           ON CONFLICT(date) DO UPDATE SET
             total_flows=excluded.total_flows,
             bytes_out=excluded.bytes_out,
             bytes_in=excluded.bytes_in,
             distinct_dests=excluded.distinct_dests,
             alerts=excluded.alerts,
             top_talkers_json=excluded.top_talkers_json,
             top_countries_json=excluded.top_countries_json""",
        (
            day,
            int(agg["total_flows"]),
            int(agg["bytes_out"]),
            int(agg["bytes_in"]),
            len(agg["dests"]),
            int(agg["alerts"]),
            json.dumps([{"ip": ip, "bytes": b} for ip, b in talkers], separators=(",", ":")),
            json.dumps([{"iso": c, "flows": n} for c, n in countries], separators=(",", ":")),
        ),
    )


def upsert_dest(conn: sqlite3.Connection, r: dict) -> None:
    """Write one dest's LIFETIME totals (dest_rollup is a per-dest rollup).

    Values here are already summed across every shard being ingested, so they
    replace rather than accumulate — that is what makes re-running distill on the
    same inputs a no-op. first/last_seen widen monotonically because those are
    genuinely cumulative and must survive seeing an older shard after a newer one.
    """
    conn.execute(
        """INSERT INTO dest_rollup(dest_ip, iso, asn_org, asn, first_seen, last_seen,
                                   flows, bytes, alert_count)
           VALUES(?,?,?,?,?,?,?,?,?)
           ON CONFLICT(dest_ip) DO UPDATE SET
             iso         = COALESCE(excluded.iso, dest_rollup.iso),
             asn_org     = COALESCE(excluded.asn_org, dest_rollup.asn_org),
             asn         = COALESCE(excluded.asn, dest_rollup.asn),
             first_seen  = MIN(dest_rollup.first_seen, excluded.first_seen),
             last_seen   = MAX(dest_rollup.last_seen,  excluded.last_seen),
             flows       = excluded.flows,
             bytes       = excluded.bytes,
             alert_count = excluded.alert_count""",
        (
            r["dest_ip"], r.get("iso"), r.get("asn_org"), r.get("asn"),
            float(r["first_seen"]), float(r["last_seen"]),
            int(r["flows"]), int(r["bytes"]), int(r["alert_count"]),
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Ingest driver
# ─────────────────────────────────────────────────────────────────────────────

def ingest(db_path, shards, geo=None, trusted_asns=None, rebuild=False,
           verbose=True, dry_run=False):
    """Ingest `shards` [(date, Path)] into db_path. Returns a stats dict.

    Idempotency model: a shard belongs to exactly one date. For each affected
    date we re-aggregate EVERY shard carrying that date (cheap: shards are
    day-sized) and REPLACE the day row. dest_rollup upserts widen timestamps and
    take MAX() of counters, so running this twice on the same inputs is a no-op.
    """
    db_path = Path(db_path)
    stats = {"shards": 0, "days": 0, "dests": 0, "bad_lines": 0,
             "flows": 0, "skipped_shards": 0, "dry_run": dry_run}

    if dry_run:
        # Aggregate against a scratch DB so the real file is never touched.
        tmp_dir = tempfile.mkdtemp(prefix="distill_dry_")
        conn = connect(Path(tmp_dir) / "s.sqlite")
    else:
        tmp_dir = None
        conn = connect(db_path)

    try:
        if rebuild:
            conn.execute("DELETE FROM daily_summary")
            conn.execute("DELETE FROM dest_rollup")
            conn.commit()

        by_day = defaultdict(list)
        for d, p in shards:
            by_day[d].append(p)

        # dest_rollup holds LIFETIME totals per destination, so a dest seen on
        # three different days must sum across all three. Accumulate everything
        # first, then write once — that ordering is what makes the replace-style
        # upsert both correct and idempotent.
        dest_tot = {}
        day_count = 0
        flow_count = 0

        for day in sorted(by_day.keys()):
            day_agg = _new_day_bucket()
            for shard in sorted(by_day[day]):
                # A single unreadable shard must not abort the run: this is a
                # nightly batch over months of history, and one truncated or
                # garbage .zst would otherwise silently cost every later day.
                # Skip it, keep going, and surface the count in the report.
                try:
                    daily, dests, bad = aggregate_shard(shard, day, geo, trusted_asns)
                except (RuntimeError, OSError) as exc:
                    stats["skipped_shards"] += 1
                    print(f"distill: SKIPPED {Path(shard).name}: {exc}",
                          file=sys.stderr)
                    continue
                stats["bad_lines"] += bad
                stats["shards"] += 1
                for d, agg in daily.items():
                    if d != day:
                        continue  # a shard may hold stray dates; own day only
                    _merge_day(day_agg[d], agg)

                for ip, r in dests.items():
                    cur = dest_tot.get(ip)
                    if cur is None:
                        dest_tot[ip] = dict(r)
                    else:
                        cur["flows"] += r["flows"]
                        cur["bytes"] += r["bytes"]
                        cur["alert_count"] += r["alert_count"]
                        cur["first_seen"] = min(cur["first_seen"], r["first_seen"])
                        cur["last_seen"]  = max(cur["last_seen"], r["last_seen"])
                        cur["iso"]     = cur["iso"] or r["iso"]
                        cur["asn_org"] = cur["asn_org"] or r["asn_org"]
                        cur["asn"]     = cur["asn"] or r["asn"]

            write_daily(conn, day, day_agg[day])
            flow_count += day_agg[day]["total_flows"]
            day_count += 1

        for ip, r in dest_tot.items():
            upsert_dest(conn, r)

        stats["days"] = day_count
        stats["dests"] = len(dest_tot)
        stats["flows"] = flow_count

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        set_meta(conn, "schema_version", SCHEMA_VERSION)
        set_meta(conn, "distilled_at", now)
        set_meta(conn, "shard_count", len(shards))
        if shards:
            set_meta(conn, "last_shard", Path(max(shards, key=lambda t: t[0])[1]).name)
        set_meta(conn, "geo_available", "1" if geo is not None else "0")
        conn.commit()
    finally:
        conn.close()
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    if verbose:
        print(
            f"distill: {stats['shards']} shard(s) → {stats['days']} day row(s), "
            f"{stats['dests']} dest upsert(s), {stats['flows']} flow(s)"
            + (f", {stats['bad_lines']} unparseable line(s)" if stats["bad_lines"] else "")
            + (f", {stats['skipped_shards']} unreadable shard(s) skipped"
               if stats["skipped_shards"] else "")
            + (" [DRY RUN — nothing written]" if dry_run else f" → {db_path}")
        )
    return stats


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main(argv=None):
    p = argparse.ArgumentParser(description="Distill cold flow shards into summary.sqlite")
    p.add_argument("--cold", default=os.environ.get("FLOW_COLD_DIR", DEFAULT_COLD_DIR),
                   metavar="DIR", help="directory of flows-YYYY-MM-DD.ndjson.zst shards")
    p.add_argument("--db", default=os.environ.get("FLOW_SUMMARY_DB", DEFAULT_DB),
                   metavar="PATH", help="SQLite output (default ./ndpi_state/summary.sqlite)")
    p.add_argument("--mmdb-dir", default=os.environ.get("NETFLOW_MMDB_DIR", "/usr/share/GeoIP"),
                   metavar="DIR", help="GeoLite2 directory; absent → geo columns stay NULL")
    p.add_argument("--shard", action="append", default=[], metavar="PATH",
                   help="ingest only this shard (repeatable)")
    p.add_argument("--rebuild", action="store_true",
                   help="clear rollup tables first (full recompute)")
    p.add_argument("--since", metavar="DATE", help="only shards dated >= DATE (YYYY-MM-DD)")
    p.add_argument("--dry-run", action="store_true", help="aggregate and report, write nothing")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    cold_dir = Path(args.cold)

    if args.shard:
        shards = []
        for s in args.shard:
            d = shard_date(s)
            if not d:
                print(f"distill: skipping {s} (not a flows-YYYY-MM-DD.ndjson[.zst] shard)",
                      file=sys.stderr)
                continue
            shards.append((d, Path(s)))
    else:
        shards = find_shards(cold_dir)

    if args.since:
        shards = [(d, p) for d, p in shards if d >= args.since]

    if not shards:
        if not args.quiet:
            print(f"distill: no shards found in {cold_dir}/ — nothing to do")
        return 0

    geo = open_geo(args.mmdb_dir)
    if geo is None and not args.quiet:
        print("distill: GeoLite2 unavailable — iso/asn_org columns will be NULL",
              file=sys.stderr)

    ingest(Path(args.db), shards, geo=geo, rebuild=args.rebuild,
           verbose=not args.quiet, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())

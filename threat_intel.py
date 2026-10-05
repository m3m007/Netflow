#!/usr/bin/env python3
"""
threat_intel.py — deterministic abuse.ch IP threat-feed poller (Task 3).

Downloads public abuse.ch blocklists, reduces them to plain IP/CIDR sets, and
writes a small machine-readable JSON file that flow_server.py joins against
live flows. Zero LLM, stdlib only (urllib), no third-party packages.

Output schema (`threats.json`) — the contract with flow_server.py:
{
  "retrieved_at": "<ISO-8601 UTC>",            # newest retrieval in the merge
  "epoch":        <int>,                        # same instant, unix seconds
  "source":       "feodotracker+urlhaus+threatfox",  # sources that contributed
  "ips":     ["1.2.3.4", ...],   # sorted union of every source's exact IPs
  "cidrs":   ["1.2.3.0/24", ...],# sorted union; /24../32 prefixes from feeds
  "count_ips":   <int>,
  "count_cidrs": <int>,
  "sources": {                                  # provenance + freshness only
    "feodotracker": {"ok": true, "retrieved_at": "...", "url": "...",
                     "count_ips": 5, "count_cidrs": 0}, ...
  },
  "stale_sources": ["threatfox"]                # present only when a source is ok:false
}

Per-source IP/CIDR sets are NOT inlined in threats.json (that would roughly
double its size). They live beside it in `threats.sources.json` keyed by source
name, and they are what makes an outage survivable: if a feed fails, its
last-good set is carried forward from that file rather than being dropped.
Both files are written temp-file + fsync + os.replace().
Set-file schema: {"updated_at": "...", "sources": {"<name>": {"ips": [...],
"cidrs": [...], "retrieved_at": "...", "url": "..."}}}

Feeds (all IPv4-only by design — nDPI dest_ip matching is exact/prefix):
  Feodo Tracker  https://feodotracker.abuse.ch/downloads/ipblocklist.csv
                 CSV: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
  URLhaus        https://urlhaus.abuse.ch/downloads/text_recent/
                 one malicious URL per line; only literal-IPv4 hosts are usable
  ThreatFox      https://threatfox.abuse.ch/export/csv/recent/  (optional)
                 NOTE: the brief's /export/text/recent/ returns HTTP 404 as of
                 2026-10-05; the working path is the CSV export below. The CSV
                 has NO header row; columns are positional:
                 [0]=added_date [1]=id [2]=ioc [3]=ioc_type [4]=threat [5]=name ...
                 Only ioc_type in {ip, ip:port, monit} carries a bare address.

Offline-safety contract (acceptance gate 5):
  * Every source is fetched with retry-once semantics. A source that still
    fails is SKIPPED, never fatal.
  * The last-good per-source sets are always loaded first and merged, so a
    total network outage leaves the effective blocklist intact (same IPs,
    older timestamps, stale_sources flagged) instead of blanking it.
  * The write is temp-file + fsync + os.replace(), so a reader can never see a
    partial file (same discipline as flows.json).
  * --base-url overrides the host of every feed URL, which is how the outage
    path is exercised without touching the real feeds.

Usage:
  python3 threat_intel.py                      # fetch, write ./ndpi_state/threats.json
  python3 threat_intel.py --out /tmp/t.json --quiet
  python3 threat_intel.py --no-threatfox       # skip the optional ThreatFox feed
  python3 threat_intel.py --once               # single pass (for cron/systemd)
  python3 threat_intel.py --interval 900       # keep polling (15 min default)
  python3 threat_intel.py --base-url https://127.0.0.1:9 --dry-run   # offline proof
"""

import argparse
import io
import json
import os
import re
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

DEFAULT_OUT      = "./ndpi_state/threats.json"
DEFAULT_INTERVAL = 900          # 15 min: polite for free feeds, fresh enough
MIN_INTERVAL     = 60           # refuse to hammer abuse.ch faster than this
TIMEOUT          = 30
RETRIES          = 2            # 1 attempt + 1 retry ("retry-once semantics")
BACKOFF          = 2.0          # seconds between attempts
USER_AGENT       = "netflow-threat-intel/1.0 (+local flow monitor; stdlib urllib)"
MAX_BYTES        = 32 * 1024 * 1024   # sanity cap; feeds are ~1 MB today

FEEDS = {
    "feodotracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "parser": "feodo_csv",
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
        "parser": "urlhaus_urls",
    },
    "threatfox": {
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "parser": "threatfox_csv",
        "optional": True,
    },
}

# ThreatFox ioc_type values whose "ioc" column is a bare IPv4 (or IPv4:port).
THREATFOX_IP_TYPES = {"ip", "ip:port", "monit"}

_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


# ─────────────────────────────────────────────────────────────────────────────
# Address validation (pure, unit-testable)
# ─────────────────────────────────────────────────────────────────────────────

def valid_ipv4(s: str) -> bool:
    """True for a strict dotted-quad IPv4 with every octet 0-255.

    Rejects anything inet_aton() would happily accept ("10.1", "0x1.",
    "1.2.3.4.5"), because those would poison the match set.
    """
    if not isinstance(s, str):
        return False
    m = _IPV4_RE.match(s.strip())
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def parse_cidr(text: str):
    """Return (network_ip, prefix_len) for an IPv4 CIDR, else None.

    Deliberately does NOT use the ipaddress module: it normalises
    "1.2.3.5/24" to "1.2.3.0/24", and silently accepting sloppy feed data
    would hide upstream format changes. Here a non-zero host part is rejected
    and logged by the caller.
    """
    if not isinstance(text, str) or "/" not in text:
        return None
    ip_part, _, pfx = text.strip().partition("/")
    if not valid_ipv4(ip_part) or not pfx.isdigit():
        return None
    length = int(pfx)
    if not 0 <= length <= 32:
        return None
    octets = [int(o) for o in ip_part.split(".")]
    value = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    host_bits = 32 - length
    if (value & ((1 << host_bits) - 1)) != 0:
        return None          # host bits set — not a network address
    return (ip_part, length)


def cidr_covered(ip: str, cidrs) -> bool:
    """True if `ip` falls inside any of `cidrs` ("/a.b.c.d/nn" strings)."""
    if not valid_ipv4(ip):
        return False
    octets = [int(o) for o in ip.split(".")]
    value = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    for entry in cidrs or []:
        parsed = parse_cidr(entry if isinstance(entry, str) else "")
        if parsed is None:
            continue
        net_ip, length = parsed
        no = [int(o) for o in net_ip.split(".")]
        nval = (no[0] << 24) | (no[1] << 16) | (no[2] << 8) | no[3]
        mask = (0xFFFFFFFF << length) & 0xFFFFFFFF if length else 0
        if value & mask == nval & mask:
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Feed parsers (pure functions over decoded text → dict, unit-testable)
# ─────────────────────────────────────────────────────────────────────────────

def _dedupe_sorted(values) -> list:
    return sorted(set(values))


def _split_csv_row(line: str) -> list:
    """Split one CSV record, honouring double quotes.

    Uses csv under the hood but keeps the API line-at-a-time so callers can
    skip comment banners without importing the whole file into memory.
    """
    import csv
    try:
        return next(csv.reader([line]))
    except StopIteration:
        return []


def parse_feodo_csv(text: str) -> dict:
    """Feodo Tracker blocklist CSV → {"ips": [...], "cidrs": [...]}.

    Record layout: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware.
    Both online and offline entries are kept: the dashboard alerts on contact
    with either, and "was recently a C2" is still worth knowing.
    """
    ips, cidrs, bad = [], [], 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cols = _split_csv_row(line)
        if len(cols) < 2:
            continue
        if cols[0].strip().strip('"').lower() == "first_seen_utc" or \
           cols[1].strip().strip('"').lower() == "dst_ip":
            continue                                   # header row, if present
        candidate = cols[1].strip().strip('"')
        if valid_ipv4(candidate):
            ips.append(candidate)
            continue
        parsed = parse_cidr(candidate)
        if parsed:
            cidrs.append("%s/%d" % parsed)
        else:
            bad += 1
    return {"ips": _dedupe_sorted(ips), "cidrs": _dedupe_sorted(cidrs),
            "rejected": bad}


_URL_HOST_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/?#]+)")


def _host_from_url(url: str):
    """Extract the host from a URL string, dropping userinfo and port."""
    m = _URL_HOST_RE.match(url.strip())
    authority = m.group(1) if m else url.strip()
    if "@" in authority:                              # strip user:pass@
        authority = authority.rsplit("@", 1)[1]
    if ":" in authority:
        authority = authority.split(":", 1)[0]
    return authority


def parse_urlhaus_urls(text: str) -> dict:
    """URLhaus text_recent → {"ips": [...], "cidrs": [...]}.

    One malicious URL per line. Only lines whose host is a *literal* IPv4 are
    useful here — resolving domain hosts would need DNS (slow, non-deterministic,
    out of scope for this poller). Comment/banner lines start with '#'.
    """
    ips, cidrs, domains = [], [], 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        host = _host_from_url(line)
        if valid_ipv4(host):
            ips.append(host)
        elif parse_cidr(host):
            cidrs.append("%s/%d" % parse_cidr(host))
        else:
            domains += 1
    return {"ips": _dedupe_sorted(ips), "cidrs": _dedupe_sorted(cidrs),
            "skipped_non_ip_hosts": domains}


def parse_threatfox_csv(text: str) -> dict:
    """ThreatFox recent CSV → {"ips": [...], "cidrs": [...]}.

    No header row. Positional columns:
      0 added_date, 1 id, 2 ioc, 3 ioc_type, 4 threat_type, 5 threat_name ...
    Keep only ioc_type in THREATFOX_IP_TYPES and take the address part of the
    IOC (drops ":port"). sha256_hash/domain/url rows are ignored on purpose.
    """
    ips, cidrs, skipped = [], [], 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cols = _split_csv_row(line)
        if len(cols) < 4:
            continue
        # ThreatFox writes '", "'-style separators, so unquoted fields keep a
        # leading space (' "ip:port"'); strip before comparing or nothing matches.
        ioc, ioc_type = cols[2].strip(), cols[3].strip().strip('"').strip().lower()
        if ioc_type not in THREATFOX_IP_TYPES:
            skipped += 1
            continue
        candidate = ioc.strip('"')
        if candidate.count(":") == 1:                 # "1.2.3.4:8080"
            candidate = candidate.rsplit(":", 1)[0]
        if valid_ipv4(candidate):
            ips.append(candidate)
            continue
        parsed = parse_cidr(candidate)
        if parsed:
            cidrs.append("%s/%d" % parsed)
        else:
            skipped += 1
    return {"ips": _dedupe_sorted(ips), "cidrs": _dedupe_sorted(cidrs),
            "skipped_rows": skipped}


PARSERS = {
    "feodo_csv": parse_feodo_csv,
    "urlhaus_urls": parse_urlhaus_urls,
    "threatfox_csv": parse_threatfox_csv,
}


# ─────────────────────────────────────────────────────────────────────────────
# Fetching
# ─────────────────────────────────────────────────────────────────────────────

def apply_base_override(url: str, base_url: str) -> str:
    """Swap scheme+host(+port) of `url` for `base_url`, keeping the path.

    This is what makes the offline dry-run possible: point --base-url at a
    closed port and every feed becomes unreachable while paths stay identical.
    """
    if not base_url:
        return url
    parts = urllib.parse.urlparse(base_url.rstrip("/"))
    if not parts.scheme or not parts.netloc:
        raise ValueError("--base-url needs a scheme and host, e.g. https://host:port")
    original = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(
        (parts.scheme, parts.netloc, original.path, "", original.query, ""))


def fetch_url(url: str, timeout: int = TIMEOUT, retries: int = RETRIES,
              log=print) -> bytes:
    """GET a URL, retry once on failure. Returns body bytes or raises the last error.

    Only 2xx is accepted (urllib already raises HTTPError for 3xx→4xx/5xx);
    a redirect chain is followed by the default handler and the final status
    must still be 2xx.
    """
    last = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": USER_AGENT, "Accept": "*/*"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                if not (200 <= int(status) < 300):
                    raise urllib.error.HTTPError(url, int(status), "non-2xx", {}, None)
                data = resp.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    raise ValueError(f"response larger than {MAX_BYTES} bytes: {url}")
                return data
        except Exception as exc:                       # noqa: BLE001 — report & retry
            last = exc
            if attempt < retries:
                log(f"    attempt {attempt} failed ({type(exc).__name__}: {exc}); "
                    f"retrying in {BACKOFF:.0f}s")
                time.sleep(BACKOFF)
    raise RuntimeError(f"fetch failed after {retries} attempts: {last}")


def fetch_source(name: str, feed: dict, base_url=None, timeout=TIMEOUT,
                 log=print):
    """Fetch + parse one feed. Returns (record_dict|None, err_string|None)."""
    url = apply_base_override(feed["url"], base_url)
    parser = PARSERS[feed["parser"]]
    try:
        body = fetch_url(url, timeout=timeout, log=log)
    except Exception as exc:                           # noqa: BLE001 — never fatal
        return None, f"{type(exc).__name__}: {exc}"
    text = body.decode("utf-8", errors="replace")
    parsed = parser(text)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = {
        "ok": True,
        "url": url,
        "retrieved_at": now,
        "ips": parsed["ips"],
        "cidrs": parsed["cidrs"],
    }
    for extra in ("rejected", "skipped_non_ip_hosts", "skipped_rows"):
        if parsed.get(extra):
            record[extra] = parsed[extra]
    return record, None


# ─────────────────────────────────────────────────────────────────────────────
# Merge + atomic write
# ─────────────────────────────────────────────────────────────────────────────

def load_previous(path: str) -> dict:
    """Read a JSON object from `path`; {} when absent/corrupt (never raises)."""
    try:
        with open(path) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, NotADirectoryError, IsADirectoryError,
            json.JSONDecodeError, UnicodeDecodeError, OSError):
        return {}


def sources_path(out_path: str) -> str:
    """Sidecar holding each source's own IP/CIDR set, beside threats.json."""
    base, ext = os.path.splitext(out_path)
    return f"{base}.sources{ext or '.json'}"


def load_sources_sidecar(path: str) -> dict:
    """Read the sidecar and return its `{name: record}` map ({} if unusable).

    Records here carry no `ok` flag — that is recomputed every pass from whether
    this run managed to fetch the source. A missing/corrupt sidecar means we
    simply have nothing to carry forward; it must never abort a poll.
    """
    data = load_previous(path)
    raw = data.get("sources")
    if not isinstance(raw, dict):
        return {}
    out = {}
    for name, rec in raw.items():
        if not isinstance(rec, dict) or not isinstance(name, str):
            continue
        if not (rec.get("ips") or rec.get("cidrs")):
            continue
        out[name] = {
            "ips": [str(x) for x in (rec.get("ips") or [])],
            "cidrs": [str(x) for x in (rec.get("cidrs") or [])],
            "retrieved_at": rec.get("retrieved_at") or "",
            "url": rec.get("url") or "",
        }
    return out


def write_sources_sidecar(path: str, sources: dict) -> None:
    """Persist the per-source sets that back an outage merge.

    Only sources that actually hold data are written, so the sidecar stays the
    size of the blocklist rather than growing with failed-fetch bookkeeping.
    """
    payload = {
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": {
            name: {
                "ips": rec.get("ips") or [],
                "cidrs": rec.get("cidrs") or [],
                "retrieved_at": rec.get("retrieved_at") or "",
                "url": rec.get("url") or "",
            }
            for name, rec in sorted((sources or {}).items())
            if isinstance(rec, dict) and (rec.get("ips") or rec.get("cidrs"))
        },
    }
    atomic_write_json(path, payload)


def merge_sources(previous: dict, fresh: dict) -> dict:
    """Combine per-source records; for each source the newest retrieval wins.

    `previous` entries are only ever superseded by a *successful* fetch in
    `fresh`. A failed source is carried forward untouched so an outage keeps
    the last-good blocklist instead of blanking it.

    Sources absent from `fresh` entirely — deliberately disabled with --only or
    --no-threatfox — are still carried forward: their last-good IPs must keep
    matching while they are switched off, otherwise disabling one feed would
    silently disarm the others' history too. The canonical feed URL is backfilled
    onto carried records because the sidecar may predate the `url` field and
    build_document() drops sources without one.
    """
    sources = {}
    for name, rec in (previous or {}).items():
        if isinstance(rec, dict) and (rec.get("ips") or rec.get("cidrs")):
            held = {**rec, "ok": bool(rec.get("ok", True))}
            if not held.get("url"):
                held["url"] = (FEEDS.get(name) or {}).get("url", "")
            sources[name] = held
    for name, rec in (fresh or {}).items():
        if not isinstance(rec, dict):
            continue
        if rec.get("ok"):
            held = sources.get(name)
            stamp, prev_stamp = rec.get("retrieved_at") or "", (held or {}).get(
                "retrieved_at") or ""
            if held and prev_stamp >= stamp:
                held["ok"] = True
                continue
            sources[name] = rec
        elif name in sources:
            sources[name] = {**sources[name], "ok": False}
        elif rec.get("ips") or rec.get("cidrs"):
            sources[name] = rec
    return sources


def build_document(sources: dict) -> dict:
    """Collapse per-source records into the flat union consumed by the server."""
    ips, cidrs, names, stale = set(), set(), [], []
    newest = ""
    for name in sorted(sources):
        rec = sources[name]
        names.append(name)
        if not rec.get("ok", True):
            stale.append(name)
        ips.update(ip for ip in (rec.get("ips") or []) if valid_ipv4(ip))
        cidrs.update(c for c in (rec.get("cidrs") or []) if parse_cidr(c))
        newest = max(newest, rec.get("retrieved_at") or "")
    doc = {
        "retrieved_at": newest or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "epoch": _epoch(newest),
        "source": "+".join(names) if names else "none",
        "ips": sorted(ips),
        "cidrs": sorted(cidrs, key=_cidr_sort_key),
        "count_ips": len(ips),
        "count_cidrs": len(cidrs),
        "sources": {
            name: {
                "ok": bool(sources[name].get("ok", True)),
                "retrieved_at": sources[name].get("retrieved_at", ""),
                "url": sources[name].get("url", ""),
                "count_ips": len(sources[name].get("ips") or []),
                "count_cidrs": len(sources[name].get("cidrs") or []),
            }
            for name in sorted(sources)
        },
    }
    if stale:
        doc["stale_sources"] = stale
    return doc


def _cidr_sort_key(entry: str):
    parsed = parse_cidr(entry)
    if parsed is None:
        return (0xFFFFFFFF, 0)
    octets = [int(o) for o in parsed[0].split(".")]
    return (((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]),
            parsed[1])


def _epoch(iso: str) -> int:
    """ISO-8601 (…Z) → unix seconds, 0 when unparseable."""
    try:
        return int(datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc).timestamp())
    except (ValueError, TypeError):
        return 0


def atomic_write_json(path: str, doc: dict) -> None:
    """temp file + fsync + os.replace() — readers never see a partial file."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".threats-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(doc, fh, separators=(",", ":"), sort_keys=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def run_once(out_path: str, base_url=None, only=None, timeout=TIMEOUT,
             log=print) -> dict:
    """Poll every enabled source once and write the merged document.

    Never raises for network reasons: failures degrade to keeping the previous
    data. Returns the written document — which, when a pass would have emptied
    the blocklist, is the *previous* document rather than a blank one.
    """
    enabled = {}
    for name, feed in FEEDS.items():
        if only and name not in only:
            continue
        enabled[name] = feed

    sidecar = sources_path(out_path)
    # The sidecar (not threats.json) holds per-source sets; threats.json's own
    # `sources` map is provenance bookkeeping with counts only, so feeding it to
    # merge_sources() would silently drop every carried-forward IP.
    previous_sets = load_sources_sidecar(sidecar)
    fresh = {}
    for name, feed in enabled.items():
        log(f"  [{name}] fetching {apply_base_override(feed['url'], base_url)}")
        record, err = fetch_source(name, feed, base_url=base_url, timeout=timeout,
                                   log=log)
        if record is None:
            log(f"  [{name}] SKIP — {err} (keeping previous data for this source)")
            held = previous_sets.get(name)
            if held:
                held = dict(held)
                held["ok"] = False
                fresh[name] = held          # carry forward, flagged stale
            continue
        log(f"  [{name}] ok — {len(record['ips'])} ips, {len(record['cidrs'])} cidrs")
        fresh[name] = record

    sources = merge_sources(previous_sets, fresh)
    doc = build_document(sources)

    if not doc["ips"] and not doc["cidrs"]:
        # Nothing usable this pass. Blanking the file would disarm the classifier
        # exactly when feeds are down, so keep the last non-empty document intact.
        old = load_previous(out_path)
        if isinstance(old.get("ips"), list) and (old["ips"] or old.get("cidrs")):
            log(f"threat_intel: no usable data ({', '.join(sorted(enabled))} all "
                f"failed); leaving existing {out_path} intact "
                f"({len(old['ips'])} ips / {len(old.get('cidrs') or [])} cidrs)")
            return old
        log("threat_intel: no usable data and no previous file — writing empty set")

    atomic_write_json(out_path, doc)
    try:
        write_sources_sidecar(sidecar, sources)
    except OSError as exc:
        # Losing the sidecar costs outage resilience on the next pass only; the
        # live blocklist is already committed.
        log(f"threat_intel: warning — could not write {sidecar}: {exc}")
    log(f"wrote {out_path}: {doc['count_ips']} ips / {doc['count_cidrs']} cidrs "
        f"from [{doc['source']}]")
    return doc


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Poll abuse.ch IP threat feeds into threats.json (stdlib only).")
    p.add_argument("--out", default=os.environ.get("FLOW_THREATS_PATH", DEFAULT_OUT),
                   metavar="PATH", help=f"output file (default {DEFAULT_OUT})")
    p.add_argument("--base-url", default=os.environ.get("FLOW_THREAT_BASE_URL"),
                   metavar="URL", help="override scheme+host of every feed "
                   "(offline dry-run / mirror)")
    p.add_argument("--timeout", type=int, default=TIMEOUT, metavar="SECS")
    p.add_argument("--interval", type=int,
                   default=int(os.environ.get("FLOW_THREAT_INTERVAL", DEFAULT_INTERVAL)),
                   metavar="SECS", help="poll period for --loop (min %d)" % MIN_INTERVAL)
    p.add_argument("--once", action="store_true", help="single pass then exit (cron)")
    p.add_argument("--loop", action="store_true", help="keep polling forever")
    p.add_argument("--no-threatfox", action="store_true",
                   help="skip the optional ThreatFox feed")
    p.add_argument("--with-threatfox", action="store_true",
                   help="explicitly enable ThreatFox (it is already the default)")
    p.add_argument("--only", action="append", default=[], metavar="SOURCE",
                   choices=sorted(FEEDS), help="restrict to this source (repeatable)")
    p.add_argument("--dry-run", action="store_true",
                   help="do everything except replace the output file")
    p.add_argument("--quiet", action="store_true", help="suppress progress output")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    log = (lambda *a, **k: None) if args.quiet else print

    only = set(args.only)
    if only:
        enabled = sorted(only)
    else:
        enabled = [n for n in FEEDS
                   if not (args.no_threatfox and n == "threatfox")]

    log(f"threat_intel: sources={','.join(enabled)} out={args.out}")
    if args.dry_run:
        log("threat_intel: --dry-run, output file will NOT be modified")

    def pass_():
        target = args.out
        if args.dry_run:
            fd, target = tempfile.mkstemp(prefix="threats-dryrun-", suffix=".json")
            os.close(fd)
        try:
            doc = run_once(target, base_url=args.base_url, only=set(enabled),
                           timeout=args.timeout, log=log)
            if args.dry_run:
                preview = {**doc, "ips": doc["ips"][:5], "cidrs": doc["cidrs"][:5]}
                log("dry-run document (ips/cidrs truncated to 5):")
                log(json.dumps(preview, indent=2)[:4000])
        finally:
            if args.dry_run:
                try:
                    os.unlink(target)
                except OSError:
                    pass
        return doc

    loop = args.loop and not args.once
    while True:
        try:
            pass_()
        except Exception as exc:                       # noqa: BLE001 — keep serving
            log(f"threat_intel: pass failed ({type(exc).__name__}: {exc}); "
                f"previous threats.json left intact")
            if not loop:
                return 1
        if not loop:
            return 0
        pause = max(MIN_INTERVAL, args.interval)
        log(f"threat_intel: sleeping {pause}s")
        try:
            time.sleep(pause)
        except KeyboardInterrupt:
            log("\nthreat_intel: interrupted, shutting down.")
            return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)

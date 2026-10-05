#!/usr/bin/env python3
"""
flow_server.py — Network Flow Monitor with security analytics.

Serves on 0.0.0.0:7000 (reachable on Tailscale automatically).

Endpoints:
  GET /              → tabbed HTML5 dashboard
  GET /api/flows     → raw flows (optionally ?limit=N&verdict=alert)
  GET /api/summary   → aggregate stats, verdict counts, top talkers
  GET /api/scanners  → top scanner IPs with breadth/intensity metrics
  GET /api/timeline  → per-minute bytes/packets/alerts for sparklines
  GET /api/protocols → protocol + category distribution
  GET /api/alerts    → alert/suspicious/threat flows, newest first
  GET /api/agent/status  → compact machine-readable snapshot (<30 kB, Task 4)
  GET /api/agent/diff?since=<ISO> → events newer than since (Task 4)
  GET /api/agent/schema → endpoint contract + verdict meanings (Task 4)
  GET /favicon.ico   → inline SVG fallback

Per-flow fields added by enrichment: country_iso, asn, asn_org, dest_geo
(from GeoLite2 via libmaxminddb/ctypes, null when unavailable) and
threat_source (exact IP/CIDR matched from threats.json, Task 3).

Usage:
  python3 flow_server.py [--port 7000] [--data ./ndpi_state/flows.json]
                         [--html ./html] [--whitelist ./whitelist.json]
                         [--mmdb-dir /usr/share/GeoIP]
                         [--threats ./ndpi_state/threats.json]
                         [--retain-days 7]
"""

import argparse
import ctypes
import http.server
import ipaddress
import json
import math
import mimetypes
import os
import re
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_PORT       = 7000
DEFAULT_DATA_FILE  = "./ndpi_state/flows.json"
DEFAULT_HTML_DIR   = "./html"
DEFAULT_WHITELIST  = "./whitelist.json"
# GeoLite2 databases + threat feed live beside flows.json by default.
DEFAULT_MMDB_DIR   = os.environ.get("NETFLOW_MMDB_DIR", "/usr/share/GeoIP")
DEFAULT_THREATS    = "./ndpi_state/threats.json"
DEFAULT_SUMMARY_DB = "./ndpi_state/summary.sqlite"
DEFAULT_COLD_DIR   = os.environ.get("FLOW_COLD_DIR", "./cold")

EXTRA_MIME = {
    ".ico": "image/x-icon", ".png": "image/png", ".svg": "image/svg+xml",
    ".webp": "image/webp", ".woff2": "font/woff2", ".js": "application/javascript",
    ".css": "text/css", ".txt": "text/plain; charset=utf-8",
}

# ─────────────────────────────────────────────────────────────────────────────
# Trusted ASN / org name fragments — flows matching these are never "alert"
# regardless of risk score (they may still be "suspicious" if something is
# really wrong, but scanner noise from them is suppressed).
# ─────────────────────────────────────────────────────────────────────────────

TRUSTED_ORGS = {
    "microsoft", "google", "amazon", "cloudflare", "akamai", "fastly",
    "apple", "meta", "facebook", "twitter", "github", "digitalocean",
    "linode", "vultr", "hetzner", "ovh", "letsencrypt", "mozilla",
}

# Risk names that are "background internet noise" — logged but not alerted
NOISE_RISKS = {
    "tcp_issues", "unidirectional_traffic", "malicious_fingerprint",
    "known_proto_on_non_std_port", "tls_selfsigned_certificate",
}

# Risk names that are genuinely concerning even in small numbers
HIGH_SIGNAL_RISKS = {
    "malware_host_contacted", "blacklisted_ip", "dns_suspicious_traffic",
    "http_suspicious_header", "suspicious_dga_domain", "data_exfiltration",
    "malicious_ja3", "malicious_sha1_certificate",
}

# ─────────────────────────────────────────────────────────────────────────────
# Whitelist: default well-known safe networks. User can override with a JSON
# file containing {"prefixes": ["8.8.8.0/24", ...], "asns": [15169, ...]}
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_WHITELIST_DATA = {
    "asns": [15169, 8075, 16509, 13335, 20940, 32934, 36459, 54113],
    "org_fragments": list(TRUSTED_ORGS),
    "comment": "Edit to add your own trusted IPs/ASNs. Flows matching these are classified as noise at worst.",
}

# ─────────────────────────────────────────────────────────────────────────────
# GeoIP / ASN enrichment (Task 1) — libmaxminddb through ctypes.
#
# WHY ctypes and not a pip package or a hand-written mmdb parser:
#   * The Python server must stay stdlib-only (hard constraint), so `maxminddb`
#     from PyPI is out.
#   * libmaxminddb IS installed on this host (/usr/lib/libmaxminddb.so.0, with
#     headers in /usr/include/maxminddb.h) and ctypes ships with CPython, so we
#     get MaxMind's real, tested tree walk for free instead of reimplementing
#     it (IPv6 trees, extended records, ipv4_start_node, every data type…).
#   * If the .so or the .mmdb files are missing (owner has not run geoipupdate
#     yet), GeoReader.available stays False and every lookup returns None: flows
#     carry null geo fields. Nothing crashes, startup never blocks.
#
# Struct layouts below were verified against the installed header by compiling
# offsetof()/sizeof() probes (not guessed):
#   sizeof(MMDB_s)=136  sizeof(MMDB_entry_data_s)=48  sizeof(MMDB_lookup_result_s)=32
#   MMDB_entry_data_s: has_data@0 | union{utf8_string,uint16,uint32,int32,uint64}@16
#                      offset@32  offset_to_next@36  data_size@40  type@44
#   MMDB_lookup_result_s: found_entry@0 | entry(MMDB_entry_s){mmdb@0,offset@8}@8 | netmask@24
#   MMDB_SUCCESS=0; data types UTF8=2 UINT16=5 UINT32=6 INT32=8 UINT64=9 DOUBLE=3 BOOL=14
# We use MMDB_aget_value (the char** path form of the varargs MMDB_get_value)
# because ctypes cannot safely synthesise C varargs.
# ─────────────────────────────────────────────────────────────────────────────

MMDB_SUCCESS = 0
_MMDB_TYPE_UTF8   = 2
_MMDB_TYPE_UINT16 = 5
_MMDB_TYPE_UINT32 = 6
_MMDB_TYPE_INT32  = 8
_MMDB_TYPE_UINT64 = 9


class _MMDBHandle(ctypes.Structure):
    """MMDB_s — allocated BY US and filled in by MMDB_open.

    The library's own header warns that this struct's size is ABI-frozen ("do
    not add new fields without bumping the SONAME"), which is exactly what makes
    a fixed-size opaque buffer safe here: MMDB_open only ever writes the bytes
    the compiled header says the struct occupies.
    """
    _fields_ = [("raw", ctypes.c_uint8 * 136)]


class _MMDBEntry(ctypes.Structure):
    """MMDB_entry_s — a pointer into the data section for one IP's record."""
    _fields_ = [
        ("mmdb",   ctypes.c_void_p),
        ("offset", ctypes.c_uint32),
    ]


class _MMDBEntryData(ctypes.Structure):
    """MMDB_entry_data_s (48 bytes) — scalar value decoded from an entry.

    C's anonymous union at offset 16 cannot be spelled in ctypes, and the two
    obvious attempts both fail *silently* (they produce a struct that loads fine
    and returns has_data=True/type=0 for every real record):

      * sibling fields utf8_string/uint16/uint32/int32/uint64 → each gets its own
        storage; sizeof becomes 56.
      * byte-array padding → ctypes gives c_uint8*N alignment 1 and never inserts
        slack before the next field, so pointers end up at 8 instead of 16.

    Fix: `_pack_ = 1` disables all implicit padding, then explicit reserved
    blocks place every field at the offset offsetof() reported for this host:
        has_data@0  union(utf8_string|u16|u32|i32|u64)@16  offset@32
        offset_to_next@36  data_size@40  type@44   sizeof=48
    Narrower union members are read as raw bytes out of the same 16-byte slot.

    `_layout_ = 'ms'` is declared explicitly because combining `_pack_` with the
    default layout is deprecated (it warns since 3.14 and becomes an error in
    3.19). MSVC layout is what we want: with _pack_=1 both gcc and msvc produce
    the same byte-for-byte offsets, which the layout tests assert against the
    offsetof() values measured from the installed header.
    """
    _pack_ = 1
    _layout_ = 'ms'
    _fields_ = [
        ("has_data",       ctypes.c_bool),        # @0
        ("_pad0",          ctypes.c_uint8 * 15),  # @1..15
        ("utf8_string",    ctypes.c_void_p),      # @16 (union slot, pointer view)
        ("_pad1",          ctypes.c_uint8 * 8),   # @24..31 rest of the union
        ("offset",         ctypes.c_uint32),      # @32
        ("offset_to_next", ctypes.c_uint32),      # @36
        ("data_size",      ctypes.c_uint32),      # @40
        ("type",           ctypes.c_uint32),      # @44
    ]

    _UNION_OFF = 16

    def _union_bytes(self, n: int) -> bytes:
        """Raw bytes of the first n bytes of the union slot at @16."""
        return ctypes.string_at(ctypes.addressof(self) + self._UNION_OFF, n)

    def u16(self):
        return int.from_bytes(self._union_bytes(2), "little")

    def u32(self):
        return int.from_bytes(self._union_bytes(4), "little")

    def i32(self):
        return int.from_bytes(self._union_bytes(4), "little", signed=True)

    def u64(self):
        return int.from_bytes(self._union_bytes(8), "little")


class _MMDBLookupResult(ctypes.Structure):
    """MMDB_lookup_result_s (32 bytes) — returned by value from MMDB_lookup_string.

    found_entry@0 | pad@1..7 | entry(MMDB_entry_s)@8..23 | netmask@24 | pad@26..31
    See _MMDBEntryData for why _pack_ and _layout_ are both explicit.
    """
    _pack_ = 1
    _layout_ = 'ms'
    _fields_ = [
        ("found_entry", ctypes.c_bool),      # @0
        ("_pad0",       ctypes.c_uint8 * 7), # @1..7
        ("entry",       _MMDBEntry),         # @8..23
        ("netmask",     ctypes.c_uint16),    # @24
        ("_pad1",       ctypes.c_uint8 * 6), # @26..31
    ]


def _load_libmaxminddb():
    """Return a configured CDLL, or None if unavailable. Never raises."""
    candidates = ("libmaxminddb.so.0", "libmaxminddb.so",
                  "/usr/lib/libmaxminddb.so.0", "/usr/lib64/libmaxminddb.so.0")
    for name in candidates:
        try:
            lib = ctypes.CDLL(name)
        except OSError:
            continue
        try:
            lib.MMDB_open.argtypes = [ctypes.c_char_p, ctypes.c_uint32,
                                      ctypes.POINTER(_MMDBHandle)]
            lib.MMDB_open.restype = ctypes.c_int
            lib.MMDB_close.argtypes = [ctypes.POINTER(_MMDBHandle)]
            lib.MMDB_close.restype = None
            lib.MMDB_strerror.argtypes = [ctypes.c_int]
            lib.MMDB_strerror.restype = ctypes.c_char_p
            lib.MMDB_lib_version.argtypes = []
            lib.MMDB_lib_version.restype = ctypes.c_char_p
            lib.MMDB_lookup_string.argtypes = [ctypes.POINTER(_MMDBHandle),
                                               ctypes.c_char_p,
                                               ctypes.POINTER(ctypes.c_int),
                                               ctypes.POINTER(ctypes.c_int)]
            lib.MMDB_lookup_string.restype = _MMDBLookupResult
            lib.MMDB_aget_value.argtypes = [ctypes.POINTER(_MMDBEntry),
                                            ctypes.POINTER(_MMDBEntryData),
                                            ctypes.POINTER(ctypes.c_char_p)]
            lib.MMDB_aget_value.restype = ctypes.c_int
        except (OSError, AttributeError):
            return None
        return lib
    return None


class GeoReader:
    """Crash-proof GeoLite2 City + ASN reader over libmaxminddb.

    `available` is False unless the library loaded AND at least one database
    opened. Every lookup then degrades to None, so callers must treat geo as
    optional — that is the brief's "never crash, degrade gracefully" rule.
    Results are cached per (kind, ip); feeds churn far less than flows do.
    """

    def __init__(self, mmdb_dir: str = DEFAULT_MMDB_DIR,
                 city_file: str = "GeoLite2-City.mmdb",
                 asn_file: str = "GeoLite2-ASN.mmdb"):
        self.mmdb_dir = mmdb_dir
        self.city_file = city_file
        self.asn_file = asn_file
        self.city_path = Path(mmdb_dir) / city_file
        self.asn_path = Path(mmdb_dir) / asn_file
        self.lib = None
        self._city = None      # (_MMDBHandle, c_void_p kept alive)
        self._asn = None
        self.error = None
        self.available = False
        self._cache = {}
        self._cache_max = 50_000
        self.lookups = 0
        self.hits = 0
        self._open()

    # ── lifecycle ────────────────────────────────────────────────────────────

    def _open(self):
        try:
            self.lib = _load_libmaxminddb()
            if self.lib is None:
                self.error = "libmaxminddb not found (install libmaxminddb)"
                return
            if not self.city_path.is_file() and not self.asn_path.is_file():
                self.error = f"no GeoLite2 databases under {self.mmdb_dir}"
                return
            self._city = self._open_one(self.city_path)
            self._asn = self._open_one(self.asn_path)
            self.available = bool(self._city or self._asn)
            if not self.available and not self.error:
                self.error = "databases present but none opened"
        except Exception as exc:                    # pragma: no cover - defensive
            self.error = f"geo init error: {exc}"
            self.available = False

    def _open_one(self, path: Path):
        if not path.is_file():
            return None
        try:
            handle = _MMDBHandle()
            rc = self.lib.MMDB_open(str(path).encode("utf-8", "surrogateescape"),
                                    0, ctypes.byref(handle))
            if rc != MMDB_SUCCESS:
                msg = self.lib.MMDB_strerror(rc)
                self.error = f"{path.name}: {msg.decode('utf-8','replace') if msg else rc}"
                return None
            # The handle must outlive every lookup made with it, so we keep the
            # struct AND a raw pointer to it on the instance.
            ptr = ctypes.cast(ctypes.byref(handle), ctypes.c_void_p)
            holder = (handle, ptr, path)
            return holder
        except Exception as exc:                    # pragma: no cover - defensive
            self.error = f"{path.name}: {exc}"
            return None

    def close(self):
        for attr in ("_city", "_asn"):
            db = getattr(self, attr, None)
            if db is not None and self.lib is not None:
                try:
                    self.lib.MMDB_close(ctypes.byref(db[0]))
                except Exception:
                    pass
            setattr(self, attr, None)
        self.available = False

    def __del__(self):                              # pragma: no cover - GC timing
        try:
            self.close()
        except Exception:
            pass

    # ── decoding ─────────────────────────────────────────────────────────────

    def _scalar(self, ent: "_MMDBEntryData"):
        """Convert a decoded entry into str/int, or None if not a usable scalar.

        has_data must be checked explicitly: MMDB_aget_value returns MMDB_SUCCESS
        for a key path that does not exist in this record, leaving type == 0
        (MMDB_DATA_TYPE_UNKNOWN) with has_data cleared. Only checking rc makes
        every lookup look like a miss.
        """
        if not ent.has_data:
            return None
        t = ent.type
        try:
            if t == _MMDB_TYPE_UTF8:
                size = ent.data_size
                addr = ent.utf8_string
                if not size or not addr:
                    return None
                # utf8_string points INTO the mmap'd data section and is not
                # NUL-terminated — read exactly data_size bytes.
                raw = ctypes.string_at(addr, size)
                return raw.decode("utf-8", "replace")
            if t == _MMDB_TYPE_UINT32:
                return ent.u32()
            if t == _MMDB_TYPE_UINT16:
                return ent.u16()
            if t == _MMDB_TYPE_UINT64:
                return ent.u64()
            if t == _MMDB_TYPE_INT32:
                return ent.i32()
        except Exception:
            return None
        return None

    def _get(self, entry: "_MMDBEntry", *keys: str):
        """Read one value at a key path relative to a looked-up ENTRY.

        MMDB_aget_value walks a map starting where `entry` points, so passing a
        root entry (offset 0) here would return MMDB_NOT_MAPPABLE — the record
        for an IP is not itself a map root. Callers get their entry from
        _lookup_entry() and hand it back in.

        Note the two distinct failure modes, both observed against real GeoLite2:
          * rc != MMDB_SUCCESS            → structurally wrong (not a map, bad db)
          * rc == 0 but has_data == False → the key path simply does not exist in
            this record (e.g. ASN databases have no 'country' key). The library
            reports that as success with an empty entry_data, so checking only
            the return code silently yields None for every lookup.
        """
        ent = _MMDBEntryData()
        n = len(keys)
        arr = (ctypes.c_char_p * (n + 1))()
        for i, k in enumerate(keys):
            arr[i] = k.encode("utf-8")
        arr[n] = None  # NULL-terminated path, as MMDB_aget_value expects
        rc = self.lib.MMDB_aget_value(ctypes.byref(entry), ctypes.byref(ent), arr)
        if rc != MMDB_SUCCESS:
            return None
        # A missing key path is reported as SUCCESS with has_data cleared, so
        # _scalar() (which requires has_data) is the real gatekeeper here.
        return self._scalar(ent)

    def _lookup_entry(self, db, ip: str):
        """Return the MMDB_entry_s for `ip`, or None when absent/unusable."""
        handle, ptr, _ = db
        gai = ctypes.c_int(0)
        merr = ctypes.c_int(0)
        try:
            res = self.lib.MMDB_lookup_string(ctypes.byref(handle),
                                              ip.encode("utf-8"),
                                              ctypes.byref(gai), ctypes.byref(merr))
        except Exception:
            return None
        if gai.value != MMDB_SUCCESS or merr.value != MMDB_SUCCESS:
            return None
        if not res.found_entry:
            return None
        # The returned struct embeds a pointer into `handle`; keep both alive by
        # re-anchoring mmdb to the pointer we already own.
        entry = res.entry
        entry.mmdb = ptr
        return entry

    # ── public lookups ───────────────────────────────────────────────────────

    def city(self, ip: str):
        """{'country_iso','country_name','city'} | None."""
        return self._lookup(ip, "city")

    def asn(self, ip: str):
        """{'asn','asn_org'} | None."""
        return self._lookup(ip, "asn")

    def _lookup(self, ip: str, kind: str):
        if not self.available or not ip:
            return None
        ck = (kind, ip)
        self.lookups += 1
        if ck in self._cache:
            self.hits += 1
            return self._cache[ck]
        out = None
        try:
            if kind == "city" and self._city is not None:
                entry = self._lookup_entry(self._city, ip)
                if entry is not None:
                    iso = self._get(entry, "country", "iso_code")
                    cname = self._get(entry, "country", "names", "en")
                    city = self._get(entry, "city", "names", "en")
                    if iso or cname or city:
                        out = {"country_iso": iso, "country_name": cname, "city": city}
            elif kind == "asn" and self._asn is not None:
                entry = self._lookup_entry(self._asn, ip)
                if entry is not None:
                    num = self._get(entry, "autonomous_system_number")
                    org = self._get(entry, "autonomous_system_organization")
                    if num is not None or org:
                        out = {"asn": num, "asn_org": org}
        except Exception:
            out = None
        if len(self._cache) < self._cache_max:
            self._cache[ck] = out
        return out

    def status(self) -> dict:
        libver = None
        if self.lib is not None:
            try:
                libver = self.lib.MMDB_lib_version().decode("utf-8", "replace")
            except Exception:
                libver = None
        return {
            "available": self.available,
            "mmdb_dir": self.mmdb_dir,
            "city_db": bool(self._city),
            "asn_db": bool(self._asn),
            "libmaxminddb": libver,
            "error": self.error,
            "cache_entries": len(self._cache),
            "lookups": self.lookups,
            "cache_hits": self.hits,
        }


# ─────────────────────────────────────────────────────────────────────────────
# CIDR matching (Task 1 trusted prefixes + Task 3 threat prefixes)
#
# The brief says a full trie isn't needed: threat feeds publish /24–/32 and the
# whitelist holds a handful of prefixes. We therefore keep two small buckets —
# exact IPs (O(1) set) and parsed networks probed longest-prefix-first — which
# stays fast at feed size and needs no third-party module.
# ─────────────────────────────────────────────────────────────────────────────

def parse_cidr(text: str):
    """'1.2.3.0/24' or bare '1.2.3.4' → ip_network(strict=False), else None."""
    try:
        text = text.strip()
        if not text:
            return None
        if "/" in text:
            return ipaddress.ip_network(text, strict=False)
        return ipaddress.ip_network(text + "/32" if ":" not in text else text + "/128",
                                    strict=False)
    except ValueError:
        return None


def match_network(ip: str, nets) -> bool:
    """True if `ip` falls inside any network in `nets`."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in nets:
        if addr in net:
            return True
    return False


_PREFIX_CACHE = {}


def _compile_prefixes(prefixes) -> list:
    """Parse a whitelist's CIDR list once and memoise it (keyed by content).

    Operators edit whitelist.json rarely but every flow asks the question, so
    re-parsing per flow would be pure waste. Bad entries are skipped rather than
    raising — one typo must not disable the whole whitelist.
    """
    key = tuple(sorted(str(p) for p in (prefixes or [])))
    cached = _PREFIX_CACHE.get(key)
    if cached is not None:
        return cached
    nets = []
    for p in key:
        net = parse_cidr(p)
        if net is not None:
            nets.append(net)
    nets.sort(key=lambda n: -n.prefixlen)
    _PREFIX_CACHE[key] = nets
    return nets


# ─────────────────────────────────────────────────────────────────────────────
# Threat feed (Task 3) — reads threats.json written by threat_intel.py.
#
# Matching contract with threat_intel.py's output schema:
#   {"retrieved_at", "epoch", "source", "ips": [...], "cidrs": [...], ...}
# Exact IPs hit an O(1) set; CIDRs are parsed once and probed in order. The
# file is refreshed on mtime change so a poller update lands without a restart,
# and any read/parse failure keeps the LAST GOOD set rather than going blind.
# ─────────────────────────────────────────────────────────────────────────────

class ThreatStore:
    def __init__(self, path: str = DEFAULT_THREATS):
        self.path = path
        self.ips = set()
        self.nets = []
        self.retrieved_at = None
        self.source = None
        self.stale_sources = []
        self.loaded_at = None
        self.error = None
        self._mtime = 0
        self.reload(force=True)

    def reload(self, force: bool = False) -> bool:
        """Re-read threats.json if its mtime changed. Returns True if usable."""
        p = Path(self.path)
        try:
            mtime = p.stat().st_mtime
        except FileNotFoundError:
            if not self.ips and not self.nets:
                self.error = f"no threat file at {p} (run threat_intel.py)"
            return bool(self.ips or self.nets)
        except OSError as exc:
            self.error = f"stat failed: {exc}"
            return bool(self.ips or self.nets)

        if mtime == self._mtime and not force:
            return bool(self.ips or self.nets)

        try:
            with open(p, "r") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            # Keep whatever we already had — a corrupt or half-written refresh
            # must never disable matching.
            self.error = f"parse failed: {exc}"
            self._mtime = mtime
            return bool(self.ips or self.nets)

        if not isinstance(data, dict):
            self.error = "threats.json is not an object"
            self._mtime = mtime
            return bool(self.ips or self.nets)

        ips = {str(x).strip() for x in (data.get("ips") or []) if isinstance(x, str)}
        nets = []
        for c in (data.get("cidrs") or []):
            net = parse_cidr(str(c)) if isinstance(c, str) else None
            if net is not None:
                nets.append(net)
        # Longest prefix first so a /32 beats the /24 that contains it (only the
        # matched source string is reported, so ordering affects nothing else).
        nets.sort(key=lambda n: -n.prefixlen)

        self.ips = ips
        self.nets = nets
        self.retrieved_at = data.get("retrieved_at")
        self.source = data.get("source")
        self.stale_sources = list(data.get("stale_sources") or [])
        self.loaded_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.error = None
        self._mtime = mtime
        return bool(ips or nets)

    def match(self, ip: str):
        """Return 'ip' or the matching CIDR string when `ip` is listed, else None."""
        if not ip:
            return None
        if ip in self.ips:
            return ip
        if self.nets and match_network(ip, self.nets):
            for net in self.nets:
                try:
                    if ipaddress.ip_address(ip) in net:
                        return str(net)
                except ValueError:
                    return None
        return None

    def status(self) -> dict:
        return {
            "path": self.path,
            "loaded": bool(self.ips or self.nets),
            "count_ips": len(self.ips),
            "count_cidrs": len(self.nets),
            "retrieved_at": self.retrieved_at,
            "source": self.source,
            "stale_sources": self.stale_sources,
            "error": self.error,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Flow analytics engine
# ─────────────────────────────────────────────────────────────────────────────

class FlowAnalytics:
    def __init__(self, whitelist_path: str, geo: "GeoReader|None" = None,
                 threats: "ThreatStore|None" = None):
        self.whitelist_path = whitelist_path
        self.geo = geo if geo is not None else GeoReader()
        self.threats = threats if threats is not None else ThreatStore()
        self._whitelist = None
        self._wl_mtime = 0

    def _load_whitelist(self):
        p = Path(self.whitelist_path)
        try:
            mtime = p.stat().st_mtime
            if mtime != self._wl_mtime:
                with open(p) as fh:
                    self._whitelist = json.load(fh)
                self._wl_mtime = mtime
        except FileNotFoundError:
            # Write default whitelist so user knows it exists
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, 'w') as fh:
                json.dump(DEFAULT_WHITELIST_DATA, fh, indent=2)
            self._whitelist = DEFAULT_WHITELIST_DATA
            self._wl_mtime = p.stat().st_mtime
        except Exception:
            if self._whitelist is None:
                self._whitelist = DEFAULT_WHITELIST_DATA
        return self._whitelist

    def _geo_for(self, ip: str) -> dict:
        """Country + ASN for one destination IP, or an empty stub.

        Returns a dict with all keys present (None values) so the JSON shape is
        stable for the dashboard whether or not GeoLite2 is installed — that is
        the graceful-degradation contract from Task 1.
        """
        out = {"country_iso": None, "country_name": None, "city": None,
               "asn": None, "asn_org": None}
        if self.geo is None or not getattr(self.geo, "available", False) or not ip:
            return out
        try:
            c = self.geo.city(ip)
            a = self.geo.asn(ip)
        except Exception:
            return out
        if c:
            out["country_iso"] = c.get("country_iso")
            out["country_name"] = c.get("country_name")
            out["city"] = c.get("city")
        if a:
            out["asn"] = a.get("asn")
            out["asn_org"] = a.get("asn_org")
        return out

    def _is_whitelisted(self, flow: dict, wl: dict, geo: dict | None = None) -> bool:
        """True when the destination is a network the operator trusts.

        Preference order matters (Task 1): the REAL ASN number from GeoLite2-ASN
        is authoritative; nDPI's proto_by_ip_id and org-name fragments are
        fallbacks that only apply while geo is unavailable, because proto_by_ip_id
        is an nDPI reputation id, not an ASN, and hostname fragments match on
        whatever string the client happened to send.
        """
        geo = geo or {}
        asn = geo.get("asn")
        trusted_asns = wl.get("asns", []) or []

        # 1. Authoritative: ASN resolved from the destination IP itself.
        if asn is not None and asn in trusted_asns:
            return True

        # 2. Trusted prefixes (CIDR) — independent of any database.
        prefixes = wl.get("prefixes", []) or []
        dest_ip = flow.get("dest_ip") or ""
        if prefixes and dest_ip:
            nets = _compile_prefixes(prefixes)
            if nets and match_network(dest_ip, nets):
                return True

        # 3. Fallback: nDPI's IP-reputation id matched against the same list.
        #    Skipped when geo told us the real ASN and it was NOT trusted — a
        #    reputation guess must not override a fact.
        nd = flow.get("ndpi") or {}
        if asn is None:
            ip_db_id = nd.get("proto_by_ip_id")
            if ip_db_id and ip_db_id in trusted_asns:
                return True

        # 4. Fallback: known-safe org names in the SNI/hostname, used only when
        #    the ASN lookup gave us nothing.
        if asn is None and geo.get("asn_org") is None:
            hostname = (nd.get("hostname") or flow.get("server_hostname") or "").lower()
            org = (geo.get("asn_org") or "").lower()
            for frag in wl.get("org_fragments", []) or []:
                f = frag.lower()
                if f and (f in hostname or f in org):
                    return True
        return False

    def _risk_names(self, flow: dict) -> list[str]:
        nd = flow.get("ndpi") or {}
        fr = nd.get("flow_risk")
        if not fr or not isinstance(fr, dict):
            return []
        names = []
        for v in fr.values():
            if isinstance(v, dict):
                name = v.get("risk", "")
                if name:
                    names.append(name.lower().replace(" ", "_"))
        return names

    def _max_severity(self, flow: dict) -> int:
        """0=none 1=low 2=medium 3=high"""
        nd = flow.get("ndpi") or {}
        fr = nd.get("flow_risk")
        if not fr or not isinstance(fr, dict):
            return 0
        sev = 0
        for v in fr.values():
            if isinstance(v, dict):
                s = (v.get("severity") or "").lower()
                if s == "high":   sev = max(sev, 3)
                elif s == "medium": sev = max(sev, 2)
                elif s == "low":    sev = max(sev, 1)
        return sev

    def _verdict(self, flow: dict, risk_names: list[str], whitelisted: bool, score: int,
                 threat_match: str | None = None) -> tuple[str, str]:
        """Returns (verdict, reason). Verdicts: threat|safe|noise|suspicious|alert

        `threat` outranks everything, including the whitelist: an IP listed by
        abuse.ch is not trusted just because it sits in a friendly ASN, and
        silently downgrading it would be the worst possible failure mode here.
        """
        if threat_match:
            return "threat", f"threat_feed_match: {threat_match}"

        # High-signal risks always alert regardless of whitelist
        hs = [r for r in risk_names if r in HIGH_SIGNAL_RISKS]
        if hs:
            return "alert", f"high_signal_risk: {', '.join(hs)}"

        if whitelisted:
            return "noise", "trusted_org"

        nd   = flow.get("ndpi") or {}
        xfer = flow.get("xfer") or {}
        only_noise = all(r in NOISE_RISKS for r in risk_names) if risk_names else True

        # Port scan detection: many ports, tiny bytes, no L7 identification
        bytes_total = (xfer.get("src2dst_bytes") or 0) + (xfer.get("dst2src_bytes") or 0)
        proto = (nd.get("proto") or "").lower()

        if only_noise and risk_names:
            return "noise", "background_internet_noise"

        if score >= 50 or (risk_names and not only_noise):
            return "alert", f"risk_score={score} risks={','.join(risk_names[:3])}"

        if score >= 10:
            return "suspicious", f"risk_score={score}"

        if proto in ("", "unknown", "unclassified") and bytes_total < 200:
            return "noise", "unclassified_tiny"

        return "safe", "no_indicators"

    def enrich(self, raw_flows: list) -> list:
        wl = self._load_whitelist()
        # Refresh the feed at most once per enrich pass (mtime-gated inside).
        self.threats.reload()
        geo_available = bool(self.geo and self.geo.available)
        enriched = []
        for f in raw_flows:
            nd   = f.get("ndpi") or {}
            xfer = f.get("xfer") or {}
            iat  = f.get("iat")  or {}
            risk_names = self._risk_names(f)
            score = nd.get("ndpi_risk_score") or 0

            dest_ip = f.get("dest_ip") or ""
            geo = self._geo_for(dest_ip) if geo_available else {
                "country_iso": None, "country_name": None, "city": None,
                "asn": None, "asn_org": None}
            threat_match = self.threats.match(dest_ip)

            whitelisted = self._is_whitelisted(f, wl, geo)
            verdict, reason = self._verdict(f, risk_names, whitelisted, score, threat_match)
            severity = self._max_severity(f)

            # Bytes and packets live under "xfer" with src2dst/dst2src naming
            bytes_s2d = xfer.get("src2dst_bytes") or 0
            bytes_d2s = xfer.get("dst2src_bytes") or 0
            pkts_s2d  = xfer.get("src2dst_packets") or 0
            pkts_d2s  = xfer.get("dst2src_packets") or 0
            bytes_total = bytes_s2d + bytes_d2s
            pkts_total  = pkts_s2d  + pkts_d2s

            # TLS SNI is at top level as "server_hostname" (from ClientHello),
            # not inside ndpi{} — the ndpi.tls sub-object has ja3/cipher/etc.
            sni = f.get("server_hostname") or ""

            city_part = geo["city"] or ""
            country_part = geo["country_name"] or geo["country_iso"] or ""
            dest_geo = ", ".join(p for p in (city_part, country_part) if p) or None

            enriched.append({
                **f,
                "_bytes":       bytes_total,
                "_pkts":        pkts_total,
                "_bytes_s2d":   bytes_s2d,
                "_bytes_d2s":   bytes_d2s,
                "_pkts_s2d":    pkts_s2d,
                "_pkts_d2s":    pkts_d2s,
                "_riskscore":   score,
                "_risknames":   risk_names,
                "_risktext":    " · ".join(r.replace("_", " ") for r in risk_names),
                "_severity":    severity,
                "_hasrisk":     bool(risk_names),
                "_verdict":     verdict,
                "_reason":      reason,
                "_whitelisted": whitelisted,
                "_sni":         sni,
                # ── Task 1: GeoIP / ASN enrichment ────────────────────────────
                "country_iso":  geo["country_iso"],
                "asn":          geo["asn"],
                "asn_org":      geo["asn_org"],
                "dest_geo":     dest_geo,
                "_geo":         geo,
                # ── Task 3: threat-feed join on dest_ip ───────────────────────
                "threat_source": threat_match,
                "_threat":      bool(threat_match),
            })
        return enriched

    def summary(self, flows: list) -> dict:
        verdicts = defaultdict(int)
        proto_bytes = defaultdict(int)
        category_counts = defaultdict(int)
        src_ip_bytes = defaultdict(int)
        src_ip_alerts = defaultdict(int)
        dest_country_counts = defaultdict(int)
        scanner_data = defaultdict(lambda: {"ports": set(), "bytes": 0, "flows": 0, "risks": set()})
        enc_count = 0
        total_bytes = 0
        total_pkts = 0
        alert_flows = []
        threat_flows = []

        for f in flows:
            v = f.get("_verdict", "safe")
            verdicts[v] += 1
            nd = f.get("ndpi") or {}

            b = f.get("_bytes", 0)
            total_bytes += b
            total_pkts  += f.get("_pkts", 0)

            p = nd.get("proto") or f.get("proto") or "Unknown"
            proto_bytes[p] += b

            cat = nd.get("category") or "Unknown"
            category_counts[cat] += 1

            if nd.get("encrypted"):
                enc_count += 1

            iso = f.get("country_iso")
            if iso:
                dest_country_counts[iso] += 1

            src = f.get("src_ip", "")
            src_ip_bytes[src] += b

            if v == "threat":
                threat_flows.append(f)
                alert_flows.append(f)
                src_ip_alerts[src] += 1
            elif v in ("alert", "suspicious"):
                alert_flows.append(f)
                src_ip_alerts[src] += 1

            # Scanner tracking: probing many dst_ports with tiny/no response.
            # "bidirectional": 0 means no reply at all — stronger scan signal.
            dst_port = f.get("dst_port")
            xfer_b   = f.get("xfer") or {}
            flow_bytes = (xfer_b.get("src2dst_bytes") or 0) + (xfer_b.get("dst2src_bytes") or 0)
            is_unidir  = f.get("bidirectional") == 0
            if dst_port and (flow_bytes < 2000 or is_unidir):
                sd = scanner_data[src]
                sd["ports"].add(dst_port)
                sd["bytes"] += b
                sd["flows"] += 1
                for r in f.get("_risknames", []):
                    sd["risks"].add(r)

        # Top scanners: IPs that probed many ports
        scanners = []
        for ip, sd in scanner_data.items():
            if len(sd["ports"]) >= 5:
                scanners.append({
                    "ip":       ip,
                    "ports":    len(sd["ports"]),
                    "flows":    sd["flows"],
                    "bytes":    sd["bytes"],
                    "risks":    list(sd["risks"]),
                    "severity": "high" if len(sd["ports"]) > 50 else
                                "medium" if len(sd["ports"]) > 15 else "low",
                })
        scanners.sort(key=lambda x: x["ports"], reverse=True)

        top_talkers = sorted(src_ip_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
        top_alerters = sorted(src_ip_alerts.items(), key=lambda x: x[1], reverse=True)[:10]

        top_proto = sorted(proto_bytes.items(), key=lambda x: x[1], reverse=True)
        top_cat   = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
        top_countries = sorted(dest_country_counts.items(), key=lambda x: x[1], reverse=True)

        return {
            "total_flows":   len(flows),
            "total_bytes":   total_bytes,
            "total_pkts":    total_pkts,
            "verdicts":      dict(verdicts),
            "enc_count":     enc_count,
            "enc_pct":       round(enc_count * 100 / len(flows), 1) if flows else 0,
            "top_proto":     top_proto[:10],
            "top_category":  top_cat[:10],
            "top_countries": top_countries[:15],
            "top_talkers":   [{"ip": ip, "bytes": b} for ip, b in top_talkers],
            "top_alerters":  [{"ip": ip, "alerts": c} for ip, c in top_alerters],
            "scanners":      scanners[:20],
            "alert_count":   len(alert_flows),
            "alert_flows":   alert_flows[:50],  # newest 50 for overview
            "threat_count":  len(threat_flows),
            "threat_flows":  threat_flows[:50],
        }

    def timeline(self, flows: list) -> list:
        """Bucket flows into per-minute buckets by first_seen timestamp."""
        buckets = defaultdict(lambda: {"bytes": 0, "pkts": 0, "alerts": 0, "flows": 0})
        for f in flows:
            ts = f.get("first_seen") or f.get("last_seen") or 0
            if not ts:
                continue
            try:
                minute = int(float(ts) // 60) * 60
            except (ValueError, TypeError):
                continue
            b = buckets[minute]
            b["bytes"]  += f.get("_bytes", 0)
            b["pkts"]   += f.get("_pkts", 0)
            b["flows"]  += 1
            if f.get("_verdict") in ("alert", "suspicious"):
                b["alerts"] += 1

        if not buckets:
            return []

        result = sorted(
            [{"ts": k, **v} for k, v in buckets.items()],
            key=lambda x: x["ts"]
        )
        return result

    # ─────────────────────────────────────────────────────────────────────────
    # Task 4 — agent-facing surface (small, machine-readable, size-capped)
    #
    # Design rule from the owner: everything deterministic stays deterministic,
    # and the agent reads ONLY these compact summaries. So every array here is
    # explicitly capped and the whole payload is guarded to stay well under the
    # ~32 kB budget; if it would exceed it, arrays shrink in a fixed priority
    # order rather than the response being truncated mid-JSON.
    # ─────────────────────────────────────────────────────────────────────────

    AGENT_BUDGET_BYTES   = 30_000   # hard ceiling for /api/agent/status
    AGENT_MAX_ALERTS     = 50       # brief: "max 50"
    AGENT_MAX_THREATS    = 50
    AGENT_MAX_DESTS      = 25
    LOOKBACK_SECS        = 86_400   # "last 24h"

    @staticmethod
    def _flow_ts(f: dict) -> float:
        try:
            return float(f.get("last_seen") or f.get("first_seen") or 0.0)
        except (TypeError, ValueError):
            return 0.0

    def _trim_alert(self, f: dict) -> dict:
        """Compact one flow into an agent-sized event record."""
        nd = f.get("ndpi") or {}
        return {
            "t": round(self._flow_ts(f), 3),
            "src": f.get("src_ip"),
            "dst": f.get("dest_ip"),
            "dport": f.get("dst_port"),
            "proto": nd.get("proto") or f.get("proto"),
            "verdict": f.get("_verdict"),
            "score": f.get("_riskscore", 0),
            "sev": f.get("_severity", 0),
            "risks": f.get("_risknames", [])[:4],
            "bytes": f.get("_bytes", 0),
            "iso": f.get("country_iso"),
            "asn": f.get("asn"),
            "asn_org": f.get("asn_org"),
            "threat_source": f.get("threat_source"),
            "host": f.get("_sni") or nd.get("hostname") or None,
        }

    def agent_status(self, flows: list, retention_days: int = 7,
                     now: float | None = None) -> dict:
        """GET /api/agent/status — one small snapshot of everything that matters."""
        if now is None:
            now = time.time()
        cutoff = now - self.LOOKBACK_SECS

        recent = [f for f in flows if self._flow_ts(f) >= cutoff]
        alerts = [f for f in recent if f.get("_verdict") in ("alert", "suspicious")]
        threats = [f for f in recent if f.get("_verdict") == "threat"]

        # newest first, then highest score as a tiebreak
        alerts.sort(key=lambda f: (self._flow_ts(f), f.get("_riskscore", 0)), reverse=True)
        threats.sort(key=lambda f: self._flow_ts(f), reverse=True)

        summ = self.summary(flows)
        scanners = summ.get("scanners", [])

        # Destinations that look anomalous: scanner sources plus any dest hit by
        # a threat verdict, deduped, newest evidence first.
        anomalous = {}
        for s in scanners:
            anomalous[s["ip"]] = {
                "ip": s["ip"], "why": "port_scanner", "ports": s["ports"],
                "flows": s["flows"], "severity": s["severity"],
            }
        for f in threats[:self.AGENT_MAX_THREATS]:
            ip = f.get("dest_ip")
            if not ip:
                continue
            e = anomalous.setdefault(ip, {"ip": ip, "why": "threat_feed",
                                          "ports": 0, "flows": 0, "severity": "high"})
            e["why"] = "threat_feed"
            e["flows"] += 1
            e["threat_source"] = f.get("threat_source")
        anomalous_list = sorted(anomalous.values(),
                                key=lambda e: (-{"high": 3, "medium": 2, "low": 1}.get(e["severity"], 0),
                                               -e["flows"]))[:self.AGENT_MAX_DESTS]

        status = {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "hot_flow_count": len(flows),
            "retention_days": retention_days,
            "db_size_mb": _dir_size_mb("./ndpi_db"),
            "cold_shard_count": _count_cold_shards(),
            "alerts_last_24h": [self._trim_alert(f) for f in alerts[:self.AGENT_MAX_ALERTS]],
            "alert_count_last_24h": len(alerts),
            "threat_hits_last_24h": [self._trim_alert(f) for f in threats[:self.AGENT_MAX_THREATS]],
            "threat_hit_count": len(threats),
            "top_anomalous_dests": anomalous_list,
            "verdicts": summ.get("verdicts", {}),
            "top_countries": summ.get("top_countries", [])[:10],
            "geo": getattr(self.geo, "status", lambda: {"available": False})(),
            "threat_feed": self.threats.status(),
        }
        return _shrink_to_budget(status, self.AGENT_BUDGET_BYTES)

    def agent_diff(self, flows: list, since: float | None, now: float | None = None,
                   limit: int = 200) -> dict:
        """GET /api/agent/diff?since=<ISO|epoch> — events strictly newer than since.

        Events are alerts, threat hits and newly-seen scanner sources: exactly
        the things worth waking an agent for. A polling agent stores the returned
        `cursor` and passes it back next time, so each fetch costs only the delta.
        """
        if now is None:
            now = time.time()
        bad_since = False
        if since is None:
            cutoff = now - 3600          # no argument → last hour
        elif isinstance(since, (int, float)):
            cutoff = float(since)
        else:
            parsed = parse_iso_maybe(str(since))
            if parsed is None:
                bad_since = True
                cutoff = now - 3600
            else:
                cutoff = parsed

        events = []
        for f in flows:
            ts = self._flow_ts(f)
            if ts <= cutoff:
                continue
            v = f.get("_verdict")
            if v == "threat":
                kind = "threat"
            elif v == "alert":
                kind = "alert"
            elif v == "suspicious":
                kind = "suspicious"
            else:
                continue
            ev = self._trim_alert(f)
            ev["kind"] = kind
            events.append(ev)

        # Scanner detections are per-source aggregates, emitted as their own kind
        # so an agent can dedupe on (kind, ip) instead of re-reading flows.
        summ = self.summary(flows)
        for s in summ.get("scanners", []):
            if s["severity"] == "low":
                continue
            events.append({
                "t": round(now, 3), "kind": "scanner", "ip": s["ip"],
                "ports": s["ports"], "flows": s["flows"], "bytes": s["bytes"],
                "severity": s["severity"], "risks": s["risks"][:4],
            })

        events.sort(key=lambda e: e.get("t", 0), reverse=True)
        out = {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "since": None if cutoff is None else round(cutoff, 3),
            "cursor": round(now, 3),
            "event_count": len(events),
            "events": events[:limit],
            "truncated": len(events) > limit,
        }
        if bad_since:
            out["warning"] = "unparseable 'since' — defaulted to the last hour"
        return _shrink_to_budget(out, self.AGENT_BUDGET_BYTES, drop_key="events")


def parse_iso_maybe(text: str) -> float | None:
    """ISO-8601 (or bare epoch seconds as a string) → unix float, else None.

    Accepts the forms an agent is likely to send: '2026-10-05T12:34:56Z', with an
    explicit offset, or date-only 'YYYY-MM-DD'. Naive timestamps are assumed UTC —
    the dashboard's own clock and every stored timestamp are UTC, so interpreting
    them in the host's local timezone would silently shift the diff window by the
    zone offset (fromisoformat() does exactly that for a naive value).
    """
    text = (text or "").strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    candidate = text[:-1] if text.endswith("Z") else text
    # Date-only has no time part at all; treat it as 00:00 UTC.
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", candidate):
        candidate += "T00:00:00"
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()



def _dir_size_mb(path: str) -> float | None:
    """Total size of a directory in MB, or None when absent. Never raises."""
    try:
        total = 0
        p = Path(path)
        if not p.exists():
            return None
        for root, _dirs, files in os.walk(p):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(root, name))
                except OSError:
                    continue
        return round(total / (1024 * 1024), 2)
    except Exception:
        return None


def _count_cold_shards(cold_dir: str = DEFAULT_COLD_DIR) -> int:
    try:
        p = Path(cold_dir)
        if not p.is_dir():
            return 0
        return sum(1 for f in p.iterdir()
                   if f.is_file() and f.name.startswith("flows-") and f.suffix == ".zst")
    except Exception:
        return 0


def _shrink_to_budget(payload: dict, budget: int, drop_key: str | None = None) -> dict:
    """Guarantee the serialised body fits `budget` bytes.

    The brief says the agent surface must "always" stay under ~32 kB, so this is
    a real invariant, not a nicety. Arrays are trimmed from the tail in a fixed
    order (largest first) until it fits, and `capped` records what was dropped so
    a reader knows it is looking at a partial view.
    """
    def size(d):
        return len(json.dumps(d, separators=(",", ":")).encode("utf-8"))

    if size(payload) <= budget:
        return payload

    capped = {}
    order = ([drop_key] if drop_key else []) + [
        "alerts_last_24h", "threat_hits_last_24h", "top_anomalous_dests",
        "top_countries", "verdicts",
    ]
    for key in order:
        val = payload.get(key)
        if not isinstance(val, list) or not val:
            continue
        capped[key] = len(val)
        while val and size(payload) > budget:
            val.pop()
            payload[key] = val
        if not val:
            payload.pop(key, None)
        if size(payload) <= budget:
            break

    if capped:
        payload["capped"] = capped
    # Last resort: nothing left to trim means the fixed overhead alone exceeds
    # the budget. Report honestly instead of emitting broken JSON.
    payload["_fits_budget"] = size(payload) <= budget
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# Favicon
# ─────────────────────────────────────────────────────────────────────────────

FAVICON_SVG = b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect width="32" height="32" rx="6" fill="#0a0e17"/>
  <circle cx="16" cy="16" r="9" fill="none" stroke="#00d4aa" stroke-width="2"/>
  <circle cx="16" cy="16" r="3" fill="#00d4aa"/>
  <line x1="16" y1="4"  x2="16" y2="10" stroke="#00d4aa" stroke-width="1.5"/>
  <line x1="16" y1="22" x2="16" y2="28" stroke="#00d4aa" stroke-width="1.5"/>
  <line x1="4"  y1="16" x2="10" y2="16" stroke="#00d4aa" stroke-width="1.5"/>
  <line x1="22" y1="16" x2="28" y2="16" stroke="#00d4aa" stroke-width="1.5"/>
</svg>"""

# ─────────────────────────────────────────────────────────────────────────────
# HTML dashboard — tabbed, dark, terminal aesthetic
# ─────────────────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Flow Monitor</title>
<link rel="icon" type="image/svg+xml" href="/favicon.ico">
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600&family=IBM+Plex+Sans:wght@300;400;500&display=swap');

:root {
  --bg:       #080c12;
  --bg2:      #0d1219;
  --bg3:      #121920;
  --bg4:      #1a2230;
  --border:   #1e2d3d;
  --border2:  #243040;
  --text:     #c8d8e8;
  --muted:    #506070;
  --dim:      #304050;
  --teal:     #00d4aa;
  --teal2:    #00a888;
  --blue:     #4da8ff;
  --red:      #ff4560;
  --red2:     #cc2040;
  --orange:   #ff8c42;
  --yellow:   #ffd166;
  --green:    #06d6a0;
  --purple:   #9b72cf;
  --font-mono: 'IBM Plex Mono', 'Courier New', monospace;
  --font-sans: 'IBM Plex Sans', system-ui, sans-serif;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

html, body { height: 100%; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.5;
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

/* ── SCANLINES OVERLAY ─────────────────────────────────────────────────── */
body::before {
  content: '';
  position: fixed; inset: 0;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0,212,170,0.012) 2px,
    rgba(0,212,170,0.012) 4px
  );
  pointer-events: none;
  z-index: 9999;
}

/* ── HEADER ──────────────────────────────────────────────────────────────── */
header {
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  padding: 0 20px;
  display: flex;
  align-items: center;
  gap: 16px;
  height: 44px;
  flex-shrink: 0;
}

.logo {
  font-size: 13px;
  font-weight: 600;
  color: var(--teal);
  letter-spacing: 2px;
  white-space: nowrap;
  display: flex;
  align-items: center;
  gap: 8px;
}

.logo-icon {
  width: 18px; height: 18px;
  border: 1.5px solid var(--teal);
  border-radius: 50%;
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  animation: pulse-ring 3s ease-in-out infinite;
}

.logo-dot {
  width: 5px; height: 5px;
  background: var(--teal);
  border-radius: 50%;
}

@keyframes pulse-ring {
  0%, 100% { box-shadow: 0 0 0 0 rgba(0,212,170,0.4); }
  50%       { box-shadow: 0 0 0 5px rgba(0,212,170,0); }
}

#uptime { font-size: 10px; color: var(--muted); margin-left: auto; font-family: var(--font-mono); }
#status { font-size: 10px; padding: 3px 8px; border-radius: 3px; font-family: var(--font-mono); }
#status.ok  { color: var(--teal); border: 1px solid var(--teal2); }
#status.err { color: var(--red);  border: 1px solid var(--red2); }
#status.loading { color: var(--muted); border: 1px solid var(--border); }

/* ── ALERT BANNER ────────────────────────────────────────────────────────── */
#alert-banner {
  display: none;
  background: linear-gradient(90deg, #1a0a0a, #200d0d);
  border-bottom: 1px solid var(--red2);
  padding: 6px 20px;
  font-size: 11px;
  color: var(--red);
  display: flex;
  align-items: center;
  gap: 10px;
  flex-shrink: 0;
}

#alert-banner.hidden { display: none; }

.alert-pulse {
  width: 7px; height: 7px;
  background: var(--red);
  border-radius: 50%;
  animation: blink 1s ease-in-out infinite;
  flex-shrink: 0;
}

@keyframes blink {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0.2; }
}

/* ── TABS ────────────────────────────────────────────────────────────────── */
.tab-bar {
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: flex-end;
  padding: 0 20px;
  gap: 2px;
  flex-shrink: 0;
}

.tab {
  padding: 8px 16px;
  font-size: 11px;
  font-family: var(--font-mono);
  letter-spacing: 0.5px;
  color: var(--muted);
  cursor: pointer;
  border: 1px solid transparent;
  border-bottom: none;
  border-radius: 4px 4px 0 0;
  transition: color 0.15s, background 0.15s;
  user-select: none;
  white-space: nowrap;
}

.tab:hover { color: var(--text); background: var(--bg3); }

.tab.active {
  color: var(--teal);
  background: var(--bg);
  border-color: var(--border);
  border-bottom-color: var(--bg);
  margin-bottom: -1px;
}

.tab .badge-count {
  display: inline-block;
  background: var(--red2);
  color: #fff;
  font-size: 9px;
  padding: 1px 4px;
  border-radius: 3px;
  margin-left: 5px;
  line-height: 1.4;
}

/* ── TAB PANELS ──────────────────────────────────────────────────────────── */
.tab-panel { display: none; flex: 1; overflow: hidden; }
.tab-panel.active { display: flex; flex-direction: column; flex: 1; }

/* ── OVERVIEW PANEL ──────────────────────────────────────────────────────── */
#panel-overview {
  overflow-y: auto;
  padding: 16px 20px;
  gap: 14px;
}

.overview-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 10px;
  margin-bottom: 14px;
}

.stat-card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 14px;
}

.stat-card .val {
  font-size: 22px;
  font-weight: 600;
  color: var(--teal);
  line-height: 1.2;
  font-variant-numeric: tabular-nums;
}

.stat-card .lbl {
  font-size: 9px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 1px;
  margin-top: 3px;
}

.stat-card.danger .val { color: var(--red); }
.stat-card.warn   .val { color: var(--orange); }
.stat-card.ok     .val { color: var(--green); }
.stat-card.enc    .val { color: var(--purple); }
.stat-card.blue   .val { color: var(--blue); }

/* verdict bar */
.verdict-bar {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 14px;
  margin-bottom: 14px;
}

.verdict-bar h3 { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; }

.vbar-track {
  height: 8px;
  border-radius: 4px;
  overflow: hidden;
  display: flex;
  background: var(--bg4);
  margin-bottom: 8px;
}

.vbar-seg {
  height: 100%;
  transition: width 0.4s ease;
}

.vbar-seg.threat     { background: #ff2038; }
.vbar-seg.alert      { background: var(--red); }
.vbar-seg.suspicious { background: var(--orange); }
.vbar-seg.noise      { background: var(--dim); }
.vbar-seg.safe       { background: var(--teal2); }

.vbar-legend {
  display: flex; gap: 14px; flex-wrap: wrap;
}

.vleg-item { display: flex; align-items: center; gap: 5px; font-size: 10px; color: var(--muted); }
.vleg-dot  { width: 8px; height: 8px; border-radius: 2px; flex-shrink: 0; }
.vleg-dot.threat     { background: #ff2038; }
.vleg-dot.alert      { background: var(--red); }
.vleg-dot.suspicious { background: var(--orange); }
.vleg-dot.noise      { background: var(--dim); }
.vleg-dot.safe       { background: var(--teal2); }

/* two-col layout for overview sub-sections */
.overview-cols {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
  margin-bottom: 14px;
}

@media (max-width: 780px) { .overview-cols { grid-template-columns: 1fr; } }

.section-box {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
}

.section-box h3 {
  font-size: 10px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 1px;
  padding: 10px 14px 8px;
  border-bottom: 1px solid var(--border);
  background: var(--bg3);
}

.mini-list { padding: 4px 0; }

.mini-row {
  display: flex;
  align-items: center;
  padding: 5px 14px;
  gap: 8px;
  font-size: 11px;
  border-bottom: 1px solid #0d1420;
}

.mini-row:last-child { border-bottom: none; }
.mini-row:hover { background: var(--bg3); }

.mini-ip  { color: var(--text); flex: 1; font-family: var(--font-mono); }
.mini-val { color: var(--muted); text-align: right; white-space: nowrap; }
.mini-bar-wrap { flex: 1; height: 3px; background: var(--bg4); border-radius: 2px; overflow: hidden; max-width: 80px; }
.mini-bar      { height: 100%; border-radius: 2px; background: var(--teal2); transition: width 0.3s; }
.mini-bar.alert { background: var(--red); }

/* recent alerts list in overview */
.alert-list { padding: 0; }

.alert-row {
  padding: 8px 14px;
  border-bottom: 1px solid #0d1420;
  cursor: pointer;
  transition: background 0.1s;
}

.alert-row:last-child { border-bottom: none; }
.alert-row:hover { background: var(--bg3); }

.alert-row-top {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 2px;
}

.verdict-tag {
  display: inline-block;
  font-size: 9px;
  padding: 1px 5px;
  border-radius: 3px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  font-weight: 600;
  flex-shrink: 0;
}

.verdict-tag.alert      { background: rgba(255,69,96,0.2); color: var(--red); border: 1px solid var(--red2); }
.verdict-tag.suspicious { background: rgba(255,140,66,0.15); color: var(--orange); border: 1px solid #804020; }
/* 'threat' = dest_ip matched a threat feed. Louder than 'alert' on purpose: it is
   an external IOC match, not just a high nDPI risk score. */
.verdict-tag.threat     { background: rgba(255,69,96,0.35); color: #fff; border: 1px solid var(--red);
                          box-shadow: 0 0 6px rgba(255,69,96,0.6); }
.verdict-tag.noise      { background: rgba(120,130,150,0.15); color: var(--muted); border: 1px solid var(--border); }
.verdict-tag.safe       { background: rgba(0,212,170,0.12); color: var(--green, #00d4aa); border: 1px solid #1a4a40; }

.alert-flow-str { font-size: 11px; color: var(--text); font-family: var(--font-mono); }
.alert-reason   { font-size: 10px; color: var(--muted); }
.alert-risk     { font-size: 10px; color: var(--orange); margin-left: auto; text-align: right; max-width: 200px; }

/* ── SPARKLINE TIMELINE ──────────────────────────────────────────────────── */
.timeline-box {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 14px;
  margin-bottom: 14px;
}

.timeline-box h3 { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; }

.sparkline-wrap {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 10px;
}

@media (max-width: 600px) { .sparkline-wrap { grid-template-columns: 1fr; } }

.spark-item { }
.spark-label { font-size: 10px; color: var(--muted); margin-bottom: 4px; }
.spark-canvas { width: 100%; height: 36px; display: block; }

/* ── FLOWS TABLE (shared) ─────────────────────────────────────────────────── */
.table-toolbar {
  padding: 8px 16px;
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}

.filter-input {
  background: var(--bg3);
  border: 1px solid var(--border2);
  color: var(--text);
  padding: 5px 10px;
  border-radius: 4px;
  font-family: var(--font-mono);
  font-size: 11px;
  width: 240px;
}

.filter-input::placeholder { color: var(--muted); }
.filter-input:focus { outline: none; border-color: var(--teal2); }

.sel {
  background: var(--bg3);
  border: 1px solid var(--border2);
  color: var(--text);
  padding: 5px 8px;
  border-radius: 4px;
  font-family: var(--font-mono);
  font-size: 11px;
  cursor: pointer;
}

.chk-label {
  font-size: 11px;
  color: var(--muted);
  display: flex;
  align-items: center;
  gap: 4px;
  cursor: pointer;
  white-space: nowrap;
}

.row-count { font-size: 10px; color: var(--muted); margin-left: auto; }

.table-wrap {
  overflow: auto;
  flex: 1;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 11px;
}

thead { position: sticky; top: 0; z-index: 5; }

th {
  background: var(--bg3);
  border-bottom: 1px solid var(--border2);
  padding: 6px 10px;
  text-align: left;
  white-space: nowrap;
  cursor: pointer;
  user-select: none;
  color: var(--muted);
  font-weight: 400;
  font-size: 10px;
  letter-spacing: 0.3px;
  text-transform: uppercase;
  font-family: var(--font-mono);
}

th:hover { color: var(--text); }
th.asc::after  { content: " ▲"; color: var(--teal); }
th.desc::after { content: " ▼"; color: var(--teal); }

td {
  padding: 4px 10px;
  border-bottom: 1px solid #0d1420;
  white-space: nowrap;
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  font-family: var(--font-mono);
}

tr:hover td { background: var(--bg2); }

tr.v-threat       { background: rgba(255,32,56,0.09); }
tr.v-threat      td:first-child { border-left: 2px solid #ff2038; }
tr.v-alert      { background: rgba(255,69,96,0.04); }
tr.v-alert      td:first-child { border-left: 2px solid var(--red); }
tr.v-suspicious td:first-child { border-left: 2px solid var(--orange); }

/* cell colours */
.c-ip     { color: var(--text); }
.c-port   { color: var(--muted); text-align: right; }
.c-proto  { color: var(--yellow); font-size: 10px; }
.c-l7     { color: var(--blue); }
.c-cat    { color: var(--muted); }
.c-bytes  { color: #9ab0c8; text-align: right; }
.c-pkts   { color: var(--muted); text-align: right; }
.c-score  { color: var(--red); text-align: right; }
.c-risk   { color: var(--orange); max-width: 200px; white-space: normal; line-height: 1.3; }
.c-enc    { text-align: center; }
.c-geo    { font-size: 10px; color: var(--muted); white-space: nowrap; }
.c-reason { color: var(--muted); font-size: 10px; }

.vtag { display: inline-block; font-size: 9px; padding: 1px 4px; border-radius: 2px; font-weight: 600; letter-spacing: 0.3px; }
.vtag.threat     { background: #ff2038; color: #fff; }
.vtag.alert      { background: rgba(255,69,96,0.2); color: var(--red); }
.vtag.suspicious { background: rgba(255,140,66,0.15); color: var(--orange); }
.vtag.noise      { color: var(--dim); }
.vtag.safe       { color: var(--teal2); }

.badge {
  display: inline-block;
  padding: 1px 4px;
  border-radius: 3px;
  font-size: 10px;
  border: 1px solid var(--border2);
  color: var(--muted);
}

.badge.tcp  { border-color: #1f4f8f; color: #5590d0; }
.badge.udp  { border-color: #1f5030; color: #40a060; }
.badge.icmp { border-color: #3d3020; color: #807040; }

.no-data { text-align: center; padding: 60px; color: var(--muted); }

/* ── SCANNERS PANEL ──────────────────────────────────────────────────────── */
#panel-scanners { overflow-y: auto; padding: 16px 20px; gap: 14px; }

.scanner-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 10px;
}

.scanner-card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 14px;
  cursor: pointer;
  transition: border-color 0.15s;
}

.scanner-card:hover { border-color: var(--border2); }
.scanner-card.sev-high   { border-left: 3px solid var(--red); }
.scanner-card.sev-medium { border-left: 3px solid var(--orange); }
.scanner-card.sev-low    { border-left: 3px solid var(--dim); }

.scanner-ip { font-size: 14px; color: var(--text); margin-bottom: 6px; }
.scanner-meta { display: flex; gap: 14px; flex-wrap: wrap; }
.scanner-stat { font-size: 10px; }
.scanner-stat .n { color: var(--teal); font-size: 13px; font-weight: 600; display: block; }
.scanner-stat .l { color: var(--muted); }
.scanner-risks { margin-top: 6px; font-size: 10px; color: var(--orange); }

/* ── PROTO PANEL ─────────────────────────────────────────────────────────── */
#panel-proto { overflow-y: auto; padding: 16px 20px; gap: 14px; }

.proto-cols {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}

@media (max-width: 700px) { .proto-cols { grid-template-columns: 1fr; } }

.bar-list { padding: 8px 0; }

.bar-row {
  padding: 5px 14px;
  display: grid;
  grid-template-columns: 110px 1fr 70px;
  align-items: center;
  gap: 10px;
  border-bottom: 1px solid #0d1420;
  font-size: 11px;
}

.bar-row:last-child { border-bottom: none; }
.bar-label { color: var(--text); overflow: hidden; text-overflow: ellipsis; }
.bar-track { height: 4px; background: var(--bg4); border-radius: 2px; overflow: hidden; }
.bar-fill  { height: 100%; border-radius: 2px; background: var(--teal2); }
.bar-fill.cat { background: var(--blue); }
.bar-val   { text-align: right; color: var(--muted); }

/* ── DRILL-DOWN MODAL ────────────────────────────────────────────────────── */
#modal-overlay {
  display: none;
  position: fixed; inset: 0;
  background: rgba(8,12,18,0.85);
  z-index: 1000;
  align-items: center;
  justify-content: center;
  backdrop-filter: blur(3px);
}

#modal-overlay.open { display: flex; }

#modal {
  background: var(--bg2);
  border: 1px solid var(--border2);
  border-radius: 8px;
  width: 620px;
  max-width: 96vw;
  max-height: 86vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0,0,0,0.7);
}

.modal-header {
  padding: 14px 18px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 10px;
}

.modal-title { font-size: 13px; color: var(--teal); flex: 1; }
.modal-close { cursor: pointer; color: var(--muted); font-size: 16px; }
.modal-close:hover { color: var(--text); }

.modal-body { padding: 16px 18px; }

.kv-grid {
  display: grid;
  grid-template-columns: 140px 1fr;
  gap: 6px 12px;
  font-size: 11px;
}

.kv-key { color: var(--muted); }
.kv-val { color: var(--text); word-break: break-all; }
.kv-val.danger { color: var(--red); }
.kv-val.warn   { color: var(--orange); }
.kv-val.good   { color: var(--green); }

.modal-section-title {
  font-size: 9px;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--muted);
  margin: 12px 0 6px;
  padding-bottom: 4px;
  border-bottom: 1px solid var(--border);
}

/* scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg2); }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--dim); }
</style>
</head>
<body>

<!-- HEADER -->
<header>
  <div class="logo">
    <div class="logo-icon"><div class="logo-dot"></div></div>
    FLOW MONITOR
  </div>
  <span id="status" class="loading">connecting…</span>
  <span id="uptime"></span>
</header>

<!-- ALERT BANNER -->
<div id="alert-banner" class="hidden">
  <div class="alert-pulse"></div>
  <span id="alert-banner-text"></span>
</div>

<!-- TAB BAR -->
<div class="tab-bar">
  <div class="tab active" data-tab="overview">Overview</div>
  <div class="tab" data-tab="alerts">Alerts <span id="tab-alert-count" class="badge-count" style="display:none"></span></div>
  <div class="tab" data-tab="flows">All Flows</div>
  <div class="tab" data-tab="scanners">Scanners</div>
  <div class="tab" data-tab="proto">Protocols</div>
</div>

<!-- OVERVIEW PANEL -->
<div class="tab-panel active" id="panel-overview">
  <div class="overview-grid" id="stat-cards">
    <div class="stat-card danger">  <div class="val" id="s-alert">—</div><div class="lbl">Alerts</div></div>
    <div class="stat-card warn">    <div class="val" id="s-susp">—</div><div class="lbl">Suspicious</div></div>
    <div class="stat-card">         <div class="val" id="s-total">—</div><div class="lbl">Total Flows</div></div>
    <div class="stat-card blue">    <div class="val" id="s-bytes">—</div><div class="lbl">Total Traffic</div></div>
    <div class="stat-card enc">     <div class="val" id="s-enc">—</div><div class="lbl">Encrypted</div></div>
    <div class="stat-card ok">      <div class="val" id="s-safe">—</div><div class="lbl">Safe</div></div>
  </div>

  <div class="verdict-bar" style="padding:12px 14px; margin: 0 0 14px;">
    <h3>Traffic verdict distribution</h3>
    <div class="vbar-track" id="vbar-track">
      <div class="vbar-seg threat"     id="vbar-threat"     style="width:0%"></div>
      <div class="vbar-seg alert"      id="vbar-alert"      style="width:0%"></div>
      <div class="vbar-seg suspicious" id="vbar-suspicious" style="width:0%"></div>
      <div class="vbar-seg noise"      id="vbar-noise"      style="width:0%"></div>
      <div class="vbar-seg safe"       id="vbar-safe"       style="width:0%"></div>
    </div>
    <div class="vbar-legend">
      <div class="vleg-item"><div class="vleg-dot threat"></div> <span id="vleg-threat">Threat</span></div>
      <div class="vleg-item"><div class="vleg-dot alert"></div> <span id="vleg-alert">Alert</span></div>
      <div class="vleg-item"><div class="vleg-dot suspicious"></div> <span id="vleg-susp">Suspicious</span></div>
      <div class="vleg-item"><div class="vleg-dot noise"></div> <span id="vleg-noise">Noise</span></div>
      <div class="vleg-item"><div class="vleg-dot safe"></div> <span id="vleg-safe">Safe</span></div>
    </div>
  </div>

  <div class="timeline-box">
    <h3>Traffic timeline</h3>
    <div class="sparkline-wrap">
      <div class="spark-item">
        <div class="spark-label">Bytes / min</div>
        <canvas class="spark-canvas" id="spark-bytes"></canvas>
      </div>
      <div class="spark-item">
        <div class="spark-label">Flows / min</div>
        <canvas class="spark-canvas" id="spark-flows"></canvas>
      </div>
      <div class="spark-item">
        <div class="spark-label">Alerts / min</div>
        <canvas class="spark-canvas" id="spark-alerts"></canvas>
      </div>
    </div>
  </div>

  <div class="overview-cols">
    <div class="section-box">
      <h3>Recent Alerts</h3>
      <div class="alert-list" id="ov-alert-list"><div class="no-data">No alerts</div></div>
    </div>
    <div class="section-box">
      <h3>Top Talkers (bytes)</h3>
      <div class="mini-list" id="ov-talkers"></div>
    </div>
  </div>

  <div class="overview-cols">
    <div class="section-box">
      <h3>Top Scanners (ports probed)</h3>
      <div class="mini-list" id="ov-scanners"></div>
    </div>
    <div class="section-box">
      <h3>Top Alert Sources</h3>
      <div class="mini-list" id="ov-alerters"></div>
    </div>
  </div>
</div>

<!-- ALERTS PANEL -->
<div class="tab-panel" id="panel-alerts">
  <div class="table-toolbar">
    <input class="filter-input" id="alert-filter" placeholder="Filter IP, risk, reason…" oninput="renderAlerts()">
    <span class="row-count" id="alert-count-lbl"></span>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr id="alert-hdr">
        <th data-k="_verdict">Verdict</th>
        <th data-k="src_ip">Source IP</th>
        <th data-k="src_port" style="text-align:right">Sport</th>
        <th>→</th>
        <th data-k="dest_ip">Dest IP</th>
        <th data-k="dst_port" style="text-align:right">Dport</th>
        <th data-k="ndpi.proto">L7</th>
        <th data-k="_riskscore" style="text-align:right">Score</th>
        <th data-k="_risktext">Risk Flags</th>
        <th data-k="_reason">Reason</th>
      </tr></thead>
      <tbody id="alert-tbody"></tbody>
    </table>
  </div>
</div>

<!-- ALL FLOWS PANEL -->
<div class="tab-panel" id="panel-flows">
  <div class="table-toolbar">
    <input class="filter-input" id="flow-filter" placeholder="Filter IP, port, protocol…" oninput="renderFlows()">
    <select class="sel" id="sel-verdict" onchange="renderFlows()">
      <option value="">All verdicts</option>
      <option value="threat">Threat</option>
      <option value="alert">Alert</option>
      <option value="suspicious">Suspicious</option>
      <option value="noise">Noise</option>
      <option value="safe">Safe</option>
    </select>
    <select class="sel" id="sel-cat"  onchange="renderFlows()"><option value="">All categories</option></select>
    <select class="sel" id="sel-l7"   onchange="renderFlows()"><option value="">All L7 protos</option></select>
    <label class="chk-label"><input type="checkbox" id="chk-enc" onchange="renderFlows()"> Encrypted</label>
    <span class="row-count" id="flow-count-lbl"></span>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr id="flow-hdr">
        <th data-k="_verdict">Verdict</th>
        <th data-k="proto">L4</th>
        <th data-k="src_ip">Source IP</th>
        <th data-k="src_port" style="text-align:right">Sport</th>
        <th>→</th>
        <th data-k="dest_ip">Dest IP</th>
        <th data-k="dst_port" style="text-align:right">Dport</th>
        <th data-k="ndpi.proto">L7</th>
        <th data-k="ndpi.category">Category</th>
        <th data-k="dest_geo">Geo / ASN</th>
        <th data-k="ndpi.encrypted" style="text-align:center">Enc</th>
        <th data-k="_bytes" style="text-align:right">Bytes</th>
        <th data-k="_pkts"  style="text-align:right">Pkts</th>
        <th data-k="_riskscore" style="text-align:right">Score</th>
        <th data-k="_risktext">Risk Flags</th>
      </tr></thead>
      <tbody id="flow-tbody"></tbody>
    </table>
  </div>
</div>

<!-- SCANNERS PANEL -->
<div class="tab-panel" id="panel-scanners">
  <div style="padding:16px 20px">
    <div style="font-size:11px;color:var(--muted);margin-bottom:12px;">
      IPs that probed ≥5 different destination ports with small/no data exchange.
      These are likely scanners or probes — expected noise on public IPs.
    </div>
    <div class="scanner-grid" id="scanner-grid"></div>
  </div>
</div>

<!-- PROTOCOLS PANEL -->
<div class="tab-panel" id="panel-proto">
  <div style="padding:16px 20px">
    <div class="proto-cols">
      <div class="section-box">
        <h3>L7 Application Protocol (by bytes)</h3>
        <div class="bar-list" id="proto-bars"></div>
      </div>
      <div class="section-box">
        <h3>Traffic Category (by count)</h3>
        <div class="bar-list" id="cat-bars"></div>
      </div>
    </div>
  </div>
</div>

<!-- DRILL-DOWN MODAL -->
<div id="modal-overlay" onclick="closeModal(event)">
  <div id="modal">
    <div class="modal-header">
      <div class="modal-title" id="modal-title">Flow Details</div>
      <div class="modal-close" onclick="closeModalDirect()">✕</div>
    </div>
    <div class="modal-body" id="modal-body"></div>
  </div>
</div>

<script>
"use strict";

// ── State ─────────────────────────────────────────────────────────────────────
let flows     = [];
let summary   = {};
let timeline  = [];
let startTime = Date.now();

let flowSort  = { key: '_riskscore', dir: -1 };
let alertSort = { key: '_riskscore', dir: -1 };

// ── Tab switching ─────────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('panel-' + tab.dataset.tab).classList.add('active');
  });
});

// ── Data fetching ─────────────────────────────────────────────────────────────
async function fetchAll() {
  const st = document.getElementById('status');
  try {
    const [flowsRes, summaryRes, timelineRes] = await Promise.all([
      fetch('/api/flows'),
      fetch('/api/summary'),
      fetch('/api/timeline'),
    ]);

    if (!flowsRes.ok || !summaryRes.ok) throw new Error('HTTP error');

    flows    = await flowsRes.json();
    summary  = await summaryRes.json();
    timeline = await timelineRes.json();

    updateOverview();
    renderAlerts();
    renderFlows();
    renderScanners();
    renderProto();
    populateDropdowns();
    updateAlertBanner();

    const now = new Date().toLocaleTimeString();
    st.textContent = `↻ ${now}  ·  ${flows.length} flows`;
    st.className = 'ok';
  } catch(e) {
    st.textContent = `✗ ${e.message}`;
    st.className = 'err';
  }

  // Uptime
  const secs = Math.floor((Date.now() - startTime) / 1000);
  document.getElementById('uptime').textContent =
    `up ${Math.floor(secs/3600)}h ${Math.floor((secs%3600)/60)}m`;
}

// ── Alert banner ──────────────────────────────────────────────────────────────
function updateAlertBanner() {
  const banner = document.getElementById('alert-banner');
  const n = summary.verdicts?.alert || 0;
  const badge = document.getElementById('tab-alert-count');

  if (n > 0) {
    document.getElementById('alert-banner-text').textContent =
      `${n} alert${n>1?'s':''} require attention — click the Alerts tab for details`;
    banner.classList.remove('hidden');
    badge.textContent = n;
    badge.style.display = 'inline';
  } else {
    banner.classList.add('hidden');
    badge.style.display = 'none';
  }
}

// ── Overview ──────────────────────────────────────────────────────────────────
function updateOverview() {
  const v = summary.verdicts || {};
  const total = summary.total_flows || 0;

  document.getElementById('s-alert').textContent = v.alert || 0;
  document.getElementById('s-susp' ).textContent = v.suspicious || 0;
  document.getElementById('s-total').textContent = total;
  document.getElementById('s-bytes').textContent = fmtBytes(summary.total_bytes || 0);
  document.getElementById('s-enc'  ).textContent = `${summary.enc_count||0} (${summary.enc_pct||0}%)`;
  document.getElementById('s-safe' ).textContent = v.safe || 0;

  // Verdict bar
  if (total > 0) {
    const pct = k => Math.round((v[k]||0)*100/total);
    document.getElementById('vbar-threat').style.width      = pct('threat')+'%';
    document.getElementById('vbar-alert').style.width      = pct('alert')+'%';
    document.getElementById('vbar-suspicious').style.width = pct('suspicious')+'%';
    document.getElementById('vbar-noise').style.width      = pct('noise')+'%';
    document.getElementById('vbar-safe').style.width       = pct('safe')+'%';
    document.getElementById('vleg-threat').textContent = `Threat (${pct('threat')}%)`;
    document.getElementById('vleg-alert').textContent = `Alert (${pct('alert')}%)`;
    document.getElementById('vleg-susp' ).textContent = `Suspicious (${pct('suspicious')}%)`;
    document.getElementById('vleg-noise').textContent = `Noise (${pct('noise')}%)`;
    document.getElementById('vleg-safe' ).textContent = `Safe (${pct('safe')}%)`;
  }

  // Timeline sparklines
  drawSparkline('spark-bytes',  timeline.map(t => t.bytes),  '#00d4aa');
  drawSparkline('spark-flows',  timeline.map(t => t.flows),  '#4da8ff');
  drawSparkline('spark-alerts', timeline.map(t => t.alerts), '#ff4560');

  // Recent alerts
  const alertList = document.getElementById('ov-alert-list');
  const alertFlows = (summary.alert_flows || []).slice(0, 8);
  if (!alertFlows.length) {
    alertList.innerHTML = '<div class="no-data" style="padding:20px">No alerts</div>';
  } else {
    alertList.innerHTML = alertFlows.map(f => {
      const nd = f.ndpi || {};
      const flow_str = `${f.src_ip||'?'}:${f.src_port||'?'} → ${f.dest_ip||'?'}:${f.dst_port||'?'}`;
      // Geo/ASN and threat source are optional — absent when GeoLite2 or the
      // feed is unavailable, so build the suffix only from what exists.
      const geoBits = [f.dest_geo, f.asn ? 'AS'+f.asn : null, f.asn_org]
                        .filter(Boolean).join(' · ');
      const bits = [];
      if (f.threat_source) bits.push(`feed match: ${f.threat_source}`);
      if (geoBits)         bits.push(geoBits);
      const suffix = bits.length ? ' · ' + esc(bits.join(' · ')) : '';
      return `<div class="alert-row" onclick="showModal(${JSON.stringify(JSON.stringify(f)).slice(1,-1)})">
        <div class="alert-row-top">
          <span class="verdict-tag ${f._verdict}">${f._verdict}</span>
          <span class="alert-flow-str">${esc(flow_str)}</span>
          <span class="alert-risk">${esc(f._risktext||'')}</span>
        </div>
        <div class="alert-reason">${esc(f._reason||'')} · ${esc(nd.proto||f.proto||'')} ${esc(nd.category||'')}${suffix}</div>
      </div>`;
    }).join('');
  }

  // Top talkers
  const talkers = summary.top_talkers || [];
  const maxTalker = talkers[0]?.bytes || 1;
  document.getElementById('ov-talkers').innerHTML = talkers.slice(0,8).map(t =>
    `<div class="mini-row">
      <span class="mini-ip">${esc(t.ip)}</span>
      <div class="mini-bar-wrap"><div class="mini-bar" style="width:${Math.round(t.bytes*100/maxTalker)}%"></div></div>
      <span class="mini-val">${fmtBytes(t.bytes)}</span>
    </div>`
  ).join('') || '<div class="no-data" style="padding:20px">No data</div>';

  // Top scanners
  const scanners = summary.scanners || [];
  document.getElementById('ov-scanners').innerHTML = scanners.slice(0,8).map(s =>
    `<div class="mini-row">
      <span class="mini-ip">${esc(s.ip)}</span>
      <span class="mini-val" style="color:${s.severity==='high'?'var(--red)':s.severity==='medium'?'var(--orange)':'var(--muted)'}">${s.ports} ports</span>
    </div>`
  ).join('') || '<div class="no-data" style="padding:20px">No scanners detected</div>';

  // Top alerters
  const alerters = summary.top_alerters || [];
  const maxAlerts = alerters[0]?.alerts || 1;
  document.getElementById('ov-alerters').innerHTML = alerters.slice(0,8).map(a =>
    `<div class="mini-row">
      <span class="mini-ip">${esc(a.ip)}</span>
      <div class="mini-bar-wrap"><div class="mini-bar alert" style="width:${Math.round(a.alerts*100/maxAlerts)}%"></div></div>
      <span class="mini-val" style="color:var(--red)">${a.alerts}</span>
    </div>`
  ).join('') || '<div class="no-data" style="padding:20px">No alerts</div>';
}

// ── Sparkline ─────────────────────────────────────────────────────────────────
function drawSparkline(canvasId, data, color) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !data.length) return;
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.offsetWidth  || 200;
  const h = canvas.offsetHeight || 36;
  canvas.width  = w * dpr;
  canvas.height = h * dpr;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);

  const max = Math.max(...data, 1);
  const step = w / Math.max(data.length - 1, 1);

  // Fill
  ctx.beginPath();
  ctx.moveTo(0, h);
  data.forEach((v, i) => {
    const x = i * step;
    const y = h - (v / max) * (h - 4) - 2;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.lineTo((data.length-1)*step, h);
  ctx.closePath();
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, color + '66');
  grad.addColorStop(1, color + '00');
  ctx.fillStyle = grad;
  ctx.fill();

  // Line
  ctx.beginPath();
  data.forEach((v, i) => {
    const x = i * step;
    const y = h - (v / max) * (h - 4) - 2;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.5;
  ctx.stroke();
}

// ── Alerts table ──────────────────────────────────────────────────────────────
function renderAlerts() {
  const q = (document.getElementById('alert-filter')?.value || '').toLowerCase();
  let rows = flows.filter(f => f._verdict === 'alert' || f._verdict === 'suspicious');

  if (q) rows = rows.filter(f => matchQ(f, q));

  rows.sort(makeSorter(alertSort));
  document.getElementById('alert-count-lbl').textContent =
    `${rows.length} alert${rows.length !== 1 ? 's' : ''}`;

  document.getElementById('alert-tbody').innerHTML = rows.length
    ? rows.map(f => alertRow(f)).join('')
    : '<tr><td colspan="10" class="no-data">No alerts match.</td></tr>';
}

function alertRow(f) {
  const nd = f.ndpi || {};
  const cls = `v-${f._verdict}`;
  return `<tr class="${cls}" onclick="showModal('${encodeFlow(f)}')" style="cursor:pointer">
    <td><span class="vtag ${f._verdict}">${f._verdict}</span></td>
    <td class="c-ip">${esc(f.src_ip||'')}</td>
    <td class="c-port">${f.src_port||'—'}</td>
    <td style="color:var(--dim)">→</td>
    <td class="c-ip">${esc(f.dest_ip||'')}</td>
    <td class="c-port">${f.dst_port||'—'}</td>
    <td class="c-l7">${esc(nd.proto||f.proto||'')}</td>
    <td class="c-score">${f._riskscore > 0 ? f._riskscore : ''}</td>
    <td class="c-risk">${esc(f._risktext||'')}</td>
    <td class="c-reason">${esc(f._reason||'')}</td>
  </tr>`;
}

// Sortable alert header
document.getElementById('alert-hdr').addEventListener('click', e => {
  const th = e.target.closest('th[data-k]');
  if (!th) return;
  if (alertSort.key === th.dataset.k) alertSort.dir *= -1;
  else { alertSort.key = th.dataset.k; alertSort.dir = -1; }
  document.querySelectorAll('#alert-hdr th').forEach(t => t.className = '');
  th.className = alertSort.dir === -1 ? 'desc' : 'asc';
  renderAlerts();
});

// ── Flows table ───────────────────────────────────────────────────────────────
function renderFlows() {
  const q      = (document.getElementById('flow-filter')?.value || '').toLowerCase();
  const verd   = document.getElementById('sel-verdict')?.value || '';
  const cat    = document.getElementById('sel-cat')?.value || '';
  const l7     = document.getElementById('sel-l7')?.value || '';
  const onlyEnc = document.getElementById('chk-enc')?.checked;

  let rows = flows.filter(f => {
    if (verd     && f._verdict     !== verd)        return false;
    if (cat      && f.ndpi?.category !== cat)       return false;
    if (l7       && f.ndpi?.proto   !== l7)         return false;
    if (onlyEnc  && !f.ndpi?.encrypted)             return false;
    if (q        && !matchQ(f, q))                  return false;
    return true;
  });

  rows.sort(makeSorter(flowSort));
  document.getElementById('flow-count-lbl').textContent =
    `${rows.length} / ${flows.length} flows`;

  document.getElementById('flow-tbody').innerHTML = rows.length
    ? rows.map(f => flowRow(f)).join('')
    : '<tr><td colspan="15" class="no-data">No flows match.</td></tr>';
}

function flowRow(f) {
  const nd = f.ndpi || {};
  const cls = (f._verdict === 'alert' || f._verdict === 'suspicious' || f._verdict === 'threat')
    ? `v-${f._verdict}` : '';
  const proto = f.proto || '';
  // Geo column degrades to blank when GeoLite2 is absent — never "null".
  const geoBits = [];
  if (f.country_iso) geoBits.push(f.country_iso);
  if (f.asn)         geoBits.push('AS' + f.asn);
  const geoCell = geoBits.join(' ') || '<span style="color:var(--dim)">—</span>';
  return `<tr class="${cls}" onclick="showModal('${encodeFlow(f)}')" style="cursor:pointer">
    <td><span class="vtag ${f._verdict}">${f._verdict}</span></td>
    <td><span class="badge ${proto.toLowerCase()}">${esc(proto)}</span></td>
    <td class="c-ip">${esc(f.src_ip||'')}</td>
    <td class="c-port">${f.src_port||'—'}</td>
    <td style="color:var(--dim)">→</td>
    <td class="c-ip">${esc(f.dest_ip||'')}</td>
    <td class="c-port">${f.dst_port||'—'}</td>
    <td class="c-l7">${esc(nd.proto||'')}</td>
    <td class="c-cat">${esc(nd.category||'')}</td>
    <td class="c-geo" title="${esc(f.asn_org||f.dest_geo||'')}">${geoCell}</td>
    <td class="c-enc">${nd.encrypted ? '🔒' : ''}</td>
    <td class="c-bytes">${fmtBytes(f._bytes)}</td>
    <td class="c-pkts">${f._pkts||'—'}</td>
    <td class="c-score">${f._riskscore > 0 ? f._riskscore : ''}</td>
    <td class="c-risk">${esc(f._risktext||'')}</td>
  </tr>`;
}

document.getElementById('flow-hdr').addEventListener('click', e => {
  const th = e.target.closest('th[data-k]');
  if (!th) return;
  if (flowSort.key === th.dataset.k) flowSort.dir *= -1;
  else { flowSort.key = th.dataset.k; flowSort.dir = -1; }
  document.querySelectorAll('#flow-hdr th').forEach(t => t.className = '');
  th.className = flowSort.dir === -1 ? 'desc' : 'asc';
  renderFlows();
});

// ── Scanners panel ────────────────────────────────────────────────────────────
function renderScanners() {
  const scanners = summary.scanners || [];
  const grid = document.getElementById('scanner-grid');
  if (!scanners.length) {
    grid.innerHTML = '<div class="no-data" style="padding:40px">No scanners detected (≥5 ports)</div>';
    return;
  }
  grid.innerHTML = scanners.map(s =>
    `<div class="scanner-card sev-${s.severity}" onclick="filterByIP('${esc(s.ip)}')">
      <div class="scanner-ip">${esc(s.ip)}</div>
      <div class="scanner-meta">
        <div class="scanner-stat"><span class="n">${s.ports}</span><span class="l">ports probed</span></div>
        <div class="scanner-stat"><span class="n">${s.flows}</span><span class="l">flows</span></div>
        <div class="scanner-stat"><span class="n">${fmtBytes(s.bytes)}</span><span class="l">bytes</span></div>
      </div>
      ${s.risks.length ? `<div class="scanner-risks">${esc(s.risks.join(' · '))}</div>` : ''}
    </div>`
  ).join('');
}

function filterByIP(ip) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelector('[data-tab="flows"]').classList.add('active');
  document.getElementById('panel-flows').classList.add('active');
  document.getElementById('flow-filter').value = ip;
  renderFlows();
}

// ── Protocols panel ───────────────────────────────────────────────────────────
function renderProto() {
  const protos = summary.top_proto || [];
  const cats   = summary.top_category || [];

  const maxP = protos[0]?.[1] || 1;
  document.getElementById('proto-bars').innerHTML = protos.slice(0, 15).map(([name, bytes]) =>
    `<div class="bar-row">
      <span class="bar-label">${esc(name)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.round(bytes*100/maxP)}%"></div></div>
      <span class="bar-val">${fmtBytes(bytes)}</span>
    </div>`
  ).join('') || '<div class="no-data">No data</div>';

  const maxC = cats[0]?.[1] || 1;
  document.getElementById('cat-bars').innerHTML = cats.slice(0, 15).map(([name, count]) =>
    `<div class="bar-row">
      <span class="bar-label">${esc(name)}</span>
      <div class="bar-track"><div class="bar-fill cat" style="width:${Math.round(count*100/maxC)}%"></div></div>
      <span class="bar-val">${count}</span>
    </div>`
  ).join('') || '<div class="no-data">No data</div>';
}

// ── Dropdowns ─────────────────────────────────────────────────────────────────
function populateDropdowns() {
  const cats = [...new Set(flows.map(f => f.ndpi?.category).filter(Boolean))].sort();
  const l7s  = [...new Set(flows.map(f => f.ndpi?.proto).filter(Boolean))].sort();
  repop('sel-cat', cats, 'All categories');
  repop('sel-l7',  l7s,  'All L7 protos');
}

function repop(id, vals, placeholder) {
  const sel = document.getElementById(id);
  const cur = sel.value;
  sel.innerHTML = `<option value="">${placeholder}</option>` +
    vals.map(v => `<option${v===cur?' selected':''}>${esc(v)}</option>`).join('');
}

// ── Modal ─────────────────────────────────────────────────────────────────────
let _modalFlow = null;

function encodeFlow(f) {
  // Store in a global map to avoid escaping issues in onclick
  const id = 'm' + Math.random().toString(36).slice(2);
  window._modalCache = window._modalCache || {};
  window._modalCache[id] = f;
  return id;
}

function showModal(idOrJson) {
  let f = (window._modalCache || {})[idOrJson];
  if (!f) {
    try { f = JSON.parse(decodeURIComponent(idOrJson)); } catch { return; }
  }
  _modalFlow = f;
  const nd = f.ndpi || {};

  const vcolor = f._verdict === 'alert' ? 'danger' :
                 f._verdict === 'suspicious' ? 'warn' :
                 f._verdict === 'safe' ? 'good' : '';

  const rows = (label, val, cls='') => val != null && val !== ''
    ? `<div class="kv-key">${esc(label)}</div><div class="kv-val ${cls}">${esc(String(val))}</div>`
    : '';

  document.getElementById('modal-title').textContent =
    `${f.src_ip||'?'}:${f.src_port||'?'} → ${f.dest_ip||'?'}:${f.dst_port||'?'}`;

  document.getElementById('modal-body').innerHTML = `
    <div class="kv-grid">
      <div class="modal-section-title" style="grid-column:1/-1">Verdict</div>
      ${rows('Verdict',    f._verdict, vcolor)}
      ${rows('Reason',     f._reason)}
      ${rows('Risk Score', f._riskscore > 0 ? f._riskscore : null, 'danger')}
      ${rows('Risk Flags', f._risktext, 'warn')}

      <div class="modal-section-title" style="grid-column:1/-1">Flow</div>
      ${rows('Source IP',   f.src_ip)}
      ${rows('Source Port', f.src_port)}
      ${rows('Dest IP',     f.dest_ip)}
      ${rows('Dest Port',   f.dst_port)}
      ${rows('L4 Protocol', f.proto)}
      ${rows('Bytes',       f._bytes ? fmtBytes(f._bytes) : null)}
      ${rows('Packets',     f._pkts)}

      <div class="modal-section-title" style="grid-column:1/-1">nDPI</div>
      ${rows('L7 Protocol', nd.proto)}
      ${rows('Category',    nd.category)}
      ${rows('Breed',       nd.breed)}
      ${rows('Encrypted',   nd.encrypted ? 'Yes' : 'No')}
      ${rows('Hostname',    nd.hostname)}
      ${rows('SNI',         f._sni)}
      ${rows('DNS Queries', nd.dns?.num_queries)}
      ${rows('DNS RCODE',   nd.dns?.reply_code != null ? nd.dns.reply_code + (nd.dns.reply_code===3?' (NXDOMAIN)':nd.dns.reply_code===0?' (OK)':'') : null)}
      ${rows('TLS Version', nd.tls?.version)}
      ${rows('TLS Cipher',  nd.tls?.cipher)}
      ${rows('TLS JA3',     nd.tls?.ja3)}
      ${rows('TLS JA4',     nd.tls?.ja4)}
      ${rows('TLS SANs',    nd.tls?.server_names)}
      ${rows('ALPN',        nd.tls?.alpn)}
      ${rows('IP Proto DB', nd.proto_by_ip ? `${nd.proto_by_ip} (id ${nd.proto_by_ip_id||'?'})` : null)}
      ${rows('Src→Dst',     f._bytes_s2d != null ? fmtBytes(f._bytes_s2d) + ' / ' + (f._pkts_s2d||0) + ' pkts' : null)}
      ${rows('Dst→Src',     f._bytes_d2s != null ? fmtBytes(f._bytes_d2s) + ' / ' + (f._pkts_d2s||0) + ' pkts' : null)}
      ${rows('Bidirectional', f.bidirectional != null ? (f.bidirectional ? 'Yes' : 'No (unidir)') : null)}
      ${rows('Data Ratio',  f.xfer?.data_ratio_str)}
    </div>
    <div style="margin-top:12px;text-align:right">
      <button onclick="filterByIP('${esc(f.src_ip||'')}'); closeModalDirect();"
        style="background:var(--bg4);border:1px solid var(--border2);color:var(--text);padding:5px 10px;border-radius:4px;cursor:pointer;font-family:var(--font-mono);font-size:11px;">
        Filter flows by this IP
      </button>
    </div>
  `;

  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal(e) {
  if (e.target === document.getElementById('modal-overlay')) closeModalDirect();
}

function closeModalDirect() {
  document.getElementById('modal-overlay').classList.remove('open');
}

// ── Sorting ───────────────────────────────────────────────────────────────────
function makeSorter(state) {
  return (a, b) => {
    let av = getVal(a, state.key), bv = getVal(b, state.key);
    if (typeof av === 'string') av = av.toLowerCase();
    if (typeof bv === 'string') bv = bv.toLowerCase();
    return av < bv ?  state.dir :
           av > bv ? -state.dir : 0;
  };
}

function getVal(obj, key) {
  if (key.startsWith('ndpi.')) return (obj.ndpi||{})[key.slice(5)] ?? '';
  return obj[key] ?? '';
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function matchQ(f, q) {
  const nd = f.ndpi || {};
  return (f.src_ip + ' ' + (f.dest_ip||'') + ' ' + f.proto + ' ' +
          f.src_port + ' ' + f.dst_port + ' ' +
          (nd.proto||'') + ' ' + (nd.category||'') + ' ' +
          (nd.hostname||'') + ' ' + (f._sni||'') + ' ' +
          (f.server_hostname||'') + ' ' +
          (f.country_iso||'') + ' ' + (f.asn_org||'') + ' AS' + (f.asn||'') + ' ' +
          (f.threat_source||'') + ' ' +
          f._risktext + ' ' + f._verdict + ' ' + f._reason)
         .toLowerCase().includes(q);
}

function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B','KB','MB','GB','TB'];
  let i = 0;
  while (n >= 1024 && i < u.length-1) { n/=1024; i++; }
  return (i ? n.toFixed(1) : n) + '\u202f' + u[i];
}

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Boot ──────────────────────────────────────────────────────────────────────
fetchAll();
setInterval(fetchAll, 10000);
</script>
</body>
</html>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Request handler
# ─────────────────────────────────────────────────────────────────────────────

_analytics = None  # module-level, set at startup

def _load_flows(data_file: str) -> list:
    try:
        with open(data_file) as fh:
            raw = json.load(fh)
        if not isinstance(raw, list):
            raw = []
    except (FileNotFoundError, json.JSONDecodeError):
        raw = []
    return raw


class Handler(http.server.BaseHTTPRequestHandler):
    data_file:      str = DEFAULT_DATA_FILE
    html_dir:       str = DEFAULT_HTML_DIR
    whitelist_file: str = DEFAULT_WHITELIST
    # Task 2 knobs surfaced through /api/agent/status (set in main()).
    retention_days: int = 7

    def log_message(self, fmt, *args):
        if args and str(args[1]) not in ('200', '304'):
            super().log_message(fmt, *args)

    def _query(self) -> dict:
        """Parse the query string once per request."""
        qs = self.path.split('?', 1)[1] if '?' in self.path else ''
        return urllib.parse.parse_qs(qs, keep_blank_values=True)

    def do_GET(self):
        path = self.path.split('?')[0]

        if path in ('/', '/index.html'):
            self._send(200, 'text/html; charset=utf-8', HTML.encode())

        elif path == '/api/flows':
            raw = _load_flows(self.data_file)
            enriched = _analytics.enrich(raw)
            self._json(enriched)

        elif path == '/api/summary':
            raw = _load_flows(self.data_file)
            enriched = _analytics.enrich(raw)
            summ = _analytics.summary(enriched)
            # Don't send full flow objects for alert_flows in summary — trim them
            summ['alert_flows'] = summ.get('alert_flows', [])[:50]
            self._json(summ)

        elif path == '/api/timeline':
            raw = _load_flows(self.data_file)
            enriched = _analytics.enrich(raw)
            tl = _analytics.timeline(enriched)
            self._json(tl)

        elif path == '/api/alerts':
            raw = _load_flows(self.data_file)
            enriched = _analytics.enrich(raw)
            alerts = [f for f in enriched if f.get('_verdict') in ('alert', 'suspicious', 'threat')]
            alerts.sort(key=lambda x: x.get('_riskscore', 0), reverse=True)
            self._json(alerts[:500])

        elif path == '/api/scanners':
            raw = _load_flows(self.data_file)
            enriched = _analytics.enrich(raw)
            summ = _analytics.summary(enriched)
            self._json(summ.get('scanners', []))

        elif path == '/api/protocols':
            # Documented since the first version but never actually routed; the
            # dashboard's protocol tab was reading it off /api/summary instead.
            raw = _load_flows(self.data_file)
            enriched = _analytics.enrich(raw)
            summ = _analytics.summary(enriched)
            self._json({
                'protocols':  [{'proto': p, 'bytes': b} for p, b in summ.get('top_proto', [])],
                'categories': [{'category': c, 'count': n} for c, n in summ.get('top_category', [])],
            })

        # ── Task 4: agent-facing surface ─────────────────────────────────────
        elif path == '/api/agent/status':
            raw = _load_flows(self.data_file)
            enriched = _analytics.enrich(raw)
            self._json(_analytics.agent_status(enriched, self.retention_days))

        elif path == '/api/agent/diff':
            q = self._query()
            since_raw = (q.get('since') or [None])[0]
            limit_raw = (q.get('limit') or ['200'])[0]
            try:
                limit = max(1, min(1000, int(limit_raw)))
            except ValueError:
                limit = 200
            raw = _load_flows(self.data_file)
            enriched = _analytics.enrich(raw)
            self._json(_analytics.agent_diff(enriched, since_raw, limit=limit))

        elif path == '/api/agent/schema':
            # Self-describing so an agent can read one endpoint and know how to
            # use the rest without being handed prose.
            self._json({
                "endpoints": {
                    "/api/agent/status": "compact snapshot: counts, last-24h alerts/threats, anomalous dests, geo+feed status. Capped at ~30 kB.",
                    "/api/agent/diff?since=<ISO8601|epoch>": "events newer than `since` (kinds: threat|alert|suspicious|scanner). Echoes `cursor` to pass back next poll.",
                    "/api/flows": "full enriched flow list (large; prefer the agent endpoints)",
                    "/api/summary": "aggregate stats incl. top_countries + threat_count",
                    "/api/alerts": "alert/suspicious/threat flows, up to 500",
                    "/api/scanners": "port-scanner detections by source IP",
                    "/api/timeline": "per-minute traffic buckets",
                    "/api/protocols": "protocol and category distribution",
                },
                "verdicts_ordered_by_severity": ["threat", "alert", "suspicious", "noise", "safe"],
                "verdict_meaning": {
                    "threat": "dest_ip is listed in threats.json from abuse.ch (outranks the whitelist)",
                    "alert": "high-signal nDPI risk, or risk score >= 50 with non-noise risks",
                    "suspicious": "risk score >= 10",
                    "noise": "trusted ASN/prefix/org, or background internet noise",
                    "safe": "no indicators",
                },
                "per_flow_fields_added": {
                    "country_iso": "GeoLite2-City country code, null when geo unavailable",
                    "asn": "real ASN number from GeoLite2-ASN (what the whitelist matches on)",
                    "asn_org": "ASN organisation name",
                    "dest_geo": "'City, Country' display string or null",
                    "threat_source": "the exact IP or CIDR from threats.json that matched dest_ip",
                },
                "offline_summaries": {
                    "summary_sqlite": DEFAULT_SUMMARY_DB,
                    "cold_shards": DEFAULT_COLD_DIR + "/flows-YYYY-MM-DD.ndjson.zst",
                    "tables": ["daily_summary(date,total_flows,bytes_out,bytes_in,distinct_dests,alerts,top_talkers_json,top_countries_json)",
                               "dest_rollup(dest_ip,iso,asn_org,asn,first_seen,last_seen,flows,bytes,alert_count)"],
                    "written_by": "distill.py",
                },
            })

        else:
            served = self._try_static(self.path)
            if not served:
                if self.path == '/favicon.ico':
                    self._send(200, 'image/svg+xml', FAVICON_SVG)
                else:
                    self._send(404, 'text/plain', b'Not found')

    def _json(self, data):
        body = json.dumps(data, separators=(',', ':')).encode()
        self._send(200, 'application/json', body,
                   extra_headers=[('Cache-Control', 'no-store')])

    def _try_static(self, url_path):
        clean = url_path.split('?')[0]
        try:
            clean = clean.encode('ascii').decode('unicode_escape')
        except Exception:
            return False
        base   = Path(self.html_dir).resolve()
        target = (base / clean.lstrip('/')).resolve()
        if not str(target).startswith(str(base)):
            self._send(403, 'text/plain', b'Forbidden')
            return True
        if not target.is_file():
            return False
        ext   = target.suffix.lower()
        ctype = EXTRA_MIME.get(ext) or mimetypes.guess_type(str(target))[0] or 'application/octet-stream'
        try:
            self._send(200, ctype, target.read_bytes())
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
    global _analytics

    p = argparse.ArgumentParser(description='Flow Monitor web server')
    p.add_argument('--port',      type=int, default=DEFAULT_PORT,      metavar='N')
    p.add_argument('--data',      type=str, default=DEFAULT_DATA_FILE,  metavar='PATH')
    p.add_argument('--html',      type=str, default=DEFAULT_HTML_DIR,   metavar='DIR')
    p.add_argument('--whitelist', type=str, default=DEFAULT_WHITELIST,  metavar='PATH',
                   help='JSON file with trusted ASNs / org fragments')
    p.add_argument('--mmdb-dir',  type=str, default=DEFAULT_MMDB_DIR,   metavar='DIR',
                   help='GeoLite2 directory (env NETFLOW_MMDB_DIR); absent → geo degrades to null')
    p.add_argument('--threats',   type=str, default=DEFAULT_THREATS,    metavar='PATH',
                   help='threats.json written by threat_intel.py')
    p.add_argument('--retain-days', type=int, default=int(os.environ.get('FLOW_RETAIN_DAYS', 7)),
                   metavar='N', help='hot retention window reported by /api/agent/status')
    args = p.parse_args()

    Handler.data_file      = args.data
    Handler.html_dir       = args.html
    Handler.whitelist_file = args.whitelist
    Handler.retention_days = max(0, args.retain_days)

    geo = GeoReader(mmdb_dir=args.mmdb_dir)
    threats = ThreatStore(args.threats)
    _analytics = FlowAnalytics(args.whitelist, geo=geo, threats=threats)

    Path(args.html).mkdir(parents=True, exist_ok=True)

    server = http.server.ThreadingHTTPServer(('0.0.0.0', args.port), Handler)

    print(f"Flow Monitor  http://0.0.0.0:{args.port}/")
    print(f"Data file:    {args.data}")
    print(f"Whitelist:    {args.whitelist}")
    print(f"Static files: {args.html}/")
    if geo.available:
        print(f"GeoIP:        {args.mmdb_dir} (city={bool(geo._city)} asn={bool(geo._asn)})")
    else:
        print(f"GeoIP:        UNAVAILABLE — {geo.error}; country_iso/asn stay null")
    if threats.ips or threats.nets:
        print(f"Threat feed:  {len(threats.ips)} IP(s), {len(threats.nets)} CIDR(s) "
              f"(retrieved {threats.retrieved_at})")
    else:
        print(f"Threat feed:  EMPTY — {threats.error or args.threats + ' not loaded'}; "
              f"no flow can be verdict 'threat'")
    print(f"Started:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print("API endpoints:")
    print(f"  GET /api/flows        — enriched flow list (verdict, risk, reason, geo)")
    print(f"  GET /api/summary      — aggregate stats, top talkers, scanners")
    print(f"  GET /api/timeline     — per-minute traffic buckets")
    print(f"  GET /api/alerts       — alert/suspicious/threat flows only")
    print(f"  GET /api/scanners     — detected port scanners")
    print(f"  GET /api/protocols    — protocol + category distribution")
    print(f"  GET /api/agent/status — compact agent snapshot (<30 kB)")
    print(f"  GET /api/agent/diff   — events since ?since=<ISO|epoch>")
    print(f"  GET /api/agent/schema — self-describing endpoint contract")
    print("\nCtrl-C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == '__main__':
    main()

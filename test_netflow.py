#!/usr/bin/env python3
"""
test_netflow.py — stdlib unit tests for the netflow improvement brief (gates 2-3-5).

Covers the pure logic only: verdict classification with and without a threat
feed, the CIDR/IP matcher, GeoIP graceful degradation, the distiller's SQLite
idempotency, retention-side shard naming, and the agent surface size caps.

No network, no root, no ndpiReader, no running server. Run with either:
    python3 -m unittest discover -s . -p 'test_*.py' -v
    python3 test_netflow.py
"""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zlib
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import distill           # noqa: E402
import flow_server as fs  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

def make_flow(src="10.0.0.5", dst="203.0.113.77", dport=443, proto="TCP",
              l7="TLS", score=0, risks=None, bytes_s2d=500, bytes_d2s=800,
              first_seen=None, last_seen=None,
              bidirectional=1, hostname="", sni="", encrypted=1):
    """A flow shaped exactly like ndpiReader's NDJSON (dest_ip, not dst_ip).

    Timestamps default to TEST_DAY so a flow lands in the same UTC date as the
    shard it is stored in; pass them explicitly to test cross-day behaviour.
    """
    if first_seen is None:
        first_seen = TEST_DAY_EPOCH
    if last_seen is None:
        last_seen = first_seen + 10.0
    flow_risk = {}
    for i, r in enumerate(risks or []):
        name, sev = (r, "high") if isinstance(r, str) else r
        flow_risk[str(i)] = {"risk": name, "severity": sev}
    return {
        "src_ip": src, "dest_ip": dst, "src_port": 51000, "dst_port": dport,
        "ip": 4, "proto": proto,
        "server_hostname": sni,
        "first_seen": first_seen, "last_seen": last_seen,
        "duration": last_seen - first_seen, "bidirectional": bidirectional,
        "ndpi": {
            "proto": l7, "encrypted": encrypted, "ndpi_risk_score": score,
            "category": "Web", "hostname": hostname, "flow_risk": flow_risk,
            "proto_by_ip_id": 0,
        },
        "xfer": {"src2dst_bytes": bytes_s2d, "dst2src_bytes": bytes_d2s,
                 "src2dst_packets": 5, "dst2src_packets": 5},
    }


# A fixed recent day so distill tests are deterministic and self-consistent.
TEST_DAY = "2026-10-01"
TEST_DAY_EPOCH = datetime.strptime(TEST_DAY + "T12:00:00", "%Y-%m-%dT%H:%M:%S"
                                   ).replace(tzinfo=timezone.utc).timestamp()


def epoch_of(day: str, hour: int = 12) -> float:
    """UTC epoch for 'YYYY-MM-DD' at a given hour — keeps flow dates explicit."""
    return (datetime.strptime(f"{day}T{hour:02d}:00:00", "%Y-%m-%dT%H:%M:%S")
            .replace(tzinfo=timezone.utc).timestamp())


class StubGeo:
    """Stand-in GeoReader with fixed answers — keeps tests offline and fast."""

    def __init__(self, table=None, available=True, error=None):
        self.table = table or {}
        self.available = available
        self.error = error
        self.calls = []

    def city(self, ip):
        self.calls.append(("city", ip))
        g = self.table.get(ip)
        if not g:
            return None
        return {"country_iso": g.get("iso"), "country_name": g.get("country"),
                "city": g.get("city")}

    def asn(self, ip):
        self.calls.append(("asn", ip))
        g = self.table.get(ip)
        if not g or g.get("asn") is None:
            return None
        return {"asn": g["asn"], "asn_org": g.get("org")}

    def status(self):
        return {"available": self.available, "error": self.error,
                "mmdb_dir": "stub", "city_db": True, "asn_db": True,
                "libmaxminddb": "stub", "cache_entries": 0,
                "lookups": len(self.calls), "cache_hits": 0}


class StubThreats:
    """ThreatStore interface backed by an in-memory set."""

    def __init__(self, ips=(), nets_text=()):
        self.ips = set(ips)
        self.nets = [fs.parse_cidr(n) for n in nets_text]
        self.nets = [n for n in self.nets if n]
        self.retrieved_at = "2026-10-05T00:00:00Z"
        self.source = "stub"
        self.stale_sources = []
        self.error = None
        self.reload_calls = 0

    def reload(self, force=False):
        self.reload_calls += 1
        return bool(self.ips or self.nets)

    def match(self, ip):
        if not ip:
            return None
        if ip in self.ips:
            return ip
        for net in self.nets:
            try:
                import ipaddress
                if ipaddress.ip_address(ip) in net:
                    return str(net)
            except ValueError:
                return None
        return None

    def status(self):
        return {"path": "stub", "loaded": bool(self.ips or self.nets),
                "count_ips": len(self.ips), "count_cidrs": len(self.nets),
                "retrieved_at": self.retrieved_at, "source": self.source,
                "stale_sources": [], "error": None}


def analytics(whitelist_path, geo=None, threats=None):
    """FlowAnalytics wired to stubs; geo defaults to 'unavailable'."""
    return fs.FlowAnalytics(whitelist_path,
                            geo=geo if geo is not None else StubGeo(available=False),
                            threats=threats if threats is not None else StubThreats())


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="netflow_test_"))
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def whitelist(self, data):
        p = self.tmp / "whitelist.json"
        p.write_text(json.dumps(data))
        return str(p)


# ─────────────────────────────────────────────────────────────────────────────
# Task 3 + 1: verdict classifier
# ─────────────────────────────────────────────────────────────────────────────

class TestVerdictClassifier(TempDirCase):
    def test_clean_flow_is_safe(self):
        a = analytics(self.whitelist({"asns": [], "org_fragments": []}))
        out = a.enrich([make_flow(score=0)])[0]
        self.assertEqual(out["_verdict"], "safe")

    def test_high_signal_risk_alerts(self):
        a = analytics(self.whitelist({"asns": [], "org_fragments": []}))
        out = a.enrich([make_flow(risks=["malware_host_contacted"])])[0]
        self.assertEqual(out["_verdict"], "alert")
        self.assertIn("high_signal_risk", out["_reason"])

    def test_risk_score_thresholds(self):
        a = analytics(self.whitelist({"asns": [], "org_fragments": []}))
        cases = [(9, "safe"), (10, "suspicious"), (49, "suspicious"), (50, "alert")]
        for score, want in cases:
            got = a.enrich([make_flow(score=score)])[0]["_verdict"]
            self.assertEqual(got, want, f"score={score}")

    def test_noise_only_risks_are_noise(self):
        a = analytics(self.whitelist({"asns": [], "org_fragments": []}))
        out = a.enrich([make_flow(risks=[("tcp_issues", "low")], score=5)])[0]
        self.assertEqual(out["_verdict"], "noise")

    def test_threat_beats_everything_including_whitelist(self):
        """The single most important precedence rule in Task 3."""
        wl = self.whitelist({"asns": [15169], "org_fragments": ["google"]})
        geo = StubGeo({"8.8.8.8": {"iso": "US", "asn": 15169, "org": "Google LLC"}})
        threats = StubThreats(ips=["8.8.8.8"])
        a = analytics(wl, geo=geo, threats=threats)
        out = a.enrich([make_flow(dst="8.8.8.8", sni="www.google.com",
                                  risks=["malware_host_contacted"])])[0]
        self.assertEqual(out["_verdict"], "threat")
        self.assertEqual(out["threat_source"], "8.8.8.8")
        # Whitelisting still recorded, just not allowed to win.
        self.assertTrue(out["_whitelisted"])

    def test_threat_via_cidr_sets_matched_prefix_as_source(self):
        threats = StubThreats(nets_text=["198.51.100.0/24"])
        a = analytics(self.whitelist({"asns": [], "org_fragments": []}), threats=threats)
        out = a.enrich([make_flow(dst="198.51.100.42")])[0]
        self.assertEqual(out["_verdict"], "threat")
        self.assertEqual(out["threat_source"], "198.51.100.0/24")

    def test_no_threat_file_means_no_threat_verdict(self):
        a = analytics(self.whitelist({"asns": [], "org_fragments": []}),
                      threats=StubThreats())
        out = a.enrich([make_flow(dst="203.0.113.77")])[0]
        self.assertNotEqual(out["_verdict"], "threat")
        self.assertIsNone(out["threat_source"])

    def test_trusted_real_asn_becomes_noise(self):
        wl = self.whitelist({"asns": [13335], "org_fragments": []})
        geo = StubGeo({"1.1.1.1": {"iso": "AU", "asn": 13335, "org": "Cloudflare, Inc."}})
        a = analytics(wl, geo=geo)
        out = a.enrich([make_flow(dst="1.1.1.1", score=49)])[0]
        self.assertEqual(out["_verdict"], "noise")
        self.assertEqual(out["_reason"], "trusted_org")

    def test_untrusted_real_asn_does_not_trust_on_hostname_fragment(self):
        """Task 1's core fix: a real ASN must override org-name guessing.

        Old code matched `proto_by_ip_id` and hostname fragments, so a host
        claiming to be google.com could be whitelisted while actually sitting in
        an untrusted ASN. With geo resolved, that guess path is closed.
        """
        wl = self.whitelist({"asns": [15169], "org_fragments": ["example-noise"]})
        geo = StubGeo({"198.18.0.9": {"iso": "US", "asn": 64512, "org": "Rogue Net"}})
        a = analytics(wl, geo=geo)
        out = a.enrich([make_flow(dst="198.18.0.9", score=49,
                                 hostname="example-noise.tld")])[0]
        self.assertFalse(out["_whitelisted"])
        self.assertEqual(out["_verdict"], "suspicious")

    def test_proto_by_ip_id_fallback_only_without_geo(self):
        wl = self.whitelist({"asns": [126], "org_fragments": []})
        flow = make_flow(dst="203.0.113.5", score=49)
        flow["ndpi"]["proto_by_ip_id"] = 126

        no_geo = analytics(wl, geo=StubGeo(available=False))
        self.assertTrue(no_geo.enrich([flow])[0]["_whitelisted"])

        with_geo = analytics(wl, geo=StubGeo({"203.0.113.5": {"asn": 9999, "org": "X"}}))
        self.assertFalse(with_geo.enrich([flow])[0]["_whitelisted"],
                        "a resolved ASN must supersede the reputation-id guess")

    def test_trusted_prefix_matches_destination(self):
        wl = self.whitelist({"asns": [], "prefixes": ["198.51.100.0/24"],
                             "org_fragments": []})
        a = analytics(wl)
        inside = a.enrich([make_flow(dst="198.51.100.9", score=49)])[0]
        outside = a.enrich([make_flow(dst="198.51.101.9", score=49)])[0]
        self.assertTrue(inside["_whitelisted"])
        self.assertFalse(outside["_whitelisted"])

    def test_geo_fields_present_and_null_when_unavailable(self):
        a = analytics(self.whitelist({"asns": [], "org_fragments": []}),
                      geo=StubGeo(available=False))
        out = a.enrich([make_flow()])[0]
        for key in ("country_iso", "asn", "asn_org", "dest_geo"):
            self.assertIn(key, out, f"{key} missing from enriched flow")
            self.assertIsNone(out[key])

    def test_geo_fields_populated_when_available(self):
        geo = StubGeo({"93.184.216.34": {"iso": "US", "country": "United States",
                                        "city": "Norwood", "asn": 15133,
                                        "org": "MCI Communications Services, Inc. d/b/a Verizon Business"}})
        a = analytics(self.whitelist({"asns": [], "org_fragments": []}), geo=geo)
        out = a.enrich([make_flow(dst="93.184.216.34")])[0]
        self.assertEqual(out["country_iso"], "US")
        self.assertEqual(out["asn"], 15133)
        self.assertEqual(out["dest_geo"], "Norwood, United States")

    def test_enrich_never_mutates_input_flows(self):
        a = analytics(self.whitelist({"asns": [], "org_fragments": []}))
        raw = [make_flow()]
        snapshot = json.dumps(raw, sort_keys=True)
        a.enrich(raw)
        self.assertEqual(json.dumps(raw, sort_keys=True), snapshot)


# ─────────────────────────────────────────────────────────────────────────────
# Task 1/3: CIDR + IP matching primitives
# ─────────────────────────────────────────────────────────────────────────────

class TestCidrMatcher(unittest.TestCase):
    def test_parse_cidr_accepts_prefix_and_bare_ip(self):
        self.assertEqual(str(fs.parse_cidr("10.0.0.0/24")), "10.0.0.0/24")
        self.assertEqual(str(fs.parse_cidr("10.0.0.1")), "10.0.0.1/32")
        self.assertEqual(str(fs.parse_cidr("2001:db8::/32")), "2001:db8::/32")

    def test_parse_cidr_rejects_garbage_without_raising(self):
        for bad in ("", "   ", "not-an-ip", "10.0.0.0/999", "999.1.1.1/32", "1.2.3.4/24x"):
            self.assertIsNone(fs.parse_cidr(bad), f"should reject {bad!r}")

    def test_match_network_membership(self):
        nets = [fs.parse_cidr("192.0.2.0/24"), fs.parse_cidr("198.51.100.7/32")]
        self.assertTrue(fs.match_network("192.0.2.100", nets))
        self.assertTrue(fs.match_network("198.51.100.7", nets))
        self.assertFalse(fs.match_network("198.51.100.8", nets))
        self.assertFalse(fs.match_network("203.0.113.1", nets))

    def test_match_network_bad_ip_is_false_not_error(self):
        self.assertFalse(fs.match_network("garbage", [fs.parse_cidr("10.0.0.0/8")]))
        self.assertFalse(fs.match_network("", []))

    def test_family_mismatch_never_matches(self):
        """An IPv6 net must not swallow an IPv4 address and vice versa."""
        self.assertFalse(fs.match_network("10.0.0.1", [fs.parse_cidr("2001:db8::/32")]))
        self.assertFalse(fs.match_network("2001:db8::1", [fs.parse_cidr("10.0.0.0/8")]))

    def test_compile_prefixes_skips_bad_entries_and_caches(self):
        nets = fs._compile_prefixes(["10.0.0.0/8", "bogus", "192.168.0.0/16"])
        self.assertEqual(len(nets), 2)
        # Longest prefix first.
        self.assertEqual([str(n) for n in nets], ["192.168.0.0/16", "10.0.0.0/8"])
        # Same content → identical cached object (no re-parse per flow).
        self.assertIs(nets, fs._compile_prefixes(["192.168.0.0/16", "10.0.0.0/8", "bogus"]))

    def test_threat_store_exact_then_prefix_match(self):
        store = StubThreats(ips=["1.2.3.4"], nets_text=["5.6.0.0/16"])
        self.assertEqual(store.match("1.2.3.4"), "1.2.3.4")
        self.assertEqual(store.match("5.6.7.8"), "5.6.0.0/16")
        self.assertIsNone(store.match("9.9.9.9"))
        self.assertIsNone(store.match(""))


class TestThreatStoreFile(TempDirCase):
    def test_loads_writes_and_survives_corrupt_refresh(self):
        path = self.tmp / "threats.json"
        good = {"retrieved_at": "2026-10-05T00:00:00Z", "source": "feodotracker",
                "ips": ["1.2.3.4", "5.6.7.8"], "cidrs": ["198.51.100.0/24"]}
        path.write_text(json.dumps(good))

        store = fs.ThreatStore(str(path))
        self.assertTrue(store.reload(force=True))
        self.assertEqual(store.match("1.2.3.4"), "1.2.3.4")
        self.assertEqual(store.match("198.51.100.5"), "198.51.100.0/24")
        self.assertEqual(store.status()["count_ips"], 2)

        # Corrupt overwrite must NOT blank the live blocklist.
        before = set(store.ips)
        path.write_text("{ this is not json")
        os.utime(path, (path.stat().st_atime + 5, path.stat().st_mtime + 5))
        self.assertTrue(store.reload())
        self.assertEqual(set(store.ips), before)
        self.assertIsNotNone(store.error)

    def test_missing_file_is_not_fatal(self):
        store = fs.ThreatStore(str(self.tmp / "absent.json"))
        self.assertFalse(store.reload())
        self.assertIsNone(store.match("1.2.3.4"))
        st = store.status()
        self.assertFalse(st["loaded"])
        self.assertIn("threat_intel.py", st["error"])

    def test_non_dict_payload_is_rejected(self):
        path = self.tmp / "t.json"
        path.write_text("[1,2,3]")
        store = fs.ThreatStore(str(path))
        self.assertFalse(store.reload(force=True))
        self.assertEqual(store.error, "threats.json is not an object")


# ─────────────────────────────────────────────────────────────────────────────
# Task 1: GeoReader graceful degradation (real libmaxminddb, absent databases)
# ─────────────────────────────────────────────────────────────────────────────

class TestGeoReaderDegradation(TempDirCase):
    def test_absent_databases_degrade_to_unavailable(self):
        g = fs.GeoReader(mmdb_dir=str(self.tmp / "nope"))
        self.assertFalse(g.available)
        self.assertIsNotNone(g.error)
        self.assertIsNone(g.city("8.8.8.8"))
        self.assertIsNone(g.asn("8.8.8.8"))
        st = g.status()
        self.assertFalse(st["available"])
        self.assertIn("mmdb_dir", st)

    def test_empty_directory_yields_none_lookups(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        g = fs.GeoReader(mmdb_dir=str(empty))
        self.assertFalse(g.available)
        self.assertIsNone(g.city("1.1.1.1"))

    def test_garbage_mmdb_is_handled_not_fatal(self):
        bad = self.tmp / "GeoLite2-City.mmdb"
        bad.write_bytes(b"this is definitely not an mmdb file" * 10)
        g = fs.GeoReader(mmdb_dir=str(self.tmp))
        self.assertFalse(g.available)
        self.assertIsNotNone(g.error)
        self.assertIsNone(g.city("8.8.8.8"))

    def test_unavailable_geo_keeps_enrichment_running(self):
        """End-to-end: with geo down, enrich() still classifies everything."""
        g = fs.GeoReader(mmdb_dir=str(self.tmp / "missing"))
        a = analytics(self.whitelist({"asns": [], "org_fragments": ["google"]}), geo=g)
        out = a.enrich([make_flow(dst="8.8.8.8", sni="accounts.google.com")])[0]
        self.assertIsNone(out["country_iso"])
        self.assertEqual(out["_verdict"], "noise", "org-fragment fallback still works")

    def test_real_databases_resolve_known_asns(self):
        """Only runs when GeoLite2 is actually present (default or NETFLOW_MMDB_DIR).

        The brief's Task 0 install may not have happened yet; this keeps the real
        end-to-end ctypes path covered whenever databases do exist without making
        the suite depend on root-owned system state.
        """
        candidates = [os.environ.get("NETFLOW_MMDB_DIR"), "/usr/share/GeoIP",
                      str(Path.home() / ".hermes/cache/scratch/geoip")]
        root = next((c for c in candidates
                     if c and (Path(c) / "GeoLite2-ASN.mmdb").is_file()), None)
        if root is None:
            self.skipTest("no GeoLite2 databases found (checked NETFLOW_MMDB_DIR, "
                          "/usr/share/GeoIP)")
        g = fs.GeoReader(mmdb_dir=root)
        if not g.available:
            self.skipTest(f"geo unavailable: {g.error}")
        self.assertEqual((g.asn("8.8.8.8") or {}).get("asn"), 15169)
        self.assertEqual((g.asn("1.1.1.1") or {}).get("asn"), 13335)
        self.assertEqual((g.city("8.8.8.8") or {}).get("country_iso"), "US")
        # Reserved/documentation ranges legitimately have no record → must be
        # None rather than a guess, and must not raise.
        self.assertIsNone(g.asn("203.0.113.7"))
        self.assertIsNone(g.city("198.51.100.1"))


# ─────────────────────────────────────────────────────────────────────────────
# ctypes layout regression — the bug that silently broke every lookup
# ─────────────────────────────────────────────────────────────────────────────

class TestMmdbStructLayout(unittest.TestCase):
    """sizeof()/offsetof() must match the compiled header, or lookups fail
    silently (has_data=True, type=0) instead of raising. These assertions pin
    the layout against the values verified with offsetof() on this host."""

    def test_entry_data_layout(self):
        import ctypes
        S = fs._MMDBEntryData
        self.assertEqual(ctypes.sizeof(S), 48)
        self.assertEqual(S.has_data.offset, 0)
        self.assertEqual(S.utf8_string.offset, 16)
        self.assertEqual(S.offset.offset, 32)
        self.assertEqual(S.offset_to_next.offset, 36)
        self.assertEqual(S.data_size.offset, 40)
        self.assertEqual(S.type.offset, 44)

    def test_lookup_result_layout(self):
        import ctypes
        R = fs._MMDBLookupResult
        self.assertEqual(ctypes.sizeof(R), 32)
        self.assertEqual(R.found_entry.offset, 0)
        self.assertEqual(R.entry.offset, 8)
        self.assertEqual(R.netmask.offset, 24)
        self.assertEqual(fs._MMDBEntry.mmdb.offset, 0)
        self.assertEqual(fs._MMDBEntry.offset.offset, 8)

    def test_handle_size_matches_abi_frozen_struct(self):
        import ctypes
        self.assertEqual(ctypes.sizeof(fs._MMDBHandle), 136)

    def test_type_constants_match_header(self):
        self.assertEqual(fs.MMDB_SUCCESS, 0)
        self.assertEqual(fs._MMDB_TYPE_UTF8, 2)
        self.assertEqual(fs._MMDB_TYPE_UINT16, 5)
        self.assertEqual(fs._MMDB_TYPE_UINT32, 6)
        self.assertEqual(fs._MMDB_TYPE_INT32, 8)
        self.assertEqual(fs._MMDB_TYPE_UINT64, 9)


# ─────────────────────────────────────────────────────────────────────────────
# Task 2: distiller — shard naming, aggregation, upsert idempotency
# ─────────────────────────────────────────────────────────────────────────────

def zstd_compress_lines(lines, out_path: Path):
    """Write an NDJSON shard through the zstd CLI, exactly like the Rust side."""
    payload = ("\n".join(lines) + "\n").encode()
    proc = subprocess.run(["zstd", "-q", "-f", "-9", "-o", str(out_path)],
                          input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.returncode == 0, proc.stderr.decode()
    return out_path


class TestShardNaming(unittest.TestCase):
    def test_shard_date_parses_both_extentions(self):
        self.assertEqual(distill.shard_date("flows-2026-10-04.ndjson.zst"), "2026-10-04")
        self.assertEqual(distill.shard_date("flows-2026-10-04.ndjson"), "2026-10-04")
        self.assertEqual(distill.shard_date("/tmp/cold/flows-2026-01-01.ndjson.zst"), "2026-01-01")

    def test_shard_date_rejects_foreign_files(self):
        for name in ("flows.ndjson", "summary.sqlite", "flows-2026-13-45.ndjson.zst",
                     "flows-2026-10-4.ndjson.zst", "tmp", "flows-2026-10-04.ndjson.zst.tmp"):
            self.assertIsNone(distill.shard_date(name), f"should reject {name}")

    def test_day_of_is_utc(self):
        # 2026-10-04T23:30:00Z stays on the 4th regardless of local timezone.
        self.assertEqual(distill._day_of(1_791_171_000), "2026-10-05")
        self.assertEqual(distill._day_of(0), "1970-01-01")
        self.assertEqual(distill._day_of(None), "")
        self.assertEqual(distill._day_of("junk"), "")


class TestDistillAggregation(TempDirCase):
    def make_shard(self, day=None, flows=None, name=None):
        day = day or TEST_DAY
        flows = flows if flows is not None else [make_flow()]
        lines = [json.dumps(f) for f in flows]
        p = self.tmp / (name or f"flows-{day}.ndjson.zst")
        return zstd_compress_lines(lines, p)

    def test_reads_compressed_shard_stream(self):
        shard = self.make_shard(flows=[make_flow(dst="1.1.1.1"), make_flow(dst="2.2.2.2")])
        daily, dests, bad = distill.aggregate_shard(shard, TEST_DAY)
        self.assertEqual(bad, 0)
        self.assertEqual(daily[TEST_DAY]["total_flows"], 2)
        self.assertEqual(len(dests), 2)

    def test_bytes_split_directionally(self):
        shard = self.make_shard(flows=[make_flow(bytes_s2d=1000, bytes_d2s=250)])
        daily, _, _ = distill.aggregate_shard(shard, TEST_DAY)
        self.assertEqual(daily[TEST_DAY]["bytes_out"], 1000)
        self.assertEqual(daily[TEST_DAY]["bytes_in"], 250)

    def test_distinct_dests_counts_unique_not_total(self):
        shard = self.make_shard(flows=[
            make_flow(dst="9.9.9.9", src="10.0.0.1"),
            make_flow(dst="9.9.9.9", src="10.0.0.2"),
            make_flow(dst="8.8.8.8", src="10.0.0.1"),
        ])
        daily, dests, _ = distill.aggregate_shard(shard, TEST_DAY)
        # `dests` is held as a set until write_daily() turns it into a count.
        self.assertEqual(len(daily[TEST_DAY]["dests"]), 2)
        self.assertEqual(dests["9.9.9.9"]["flows"], 2)

    def test_malformed_lines_are_counted_not_fatal(self):
        p = self.tmp / "flows-2026-10-02.ndjson.zst"
        zstd_compress_lines([json.dumps(make_flow(first_seen=epoch_of("2026-10-02"))),
                             "{ broken json", "not json at all"], p)
        daily, dests, bad = distill.aggregate_shard(p, "2026-10-02")
        self.assertEqual(bad, 2)
        self.assertEqual(daily["2026-10-02"]["total_flows"], 1)

    def test_alert_counting_follows_verdict(self):
        shard = self.make_shard(flows=[
            make_flow(risks=["malware_host_contacted"]),
            make_flow(score=60),
            make_flow(score=0),
        ])
        daily, dests, _ = distill.aggregate_shard(shard, TEST_DAY)
        self.assertEqual(daily[TEST_DAY]["alerts"], 2)
        self.assertGreaterEqual(dests["203.0.113.77"]["alert_count"], 2)

    def test_geo_from_record_body_is_used(self):
        f = make_flow(dst="8.8.8.8")
        f["_geo"] = {"country_iso": "US", "asn_org": "Google LLC", "asn": 15169}
        shard = self.make_shard(flows=[f])
        daily, dests, _ = distill.aggregate_shard(shard, TEST_DAY)
        self.assertEqual(dests["8.8.8.8"]["iso"], "US")
        self.assertEqual(dests["8.8.8.8"]["asn"], 15169)
        self.assertEqual(daily[TEST_DAY]["countries"]["US"], 1)

    def test_first_last_seen_widen_across_records(self):
        early = make_flow(first_seen=TEST_DAY_EPOCH, last_seen=TEST_DAY_EPOCH + 5)
        late = make_flow(first_seen=TEST_DAY_EPOCH + 9_000, last_seen=TEST_DAY_EPOCH + 9_999)
        shard = self.make_shard(flows=[late, early])
        _, dests, _ = distill.aggregate_shard(shard, TEST_DAY)
        r = dests["203.0.113.77"]
        self.assertAlmostEqual(r["first_seen"], TEST_DAY_EPOCH)
        self.assertAlmostEqual(r["last_seen"], TEST_DAY_EPOCH + 9_999)


class TestDistillIdempotency(TempDirCase):
    """Acceptance gate 3: 'distiller upsert idempotency (sqlite in temp dir)'."""

    def shard(self, day, flows, extra=""):
        # Stamp every flow inside the shard's own date, exactly as retention
        # would have done when it archived them.
        stamped = []
        for i, f in enumerate(flows):
            g = dict(f)
            g["first_seen"] = epoch_of(day) + i
            g["last_seen"] = epoch_of(day) + i + 5
            stamped.append(g)
        lines = [json.dumps(f) for f in stamped]
        p = self.tmp / f"flows-{day}{extra}.ndjson.zst"
        return zstd_compress_lines(lines, p)

    def rows(self, db, table):
        con = sqlite3.connect(str(db))
        try:
            cols = [c[1] for c in con.execute(f"PRAGMA table_info({table})")]
            return [dict(zip(cols, r)) for r in con.execute(f"SELECT * FROM {table} ORDER BY 1")]
        finally:
            con.close()

    def test_same_shard_twice_identical_state(self):
        db = self.tmp / "summary.sqlite"
        s = self.shard("2026-10-01", [make_flow(dst="1.1.1.1", bytes_s2d=100, bytes_d2s=50),
                                      make_flow(dst="2.2.2.2", score=60)])
        shards = [("2026-10-01", s)]

        distill.ingest(db, shards, verbose=False)
        first_daily = self.rows(db, "daily_summary")
        first_dest = self.rows(db, "dest_rollup")

        distill.ingest(db, shards, verbose=False)
        distill.ingest(db, shards, verbose=False)
        self.assertEqual(self.rows(db, "daily_summary"), first_daily,
                         "daily_summary changed on re-ingest")
        self.assertEqual(self.rows(db, "dest_rollup"), first_dest,
                         "dest_rollup changed on re-ingest")

    def test_totals_are_exact_not_doubled(self):
        db = self.tmp / "summary.sqlite"
        s = self.shard("2026-10-03", [make_flow(dst="7.7.7.7", bytes_s2d=1000, bytes_d2s=1000)])
        for _ in range(4):
            distill.ingest(db, [("2026-10-03", s)], verbose=False)
        row = self.rows(db, "daily_summary")[0]
        self.assertEqual(row["total_flows"], 1)
        self.assertEqual(row["bytes_out"], 1000)
        self.assertEqual(row["bytes_in"], 1000)
        self.assertEqual(row["distinct_dests"], 1)

    def test_two_shards_same_day_sum_once(self):
        db = self.tmp / "summary.sqlite"
        a = self.shard("2026-10-04", [make_flow(dst="1.1.1.1", bytes_s2d=100)], extra="-a")
        b = self.shard("2026-10-04", [make_flow(dst="2.2.2.2", bytes_s2d=200)], extra="-b")
        distill.ingest(db, [("2026-10-04", a), ("2026-10-04", b)], verbose=False)
        row = self.rows(db, "daily_summary")[0]
        self.assertEqual(row["total_flows"], 2)
        self.assertEqual(row["bytes_out"], 300)
        # Re-ingesting one of them alone must not change the day (both are known).
        distill.ingest(db, [("2026-10-04", a), ("2026-10-04", b)], verbose=False)
        self.assertEqual(self.rows(db, "daily_summary")[0]["total_flows"], 2)

    def test_separate_days_get_separate_rows(self):
        db = self.tmp / "summary.sqlite"
        d1 = self.shard("2026-10-01", [make_flow(dst="1.1.1.1")])
        d2 = self.shard("2026-10-02", [make_flow(dst="1.1.1.1")])
        distill.ingest(db, [("2026-10-01", d1), ("2026-10-02", d2)], verbose=False)
        rows = self.rows(db, "daily_summary")
        self.assertEqual([r["date"] for r in rows], ["2026-10-01", "2026-10-02"])
        # One dest row spanning both days with widened timestamps...
        dests = self.rows(db, "dest_rollup")
        self.assertEqual(len(dests), 1)
        self.assertAlmostEqual(dests[0]["first_seen"], epoch_of("2026-10-01"))
        self.assertGreater(dests[0]["last_seen"], epoch_of("2026-10-02"))

    def test_dest_rollup_accumulates_lifetime_totals_across_days(self):
        """A dest seen on N days must sum to N, not report one day's count.

        This is why ingest() aggregates the whole shard set before writing: with
        a per-day MAX() upsert the row silently under-reported history, which is
        exactly the kind of wrong-but-quiet number an agent would act on.
        """
        db = self.tmp / "summary.sqlite"
        d1 = self.shard("2026-10-01", [make_flow(dst="5.5.5.5"), make_flow(dst="5.5.5.5")])
        d2 = self.shard("2026-10-02", [make_flow(dst="5.5.5.5")])
        distill.ingest(db, [("2026-10-01", d1), ("2026-10-02", d2)], verbose=False)
        row = self.rows(db, "dest_rollup")[0]
        self.assertEqual(row["flows"], 3, "lifetime flow count across both days")
        self.assertAlmostEqual(row["first_seen"], epoch_of("2026-10-01"))
        self.assertGreater(row["last_seen"], epoch_of("2026-10-02"))

    def test_reingesting_all_shards_does_not_double_counts(self):
        db = self.tmp / "summary.sqlite"
        d1 = self.shard("2026-10-01", [make_flow(dst="6.6.6.6"), make_flow(dst="6.6.6.6")])
        d2 = self.shard("2026-10-02", [make_flow(dst="6.6.6.6")])
        shards = [("2026-10-01", d1), ("2026-10-02", d2)]
        for _ in range(3):
            distill.ingest(db, shards, verbose=False)
        row = self.rows(db, "dest_rollup")[0]
        self.assertEqual(row["flows"], 3, "re-ingest must not inflate lifetime totals")
        self.assertEqual(sum(r["total_flows"] for r in self.rows(db, "daily_summary")), 3)

    def test_unreadable_shard_is_skipped_not_fatal(self):
        """One corrupt shard must not cost the rest of the history.

        distill runs as a nightly batch over months of shards. Before this, a
        truncated or non-zstd file raised out of aggregate_shard() and aborted
        ingest(), so every later day silently went undistilled — the summary DB
        an agent reads would quietly stop advancing with no error surfaced.
        """
        db = self.tmp / "summary.sqlite"
        good_a = self.shard("2026-10-01", [make_flow(dst="1.1.1.1")])
        good_b = self.shard("2026-10-03", [make_flow(dst="2.2.2.2")])
        empty = self.tmp / "flows-2026-10-02.ndjson.zst"
        empty.write_bytes(b"")                      # unexpected end of file
        garbage = self.tmp / "flows-2026-10-04.ndjson.zst"
        garbage.write_bytes(b"this is not a zstd frame\n")   # unsupported format

        shards = [("2026-10-01", good_a), ("2026-10-02", empty),
                  ("2026-10-03", good_b), ("2026-10-04", garbage)]
        stats = distill.ingest(db, shards, verbose=False)

        self.assertEqual(stats["skipped_shards"], 2,
                         f"both bad shards reported skipped: {stats}")
        self.assertEqual(stats["shards"], 2, "good shards still ingested")
        days = [r["date"] for r in self.rows(db, "daily_summary")]
        self.assertIn("2026-10-03", days,
                      "a day after the corrupt shard must still be distilled")
        dests = {r["dest_ip"] for r in self.rows(db, "dest_rollup")}
        self.assertEqual(dests, {"1.1.1.1", "2.2.2.2"})

    def test_rebuild_clears_stale_rows(self):
        db = self.tmp / "summary.sqlite"
        old = self.shard("2026-09-09", [make_flow(dst="9.9.9.9")])
        new = self.shard("2026-10-10", [make_flow(dst="8.8.8.8")])
        distill.ingest(db, [("2026-09-09", old)], verbose=False)
        distill.ingest(db, [("2026-10-10", new)], rebuild=True, verbose=False)
        self.assertEqual([r["date"] for r in self.rows(db, "daily_summary")], ["2026-10-10"])
        self.assertEqual([r["dest_ip"] for r in self.rows(db, "dest_rollup")], ["8.8.8.8"])

    def test_meta_table_tracks_schema_and_provenance(self):
        db = self.tmp / "summary.sqlite"
        s = self.shard("2026-10-05", [make_flow()])
        distill.ingest(db, [("2026-10-05", s)], verbose=False)
        meta = {r[0]: r[1] for r in sqlite3.connect(str(db)).execute("SELECT key,value FROM meta")}
        self.assertEqual(meta["schema_version"], str(distill.SCHEMA_VERSION))
        self.assertEqual(meta["shard_count"], "1")
        self.assertEqual(meta["last_shard"], s.name)
        self.assertEqual(meta["geo_available"], "0")
        self.assertRegex(meta["distilled_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_json_columns_are_valid_and_top_n_bounded(self):
        db = self.tmp / "summary.sqlite"
        flows = [make_flow(src=f"10.0.0.{i}", dst="1.1.1.1", bytes_s2d=i * 100)
                 for i in range(1, 30)]
        s = self.shard("2026-10-06", flows)
        distill.ingest(db, [("2026-10-06", s)], verbose=False)
        row = self.rows(db, "daily_summary")[0]
        talkers = json.loads(row["top_talkers_json"])
        self.assertLessEqual(len(talkers), distill.TOP_N)
        # src IPs are re-stamped by shard(), so rank on the fixture's own order:
        # highest index carries the most bytes.
        self.assertEqual(talkers[0]["ip"], "10.0.0.29", "highest byte talker first")
        self.assertIsInstance(json.loads(row["top_countries_json"]), list)

    def test_dry_run_writes_nothing(self):
        db = self.tmp / "never.sqlite"
        s = self.shard("2026-10-07", [make_flow()])
        stats = distill.ingest(db, [("2026-10-07", s)], verbose=False, dry_run=True)
        self.assertFalse(db.exists(), "dry run created the database file")
        self.assertEqual(stats["dry_run"], True)
        self.assertEqual(stats["flows"], 1)

    def test_schema_columns_match_the_brief(self):
        db = self.tmp / "summary.sqlite"
        connect = distill.connect(db)
        connect.close()
        daily = {c[1] for c in sqlite3.connect(str(db)).execute("PRAGMA table_info(daily_summary)")}
        dest = {c[1] for c in sqlite3.connect(str(db)).execute("PRAGMA table_info(dest_rollup)")}
        self.assertEqual(daily, {"date", "total_flows", "bytes_out", "bytes_in",
                                 "distinct_dests", "alerts", "top_talkers_json",
                                 "top_countries_json"})
        self.assertEqual(dest, {"dest_ip", "iso", "asn_org", "asn", "first_seen",
                                "last_seen", "flows", "bytes", "alert_count"})

    def test_find_shards_sorts_oldest_first_and_skips_junk(self):
        cold = self.tmp / "cold"
        cold.mkdir()
        zstd_compress_lines([json.dumps(make_flow())], cold / "flows-2026-10-02.ndjson.zst")
        zstd_compress_lines([json.dumps(make_flow())], cold / "flows-2026-10-01.ndjson.zst")
        (cold / "notes.txt").write_text("ignore me")
        found = distill.find_shards(cold)
        self.assertEqual([d for d, _ in found], ["2026-10-01", "2026-10-02"])

    def test_cli_end_to_end_with_temp_paths(self):
        cold = self.tmp / "cold"
        cold.mkdir()
        day = "2026-10-08"
        # Build through shard() so the flow's own timestamp matches the shard's
        # date; distill files records by first_seen, not by filename.
        s = self.shard(day, [make_flow(dst="1.1.1.1", score=60)])
        import shutil
        shutil.copy(s, cold / s.name)
        db = self.tmp / "out" / "summary.sqlite"
        rc = distill.main(["--cold", str(cold), "--db", str(db),
                           "--mmdb-dir", str(self.tmp / "nommdb"), "--quiet"])
        self.assertEqual(rc, 0)
        self.assertTrue(db.is_file())
        rows = self.rows(db, "daily_summary")
        self.assertEqual(rows[0]["date"], day)
        self.assertEqual(rows[0]["alerts"], 1)
        self.assertEqual(rows[0]["total_flows"], 1)
        dests = self.rows(db, "dest_rollup")
        self.assertEqual(dests[0]["dest_ip"], "1.1.1.1")
        self.assertEqual(dests[0]["alert_count"], 1)
        # The geo stub was unavailable → columns stay NULL rather than guessing.
        self.assertIsNone(dests[0]["iso"])
        self.assertIsNone(dests[0]["asn"])

    def test_cli_reports_and_writes_nothing_when_geo_absent(self):
        cold = self.tmp / "cold3"
        cold.mkdir()
        self.shard("2026-10-09", [make_flow(dst="4.4.4.4")])
        import shutil
        shutil.copy(self.tmp / "flows-2026-10-09.ndjson.zst", cold / "flows-2026-10-09.ndjson.zst")
        db = self.tmp / "g.sqlite"
        rc = distill.main(["--cold", str(cold), "--db", str(db),
                           "--mmdb-dir", str(self.tmp / "definitely-absent")])
        self.assertEqual(rc, 0)
        meta = {r[0]: r[1] for r in sqlite3.connect(str(db)).execute("SELECT key,value FROM meta")}
        self.assertEqual(meta["geo_available"], "0")

    def test_cli_no_shards_is_a_clean_noop(self):
        rc = distill.main(["--cold", str(self.tmp / "absent"),
                           "--db", str(self.tmp / "x.sqlite"), "--quiet"])
        self.assertEqual(rc, 0)
        self.assertFalse((self.tmp / "x.sqlite").exists())


# ─────────────────────────────────────────────────────────────────────────────
# Task 2: distiller classify() parity with the server ladder
# ─────────────────────────────────────────────────────────────────────────────

class TestDistillClassify(unittest.TestCase):
    def test_high_signal_risk_is_alert(self):
        self.assertEqual(distill.classify(make_flow(risks=["blacklisted_ip"])), "alert")

    def test_score_bands(self):
        self.assertEqual(distill.classify(make_flow(score=0)), "safe")
        self.assertEqual(distill.classify(make_flow(score=20)), "suspicious")
        self.assertEqual(distill.classify(make_flow(score=80)), "alert")

    def test_trusted_asn_suppresses_alert(self):
        f = make_flow(score=80)
        f["_asn"] = {"asn": 15169, "asn_org": "Google LLC"}
        self.assertEqual(distill.classify(f, trusted_asns={15169}), "noise")

    def test_high_signal_risk_beats_trusted_asn(self):
        f = make_flow(risks=["data_exfiltration"])
        f["_asn"] = {"asn": 15169}
        self.assertEqual(distill.classify(f, trusted_asns={15169}), "alert")

    def test_risk_names_normalisation(self):
        f = make_flow(risks=["Known TCP issues"])
        self.assertEqual(distill.risk_names(f), ["known_tcp_issues"])


# ─────────────────────────────────────────────────────────────────────────────
# Task 4: agent surface
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentSurface(TempDirCase):
    NOW = 1_760_000_000.0   # 2025-10-09T00:00:00Z-ish, pinned for determinism

    def build(self, geo=None, threats=None, wl=None):
        return analytics(self.whitelist(wl or {"asns": [], "org_fragments": []}),
                         geo=geo, threats=threats)

    def flows(self, n_alerts=3, n_threats=2, n_old=5):
        out = []
        for i in range(n_alerts):
            out.append(make_flow(dst=f"203.0.113.{i}", score=60,
                                 first_seen=self.NOW - 100 * i,
                                 last_seen=self.NOW - 100 * i))
        for i in range(n_threats):
            out.append(make_flow(dst=f"198.51.100.{i}",
                                 first_seen=self.NOW - 50 * i,
                                 last_seen=self.NOW - 50 * i))
        for i in range(n_old):
            out.append(make_flow(dst=f"192.0.2.{i}",
                                 score=60, first_seen=self.NOW - 90_000,
                                 last_seen=self.NOW - 90_000))
        return out

    def test_status_shape_and_required_keys(self):
        threats = StubThreats(ips=[f"198.51.100.{i}" for i in range(2)])
        a = self.build(threats=threats)
        fl = a.enrich(self.flows())
        st = a.agent_status(fl, retention_days=7, now=self.NOW)
        for key in ("generated_at", "hot_flow_count", "retention_days", "db_size_mb",
                    "cold_shard_count", "alerts_last_24h", "threat_hits_last_24h",
                    "top_anomalous_dests", "geo", "threat_feed"):
            self.assertIn(key, st)
        self.assertEqual(st["retention_days"], 7)
        self.assertEqual(st["hot_flow_count"], len(fl))

    def test_status_caps_alerts_at_50_newest_first(self):
        a = self.build()
        fl = a.enrich([make_flow(dst=f"203.0.113.{i % 250}", score=60,
                                 first_seen=self.NOW - i, last_seen=self.NOW - i)
                       for i in range(120)])
        st = a.agent_status(fl, now=self.NOW)
        self.assertLessEqual(len(st["alerts_last_24h"]), 50)
        self.assertEqual(st["alert_count_last_24h"], 120, "count must survive array cap")
        ts = [e["t"] for e in st["alerts_last_24h"]]
        self.assertEqual(ts, sorted(ts, reverse=True), "newest first")

    def test_old_flows_excluded_from_24h_windows(self):
        a = self.build()
        fl = a.enrich(self.flows(n_alerts=1, n_threats=0, n_old=4))
        st = a.agent_status(fl, now=self.NOW)
        self.assertEqual(st["alert_count_last_24h"], 1)

    def test_status_stays_under_32kb_under_pressure(self):
        """Brief: 'Keep it under ~32 kB always (cap arrays explicitly)'."""
        threats = StubThreats(ips=[f"198.51.100.{i}" for i in range(60)])
        a = self.build(threats=threats)
        # 400 alerty flows + a big scanner fan-out, worst realistic case.
        fl = a.enrich([make_flow(src=f"10.0.{i // 250}.{i % 250}",
                                 dst=f"198.51.100.{i % 60}", score=60,
                                 dport=1000 + (i % 500),
                                 first_seen=self.NOW - i, last_seen=self.NOW - i)
                       for i in range(400)])
        st = a.agent_status(fl, now=self.NOW)
        body = json.dumps(st, separators=(",", ":")).encode()
        self.assertLessEqual(len(body), 32_000, f"status payload is {len(body)} bytes")
        self.assertTrue(st.get("_fits_budget", True))

    def test_scanners_appear_as_anomalous_dests(self):
        a = self.build()
        # One source probing 30 distinct ports → scanner detection threshold is 5.
        fl = a.enrich([make_flow(src="10.9.8.7", dst="203.0.113.9", dport=1000 + i,
                                 bytes_s2d=60, bytes_d2s=0, bidirectional=0,
                                 first_seen=self.NOW - i, last_seen=self.NOW - i)
                       for i in range(30)])
        st = a.agent_status(fl, now=self.NOW)
        ips = {e["ip"] for e in st["top_anomalous_dests"]}
        self.assertIn("10.9.8.7", ips)

    def test_diff_returns_only_events_after_since(self):
        a = self.build()
        fl = a.enrich(self.flows(n_alerts=3, n_threats=2, n_old=5))
        cutoff = self.NOW - 300
        d = a.agent_diff(fl, since=cutoff, now=self.NOW)
        self.assertGreater(d["event_count"], 0)
        for ev in d["events"]:
            self.assertGreater(ev["t"], cutoff)

    def test_diff_accepts_iso8601(self):
        a = self.build()
        fl = a.enrich(self.flows(n_alerts=2, n_threats=0, n_old=0))
        iso = datetime.fromtimestamp(self.NOW - 60, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        d = a.agent_diff(fl, since=iso, now=self.NOW)
        self.assertGreater(d["event_count"], 0)

    def test_diff_bad_since_defaults_to_last_hour_with_warning(self):
        a = self.build()
        fl = a.enrich(self.flows(n_alerts=2, n_threats=0, n_old=3))
        d = a.agent_diff(fl, since="yesterday-ish", now=self.NOW)
        self.assertIn("warning", d)
        self.assertGreaterEqual(d["since"], self.NOW - 3601)

    def test_diff_cursor_round_trip_is_monotonic(self):
        a = self.build()
        fl = a.enrich(self.flows())
        first = a.agent_diff(fl, since=self.NOW - 10_000, now=self.NOW)
        second = a.agent_diff(fl, since=first["cursor"], now=self.NOW + 1)
        self.assertEqual(second["event_count"], 0,
                         "polling with the returned cursor must yield an empty delta")

    def test_diff_kind_labels_are_correct(self):
        threats = StubThreats(ips=["198.51.100.0", "198.51.100.1"])
        a = self.build(threats=threats)
        fl = a.enrich(self.flows(n_alerts=2, n_threats=2, n_old=0))
        d = a.agent_diff(fl, since=self.NOW - 600, now=self.NOW)
        kinds = {ev["kind"] for ev in d["events"]}
        self.assertIn("threat", kinds)
        self.assertIn("alert", kinds)
        self.assertNotIn("safe", kinds)

    def test_diff_limit_and_truncated_flag(self):
        a = self.build()
        fl = a.enrich([make_flow(dst=f"203.0.113.{i % 250}", score=60,
                                 first_seen=self.NOW - i, last_seen=self.NOW - i)
                       for i in range(40)])
        d = a.agent_diff(fl, since=self.NOW - 10_000, now=self.NOW, limit=10)
        self.assertEqual(len(d["events"]), 10)
        self.assertTrue(d["truncated"])
        self.assertEqual(d["event_count"], 40)

    def test_event_records_are_compact_not_full_flow_objects(self):
        a = self.build()
        fl = a.enrich(self.flows(n_alerts=1, n_threats=0, n_old=0))
        st = a.agent_status(fl, now=self.NOW)
        ev = st["alerts_last_24h"][0]
        self.assertNotIn("xfer", ev, "raw sub-objects must not leak into the agent view")
        self.assertNotIn("plen_bins", ev)
        self.assertLess(len(json.dumps(ev)), 600)

    def test_shrink_to_budget_reports_what_it_dropped(self):
        payload = {"events": [{"t": i, "blob": "x" * 200} for i in range(500)]}
        out = fs._shrink_to_budget(payload, 4000, drop_key="events")
        self.assertLessEqual(len(json.dumps(out, separators=(",", ":")).encode()), 4000)
        self.assertIn("capped", out)
        self.assertEqual(out["capped"]["events"], 500)

    def test_shrink_leaves_small_payload_untouched(self):
        payload = {"a": [1, 2, 3]}
        self.assertEqual(fs._shrink_to_budget(dict(payload), 10_000), payload)

    def test_parse_iso_maybe_formats(self):
        base = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc).timestamp()
        self.assertAlmostEqual(fs.parse_iso_maybe("2026-10-05T12:00:00Z"), base)
        self.assertAlmostEqual(fs.parse_iso_maybe("2026-10-05T12:00:00+00:00"), base)
        self.assertAlmostEqual(fs.parse_iso_maybe("2026-10-05"),
                               datetime(2026, 10, 5, tzinfo=timezone.utc).timestamp())
        self.assertAlmostEqual(fs.parse_iso_maybe("1760000000"), 1_760_000_000.0)
        for junk in ("", "  ", "nope", "2026-13-45T99:99:99Z"):
            self.assertIsNone(fs.parse_iso_maybe(junk))

    def test_dir_size_and_shard_count_helpers_are_safe_when_absent(self):
        self.assertIsNone(fs._dir_size_mb(str(self.tmp / "does-not-exist")))
        self.assertEqual(fs._count_cold_shards(str(self.tmp / "no-cold")), 0)
        cold = self.tmp / "cold2"
        cold.mkdir()
        zstd_compress_lines(["{}"], cold / "flows-2026-10-01.ndjson.zst")
        zstd_compress_lines(["{}"], cold / "flows-2026-10-02.ndjson.zst")
        (cold / "other.zst").write_bytes(b"x")
        self.assertEqual(fs._count_cold_shards(str(cold)), 2)


# ─────────────────────────────────────────────────────────────────────────────
# Acceptance gate 5: threat_intel.py offline safety (dry-run, unreachable URL)
# ─────────────────────────────────────────────────────────────────────────────

class TestThreatIntelOfflineSafety(TempDirCase):
    def test_unreachable_base_url_leaves_previous_file_intact(self):
        import threat_intel as ti

        out = self.tmp / "threats.json"
        seed = {"retrieved_at": "2026-10-04T00:00:00Z", "epoch": 1_791_086_400,
                "source": "seed", "ips": ["1.2.3.4"], "cidrs": [],
                "count_ips": 1, "count_cidrs": 0}
        out.write_text(json.dumps(seed))
        before = out.read_text()

        # 127.0.0.1:9 (discard port) refuses connections instantly — no wait.
        rc = ti.main(["--base-url", "http://127.0.0.1:9", "--out", str(out),
                      "--once", "--dry-run", "--quiet"])
        self.assertIn(rc, (0, 1))
        self.assertEqual(out.read_text(), before,
                         "offline run modified threats.json")

    def test_run_once_total_outage_keeps_blocklist_offline(self):
        """Acceptance gate 5, end to end through run_once().

        The helper-level test below only exercises merge_sources() directly, so
        it stayed green while the real path blanked threats.json on an outage:
        run_once() was reading per-source sets out of the flat document, where
        they never existed. This test drives the actual function with a stubbed
        transport and asserts the blocklist survives a total outage intact.
        """
        import threat_intel as ti

        out = self.tmp / "threats.json"

        def fake_fetch(name, feed, base_url=None, timeout=None, log=print):
            return ({"ok": True, "url": feed["url"],
                     "retrieved_at": "2026-10-05T00:00:00Z",
                     "ips": [f"203.0.113.{len(name)}"], "cidrs": ["198.18.0.0/24"]},
                    None)

        original = ti.fetch_source
        try:
            ti.fetch_source = fake_fetch
            doc1 = ti.run_once(str(out), only={"feodotracker"}, log=lambda *a: None)
            self.assertEqual(doc1["count_ips"], 1)
            self.assertTrue(ti.sources_path(str(out)).endswith("threats.sources.json"))
            self.assertTrue(Path(ti.sources_path(str(out))).is_file(),
                            "sidecar must be written so outages have something to carry")
            ips_after_success = list(doc1["ips"])

            # Now every fetch fails — a total outage.
            def dead(name, feed, base_url=None, timeout=None, log=print):
                return None, "URLError: connection refused"
            ti.fetch_source = dead
            doc2 = ti.run_once(str(out), only={"feodotracker"}, log=lambda *a: None)
        finally:
            ti.fetch_source = original

        self.assertEqual(sorted(doc2["ips"]), sorted(ips_after_success),
                         "outage must not drop previously good threat IPs")
        self.assertEqual(doc2["cidrs"], ["198.18.0.0/24"])
        self.assertEqual(doc2.get("stale_sources"), ["feodotracker"],
                         "failed sources are flagged stale, not deleted")
        live = json.loads(out.read_text())
        self.assertEqual(sorted(live["ips"]), sorted(ips_after_success))

    def test_disabled_feed_history_survives_later_passes(self):
        """A source switched off by --no-threatfox keeps its last-good IPs.

        build_document() skips sources with no URL, so a carried-forward record
        that lost its url would silently shrink the blocklist whenever one feed
        is disabled.
        """
        import threat_intel as ti

        out = self.tmp / "t2" / "threats.json"

        def fake_fetch(name, feed, base_url=None, timeout=None, log=print):
            return ({"ok": True, "url": feed["url"],
                     "retrieved_at": "2026-10-05T00:00:00Z",
                     "ips": [f"203.0.113.{len(name)}"], "cidrs": []}, None)

        original = ti.fetch_source
        try:
            ti.fetch_source = fake_fetch
            all_three = {"feodotracker", "urlhaus", "threatfox"}
            full = ti.run_once(str(out), only=all_three, log=lambda *a: None)
            self.assertEqual(len(full["ips"]), 3)

            # Threatfox now disabled; the other two fetched again.
            ti.fetch_source = lambda name, feed, base_url=None, timeout=None, log=print: (
                {"ok": True, "url": feed["url"],
                 "retrieved_at": "2026-10-05T01:00:00Z",
                 "ips": [f"203.0.113.{len(name)}"], "cidrs": []}, None)
            partial = ti.run_once(str(out), only={"feodotracker", "urlhaus"},
                                  log=lambda *a: None)
        finally:
            ti.fetch_source = original

        self.assertEqual(len(partial["ips"]), 3,
                         "disabled feed's history must still be loaded")
        self.assertIn("threatfox", partial["source"].split("+"))

    def test_offline_run_preserves_last_good_ips(self):
        """Total outage must keep the effective blocklist, not blank it."""
        import threat_intel as ti

        state = self.tmp / "threats.json"
        seed = {"retrieved_at": "2026-10-04T00:00:00Z", "epoch": 1_791_086_400,
                "source": "feodotracker", "ips": ["1.2.3.4", "5.6.7.8"],
                "cidrs": ["198.51.100.0/24"], "count_ips": 2, "count_cidrs": 1}
        state.write_text(json.dumps(seed))

        # load_previous() reads the document; merge_sources() carries each
        # source's last-good set forward when a fresh fetch fails.
        previous = ti.load_previous(str(state))
        self.assertEqual(sorted(previous["ips"]), ["1.2.3.4", "5.6.7.8"])

        merged = ti.merge_sources({"feodotracker": {"ips": previous["ips"],
                                                   "cidrs": previous["cidrs"]}}, {})
        self.assertIn("1.2.3.4", merged["feodotracker"]["ips"])
        self.assertEqual(merged["feodotracker"]["cidrs"], ["198.51.100.0/24"])

        doc = ti.build_document(merged)
        self.assertIn("1.2.3.4", doc["ips"])
        self.assertIn("198.51.100.0/24", doc["cidrs"])

    def test_feeds_are_ipv4_only_and_parsed_deterministically(self):
        import threat_intel as ti
        csv_text = ("first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware\n"
                    "2026-10-01 00:00:00,185.220.101.1,443,online,2026-10-04,Emotet\n"
                    "2026-10-02 00:00:00,185.220.101.1,50001,online,2026-10-05,Emotet\n"
                    "# comment line\n"
                    "\n")
        parsed = ti.parse_feodo_csv(csv_text)
        self.assertEqual(parsed["ips"], ["185.220.101.1"], "duplicate IPs collapse")
        self.assertEqual(parsed["cidrs"], [])
        self.assertEqual(parsed["rejected"], 0)

    def test_urlhaus_only_yields_literal_ipv4_hosts(self):
        import threat_intel as ti
        text = ("http://185.220.101.7/m\r\n"
                "https://malware.example.org/payload.exe\r\n"
                "# comment\r\n")
        parsed = ti.parse_urlhaus_urls(text)
        self.assertIn("185.220.101.7", parsed["ips"])
        self.assertNotIn("malware.example.org", parsed["ips"])

    def test_invalid_ipv4_strings_are_rejected(self):
        import threat_intel as ti
        for bad in ("10.1", "0x1.2.3.4", "256.0.0.1", "1.2.3.4.5", "", "1.2.3.", "::1"):
            self.assertFalse(ti.valid_ipv4(bad), f"must reject {bad!r}")
        for good in ("1.2.3.4", "10.0.0.1", "255.255.255.255", "0.0.0.0"):
            self.assertTrue(ti.valid_ipv4(good))

    def test_atomic_write_helper_leaves_no_temp_files(self):
        import threat_intel as ti
        target = self.tmp / "sub" / "out.json"
        ti.atomic_write_json(str(target), {"ips": ["1.2.3.4"]})
        self.assertTrue(target.is_file())
        self.assertEqual(json.loads(target.read_text())["ips"], ["1.2.3.4"])
        leftovers = [p.name for p in target.parent.iterdir() if p.name != "out.json"]
        self.assertEqual(leftovers, [], f"temp files left behind: {leftovers}")

    def test_urlhaus_falls_back_to_full_text_export(self):
        """URLhaus recent endpoint down → fetch_source retries the full text/ variant."""
        import threat_intel as ti
        feed = ti.FEEDS["urlhaus"]
        self.assertIn("fallback_url", feed,
                      "urlhaus feed must declare a fallback variant")
        primary, fallback = feed["url"], feed["fallback_url"]

        seen = []

        def fake_fetch_url(url, timeout=None, log=print):
            seen.append(url)
            if url == primary:
                raise RuntimeError("primary text_recent is 503")
            return b"http://203.0.113.9/bin.sh\n# banner\n"

        original = ti.fetch_url
        try:
            ti.fetch_url = fake_fetch_url
            record, err = ti.fetch_source("urlhaus", feed, log=lambda *a: None)
        finally:
            ti.fetch_url = original

        self.assertIsNone(err, "fallback success must not report an error")
        self.assertIsNotNone(record)
        self.assertTrue(record["ok"])
        self.assertEqual(seen, [primary, fallback],
                         "must try primary first, then the fallback URL")
        self.assertEqual(record["url"], fallback,
                         "record.url reflects the endpoint that actually served")
        self.assertTrue(record.get("via_fallback"))
        self.assertIn("203.0.113.9", record["ips"])

    def test_stale_sources_lists_every_failed_feed_sorted(self):
        """stale_sources flags all ok:false sources (not just one), sorted, healthy omitted."""
        import threat_intel as ti
        out = self.tmp / "stale_multi.json"

        # Pass 1: every feed succeeds, so each gets last-good history in the
        # sidecar. A failure with no prior data is dropped outright, not marked
        # stale — this seeds the history that makes the stale flag meaningful.
        def good(name, feed, base_url=None, timeout=None, log=print):
            return ({"ok": True, "url": feed["url"],
                     "retrieved_at": "2026-10-05T00:00:00Z",
                     "ips": ["203.0.113.%d" % len(name)], "cidrs": []}, None)

        # Pass 2: feodotracker + threatfox fail; urlhaus still healthy. Their
        # carried-forward records must be flagged stale (sorted), urlhaus not.
        def partly(name, feed, base_url=None, timeout=None, log=print):
            if name in ("feodotracker", "threatfox"):
                return None, "URLError: connection refused"
            return ({"ok": True, "url": feed["url"],
                     "retrieved_at": "2026-10-05T01:00:00Z",
                     "ips": ["203.0.113.%d" % len(name)], "cidrs": []}, None)

        original = ti.fetch_source
        try:
            ti.fetch_source = good
            ti.run_once(str(out), only={"feodotracker", "urlhaus", "threatfox"},
                        log=lambda *a: None)
            ti.fetch_source = partly
            doc = ti.run_once(str(out), only={"feodotracker", "urlhaus", "threatfox"},
                              log=lambda *a: None)
        finally:
            ti.fetch_source = original

        self.assertEqual(doc.get("stale_sources"), ["feodotracker", "threatfox"],
                         "both failed feeds flagged, sorted, healthy urlhaus omitted")
        self.assertNotIn("urlhaus", doc.get("stale_sources", []))


if __name__ == "__main__":
    unittest.main(verbosity=2)

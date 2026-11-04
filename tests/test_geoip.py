import gzip
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from analyze import analyze, to_markdown  # noqa: E402
from geoip import GeoResolver, Ip2AsnDb, MaxMindDb  # noqa: E402

# Tiny iptoasn-format fixture using made-up AS numbers on public ranges.
TSV = (
    "1.0.0.0\t1.0.0.255\t64500\tAU\tEXAMPLE-NET-A\n"
    "8.8.8.0\t8.8.8.255\t64501\tUS\tEXAMPLE-NET-B\n"
    "9.9.0.0\t9.9.255.255\t0\tNone\tNot routed\n"
    "2001:4860::\t2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\t64502\tUS\tEXAMPLE-V6\n"
    "garbage line\n"
)


def _ev(ip, n=1):
    return [{"event": "login_attempt", "service": "telnet", "src_ip": ip, "username": "root",
             "password": "x", "timestamp": "2025-01-01T10:00:00"}] * n


class GeoIpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "ip2asn.tsv"
        self.path.write_text(TSV, encoding="utf-8")

    def test_ip2asn_lookup(self):
        db = Ip2AsnDb(self.path)
        self.assertEqual(db.lookup("1.0.0.77")["asn"], 64500)
        self.assertEqual(db.lookup("1.0.0.77")["country_code"], "AU")
        self.assertEqual(db.lookup("2001:4860::8888")["as_org"], "EXAMPLE-V6")
        self.assertIsNone(db.lookup("9.9.1.1")["asn"])      # AS0 = unrouted
        self.assertIsNone(db.lookup("1.0.1.1")["asn"])      # gap between ranges
        self.assertIsNone(db.lookup("0.0.0.1")["asn"])      # before first range

    def test_gzip_database(self):
        gz = Path(self.tmp.name) / "ip2asn.tsv.gz"
        with gzip.open(gz, "wt", encoding="utf-8") as f:
            f.write(TSV)
        self.assertEqual(Ip2AsnDb(gz).lookup("8.8.8.8")["asn"], 64501)

    def test_resolver_scopes_and_cache(self):
        geo = GeoResolver.from_paths(ip2asn=self.path)
        self.assertEqual(geo.lookup("192.168.1.5")["scope"], "private/reserved")
        self.assertEqual(geo.lookup("203.0.113.9")["scope"], "private/reserved")  # TEST-NET-3
        self.assertEqual(geo.lookup("not-an-ip")["scope"], "invalid")
        self.assertEqual(geo.lookup("8.8.8.8")["country_code"], "US")
        self.assertIs(geo.lookup("8.8.8.8"), geo.lookup("8.8.8.8"))

    def test_report_enrichment(self):
        geo = GeoResolver.from_paths(ip2asn=self.path)
        events = _ev("8.8.8.8", 6) + _ev("1.0.0.1", 2) + _ev("10.0.0.1") + _ev("5.5.5.5")
        r = analyze(events, brute_threshold=5, geo=geo)
        self.assertEqual(r["top_countries"][0], ("US", 6))
        self.assertIn(("Private/Reserved", 1), r["top_countries"])
        self.assertIn(("Unknown", 1), r["top_countries"])
        self.assertEqual(r["top_asns"][0], ("AS64501 EXAMPLE-NET-B", 6))
        md = to_markdown(r)
        self.assertIn("| IP | Attempts | Country | ASN |", md)
        self.assertIn("Top source countries", md)
        self.assertIn("`8.8.8.8`: 6 attempts (US, AS64501 EXAMPLE-NET-B)", md)

    def test_maxmind_record_parsing(self):
        city_rec = {"country": {"iso_code": "KE", "names": {"en": "Kenya"}},
                    "city": {"names": {"en": "Nairobi"}}}
        asn_rec = {"autonomous_system_number": 64503, "autonomous_system_organization": "EX-ISP"}

        class FakeReader:
            def __init__(self, rec):
                self.rec = rec

            def get(self, ip):
                return self.rec

            def close(self):
                pass

        fake = types.SimpleNamespace(open_database=lambda path: FakeReader(
            city_rec if "city" in path else asn_rec))
        with mock.patch.dict(sys.modules, {"maxminddb": fake}):
            geo = GeoResolver.from_paths(city="city.mmdb", asn="asn.mmdb")
        info = geo.lookup("41.80.0.1")
        self.assertEqual((info["country_code"], info["country"], info["city"]),
                         ("KE", "Kenya", "Nairobi"))
        self.assertEqual((info["asn"], info["as_org"]), (64503, "EX-ISP"))

    def test_without_geo_output_unchanged(self):
        r = analyze(_ev("8.8.8.8", 6))
        self.assertNotIn("ip_info", r)
        md = to_markdown(r)
        self.assertIn("| IP | Attempts |\n", md)
        self.assertNotIn("Country", md)


if __name__ == "__main__":
    unittest.main()

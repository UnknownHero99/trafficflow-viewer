"""Run with:  python3 -m unittest discover tests"""

import os
import random
import sqlite3
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "tools")]

import fakeflow  # noqa: E402
from mmdb_writer import write  # noqa: E402
from tfv import mmdb, queries  # noqa: E402
from tfv.geo import Geo  # noqa: E402
from tfv.netflow import Decoder, Flow  # noqa: E402
from tfv.store import Classifier, Store  # noqa: E402


def sample_records(n=5):
    random.seed(42)
    recs = []
    for _ in range(n):
        recs += fakeflow.random_flow()
    return recs


class DecoderTest(unittest.TestCase):
    def check(self, build, expect_mac):
        recs = sample_records()
        d = Decoder()
        flows = d.decode(build(recs, 0, True), "10.0.0.1")
        self.assertEqual(len(flows), len(recs))
        for f, r in zip(flows, recs):
            self.assertEqual((f.src, f.dst, f.sport, f.dport, f.proto, f.bytes, f.packets),
                             tuple(r[:7]))
            self.assertEqual(f.src_mac, r[7] if expect_mac else None)
        # data-only packet reuses the cached template
        more = sample_records(6)[len(recs):]
        self.assertEqual(len(d.decode(build(more, 1, False), "10.0.0.1")), len(more))
        self.assertEqual(d.stats["errors"], 0)

    def test_v5(self):
        self.check(fakeflow.pkt_v5, expect_mac=False)

    def test_v9(self):
        self.check(fakeflow.pkt_v9, expect_mac=True)

    def test_ipfix(self):
        self.check(fakeflow.pkt_ipfix, expect_mac=True)

    def test_duplicates_dropped(self):
        recs = sample_records()
        for build in (fakeflow.pkt_v5, fakeflow.pkt_v9, fakeflow.pkt_ipfix):
            d = Decoder()
            pkt = build(recs, 0, True)
            self.assertEqual(len(d.decode(pkt, "10.0.0.1")), len(recs))
            self.assertEqual(d.decode(pkt, "10.0.0.1"), [])   # same packet again
            self.assertEqual(d.stats["duplicates"], len(recs))
            # same records from another router are not duplicates
            self.assertEqual(len(d.decode(pkt, "10.0.0.2")), len(recs))

    def test_missing_template(self):
        d = Decoder()
        self.assertEqual(d.decode(fakeflow.pkt_ipfix(sample_records(), 0, False), "x"), [])
        self.assertEqual(d.stats["no_template"], 1)

    def test_garbage(self):
        d = Decoder()
        self.assertEqual(d.decode(b"\x00\x0a\xff\xff" + os.urandom(40), "x"), [])
        self.assertEqual(d.decode(b"\x01", "x"), [])


class MmdbTest(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "t.mmdb")
            write(p, [("1.2.3.0/24", {"country": {"iso_code": "AU"}}),
                      ("2001:db8::/32", {"country": {"iso_code": "DE"}})])
            r = mmdb.Reader(p)
            self.assertEqual(r.get("1.2.3.4")["country"]["iso_code"], "AU")
            self.assertIsNone(r.get("1.2.4.4"))
            self.assertEqual(r.get("2001:db8::1")["country"]["iso_code"], "DE")

    def test_pointers(self):
        r = mmdb.Reader.__new__(mmdb.Reader)
        # data: "US" at 0, then a map {"cc": <pointer to 0>} at 3
        r.buf = bytes([0x42]) + b"US" + bytes([0xE1, 0x42]) + b"cc" + bytes([0x20, 0x00])
        self.assertEqual(r._decode(3, 0), ({"cc": "US"}, 9))
        # 2-byte pointer form (+2048 bias)
        big = bytearray(2100)
        big[2048:2051] = bytes([0x42]) + b"SI"
        big[2051:2054] = bytes([0x28, 0x00, 0x00])
        r.buf = bytes(big)
        self.assertEqual(r._decode(2051, 0)[0], "SI")


class StoreTest(unittest.TestCase):
    def test_classify_and_aggregate(self):
        with tempfile.TemporaryDirectory() as tmp:
            fakeflow.write_demo_geo(tmp)
            geo = Geo(tmp, auto_download=False)
            geo.start()
            st = Store(os.path.join(tmp, "db.sqlite"), geo,
                       Classifier(["192.168.0.0/16"], ["224.0.0.0/4"]))

            def flow(src, dst, sport, dport, nbytes, nat_dst=None):
                f = Flow()
                f.src, f.dst, f.sport, f.dport, f.proto = src, dst, sport, dport, 6
                f.bytes, f.packets, f.nat_dst = nbytes, 1, nat_dst
                return f

            st.add_flows([
                flow("192.168.1.5", "142.250.1.1", 50000, 443, 100),     # upload
                flow("142.250.1.1", "192.168.1.5", 443, 50000, 5000),    # download
                # download seen on WAN before un-NAT: post-NAT dst identifies device
                flow("193.2.1.1", "203.0.113.7", 443, 51000, 700, nat_dst="192.168.1.6"),
                flow("203.0.113.7", "8.8.8.8", 1, 53, 50),               # router itself
                flow("192.168.1.5", "224.0.0.251", 5353, 5353, 50),      # multicast
            ], now=1_000_000)
            st.flush()
            self.assertEqual(st.stats["unclassified_flows"], 1)
            self.assertEqual(st.stats["ignored_flows"], 1)
            db = st.db()
            db.row_factory = sqlite3.Row
            s = queries.summary(db, {"from": "999000", "to": "1001000"}, 60)
            self.assertEqual((s["totals"]["up"], s["totals"]["down"]), (100, 5700))
            cc = {r["cc"]: r for r in s["countries"]}
            self.assertEqual(cc["US"]["down"], 5000)
            self.assertEqual(cc["SI"]["down"], 700)
            dev = {r["ip"]: r for r in s["devices"]}
            self.assertEqual(set(dev), {"192.168.1.5", "192.168.1.6"})
            tl = queries.country_timeline(db, {"from": "999000", "to": "1001000"}, 60)
            self.assertEqual(tl["countries"], ["US", "SI"])
            self.assertEqual(sum(c[2] for c in tl["cells"]), 5700)
            st.set_device_name("192.168.1.5", "Laptop")
            st.set_device_name("192.168.1.5", "dhcp-name", source="dhcp")
            name = db.execute("SELECT name FROM devices WHERE ip='192.168.1.5'").fetchone()[0]
            self.assertEqual(name, "Laptop")  # DHCP never overrides a manual name


if __name__ == "__main__":
    unittest.main()

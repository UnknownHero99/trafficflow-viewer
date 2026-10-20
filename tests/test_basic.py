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


class AgentTest(unittest.TestCase):
    def test_hex_ip(self):
        from tfv.agent import _hex_ip
        self.assertEqual(_hex_ip("0100007F"), "127.0.0.1")
        self.assertEqual(_hex_ip("0A0AA8C0"), "192.168.10.10")
        self.assertEqual(_hex_ip("00000000000000000000000001000000"), "::1")

    def test_proc_sockets(self):
        from tfv.agent import proc_sockets
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "net"))
            hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            with open(os.path.join(tmp, "net", "tcp"), "w") as fh:
                fh.write(hdr)
                fh.write("   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1\n")
                fh.write("   1: 0A0AA8C0:B3F2 01010101:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 222 1\n")
                fh.write("   2: 0A0AA8C0:B3F3 01010101:01BB 06 00000000:00000000 00:00000000 00000000  1000        0 0 1\n")
            got = list(proc_sockets(tmp))
        self.assertEqual(got, [(6, "0.0.0.0", 8080, "0.0.0.0", 0, 111, True),
                               (6, "192.168.10.10", 46066, "1.1.1.1", 443, 222, False)])

    def test_conntrack_parsing_and_nat_matching(self):
        from unittest import mock
        from tfv import agent as ag
        out = ("tcp      6 431999 ESTABLISHED src=172.17.0.5 dst=1.1.1.1 sport=40000 dport=443 "
               "src=1.1.1.1 dst=192.168.10.10 sport=443 dport=40001 [ASSURED] mark=0 use=1\n"
               "udp      17 25 src=192.168.10.20 dst=192.168.10.10 sport=5000 dport=5353 "
               "src=172.17.0.6 dst=192.168.10.20 sport=53 dport=5000 mark=0 use=1\n")
        res = mock.Mock(returncode=0, stdout=out, stderr="")
        with mock.patch.object(ag.subprocess, "run", return_value=res), \
             mock.patch.object(ag, "docker_containers", return_value=[
                 {"id": "a" * 64, "name": "web", "ips": {"172.17.0.5"}, "ports": []},
                 {"id": "b" * 64, "name": "dns", "ips": {"172.17.0.6"}, "ports": [("*", 17, 5353)]}]), \
             mock.patch.object(ag, "proc_sockets", return_value=[]):
            exact, bound, ips = ag.Agent("http://x", "t").collect()
        self.assertIn(("192.168.10.10", 6, 40001, "1.1.1.1", 443, "web"), exact)   # masqueraded out
        self.assertIn(("192.168.10.10", 17, 5353, "192.168.10.20", 5000, "dns"), exact)  # published in
        self.assertIn(("*", 17, 5353, "dns"), bound)
        self.assertEqual(ips, {"192.168.10.10"})


class AttributionTest(unittest.TestCase):
    def test_lookup_and_store(self):
        from tfv.attribution import Attribution
        attr = Attribution()
        attr.report("srv", [("192.168.1.5", 6, 50000, "142.250.1.1", 443, "backup")],
                    [("*", 17, 53, "pihole")], {"192.168.1.5"})
        self.assertEqual(attr.lookup("192.168.1.5", 6, 50000, "142.250.1.1", 443), "backup")
        self.assertEqual(attr.lookup("192.168.1.5", 17, 53, "8.8.8.8", 40000), "pihole")
        self.assertEqual(attr.lookup("192.168.1.5", 6, 1234, "8.8.8.8", 443), "")
        self.assertEqual(attr.lookup("192.168.1.9", 6, 50000, "142.250.1.1", 443), "")  # no agent
        with tempfile.TemporaryDirectory() as tmp:
            fakeflow.write_demo_geo(tmp)
            geo = Geo(tmp, auto_download=False)
            geo.start()
            st = Store(os.path.join(tmp, "db.sqlite"), geo, Classifier(["192.168.0.0/16"]),
                       attribution=attr)
            up, down = Flow(), Flow()
            up.src, up.dst, up.sport, up.dport, up.proto, up.bytes, up.packets = \
                "192.168.1.5", "142.250.1.1", 50000, 443, 6, 100, 1
            # download seen on the WAN side: public address + post-NAT fields
            down.src, down.dst, down.sport, down.dport, down.proto, down.bytes, down.packets = \
                "142.250.1.1", "203.0.113.7", 443, 61000, 6, 5000, 4
            down.nat_dst, down.nat_dport = "192.168.1.5", 50000
            st.add_flows([up, down], now=1_000_000)
            st.flush()
            s = queries.summary(st.db(), {"from": "999000", "to": "1001000"}, 60)
            self.assertEqual([(r["app"], r["up"], r["down"]) for r in s["apps"]], [("backup", 100, 5000)])


class LocalTrafficTest(unittest.TestCase):
    def _store(self, tmp):
        fakeflow.write_demo_geo(tmp)
        geo = Geo(tmp, auto_download=False)
        geo.start()
        return Store(os.path.join(tmp, "db.sqlite"), geo, Classifier(["192.168.0.0/16"]))

    @staticmethod
    def _flow(src, dst, sport, dport, nbytes):
        f = Flow()
        f.src, f.dst, f.sport, f.dport, f.proto, f.bytes, f.packets = src, dst, sport, dport, 6, nbytes, 1
        return f

    def test_both_ends_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = self._store(tmp)
            # Jellyfin on 192.168.10.10 streams to a TV on 192.168.1.102
            st.add_flows([self._flow("192.168.10.10", "192.168.1.102", 8096, 51000, 900_000),
                          self._flow("192.168.1.102", "192.168.10.10", 51000, 8096, 20_000)], now=1_000_000)
            st.flush()
            p = {"from": "999000", "to": "1001000"}
            dev = {r["ip"]: r for r in queries.summary(st.db(), p, 60)["devices"]}
            self.assertEqual((dev["192.168.10.10"]["up"], dev["192.168.10.10"]["down"]), (900_000, 20_000))
            self.assertEqual((dev["192.168.1.102"]["up"], dev["192.168.1.102"]["down"]), (20_000, 900_000))
            # shown by default, hidden with lan=0
            self.assertEqual(queries.summary(st.db(), p, 60)["totals"]["down"], 920_000)
            self.assertEqual(queries.summary(st.db(), {**p, "lan": "0"}, 60)["totals"]["down"], 0)

    def test_backfill_old_rows_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = self._store(tmp)
            db = st.db()
            # how an older version stored the stream: only the sender's upload
            db.execute("""INSERT INTO traffic (bucket, local_ip, remote_ip, port, proto, app, country, asn,
                              bytes_up, bytes_down, pkts_up, pkts_down, flows)
                          VALUES (999960, '192.168.10.10', '192.168.1.102', 8096, 6, '', 'LAN', 0,
                                  900000, 0, 600, 0, 1)""")
            db.execute("PRAGMA user_version = 1")
            db.commit()
            for _ in range(2):  # second start must not add it again
                st = Store(os.path.join(tmp, "db.sqlite"), st.geo, Classifier(["192.168.0.0/16"]))
            row = st.db().execute("""SELECT bytes_up, bytes_down FROM traffic
                                     WHERE local_ip = '192.168.1.102'""").fetchone()
            self.assertEqual(tuple(row), (0, 900000))


class Ipv6MergeTest(unittest.TestCase):
    def test_eui64(self):
        from tfv.store import eui64_mac
        self.assertEqual(eui64_mac("fe80::9e13:9eff:fe0a:4683"), "9c:13:9e:0a:46:83")
        self.assertIsNone(eui64_mac("fd12:3456:789a:1:8a55:c3c0:37fb:ae10"))  # privacy address
        self.assertIsNone(eui64_mac("192.168.1.1"))

    def test_ipv6_filed_under_device(self):
        with tempfile.TemporaryDirectory() as tmp:
            fakeflow.write_demo_geo(tmp)
            geo = Geo(tmp, auto_download=False)
            geo.start()
            path = os.path.join(tmp, "db.sqlite")
            st = Store(path, geo, Classifier(["192.168.0.0/16", "fc00::/7", "fe80::/10"]))

            def flow(src, dst, nbytes, src_mac=None):
                f = Flow()
                f.src, f.dst, f.sport, f.dport, f.proto = src, dst, 50000, 443, 6
                f.bytes, f.packets, f.src_mac = nbytes, 1, src_mac
                return f

            mac = "bc:a8:a6:bb:10:61"
            st.add_flows([
                flow("192.168.1.54", "142.250.1.1", 100, mac),                 # learns the device's MAC
                flow("fd12:3456:789a:1:8a55:c3c0:37fb:ae10", "fd12:3456:789a:10::5", 50, mac),  # privacy addr
                flow("fe80::9e13:9eff:fe0a:4683", "fe80::1", 7),               # EUI-64, no IPv4 twin yet
            ], now=1_000_000)
            st.flush()
            devs = {r["ip"]: r for r in queries.summary(st.db(), {"from": "999000", "to": "1001000"}, 60)["devices"]}
            self.assertEqual(devs["192.168.1.54"]["up"], 150)
            self.assertNotIn("fd12:3456:789a:1:8a55:c3c0:37fb:ae10", devs)
            self.assertIn("fe80::9e13:9eff:fe0a:4683", devs)

            # later the Thread Border Router's IPv4 address shows up with that MAC; on the
            # next start its old IPv6 history is merged into it (once)
            st.add_flows([flow("192.168.10.20", "142.250.1.1", 10, "9c:13:9e:0a:46:83")], now=1_000_000)
            st.flush()
            db = st.db()
            db.execute("PRAGMA user_version = 2")
            db.commit()
            st = Store(path, geo, Classifier(["192.168.0.0/16", "fc00::/7", "fe80::/10"]))
            devs = {r["ip"]: r for r in queries.summary(st.db(), {"from": "999000", "to": "1001000"}, 60)["devices"]}
            self.assertEqual(devs["192.168.10.20"]["up"], 17)
            self.assertNotIn("fe80::9e13:9eff:fe0a:4683", devs)


class TokenTest(unittest.TestCase):
    def test_clean_and_fingerprint(self):
        from tfv.attribution import clean_token, token_fingerprint
        self.assertEqual(clean_token(' "abc123"\n'), "abc123")
        self.assertEqual(clean_token("'abc123' "), "abc123")
        self.assertEqual(token_fingerprint("abc123"), token_fingerprint(clean_token('"abc123"')))
        self.assertEqual(len(token_fingerprint("abc123")), 8)
        self.assertEqual(token_fingerprint(""), "")


class HairpinAndAgentFixesTest(unittest.TestCase):
    def test_hairpin_nat_credits_real_device(self):
        """Records as a MikroTik reports them when a device (192.168.1.57) watches
        Jellyfin through the public domain, proxied by the server on :9443."""
        with tempfile.TemporaryDirectory() as tmp:
            fakeflow.write_demo_geo(tmp)
            geo = Geo(tmp, auto_download=False)
            geo.start()
            st = Store(os.path.join(tmp, "db.sqlite"), geo, Classifier(["192.168.0.0/16"]))
            req, rep = Flow(), Flow()
            # device -> public IP:443, forwarded to the server's :9443
            req.src, req.sport, req.dst, req.dport, req.proto, req.bytes, req.packets = \
                "192.168.1.57", 40752, "213.143.93.247", 443, 6, 2_000, 20
            req.nat_src, req.nat_dst, req.nat_sport, req.nat_dport = "192.168.10.1", "192.168.10.10", 40752, 9443
            # server -> router's LAN address (masquerade); post-NAT destination is the device
            rep.src, rep.sport, rep.dst, rep.dport, rep.proto, rep.bytes, rep.packets = \
                "192.168.10.10", 9443, "192.168.10.1", 40752, 6, 5_000_000, 3500
            rep.nat_src, rep.nat_dst, rep.nat_sport, rep.nat_dport = "213.143.93.247", "192.168.1.57", 443, 40752
            st.add_flows([req, rep], now=1_000_000)
            st.flush()
            s = queries.summary(st.db(), {"from": "999000", "to": "1001000"}, 60)
            dev = {r["ip"]: (r["up"], r["down"]) for r in s["devices"]}
            self.assertEqual(dev["192.168.1.57"], (2_000, 5_000_000))
            self.assertEqual(dev["192.168.10.10"], (5_000_000, 2_000))
            self.assertNotIn("192.168.10.1", dev)
            self.assertEqual({r["port"] for r in s["ports"]}, {9443})

    def test_ipv4_mapped_socket_addresses(self):
        import ipaddress
        import struct
        from tfv.agent import _hex_ip
        packed = ipaddress.IPv6Address("::ffff:192.168.10.10").packed
        hexed = "".join(struct.pack("<I", w).hex() for w in struct.unpack(">4I", packed))
        self.assertEqual(_hex_ip(hexed.upper()), "192.168.10.10")

    def test_non_ascii_token_header(self):
        import hmac, urllib.parse
        from tfv.agent import _TOKEN_SAFE
        token = "geslo-Čmrlj-žaba"
        header = urllib.parse.quote(token, safe=_TOKEN_SAFE)
        header.encode("latin-1")  # must be sendable as an HTTP header
        self.assertTrue(hmac.compare_digest(urllib.parse.unquote(header).encode(), token.encode()))
        self.assertEqual(urllib.parse.quote("abc-DEF_123", safe=_TOKEN_SAFE), "abc-DEF_123")  # plain tokens unchanged


def _client_hello(sni, pad=0):
    import struct
    name = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    padding = struct.pack("!HH", 0x0015, pad) + b"\x00" * pad          # pushes SNI into a 2nd packet
    exts = padding + struct.pack("!HH", 0x002b, 3) + b"\x02\x03\x04" + sni_ext
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" + \
        struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def _ipv4_tcp(src, dst, sport, dport, payload):
    import socket, struct
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, 0x18, 65535, 0, 0)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return ip + tcp + payload


class ProxyDomainTest(unittest.TestCase):
    def test_parsers(self):
        from tfv.sniff import http_host, tls_server_name
        self.assertEqual(tls_server_name(_client_hello("Jellyfin.Bajta.net")), ("jellyfin.bajta.net", 0))
        hello = _client_hello("x.example", pad=1500)
        self.assertEqual(tls_server_name(hello[:600]), (None, len(hello)))
        self.assertEqual(http_host(b"GET / HTTP/1.1\r\nHost: Cloud.Example.org:9080\r\nX: y\r\n\r\n"), "cloud.example.org")
        self.assertEqual(http_host(b"\x16\x03\x01junk"), "")

    def test_filter_program(self):
        from tfv.sniff import proxy_filter
        prog = proxy_filter([9443, 9080])
        self.assertTrue(all(0 <= jt <= 255 and 0 <= jf <= 255 for _, jt, jf, _ in prog))
        self.assertEqual(prog[-1], (0x06, 0, 0, 0))       # drop
        self.assertEqual(prog[-2], (0x06, 0, 0, 65535))   # accept

    def test_sniffer_reassembles_and_skips(self):
        from tfv.sniff import Sniffer
        s = Sniffer((9443,), skip_dst=lambda ip: ip == "172.17.0.5")
        hello = _client_hello("photos.bajta.net", pad=1500)
        s.handle(_ipv4_tcp("192.168.10.1", "192.168.10.10", 40752, 9443, hello[:1400]))
        self.assertEqual(s.take(), {})
        s.handle(_ipv4_tcp("192.168.10.1", "192.168.10.10", 40752, 9443, hello[1400:]))
        self.assertEqual(s.take(), {("192.168.10.10", 9443, "192.168.10.1", 40752): "photos.bajta.net"})
        s.handle(_ipv4_tcp("192.168.10.10", "142.250.1.1", 5000, 9443, _client_hello("x.com")))  # outgoing
        s.handle(_ipv4_tcp("10.0.0.2", "172.17.0.5", 5000, 9443, _client_hello("y.com")))       # container
        self.assertEqual(s.take(), {})

    def test_domain_through_hairpin_and_storage(self):
        from tfv.attribution import Attribution
        attr = Attribution()
        attr.report("srv", [], [], {"192.168.10.10"},
                    [("192.168.10.10", 9443, "192.168.10.1", 40752, "jellyfin.bajta.net"),
                     ("192.168.10.10", 9443, "93.103.1.1", 5555, "jellyfin.bajta.net")])
        with tempfile.TemporaryDirectory() as tmp:
            fakeflow.write_demo_geo(tmp)
            geo = Geo(tmp, auto_download=False)
            geo.start()
            st = Store(os.path.join(tmp, "db.sqlite"), geo, Classifier(["192.168.0.0/16"]), attribution=attr)
            rep = Flow()  # server -> device through hairpin NAT (as the router reports it)
            rep.src, rep.sport, rep.dst, rep.dport, rep.proto, rep.bytes, rep.packets = \
                "192.168.10.10", 9443, "192.168.10.1", 40752, 6, 5_000_000, 3500
            rep.nat_src, rep.nat_dst, rep.nat_sport, rep.nat_dport = "213.143.93.247", "192.168.1.57", 443, 40752
            ext = Flow()  # external visitor arriving on the WAN port
            ext.src, ext.sport, ext.dst, ext.dport, ext.proto, ext.bytes, ext.packets = \
                "93.103.1.1", 5555, "213.143.93.247", 443, 6, 1_000, 10
            ext.nat_dst, ext.nat_dport = "192.168.10.10", 9443
            st.add_flows([rep, ext], now=1_000_000)
            st.flush()
            p = {"from": "999000", "to": "1001000"}
            doms = queries.summary(st.db(), p, 60, servers=["192.168.10.10"])["domains"]
            self.assertEqual([(d["domain"], d["up"], d["down"], d["remotes"]) for d in doms],
                             [("jellyfin.bajta.net", 5_000_000, 1_000, 2)])
            dev = queries.summary(st.db(), {**p, "device": "192.168.1.57"}, 60, servers=["192.168.10.10"])
            self.assertEqual([(d["domain"], d["down"]) for d in dev["domains"]], [("jellyfin.bajta.net", 5_000_000)])

    def test_upgrade_adds_domain_column(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "db.sqlite")
            c = sqlite3.connect(path)
            c.executescript("""CREATE TABLE traffic (bucket INTEGER NOT NULL, local_ip TEXT NOT NULL,
                remote_ip TEXT NOT NULL, port INTEGER NOT NULL, proto INTEGER NOT NULL, country TEXT NOT NULL,
                asn INTEGER NOT NULL, bytes_up INTEGER NOT NULL DEFAULT 0, bytes_down INTEGER NOT NULL DEFAULT 0,
                pkts_up INTEGER NOT NULL DEFAULT 0, pkts_down INTEGER NOT NULL DEFAULT 0,
                flows INTEGER NOT NULL DEFAULT 0, app TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (bucket, local_ip, remote_ip, port, proto, app)) WITHOUT ROWID;
                INSERT INTO traffic VALUES (60, '192.168.1.5', '1.1.1.1', 443, 6, 'AU', 13335, 10, 20, 1, 2, 1, 'curl');
                PRAGMA user_version = 3;""")
            c.close()
            fakeflow.write_demo_geo(tmp)
            geo = Geo(tmp, auto_download=False)
            st = Store(path, geo, Classifier(["192.168.0.0/16"]))
            row = st.db().execute("SELECT app, domain, bytes_up, bytes_down FROM traffic").fetchone()
            self.assertEqual(tuple(row), ("curl", "", 10, 20))


class AlertsTest(unittest.TestCase):
    def test_alerts(self):
        import time as _t
        from tfv.alerts import Alerts
        with tempfile.TemporaryDirectory() as tmp:
            fakeflow.write_demo_geo(tmp)
            geo = Geo(tmp, auto_download=False)
            geo.start()
            st = Store(os.path.join(tmp, "db.sqlite"), geo, Classifier(["192.168.0.0/16"]))
            now = int(_t.time())
            db = st.db()
            ins = """INSERT INTO traffic (bucket, local_ip, remote_ip, port, proto, app, domain, country, asn,
                         bytes_up, bytes_down, flows) VALUES (?,?,?,?,?,'','',?,0,?,?,1)"""
            with db:
                # two days of normal history for the laptop, then a big last hour
                for h in range(48, 1, -1):
                    db.execute(ins, (now - h * 3600, "192.168.10.248", "1.1.1.1", 443, 6, "AU", 1_000_000,
                                     200_000_000 if h == 20 else 10_000_000))  # one busy evening: not a spike
                db.execute(ins, (now - 600, "192.168.10.248", "142.250.1.1", 443, 6, "US", 50_000_000, 900_000_000))
                # a camera on the cameras network talking to the internet
                db.execute(ins, (now - 900, "192.168.40.10", "47.91.94.88", 32991, 6, "DE", 900_000, 600_000))
                db.execute("INSERT INTO devices (ip, name, first_seen, last_seen) VALUES (?,?,?,?)",
                           ("192.168.40.10", "Kamera", now - 3 * 86400, now))
                db.execute("INSERT INTO devices (ip, first_seen, last_seen, mac) VALUES (?,?,?,?)",
                           ("192.168.1.77", now - 3600, now, "aa:bb:cc:dd:ee:ff"))
            al = Alerts(st, no_internet_networks=["192.168.40.0/24"])
            kinds = {a["key"].split(":")[0]: a for a in al.active()}
            self.assertIn("internet", kinds)
            self.assertIn("Kamera used the internet", kinds["internet"]["title"])
            self.assertIn("spike", kinds)
            self.assertIn("new", kinds)
            al.ack([kinds["internet"]["key"]])
            self.assertNotIn("internet", {a["key"].split(":")[0] for a in al.active()})
            # per-device flag works too
            st.set_device_flag("192.168.10.248", "no_internet", True)
            al.ack([])
            self.assertTrue(any(a["key"].startswith("internet:192.168.10.248") for a in al.active()))

#!/usr/bin/env python3
"""Send fake MikroTik-style flow exports so you can try the dashboard without
a router.

    python3 tools/fakeflow.py --demo-geo data     # write small demo GeoIP DBs
    python3 tools/fakeflow.py --version ipfix     # stream flows to 127.0.0.1:2055

The demo GeoIP databases only cover the handful of ranges used below; delete
them (data/dbip-*.mmdb) to let the app download the real DB-IP Lite ones.
"""

import argparse
import ipaddress
import os
import random
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# (cidr, country, asn, org, weight, typical ports)
REMOTES = [
    ("142.250.0.0/15", "US", 15169, "Google LLC", 20, [443, 80]),
    ("157.240.0.0/16", "IE", 32934, "Meta Platforms", 10, [443]),
    ("151.101.0.0/16", "US", 54113, "Fastly", 8, [443]),
    ("104.16.0.0/13", "US", 13335, "Cloudflare", 14, [443, 80]),
    ("52.0.0.0/11", "US", 16509, "Amazon.com", 10, [443]),
    ("23.32.0.0/11", "NL", 16625, "Akamai Technologies", 8, [443]),
    ("193.2.0.0/16", "SI", 2107, "ARNES", 4, [443, 53]),
    ("89.212.0.0/16", "SI", 5603, "Telekom Slovenije", 6, [443, 53, 123]),
    ("95.216.0.0/15", "FI", 24940, "Hetzner Online", 3, [443, 22]),
    ("5.9.0.0/16", "DE", 24940, "Hetzner Online", 3, [443, 993]),
    ("91.108.4.0/22", "NL", 62041, "Telegram Messenger", 2, [443]),
    ("77.88.0.0/18", "RU", 13238, "YANDEX LLC", 1, [443]),
    ("218.92.0.0/16", "CN", 4134, "Chinanet", 1, [22, 23, 3389]),
    ("200.147.0.0/16", "BR", 7162, "Universo Online", 1, [443]),
    ("103.21.244.0/22", "SG", 13335, "Cloudflare", 2, [443]),
    ("81.2.69.0/24", "GB", 20712, "Andrews & Arnold", 1, [443, 123]),
]

DEVICES = [  # ip, mac, activity weight
    ("192.168.88.10", "a4:83:e7:11:22:01", 10),   # laptop
    ("192.168.88.11", "3c:22:fb:11:22:02", 6),    # phone
    ("192.168.88.20", "b8:27:eb:11:22:03", 2),    # raspberry pi
    ("192.168.88.30", "00:11:32:11:22:04", 4),    # NAS
    ("192.168.88.40", "f0:b4:29:11:22:05", 12),   # smart TV
    ("192.168.88.50", "18:b4:30:11:22:06", 1),    # camera
]

# IPFIX/v9 template: src, dst, sport, dport, proto, bytes, pkts, in_if, out_if, src_mac, dst_mac
TEMPLATE = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4),
            (10, 2), (14, 2), (56, 6), (80, 6)]
TID = 256


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def random_flow():
    dev_ip, dev_mac, _ = random.choices(DEVICES, [d[2] for d in DEVICES])[0]
    cidr, _cc, _asn, _org, _w, ports = random.choices(REMOTES, [r[4] for r in REMOTES])[0]
    net = ipaddress.ip_network(cidr)
    remote = str(net[random.randrange(1, min(net.num_addresses - 1, 4000))])
    port = random.choice(ports)
    proto = 17 if port in (53, 123) else 6
    eph = random.randint(40000, 65000)
    down = int(random.paretovariate(1.2) * 3000)
    up = max(60, int(down * random.uniform(0.02, 0.3)))
    if port in (22, 23, 3389):  # inbound scan, blocked: tiny
        down, up = random.randint(40, 120), 0
    router_mac = "4c:5e:0c:aa:bb:cc"
    flows = [(dev_ip, remote, eph, port, proto, up, max(1, up // 1200),
              dev_mac, router_mac)]
    if up or port not in (22, 23, 3389):
        flows.append((remote, dev_ip, port, eph, proto, down, max(1, down // 1400),
                      router_mac, dev_mac))
    else:
        flows = [(remote, dev_ip, port, eph, proto, down, 1, router_mac, dev_mac)]
    return flows


def pack_record(f):
    src, dst, sport, dport, proto, nbytes, pkts, smac, dmac = f
    return (socket.inet_aton(src) + socket.inet_aton(dst)
            + struct.pack("!HHBIIHH", sport, dport, proto, nbytes, pkts, 1, 2)
            + mac(smac) + mac(dmac))


def tpl_body():
    return struct.pack("!HH", TID, len(TEMPLATE)) + b"".join(
        struct.pack("!HH", fid, flen) for fid, flen in TEMPLATE)


def pkt_ipfix(records, seq, with_template):
    sets = b""
    if with_template:
        body = tpl_body()
        sets += struct.pack("!HH", 2, len(body) + 4) + body
    data = b"".join(pack_record(r) for r in records)
    sets += struct.pack("!HH", TID, len(data) + 4) + data
    return struct.pack("!HHIII", 10, 16 + len(sets), int(time.time()), seq, 0) + sets


def pkt_v9(records, seq, with_template):
    sets = b""
    count = len(records)
    if with_template:
        body = tpl_body()
        sets += struct.pack("!HH", 0, len(body) + 4) + body
        count += 1
    data = b"".join(pack_record(r) for r in records)
    pad = (-len(data)) % 4
    sets += struct.pack("!HH", TID, len(data) + 4 + pad) + data + b"\0" * pad
    return struct.pack("!HHIIII", 9, count, 1000, int(time.time()), seq, 0) + sets


def pkt_v5(records, seq, _with_template):
    hdr = struct.pack("!HHIIIIBBH", 5, len(records), 1000, int(time.time()), 0, seq, 0, 0, 0)
    body = b""
    for src, dst, sport, dport, proto, nbytes, pkts, _sm, _dm in records:
        body += (socket.inet_aton(src) + socket.inet_aton(dst) + b"\0" * 4
                 + struct.pack("!HHIIIIHHxBBBHHBBxx", 1, 2, pkts, nbytes, 0, 0,
                               sport, dport, 0, proto, 0, 0, 0, 24, 24))
    return hdr + body


def write_demo_geo(data_dir):
    from mmdb_writer import write
    os.makedirs(data_dir, exist_ok=True)
    write(os.path.join(data_dir, "dbip-country-lite.mmdb"),
          [(c, {"country": {"iso_code": cc, "names": {"en": cc}}})
           for c, cc, *_ in REMOTES], "DBIP-Country-Lite (demo)")
    write(os.path.join(data_dir, "dbip-asn-lite.mmdb"),
          [(c, {"autonomous_system_number": asn, "autonomous_system_organization": org})
           for c, _cc, asn, org, *_ in REMOTES], "DBIP-ASN-Lite (demo)")
    print(f"demo GeoIP databases written to {data_dir}/")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2055)
    ap.add_argument("--version", choices=["5", "9", "ipfix"], default="ipfix")
    ap.add_argument("--rate", type=float, default=50, help="connections per second")
    ap.add_argument("--count", type=int, default=0, help="stop after N packets (0 = forever)")
    ap.add_argument("--demo-geo", metavar="DIR", help="write demo GeoIP DBs to DIR and exit")
    args = ap.parse_args()
    if args.demo_geo:
        write_demo_geo(args.demo_geo)
        return
    build = {"5": pkt_v5, "9": pkt_v9, "ipfix": pkt_ipfix}[args.version]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = sent = 0
    print(f"sending {args.version} flows to {args.host}:{args.port} (Ctrl+C to stop)")
    while not args.count or sent < args.count:
        records = []
        for _ in range(10):
            records.extend(random_flow())
        records = records[:20]
        sock.sendto(build(records, seq, seq % 20 == 0), (args.host, args.port))
        seq += 1
        sent += 1
        time.sleep(10 / args.rate)


if __name__ == "__main__":
    main()

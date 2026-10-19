"""Decoders for NetFlow v5, NetFlow v9 and IPFIX (v10) export packets.

MikroTik RouterOS "Traffic Flow" can export any of these. v9 and IPFIX are
template based, so the decoder keeps a template cache per exporter.
"""

import ipaddress
import struct
import time

# Field IDs (shared by NetFlow v9 and IPFIX) that we care about.
F_IN_BYTES = 1
F_IN_PKTS = 2
F_PROTOCOL = 4
F_TCP_FLAGS = 6
F_SRC_PORT = 7
F_SRC_V4 = 8
F_INPUT_IF = 10
F_DST_PORT = 11
F_DST_V4 = 12
F_OUTPUT_IF = 14
F_OUT_BYTES = 23
F_OUT_PKTS = 24
F_SRC_V6 = 27
F_DST_V6 = 28
F_SRC_MAC = 56
F_OUT_DST_MAC = 57
F_DST_MAC = 80
F_OUT_SRC_MAC = 81
F_TOTAL_BYTES = 85
F_TOTAL_PKTS = 86
F_POSTNAT_SRC_V4 = 225
F_POSTNAT_DST_V4 = 226
F_POSTNAT_SRC_PORT = 227
F_POSTNAT_DST_PORT = 228

_V5_HEADER = struct.Struct("!HHIIIIBBH")
_V5_RECORD = struct.Struct("!4s4s4sHHIIIIHHxBBBHHBBxx")
_V9_HEADER = struct.Struct("!HHIIII")
_IPFIX_HEADER = struct.Struct("!HHIII")
_SET_HEADER = struct.Struct("!HH")

TEMPLATE_TTL = 3600 * 6
DEDUP_WINDOW = 300  # seconds an identical record is treated as a duplicate


class Flow:
    __slots__ = ("src", "dst", "sport", "dport", "proto", "bytes", "packets",
                 "in_if", "out_if", "src_mac", "dst_mac",
                 "nat_src", "nat_dst", "exporter", "raw")

    def __init__(self):
        self.src = self.dst = None
        self.sport = self.dport = 0
        self.proto = 0
        self.bytes = self.packets = 0
        self.in_if = self.out_if = 0
        self.src_mac = self.dst_mac = None
        self.nat_src = self.nat_dst = None
        self.exporter = None
        self.raw = None  # {field id: bytes} for v9/IPFIX, kept for the debug view

    def __repr__(self):
        return (f"Flow({self.src}:{self.sport} -> {self.dst}:{self.dport} "
                f"p{self.proto} {self.bytes}B {self.packets}pkt)")


def _mac(b):
    if len(b) != 6 or b == b"\x00" * 6:
        return None
    return ":".join(f"{x:02x}" for x in b)


def _ip(b):
    if len(b) == 4:
        return str(ipaddress.IPv4Address(b))
    if len(b) == 16:
        return str(ipaddress.IPv6Address(b))
    return None


def _flow_from_fields(fields, exporter):
    """Build a Flow from a {field_id: raw bytes} dict."""
    f = Flow()
    f.exporter = exporter
    f.raw = fields
    get = fields.get

    def num(fid):
        v = get(fid)
        return int.from_bytes(v, "big") if v else 0

    src = get(F_SRC_V4) or get(F_SRC_V6)
    dst = get(F_DST_V4) or get(F_DST_V6)
    if not src or not dst:
        return None
    f.src, f.dst = _ip(src), _ip(dst)
    f.sport, f.dport = num(F_SRC_PORT), num(F_DST_PORT)
    f.proto = num(F_PROTOCOL)
    f.bytes = num(F_IN_BYTES) or num(F_TOTAL_BYTES) or num(F_OUT_BYTES)
    f.packets = num(F_IN_PKTS) or num(F_TOTAL_PKTS) or num(F_OUT_PKTS)
    f.in_if, f.out_if = num(F_INPUT_IF), num(F_OUTPUT_IF)
    if get(F_SRC_MAC):
        f.src_mac = _mac(get(F_SRC_MAC))
    elif get(F_OUT_SRC_MAC):
        f.src_mac = _mac(get(F_OUT_SRC_MAC))
    if get(F_DST_MAC):
        f.dst_mac = _mac(get(F_DST_MAC))
    elif get(F_OUT_DST_MAC):
        f.dst_mac = _mac(get(F_OUT_DST_MAC))
    ns, nd = get(F_POSTNAT_SRC_V4), get(F_POSTNAT_DST_V4)
    if ns and ns != b"\x00\x00\x00\x00":
        f.nat_src = _ip(ns)
    if nd and nd != b"\x00\x00\x00\x00":
        f.nat_dst = _ip(nd)
    return f


class Decoder:
    """Stateful decoder. Feed it (packet bytes, exporter ip) and get Flows."""

    def __init__(self):
        # (exporter, domain, template_id) -> (list of (field_id, length), time)
        self.templates = {}
        self.stats = {"packets": 0, "flows": 0, "errors": 0,
                      "no_template": 0, "duplicates": 0, "versions": {}}
        # Recently seen raw records. A router with two targets pointing at us (or a
        # network that duplicates UDP) would otherwise make every byte count twice.
        self._seen = {}
        self._seen_pruned = time.time()

    def decode(self, data, exporter):
        self.stats["packets"] += 1
        if len(data) < 4:
            self.stats["errors"] += 1
            return []
        version = struct.unpack_from("!H", data)[0]
        self.stats["versions"][version] = self.stats["versions"].get(version, 0) + 1
        try:
            if version == 5:
                flows = self._v5(data, exporter)
            elif version == 9:
                flows = self._v9(data, exporter)
            elif version == 10:
                flows = self._ipfix(data, exporter)
            else:
                self.stats["errors"] += 1
                return []
        except (struct.error, ValueError, IndexError):
            self.stats["errors"] += 1
            return []
        self.stats["flows"] += len(flows)
        return flows

    def _duplicate(self, key):
        now = time.time()
        if now - self._seen_pruned > DEDUP_WINDOW:
            cutoff = now - DEDUP_WINDOW
            self._seen = {k: t for k, t in self._seen.items() if t >= cutoff}
            self._seen_pruned = now
        if key in self._seen:
            self.stats["duplicates"] += 1
            return True
        self._seen[key] = now
        return False

    # ---- NetFlow v5 -----------------------------------------------------
    def _v5(self, data, exporter):
        _, count, *_ = _V5_HEADER.unpack_from(data)
        flows = []
        off = _V5_HEADER.size
        for _ in range(count):
            if off + _V5_RECORD.size > len(data):
                break
            (src, dst, _nh, in_if, out_if, pkts, octets, _first, _last,
             sport, dport, _flags, proto, _tos, _sas, _das, _sm, _dm) = \
                _V5_RECORD.unpack_from(data, off)
            raw = data[off: off + _V5_RECORD.size]
            off += _V5_RECORD.size
            if self._duplicate((exporter, 5, raw)):
                continue
            f = Flow()
            f.exporter = exporter
            f.src, f.dst = _ip(src), _ip(dst)
            f.sport, f.dport, f.proto = sport, dport, proto
            f.bytes, f.packets = octets, pkts
            f.in_if, f.out_if = in_if, out_if
            flows.append(f)
        return flows

    # ---- NetFlow v9 -----------------------------------------------------
    def _v9(self, data, exporter):
        _, _count, _uptime, _secs, _seq, source_id = _V9_HEADER.unpack_from(data)
        source_id = (9, source_id)  # keep v9 and IPFIX templates apart
        off = _V9_HEADER.size
        flows = []
        while off + 4 <= len(data):
            set_id, length = _SET_HEADER.unpack_from(data, off)
            if length < 4:
                break
            body = data[off + 4: off + length]
            if set_id == 0:
                self._v9_templates(body, exporter, source_id)
            elif set_id == 1:
                self._v9_options_templates(body, exporter, source_id)
            elif set_id >= 256:
                flows.extend(self._data_set(body, exporter, source_id, set_id))
            off += length
        return flows

    def _v9_templates(self, body, exporter, domain):
        off = 0
        while off + 4 <= len(body):
            tid, count = struct.unpack_from("!HH", body, off)
            off += 4
            if tid < 256:
                break
            fields = []
            for _ in range(count):
                fid, flen = struct.unpack_from("!HH", body, off)
                off += 4
                fields.append((fid, flen))
            self.templates[(exporter, domain, tid)] = (fields, time.time())

    def _v9_options_templates(self, body, exporter, domain):
        off = 0
        while off + 6 <= len(body):
            tid, scope_len, opt_len = struct.unpack_from("!HHH", body, off)
            off += 6
            if tid < 256:
                break
            fields = []
            for _ in range((scope_len + opt_len) // 4):
                fid, flen = struct.unpack_from("!HH", body, off)
                off += 4
                # Mark option fields so their records are skipped.
                fields.append((-1, flen))
            self.templates[(exporter, domain, tid)] = (fields, time.time())
            # Options templates are padded to 4 bytes.
            off += (-off) % 4

    # ---- IPFIX ----------------------------------------------------------
    def _ipfix(self, data, exporter):
        _, length, _export_time, _seq, domain = _IPFIX_HEADER.unpack_from(data)
        domain = (10, domain)
        data = data[:length]
        off = _IPFIX_HEADER.size
        flows = []
        while off + 4 <= len(data):
            set_id, slen = _SET_HEADER.unpack_from(data, off)
            if slen < 4:
                break
            body = data[off + 4: off + slen]
            if set_id == 2:
                self._ipfix_templates(body, exporter, domain, options=False)
            elif set_id == 3:
                self._ipfix_templates(body, exporter, domain, options=True)
            elif set_id >= 256:
                flows.extend(self._data_set(body, exporter, domain, set_id))
            off += slen
        return flows

    def _ipfix_templates(self, body, exporter, domain, options):
        off = 0
        while off + 4 <= len(body):
            tid, count = struct.unpack_from("!HH", body, off)
            off += 4
            if tid < 256:
                break
            if options:
                off += 2  # scope field count
            fields = []
            for _ in range(count):
                fid, flen = struct.unpack_from("!HH", body, off)
                off += 4
                if fid & 0x8000:  # enterprise-specific: skip PEN, ignore field
                    off += 4
                    fid = -1
                fields.append((-1 if options else fid, flen))
            if count == 0:  # template withdrawal
                self.templates.pop((exporter, domain, tid), None)
            else:
                self.templates[(exporter, domain, tid)] = (fields, time.time())

    # ---- shared data-set decoding ---------------------------------------
    def _data_set(self, body, exporter, domain, tid):
        tpl = self.templates.get((exporter, domain, tid))
        if not tpl:
            self.stats["no_template"] += 1
            return []
        fields, _ = tpl
        if all(fid == -1 for fid, _ in fields):
            return []  # options data (sampler info etc.), not flows
        fixed = all(flen != 0xFFFF for _, flen in fields)
        min_len = sum(flen for _, flen in fields if flen != 0xFFFF) or 1
        flows = []
        off = 0
        n = len(body)
        while off + min_len <= n:
            start = off
            rec = {}
            for fid, flen in fields:
                if flen == 0xFFFF:  # IPFIX variable length
                    flen = body[off]
                    off += 1
                    if flen == 255:
                        flen = struct.unpack_from("!H", body, off)[0]
                        off += 2
                if fid >= 0:
                    rec[fid] = body[off: off + flen]
                off += flen
            if off > n:
                break
            if not self._duplicate((exporter, domain, tid, body[start:off])):
                f = _flow_from_fields(rec, exporter)
                if f:
                    flows.append(f)
            if not fixed and n - off < 4:
                break
        return flows

    def expire_templates(self):
        cutoff = time.time() - TEMPLATE_TTL
        for k in [k for k, (_, t) in self.templates.items() if t < cutoff]:
            del self.templates[k]

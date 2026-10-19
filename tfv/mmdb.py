"""Minimal pure-Python reader for MaxMind DB (.mmdb) files.

Works with DB-IP Lite and MaxMind GeoLite2 country/ASN databases, so the app
needs no third-party packages.
"""

import ipaddress
import struct

_METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"


class InvalidDatabase(Exception):
    pass


class Reader:
    def __init__(self, path):
        with open(path, "rb") as fh:
            self.buf = fh.read()
        idx = self.buf.rfind(_METADATA_MARKER)
        if idx < 0:
            raise InvalidDatabase(f"{path}: not a MaxMind DB file")
        self.metadata, _ = self._decode(idx + len(_METADATA_MARKER), base=0)
        md = self.metadata
        self.node_count = md["node_count"]
        self.record_size = md["record_size"]
        self.ip_version = md["ip_version"]
        if self.record_size not in (24, 28, 32):
            raise InvalidDatabase(f"unsupported record size {self.record_size}")
        self.node_bytes = self.record_size * 2 // 8
        self.tree_size = self.node_bytes * self.node_count
        self.data_start = self.tree_size + 16
        self._ipv4_start = None

    # ---- search tree ----------------------------------------------------
    def _record(self, node, bit):
        off = node * self.node_bytes
        b = self.buf
        if self.record_size == 24:
            off += bit * 3
            return (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]
        if self.record_size == 28:
            if bit == 0:
                return (((b[off + 3] & 0xF0) << 20) | (b[off] << 16)
                        | (b[off + 1] << 8) | b[off + 2])
            return (((b[off + 3] & 0x0F) << 24) | (b[off + 4] << 16)
                    | (b[off + 5] << 8) | b[off + 6])
        return struct.unpack_from("!I", b, off + bit * 4)[0]

    def _ipv4_root(self):
        if self._ipv4_start is None:
            node = 0
            if self.ip_version == 6:
                for _ in range(96):
                    if node >= self.node_count:
                        break
                    node = self._record(node, 0)
            self._ipv4_start = node
        return self._ipv4_start

    def get(self, ip):
        addr = ipaddress.ip_address(ip)
        packed = addr.packed
        if addr.version == 4:
            node = self._ipv4_root()
        else:
            if self.ip_version == 4:
                return None
            node = 0
        nbits = len(packed) * 8
        for i in range(nbits):
            if node >= self.node_count:
                break
            bit = (packed[i >> 3] >> (7 - (i & 7))) & 1
            node = self._record(node, bit)
        if node == self.node_count:
            return None
        if node > self.node_count:
            off = node - self.node_count - 16
            value, _ = self._decode(off, base=self.data_start)
            return value
        raise InvalidDatabase("invalid node in search tree")

    # ---- data section ---------------------------------------------------
    def _decode(self, off, base):
        """Decode the value at data offset `off` (relative to `base`).

        Returns (value, next offset relative to base).
        """
        b = self.buf
        pos = base + off
        ctrl = b[pos]
        pos += 1
        typ = ctrl >> 5
        if typ == 1:  # pointer
            ss = (ctrl >> 3) & 0x3
            vvv = ctrl & 0x7
            if ss == 0:
                ptr = (vvv << 8) | b[pos]
                pos += 1
            elif ss == 1:
                ptr = ((vvv << 16) | (b[pos] << 8) | b[pos + 1]) + 2048
                pos += 2
            elif ss == 2:
                ptr = ((vvv << 24) | (b[pos] << 16) | (b[pos + 1] << 8)
                       | b[pos + 2]) + 526336
                pos += 3
            else:
                ptr = struct.unpack_from("!I", b, pos)[0]
                pos += 4
            value, _ = self._decode(ptr, base)
            return value, pos - base
        if typ == 0:  # extended type
            typ = 7 + b[pos]
            pos += 1
        size = ctrl & 0x1F
        if size >= 29:
            if size == 29:
                size = 29 + b[pos]
                pos += 1
            elif size == 30:
                size = 285 + ((b[pos] << 8) | b[pos + 1])
                pos += 2
            else:
                size = 65821 + ((b[pos] << 16) | (b[pos + 1] << 8) | b[pos + 2])
                pos += 3
        if typ == 2:  # utf-8 string
            return b[pos:pos + size].decode("utf-8", "replace"), pos + size - base
        if typ == 3:  # double
            return struct.unpack_from("!d", b, pos)[0], pos + 8 - base
        if typ == 4:  # bytes
            return bytes(b[pos:pos + size]), pos + size - base
        if typ in (5, 6, 9, 10):  # unsigned ints
            return int.from_bytes(b[pos:pos + size], "big"), pos + size - base
        if typ == 7:  # map
            result = {}
            off = pos - base
            for _ in range(size):
                key, off = self._decode(off, base)
                val, off = self._decode(off, base)
                result[key] = val
            return result, off
        if typ == 8:  # int32
            v = int.from_bytes(b[pos:pos + size], "big", signed=False)
            if size == 4 and v & 0x80000000:
                v -= 1 << 32
            return v, pos + size - base
        if typ == 11:  # array
            result = []
            off = pos - base
            for _ in range(size):
                val, off = self._decode(off, base)
                result.append(val)
            return result, off
        if typ == 14:  # boolean
            return bool(size), pos - base
        if typ == 15:  # float
            return struct.unpack_from("!f", b, pos)[0], pos + 4 - base
        raise InvalidDatabase(f"unknown data type {typ}")

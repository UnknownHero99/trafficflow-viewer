"""Tiny MaxMind DB writer, used to build demo/test databases offline.

Not a general-purpose writer: supports maps, strings and unsigned ints,
24-bit records, and an IPv6 tree with IPv4 mapped at ::/96.
"""

import ipaddress
import struct
import time


def _ctrl(typ, size):
    out = bytearray()
    if size < 29:
        sz, ext = size, b""
    elif size < 285:
        sz, ext = 29, bytes([size - 29])
    elif size < 65821:
        sz, ext = 30, struct.pack("!H", size - 285)
    else:
        sz, ext = 31, (size - 65821).to_bytes(3, "big")
    if typ <= 7:
        out.append((typ << 5) | sz)
    else:
        out.append(sz)
        out.append(typ - 7)
    return bytes(out) + ext


def encode(v):
    if isinstance(v, dict):
        return _ctrl(7, len(v)) + b"".join(encode(k) + encode(x) for k, x in v.items())
    if isinstance(v, str):
        b = v.encode()
        return _ctrl(2, len(b)) + b
    if isinstance(v, bool):
        return _ctrl(14, int(v))
    if isinstance(v, int):
        if v < 0:
            raise ValueError("negative ints unsupported")
        b = v.to_bytes((v.bit_length() + 7) // 8, "big") if v else b""
        typ = 5 if len(b) <= 2 else 6 if len(b) <= 4 else 9
        return _ctrl(typ, len(b)) + b
    if isinstance(v, list):
        return _ctrl(11, len(v)) + b"".join(encode(x) for x in v)
    raise TypeError(type(v))


def write(path, networks, database_type="Test"):
    """networks: list of (cidr string, record dict)."""
    # Trie over 128-bit keys. node = [left, right]; child is int (node idx),
    # ("data", offset) or None.
    nodes = [[None, None]]
    data = bytearray()
    for cidr, record in networks:
        net = ipaddress.ip_network(cidr)
        if net.version == 4:
            key = int(net.network_address)
            plen = 96 + net.prefixlen
        else:
            key = int(net.network_address)
            plen = net.prefixlen
        off = len(data)
        data += encode(record)
        node = 0
        for i in range(plen):
            bit = (key >> (127 - i)) & 1
            if i == plen - 1:
                nodes[node][bit] = ("data", off)
            else:
                child = nodes[node][bit]
                if not isinstance(child, int):
                    nodes.append([None, None])
                    nodes[node][bit] = child = len(nodes) - 1
                node = child
    n = len(nodes)
    tree = bytearray()
    for left, right in nodes:
        for child in (left, right):
            if child is None:
                val = n
            elif isinstance(child, int):
                val = child
            else:
                val = n + 16 + child[1]
            tree += val.to_bytes(3, "big")
    meta = {
        "node_count": n, "record_size": 24, "ip_version": 6,
        "database_type": database_type, "languages": ["en"],
        "binary_format_major_version": 2, "binary_format_minor_version": 0,
        "build_epoch": int(time.time()), "description": {"en": "test db"},
    }
    with open(path, "wb") as fh:
        fh.write(bytes(tree) + b"\x00" * 16 + bytes(data)
                 + b"\xab\xcd\xefMaxMind.com" + encode(meta))

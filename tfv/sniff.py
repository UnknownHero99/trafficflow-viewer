"""Which domain clients ask your reverse proxy for.

Reads only the first bytes of new connections to the proxy's ports on this
host: the TLS ClientHello's server name (SNI, sent unencrypted) or the HTTP
Host header. A kernel (BPF) filter drops everything else before Python sees
it, so even multi-GB streams through the proxy cost nothing here.

Needs CAP_NET_RAW and the host's network namespace (the agent container).
"""

import ctypes
import ipaddress
import logging
import socket
import struct
import threading
import time

log = logging.getLogger("tfv.sniff")

DEFAULT_PORTS = (80, 443, 8080, 8443, 9080, 9443)
ETH_P_ALL = 0x0003
SO_ATTACH_FILTER = 26
PACKET_HOST = 0
MAX_RECORD = 16384  # a ClientHello larger than this is not worth reassembling


# ---- classic BPF ----------------------------------------------------------
# opcodes (linux/filter.h)
LD, LDX, ST, ALU, JMP, RET, MISC = 0x00, 0x01, 0x02, 0x04, 0x05, 0x06, 0x07
W, H, B = 0x00, 0x08, 0x10
IMM, ABS, IND, MEM, MSH = 0x00, 0x20, 0x40, 0x60, 0xa0
ADD, AND, RSH = 0x00, 0x50, 0x70
JA, JEQ, JGT, JSET = 0x00, 0x10, 0x20, 0x40
K, X = 0x00, 0x08
TAX = 0x00


def _assemble(prog):
    """prog: list of (label or None, code, jt, jf, k); jt/jf may be label names."""
    where = {lab: i for i, (lab, *_rest) in enumerate(prog) if lab}
    out = []
    for i, (_lab, code, jt, jf, k) in enumerate(prog):
        rel = lambda t: (where[t] - i - 1) if isinstance(t, str) else t  # noqa: E731
        if code == JMP | JA:
            k = rel(k)
        out.append((code, rel(jt), rel(jf), k))
    return out


def proxy_filter(ports):
    """BPF program for SOCK_DGRAM packet sockets (data starts at the IP header):
    TCP to one of `ports`, carrying payload (no bare ACKs), IPv4 or IPv6."""
    ports = list(ports)[:20]
    p = [
        (None, LD | B | ABS, 0, 0, 0),
        (None, ALU | AND | K, 0, 0, 0xF0),
        (None, JMP | JEQ | K, "v4", "chk6", 0x40),
        ("chk6", JMP | JEQ | K, "v6", "drop", 0x60),
        # IPv4
        ("v4", LD | B | ABS, 0, 0, 9),
        (None, JMP | JEQ | K, 0, "drop", 6),
        (None, LD | H | ABS, 0, 0, 6),
        (None, JMP | JSET | K, "drop", 0, 0x1FFF),       # skip fragments
        (None, LDX | B | MSH, 0, 0, 0),                    # X = IPv4 header length
        (None, LD | H | IND, 0, 0, 2),                     # TCP destination port
    ]
    for port in ports:
        p.append((None, JMP | JEQ | K, "v4len", 0, port))
    p += [
        (None, JMP | JA, 0, 0, "drop"),
        ("v4len", LD | B | IND, 0, 0, 12),                 # TCP data offset
        (None, ALU | AND | K, 0, 0, 0xF0),
        (None, ALU | RSH | K, 0, 0, 2),                    # A = TCP header length
        (None, ALU | ADD | X, 0, 0, 0),                    # + IP header length
        (None, ST, 0, 0, 0),
        (None, LD | H | ABS, 0, 0, 2),                     # IPv4 total length
        (None, LDX | W | MEM, 0, 0, 0),
        (None, JMP | JGT | X, "accept", "drop", 0),
        # IPv6 (no extension headers)
        ("v6", LD | B | ABS, 0, 0, 6),
        (None, JMP | JEQ | K, 0, "drop", 6),
        (None, LD | H | ABS, 0, 0, 42),
    ]
    for port in ports:
        p.append((None, JMP | JEQ | K, "v6len", 0, port))
    p += [
        (None, JMP | JA, 0, 0, "drop"),
        ("v6len", LD | B | ABS, 0, 0, 52),
        (None, ALU | AND | K, 0, 0, 0xF0),
        (None, ALU | RSH | K, 0, 0, 2),
        (None, MISC | TAX, 0, 0, 0),                       # X = TCP header length
        (None, LD | H | ABS, 0, 0, 4),                     # IPv6 payload length
        (None, JMP | JGT | X, "accept", "drop", 0),
        ("accept", RET | K, 0, 0, 65535),
        ("drop", RET | K, 0, 0, 0),
    ]
    return _assemble(p)


# ---- packet and protocol parsing -------------------------------------------
def parse_tcp(data):
    """(src, sport, dst, dport, payload) from an IP packet, or None."""
    if not data:
        return None
    v = data[0] >> 4
    if v == 4 and len(data) >= 20:
        ihl = (data[0] & 0x0F) * 4
        total = struct.unpack_from("!H", data, 2)[0]
        src, dst = socket.inet_ntop(socket.AF_INET, data[12:16]), socket.inet_ntop(socket.AF_INET, data[16:20])
        t, end = ihl, min(total, len(data))
    elif v == 6 and len(data) >= 40:
        src, dst = socket.inet_ntop(socket.AF_INET6, data[8:24]), socket.inet_ntop(socket.AF_INET6, data[24:40])
        t, end = 40, min(40 + struct.unpack_from("!H", data, 4)[0], len(data))
    else:
        return None
    if end < t + 20:
        return None
    sport, dport = struct.unpack_from("!HH", data, t)
    off = (data[t + 12] >> 4) * 4
    return src, sport, dst, dport, bytes(data[t + off:end])


def tls_server_name(buf):
    """Returns (name, needed): name from a ClientHello ('' if none), or (None, n)
    when the record is incomplete and n bytes are needed in total."""
    if len(buf) < 5 or buf[0] != 0x16:
        return "", 0
    need = 5 + int.from_bytes(buf[3:5], "big")
    if len(buf) < need:
        return None, need
    hs = buf[5:need]
    try:
        if hs[0] != 1:  # not a ClientHello
            return "", 0
        p = 4 + 2 + 32
        p += 1 + hs[p]                                   # session id
        p += 2 + int.from_bytes(hs[p:p + 2], "big")     # cipher suites
        p += 1 + hs[p]                                   # compression methods
        end = p + 2 + int.from_bytes(hs[p:p + 2], "big")
        p += 2
        while p + 4 <= min(end, len(hs)):
            etype = int.from_bytes(hs[p:p + 2], "big")
            elen = int.from_bytes(hs[p + 2:p + 4], "big")
            if etype == 0:  # server_name
                d = hs[p + 4:p + 4 + elen]
                n = int.from_bytes(d[3:5], "big")
                return d[5:5 + n].decode("ascii", "replace").lower(), 0
            p += 4 + elen
    except IndexError:
        pass
    return "", 0


_METHODS = (b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"DELE", b"PATC", b"CONN")


def http_host(buf):
    if not buf.startswith(_METHODS):
        return ""
    head = buf.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n")[1:]:
        if line[:5].lower() == b"host:":
            host = line[5:].strip().decode("ascii", "replace").lower()
            if host.startswith("["):  # [v6]:port
                return host.split("]")[0] + "]"
            return host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return ""


# ---- the capture thread ------------------------------------------------------
class Sniffer:
    def __init__(self, ports=DEFAULT_PORTS, on_found=None, skip_dst=lambda ip: False):
        self.ports = tuple(ports)
        self.on_found = on_found       # called after new names are added
        self.skip_dst = skip_dst       # e.g. container addresses (handled by the NAT table)
        self.found = {}                # (server_ip, server_port, client_ip, client_port) -> domain
        self.lock = threading.Lock()
        self.partial = {}              # flow -> (bytes so far, bytes needed, started)
        self.error = None
        self._filter = None

    def start(self):
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
        except (OSError, AttributeError) as e:
            self.error = f"can't capture ({e}); needs cap_add NET_RAW and network_mode host"
            log.warning("proxy domains off: %s", self.error)
            return False
        prog = proxy_filter(self.ports)
        self._filter = ctypes.create_string_buffer(b"".join(struct.pack("HBBI", *i) for i in prog))
        sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER,
                        struct.pack("HL", len(prog), ctypes.addressof(self._filter)))
        sock.setblocking(False)
        try:  # drop anything received before the filter was attached
            while sock.recv(65535):
                pass
        except BlockingIOError:
            pass
        sock.setblocking(True)
        threading.Thread(target=self._run, args=(sock,), daemon=True, name="proxy-domains").start()
        log.info("reading proxy domains on ports %s", ",".join(map(str, self.ports)))
        return True

    def _run(self, sock):
        while True:
            try:
                data, addr = sock.recvfrom(65535)
            except OSError as e:
                self.error = str(e)
                log.warning("capture stopped: %s", e)
                return
            if addr[2] != PACKET_HOST:
                continue
            self.handle(data)

    def handle(self, data, now=None):
        pkt = parse_tcp(data)
        if not pkt:
            return
        src, sport, dst, dport, payload = pkt
        if dport not in self.ports or not payload:
            return
        try:
            d = ipaddress.ip_address(dst)
        except ValueError:
            return
        if d.is_global or d.is_loopback or self.skip_dst(dst):
            return  # not a connection to this server (e.g. a container calling out)
        key = (dst, dport, src, sport)
        now = now or time.time()
        part = self.partial.pop(key, None)
        if part:
            payload = part[0] + payload
        name, need = tls_server_name(payload)
        if name is None:
            if need <= MAX_RECORD:
                self.partial[key] = (payload, need, part[2] if part else now)
            self._expire(now)
            return
        if not name:
            name = http_host(payload)
        if name:
            with self.lock:
                self.found[key] = name
            if self.on_found:
                self.on_found()

    def _expire(self, now):
        if len(self.partial) > 2000:
            self.partial.clear()
        for k in [k for k, v in self.partial.items() if now - v[2] > 5]:
            del self.partial[k]

    def take(self):
        """All names found since the last call."""
        with self.lock:
            found, self.found = self.found, {}
        return found

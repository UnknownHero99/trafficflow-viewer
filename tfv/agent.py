"""TrafficFlow agent: tells the viewer which app owns each connection on this host.

The router only sees IP addresses and ports, so it can't tell apart the
programs and containers on one server. This agent runs on that server and
reports whenever connections start (and at least twice a second):

- connections of Docker containers on bridge networks, from the kernel's NAT
  table (conntrack): container address/port -> host address/port;
- connections and listening sockets of host processes (and host-network
  containers), from /proc: socket -> process -> container (via cgroup);
- ports published by containers, from the Docker API.

Needs (see docker-compose.yml): network_mode host, pid host, CAP_NET_ADMIN
(conntrack), CAP_SYS_PTRACE (/proc/<pid>/fd) and the Docker socket.

    TFV_URL=http://192.168.10.10:8080 TFV_AGENT_TOKEN=... python -m tfv.agent
"""

import http.client
import ipaddress
import json
import logging
import os
import re
import socket
import struct
import subprocess
import threading
import time
import urllib.request

log = logging.getLogger("tfv.agent")

PROTOS = {"tcp": 6, "udp": 17}
RESEND = 60          # re-send unchanged entries this often so the viewer keeps them
DOCKER_REFRESH = 30  # seconds between container list refreshes
NAT_INTERVAL = 2     # seconds between NAT table reads (entries outlive their connection)
MIN_ROUND = 0.1      # at most 10 rounds per second, however many connections start


# ---- Docker API over the unix socket ----------------------------------------
class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=10)
        self.unix_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(self.unix_path)


def docker_containers(sock_path):
    """[{id, name, ips, ports}] for running containers, or [] without Docker."""
    if not os.path.exists(sock_path):
        return []
    conn = _UnixHTTP(sock_path)
    try:
        conn.request("GET", "/containers/json")
        data = json.loads(conn.getresponse().read())
    finally:
        conn.close()
    out = []
    for c in data:
        name = (c.get("Names") or ["?"])[0].lstrip("/")
        ips = set()
        for net in ((c.get("NetworkSettings") or {}).get("Networks") or {}).values():
            for key in ("IPAddress", "GlobalIPv6Address"):
                if net.get(key):
                    ips.add(net[key])
        ports = [(p.get("IP") or "*", PROTOS.get(p.get("Type"), 0), p["PublicPort"])
                 for p in c.get("Ports") or [] if p.get("PublicPort")]
        out.append({"id": c["Id"], "name": name, "ips": ips, "ports": ports})
    return out


# ---- conntrack (NAT table) -------------------------------------------------
_KV = re.compile(r"(src|dst|sport|dport)=(\S+)")


def conntrack_entries():
    """Yield (proto, orig, reply) where orig/reply = (src, dst, sport, dport)."""
    for family in ("ipv4", "ipv6"):
        try:
            res = subprocess.run(["conntrack", "-L", "-f", family], capture_output=True,
                                 text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"conntrack: {e}") from e
        if res.returncode != 0 and not res.stdout:
            raise RuntimeError("conntrack: " + res.stderr.strip()[:200])
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) < 2 or parts[0] not in PROTOS:
                continue
            kv = _KV.findall(line)
            if len(kv) < 8:
                continue
            o = {k: v for k, v in kv[:4]}
            r = {k: v for k, v in kv[4:8]}
            try:
                yield (PROTOS[parts[0]],
                       (o["src"], o["dst"], int(o["sport"]), int(o["dport"])),
                       (r["src"], r["dst"], int(r["sport"]), int(r["dport"])))
            except (KeyError, ValueError):
                continue


# ---- /proc sockets -----------------------------------------------------------
def _hex_ip(h):
    b = bytes.fromhex(h)
    if len(b) == 4:
        return str(ipaddress.IPv4Address(struct.pack("<I", struct.unpack(">I", b)[0])))
    words = struct.unpack(">4I", b)
    return str(ipaddress.IPv6Address(b"".join(struct.pack("<I", w) for w in words)))


def proc_sockets(proc="/proc"):
    """Yield (proto, local_ip, local_port, remote_ip, remote_port, inode, listening)."""
    for name, proto in (("tcp", 6), ("tcp6", 6), ("udp", 17), ("udp6", 17)):
        try:
            with open(f"{proc}/net/{name}") as fh:
                next(fh)
                for line in fh:
                    p = line.split()
                    lip, lport = p[1].split(":")
                    rip, rport = p[2].split(":")
                    inode = int(p[9])
                    if not inode:
                        continue
                    state = p[3]
                    lport, rport = int(lport, 16), int(rport, 16)
                    listening = (proto == 6 and state == "0A") or (proto == 17 and rport == 0)
                    yield proto, _hex_ip(lip), lport, _hex_ip(rip), rport, inode, listening
        except FileNotFoundError:
            continue


_CGROUP_ID = re.compile(r"([0-9a-f]{64})")


class ProcessMap:
    """socket inode -> (pid, comm, container id) by scanning /proc/<pid>/fd."""

    def __init__(self, proc="/proc"):
        self.proc = proc
        self.inodes = {}

    def refresh(self, wanted):
        missing = wanted - self.inodes.keys()
        if not missing:
            return
        found = {}
        remaining = set(missing)
        # Look where new sockets usually are first: processes that already own
        # sockets, then the newest processes (e.g. a curl that just started).
        pids = [p for p in os.listdir(self.proc) if p.isdigit()]
        owners = {str(v[0]) for v in self.inodes.values() if v}
        order = sorted(owners & set(pids), key=int, reverse=True) + \
            sorted(set(pids) - owners, key=int, reverse=True)
        for pid in order:
            if not remaining:
                break  # every new socket has an owner; skip the rest of the scan
            fd_dir = f"{self.proc}/{pid}/fd"
            try:
                fds = os.listdir(fd_dir)
            except OSError:
                continue
            for fd in fds:
                try:
                    link = os.readlink(f"{fd_dir}/{fd}")
                except OSError:
                    continue
                if link.startswith("socket:["):
                    ino = int(link[8:-1])
                    if ino in remaining:
                        found[ino] = int(pid)
                        remaining.discard(ino)
        for ino in missing:
            pid = found.get(ino)
            # None = no owner found (e.g. a kernel socket); don't rescan for it every round
            self.inodes[ino] = (pid, self._comm(pid), self._container(pid)) if pid else None
        # forget sockets that are gone
        self.inodes = {k: v for k, v in self.inodes.items() if k in wanted}

    def _comm(self, pid):
        try:
            with open(f"{self.proc}/{pid}/comm") as fh:
                return fh.read().strip()
        except OSError:
            return "?"

    def _container(self, pid):
        try:
            with open(f"{self.proc}/{pid}/cgroup") as fh:
                m = _CGROUP_ID.search(fh.read())
                return m.group(1) if m else None
        except OSError:
            return None

    def get(self, inode):
        return self.inodes.get(inode)


# ---- the agent loop ------------------------------------------------------------
class Agent:
    def __init__(self, url, token, name=None, interval=0.5, docker_sock="/var/run/docker.sock",
                 proc="/proc"):
        self.url = url.rstrip("/") + "/api/agent/report"
        self.token = token
        self.name = name or socket.gethostname()
        self.interval = interval
        self.docker_sock = docker_sock
        self.procs = ProcessMap(proc)
        self.proc = proc
        self.containers = []
        self.containers_at = 0
        self.sent = {}   # entry -> last time sent
        self.wake = threading.Event()  # set by the kernel's "new connection" events
        self.nat = (set(), set())  # (exact entries, host ips) from the last NAT table read
        self.nat_at = 0
        self.warned = set()

    def _warn_once(self, key, msg):
        if key not in self.warned:
            self.warned.add(key)
            log.warning(msg)

    def collect(self):
        """Return (exact, bound, host_ips) for this moment."""
        now = time.time()
        if now - self.containers_at > DOCKER_REFRESH:
            try:
                self.containers = docker_containers(self.docker_sock)
            except Exception as e:  # noqa: BLE001 - keep working without Docker
                self._warn_once("docker", f"Docker API unavailable ({e}); naming host processes only")
                self.containers = []
            self.containers_at = now
        by_ip = {ip: c["name"] for c in self.containers for ip in c["ips"]}
        by_id = {c["id"]: c["name"] for c in self.containers}
        published = {}
        for c in self.containers:
            for ip, proto, port in c["ports"]:
                published[(proto, port)] = c["name"]

        exact, bound, host_ips = set(), set(), set()

        # host processes and host-network containers
        socks = list(proc_sockets(self.proc))
        self.procs.refresh({s[5] for s in socks})
        for proto, lip, lport, rip, rport, inode, listening in socks:
            owner = self.procs.get(inode)
            if not owner:
                continue
            _, comm, cid = owner
            app = by_id.get(cid) if cid else None
            if comm == "docker-proxy":
                app = published.get((proto, lport), app)
            app = app or comm
            if listening:
                key_ip = "*" if ipaddress.ip_address(lip).is_unspecified else lip
                bound.add((key_ip, proto, lport, app))
            else:
                exact.add((lip, proto, lport, rip, rport, app))
                host_ips.add(lip)

        # ports published by containers (the NAT table catches the exact connections)
        for (proto, port), app in published.items():
            bound.add(("*", proto, port, app))

        # bridge-network containers, through NAT (cached between reads)
        if by_ip and now - self.nat_at >= NAT_INTERVAL:
            self.nat_at = now
            nat_exact, nat_ips = set(), set()
            try:
                for proto, (osrc, odst, osport, odport), (rsrc, rdst, rsport, rdport) in conntrack_entries():
                    if osrc in by_ip and rdst not in by_ip:
                        # outgoing from a container, masqueraded to the host address
                        nat_exact.add((rdst, proto, rdport, rsrc, rsport, by_ip[osrc]))
                        nat_ips.add(rdst)
                    elif rsrc in by_ip and osrc not in by_ip:
                        # incoming to a published port, forwarded to a container
                        nat_exact.add((odst, proto, odport, osrc, osport, by_ip[rsrc]))
                        nat_ips.add(odst)
            except RuntimeError as e:
                self._warn_once("conntrack", f"{e}; container traffic is only matched by published port")
            self.nat = (nat_exact, nat_ips)
        exact |= self.nat[0]
        host_ips |= self.nat[1]

        host_ips = {ip for ip in host_ips
                    if not ipaddress.ip_address(ip).is_loopback and ip not in by_ip}
        return exact, bound, host_ips

    def run_once(self):
        exact, bound, host_ips = self.collect()
        now = time.time()
        due = lambda e: now - self.sent.get(e, 0) > RESEND  # noqa: E731
        new_exact = [e for e in exact if due(e)]
        new_bound = [b for b in bound if due(b)]
        # keep the viewer's list of covered addresses fresh even when nothing changed
        if new_exact or new_bound or now - self.sent.get("ips", 0) > RESEND:
            body = json.dumps({"agent": self.name, "ips": sorted(host_ips),
                               "exact": new_exact, "bound": new_bound}).encode()
            req = urllib.request.Request(self.url, data=body, method="POST", headers={
                "Content-Type": "application/json", "X-Agent-Token": self.token})
            with urllib.request.urlopen(req, timeout=10) as r:
                r.read()
            for e in new_exact + new_bound:
                self.sent[e] = now
            self.sent["ips"] = now
        live = exact | bound
        self.sent = {k: v for k, v in self.sent.items() if k == "ips" or k in live}
        return len(exact), len(bound)

    def watch_new_connections(self):
        """Wake the main loop the moment any connection starts (conntrack events), so
        short transfers are seen while their socket still exists."""
        def follow(family):
            while True:
                try:
                    p = subprocess.Popen(["conntrack", "-E", "-e", "NEW", "-f", family],
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                    for _ in p.stdout:
                        self.wake.set()
                    p.wait()
                except OSError as e:
                    self._warn_once("events", f"no connection events ({e}); checking every {self.interval}s")
                    return
                time.sleep(5)  # conntrack exited (e.g. missing capability); retry slowly
        for family in ("ipv4", "ipv6"):
            threading.Thread(target=follow, args=(family,), daemon=True, name=f"events-{family}").start()

    def run(self):
        log.info("agent %s reporting to %s (every %ss and on new connections)", self.name, self.url,
                 self.interval)
        self.watch_new_connections()
        failures = 0
        while True:
            # wait for a new connection or the regular interval, but at most 10 rounds/s
            self.wake.wait(self.interval)
            self.wake.clear()
            started = time.time()
            try:
                n_exact, n_bound = self.run_once()
                if failures:
                    log.info("reporting again (%d connections, %d listening)", n_exact, n_bound)
                failures = 0
            except Exception as e:  # noqa: BLE001 - viewer restarts, network blips
                failures += 1
                if failures in (1, 10) or failures % 100 == 0:
                    hint = ""
                    if getattr(e, "code", None) == 401:
                        hint = " - TFV_AGENT_TOKEN differs between the agent and the viewer"
                    elif getattr(e, "code", None) == 403:
                        hint = " - the viewer has no TFV_AGENT_TOKEN set"
                    elif isinstance(getattr(e, "reason", e), (ConnectionRefusedError, TimeoutError, OSError)):
                        hint = f" - can't reach the viewer at {self.url}; set TFV_URL to its LAN address"
                    log.warning("report failed (%s)%s; retrying", e, hint)
            time.sleep(max(0.0, MIN_ROUND - (time.time() - started)))


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    url = os.environ.get("TFV_URL", "http://127.0.0.1:8080")
    token = os.environ.get("TFV_AGENT_TOKEN", "")
    if not token:
        raise SystemExit("TFV_AGENT_TOKEN must be set (the same value as on the viewer)")
    Agent(url, token, os.environ.get("TFV_AGENT_NAME") or None,
          float(os.environ.get("TFV_AGENT_INTERVAL", "0.5")),
          os.environ.get("TFV_DOCKER_SOCKET", "/var/run/docker.sock"),
          os.environ.get("TFV_PROC", "/proc")).run()


if __name__ == "__main__":
    main()

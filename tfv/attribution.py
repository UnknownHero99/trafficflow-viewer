"""Which app (process or container) on a host owns a connection.

Filled by agents (tfv/agent.py) running on your servers; used while storing
flows. Flow records arrive up to a minute or two after a connection was
active, so entries are kept for a while after the agent last saw them.
"""

import hashlib
import threading
import time

TTL = 15 * 60  # seconds an entry stays valid after the agent last reported it


def clean_token(token):
    """Agent token as configured, minus stray spaces/newlines and quotes that GUIs
    and YAML lists (`- TFV_AGENT_TOKEN="abc"`) tend to leave in."""
    return (token or "").strip().strip("\"'").strip()


def token_fingerprint(token):
    """Short, non-secret fingerprint so you can compare the agent's and the
    viewer's token without showing either."""
    return hashlib.sha256(token.encode()).hexdigest()[:8] if token else ""


class Attribution:
    def __init__(self):
        self.lock = threading.Lock()
        # (local_ip, proto, local_port, remote_ip, remote_port) -> (app, expires)
        self.exact = {}
        # (local_ip or "*", proto, local_port) -> (app, expires): listening and
        # unconnected sockets, e.g. a DNS server on :53 or a web UI on :8080
        self.bound = {}
        self.hosts = set()   # local IPs that have an agent, to skip lookups for the rest
        self.agents = {}     # agent name -> {"last", "exact", "bound", "ips"}
        self.stats = {"matched": 0, "unmatched": 0}
        self.rejected = {}   # sender address -> {"reason", "count", "last"}, to show in Status
        # (server_ip, server_port, client_ip, client_port) -> (domain, expires): what
        # clients asked a reverse proxy for (TLS server name / HTTP Host)
        self.domains = {}
        self.domain_errors = {}  # agent -> why it can't read domains ("" = working)
        self._pruned = time.time()

    def report(self, agent, exact, bound, ips, domains=(), domains_error=""):
        now = time.time()
        exp = now + TTL
        with self.lock:
            for sip, sport, cip, cport, name in domains:
                self.domains[(sip, int(sport), cip, int(cport))] = (name, exp)
            self.domain_errors[agent] = domains_error or ""
            for ip, proto, lport, rip, rport, app in exact:
                self.exact[(ip, int(proto), int(lport), rip, int(rport))] = (app, exp)
            for ip, proto, port, app in bound:
                self.bound[(ip, int(proto), int(port))] = (app, exp)
            self.hosts.update(ips)
            a = self.agents.setdefault(agent, {"exact": 0, "bound": 0})
            a.update(last=int(now), ips=sorted(ips))
            a["exact"] += len(exact)
            a["bound"] += len(bound)
            if now - self._pruned > 60:
                self._prune(now)

    def _prune(self, now):
        self.exact = {k: v for k, v in self.exact.items() if v[1] > now}
        self.domains = {k: v for k, v in self.domains.items() if v[1] > now}
        self.bound = {k: v for k, v in self.bound.items() if v[1] > now}
        self._pruned = now

    def lookup(self, local_ip, proto, local_port, remote_ip, remote_port):
        """App name for a connection, or "" when unknown or no agent covers the host."""
        if local_ip not in self.hosts:
            return ""
        now = time.time()
        with self.lock:
            for table, key in (
                (self.exact, (local_ip, proto, local_port, remote_ip, remote_port)),
                (self.bound, (local_ip, proto, local_port)),
                (self.bound, ("*", proto, local_port)),
            ):
                hit = table.get(key)
                if hit and hit[1] > now:
                    self.stats["matched"] += 1
                    return hit[0]
        self.stats["unmatched"] += 1
        return ""

    def domain_for(self, f):
        """Proxy domain of the connection a flow record belongs to, or "".

        The agent sees connections as the server does. A record arriving at the
        router either still has the client's addresses before NAT (client ->
        server: compare after NAT) or is the server's reply (compare before NAT).
        """
        if not self.domains:
            return ""
        a_post = (f.nat_src or f.src, f.nat_sport or f.sport)
        b_post = (f.nat_dst or f.dst, f.nat_dport or f.dport)
        now = time.time()
        with self.lock:
            for key in ((b_post[0], b_post[1], a_post[0], a_post[1]),
                        (f.src, f.sport, f.dst, f.dport)):
                hit = self.domains.get(key)
                if hit and hit[1] > now:
                    return hit[0]
        return ""

    def reject(self, sender, reason):
        with self.lock:
            r = self.rejected.setdefault(sender, {"count": 0})
            r.update(reason=reason, last=int(time.time()))
            r["count"] += 1

    def info(self):
        with self.lock:
            return {"agents": {k: dict(v) for k, v in self.agents.items()},
                    "rejected": {k: dict(v) for k, v in self.rejected.items()},
                    "domain_errors": dict(self.domain_errors), "domain_entries": len(self.domains),
                    "entries": len(self.exact) + len(self.bound), **self.stats}

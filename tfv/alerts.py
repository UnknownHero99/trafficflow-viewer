"""Things worth a look, computed from the stored traffic. Shown in the app only.

Each alert has a stable key; acknowledging it hides it until the key changes
(e.g. internet use by a no-internet device alerts again the next day).
"""

import ipaddress
import threading
import time

CACHE_SECONDS = 60
SPIKE_MIN_BYTES = 500_000_000   # last hour must be at least this…
SPIKE_FACTOR = 3                # …and this many times the device's busiest hour of the past week


class Alerts:
    def __init__(self, store, collector=None, attribution=None, no_internet_networks=()):
        self.store = store
        self.collector = collector
        self.attribution = attribution
        self.no_internet = [ipaddress.ip_network(n, strict=False) for n in no_internet_networks]
        self._cache = (0, [])
        self._lock = threading.Lock()
        db = store.db()
        with db:
            db.execute("CREATE TABLE IF NOT EXISTS alert_acks (key TEXT PRIMARY KEY, at INTEGER)")
            cols = [r[1] for r in db.execute("PRAGMA table_info(devices)")]
            if "no_internet" not in cols:
                db.execute("ALTER TABLE devices ADD COLUMN no_internet INTEGER NOT NULL DEFAULT 0")

    # ---- acknowledgements ------------------------------------------------
    def ack(self, keys):
        db = self.store.db()
        with db:
            db.executemany("INSERT OR REPLACE INTO alert_acks VALUES (?, ?)",
                           [(k, int(time.time())) for k in keys])
            # forget acknowledgements older than 60 days
            db.execute("DELETE FROM alert_acks WHERE at < ?", (int(time.time()) - 60 * 86400,))
        self._cache = (0, [])

    def active(self):
        now = time.time()
        with self._lock:
            if now - self._cache[0] > CACHE_SECONDS:
                self._cache = (now, self._compute(int(now)))
            alerts = self._cache[1]
        acked = {r[0] for r in self.store.db().execute("SELECT key FROM alert_acks")}
        return [a for a in alerts if a["key"] not in acked]

    # ---- checks ------------------------------------------------------------
    def _compute(self, now):
        db = self.store.db()
        out = []
        devices = {r["ip"]: dict(r) for r in db.execute("SELECT * FROM devices")}
        label = lambda ip: devices.get(ip, {}).get("name") or ip  # noqa: E731
        first_data = db.execute("SELECT MIN(bucket) FROM traffic").fetchone()[0] or now

        # router silent
        last = max(self.store.stats.get("last_flow") or 0,
                   db.execute("SELECT MAX(bucket) FROM traffic").fetchone()[0] or 0)
        if last and now - last > 600:
            out.append(dict(key=f"silent:{last}", level="critical", since=last,
                            title="No flows from the router",
                            detail=f"Nothing has arrived for {int((now - last) / 60)} minutes. "
                                   "Check the router's traffic-flow target and this server's UDP port."))

        # agents
        if self.attribution:
            info = self.attribution.info()
            for name, a in info["agents"].items():
                if now - a.get("last", now) > 300:
                    out.append(dict(key=f"agent-silent:{name}:{a['last']}", level="warning", since=a["last"],
                                    title=f"Agent “{name}” stopped reporting",
                                    detail="Apps and proxy domains for its server are not being recorded."))
            for ip, r in info.get("rejected", {}).items():
                if now - r["last"] < 3600:
                    out.append(dict(key=f"agent-refused:{ip}:{r['reason']}", level="warning", since=r["last"],
                                    title=f"Agent reports from {ip} are refused",
                                    detail=f"{r['reason']} ({r['count']}×)."))

        # new devices (only once the database is older than a day, so a fresh
        # install doesn't flag everything)
        for ip, d in devices.items():
            fs = d.get("first_seen")
            # real devices send through the router with their own MAC; this skips
            # broadcast addresses, Docker networks and other address-only entries
            if not fs or not d.get("mac") or ":" in ip or now - fs > 86400 or fs - first_data < 86400:
                continue
            out.append(dict(key=f"new:{ip}", level="info", since=fs, device=ip,
                            title=f"New device {label(ip)}",
                            detail=f"First seen {_ago(now - fs)} ago" + (f", MAC {d['mac']}." if d.get("mac") else ".")))

        # devices that should stay off the internet
        day = time.strftime("%Y-%m-%d", time.localtime(now))
        rows = db.execute(
            """SELECT local_ip, SUM(bytes_up + bytes_down) b, COUNT(DISTINCT remote_ip) hosts,
                      GROUP_CONCAT(DISTINCT country) ccs, MAX(bucket) last
               FROM traffic WHERE bucket >= ? AND country NOT IN ('LAN') GROUP BY local_ip""",
            (now - 86400,)).fetchall()
        for ip, b, hosts, ccs, last_b in rows:
            flagged = devices.get(ip, {}).get("no_internet")
            in_net = self._in_no_internet_net(ip)
            if not (flagged or in_net):
                continue
            why = "marked as no-internet" if flagged else "on a no-internet network"
            top = db.execute(
                """SELECT COALESCE(a.org, t.remote_ip), t.country, SUM(bytes_up + bytes_down) b
                   FROM traffic t LEFT JOIN asn_names a ON a.asn = t.asn
                   WHERE t.bucket >= ? AND t.local_ip = ? AND t.country != 'LAN'
                   GROUP BY 1, 2 ORDER BY b DESC LIMIT 3""", (now - 86400, ip)).fetchall()
            dest = ", ".join(f"{o} ({cc})" for o, cc, _ in top)
            out.append(dict(key=f"internet:{ip}:{day}", level="warning", since=last_b, device=ip,
                            title=f"{label(ip)} used the internet",
                            detail=f"{_bytes(b)} to {hosts} hosts in the last 24 h ({why}): {dest}."))

        # traffic spikes: last hour vs. the device's busiest hour of the past week,
        # so a daily habit (evening streaming) doesn't count as a spike
        hist_start = max(first_data, now - 7 * 86400)
        if now - 3600 - hist_start >= 86400:
            busiest = {}
            for ip, b in db.execute(
                    """SELECT local_ip, SUM(bytes_up + bytes_down) FROM traffic
                       WHERE bucket >= ? AND bucket < ? GROUP BY local_ip, bucket / 3600""",
                    (hist_start, now - 3600)):
                busiest[ip] = max(busiest.get(ip, 0), b)
            hour = now - now % 3600
            for ip, b in db.execute(
                    """SELECT local_ip, SUM(bytes_up + bytes_down) FROM traffic
                       WHERE bucket >= ? GROUP BY local_ip""", (now - 3600,)).fetchall():
                peak = busiest.get(ip, 0)
                if b >= SPIKE_MIN_BYTES and b >= SPIKE_FACTOR * max(peak, 1):
                    out.append(dict(key=f"spike:{ip}:{hour}", level="info", since=now - 3600, device=ip,
                                    title=f"Traffic spike on {label(ip)}",
                                    detail=f"{_bytes(b)} in the last hour; its busiest hour in the past week "
                                           f"was {_bytes(peak)}."))

        order = {"critical": 0, "warning": 1, "info": 2}
        out.sort(key=lambda a: (order[a["level"]], -(a.get("since") or 0)))
        return out

    def _in_no_internet_net(self, ip):
        if not self.no_internet:
            return False
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.no_internet)


def _bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000


def _ago(s):
    return f"{int(s / 60)} min" if s < 5400 else f"{s / 3600:.0f} h"

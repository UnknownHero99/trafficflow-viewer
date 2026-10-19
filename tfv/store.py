"""SQLite storage: per-time-bucket aggregates of traffic between a local
device and a remote host, plus device names."""

import ipaddress
import logging
import sqlite3
import threading
import time

log = logging.getLogger("tfv.store")


def eui64_mac(ip):
    """MAC address embedded in an IPv6 address built from it (…:xxff:fexx:…), or None."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.version != 6:
        return None
    b = a.packed[8:]
    if b[3:5] != b"\xff\xfe":
        return None
    return ":".join(f"{x:02x}" for x in bytes([b[0] ^ 2]) + b[1:3] + b[5:8])

SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic (
    bucket      INTEGER NOT NULL,  -- unix time, start of bucket
    local_ip    TEXT    NOT NULL,
    remote_ip   TEXT    NOT NULL,
    port        INTEGER NOT NULL,  -- service port (lower of the two ports)
    proto       INTEGER NOT NULL,
    country     TEXT    NOT NULL,
    asn         INTEGER NOT NULL,
    bytes_up    INTEGER NOT NULL DEFAULT 0,  -- local -> remote
    bytes_down  INTEGER NOT NULL DEFAULT 0,  -- remote -> local
    pkts_up     INTEGER NOT NULL DEFAULT 0,
    pkts_down   INTEGER NOT NULL DEFAULT 0,
    flows       INTEGER NOT NULL DEFAULT 0,
    app         TEXT    NOT NULL DEFAULT '',  -- process/container from an agent, '' if unknown
    PRIMARY KEY (bucket, local_ip, remote_ip, port, proto, app)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS traffic_country ON traffic(country, bucket);
CREATE INDEX IF NOT EXISTS traffic_local ON traffic(local_ip, bucket);

CREATE TABLE IF NOT EXISTS devices (
    ip          TEXT PRIMARY KEY,
    name        TEXT,
    mac         TEXT,
    name_source TEXT,   -- 'manual' or 'dhcp'
    first_seen  INTEGER,
    last_seen   INTEGER
);

CREATE TABLE IF NOT EXISTS asn_names (
    asn  INTEGER PRIMARY KEY,
    org  TEXT
);
"""


class Classifier:
    """Decides which side of a flow is "ours"."""

    def __init__(self, local_nets, ignore_nets=()):
        self.local = [ipaddress.ip_network(n, strict=False) for n in local_nets]
        self.ignore = [ipaddress.ip_network(n, strict=False) for n in ignore_nets]
        self._cache = {}

    def is_local(self, ip):
        r = self._cache.get(ip)
        if r is None:
            a = ipaddress.ip_address(ip)
            r = any(a in n for n in self.local)
            if len(self._cache) > 100000:
                self._cache.clear()
            self._cache[ip] = r
        return r

    def ignored(self, ip):
        if not self.ignore:
            return False
        a = ipaddress.ip_address(ip)
        return any(a in n for n in self.ignore)


class Store:
    def __init__(self, path, geo, classifier, bucket_seconds=60, retention_days=30,
                 attribution=None):
        self.path = path
        self.geo = geo
        self.cls = classifier
        self.attribution = attribution
        self.bucket_seconds = bucket_seconds
        self.retention_days = retention_days
        self._local = threading.local()
        self._pending = {}
        self._devices_seen = {}   # ip -> (mac, last_seen)
        # A device has one IPv4 address but several IPv6 ones; IPv6 traffic is filed
        # under the IPv4 address of the device with the same MAC.
        self._mac_v4 = {}         # mac -> IPv4 address
        self._v6_mac = {}         # IPv6 address -> mac
        self._asn_seen = {}
        self._lock = threading.Lock()
        self.stats = {"stored_flows": 0, "unclassified_flows": 0,
                      "ignored_flows": 0, "last_flow": 0}
        db = self.db()
        self._migrate(db)
        db.executescript(SCHEMA)
        db.commit()
        self._backfill_lan(db)
        for ip, mac in db.execute("SELECT ip, mac FROM devices WHERE mac IS NOT NULL ORDER BY last_seen"):
            if ":" in ip:
                self._v6_mac[ip] = mac.lower()
            else:
                self._mac_v4[mac.lower()] = ip
        self._merge_ipv6(db)

    def device_ip(self, ip, mac=None):
        """The address to file a local address's traffic under (IPv6 -> owner's IPv4)."""
        if ":" not in ip:
            if mac:
                self._mac_v4[mac.lower()] = ip
            return ip
        mac = (mac or self._v6_mac.get(ip) or eui64_mac(ip) or "").lower()
        if not mac:
            return ip
        if len(self._v6_mac) > 50000:
            self._v6_mac.clear()
        self._v6_mac[ip] = mac
        return self._mac_v4.get(mac, ip)

    def _merge_ipv6(self, db):
        """Version 3: move history stored under IPv6 addresses to the owning device."""
        if db.execute("PRAGMA user_version").fetchone()[0] >= 3:
            return
        moves = {}
        for (ip,) in db.execute("SELECT DISTINCT local_ip FROM traffic WHERE local_ip LIKE '%:%'"):
            target = self.device_ip(ip)
            if target != ip:
                moves[ip] = target
        if moves:
            log.info("merging %d IPv6 addresses into their devices (one-off)", len(moves))
            for old, new in moves.items():
                db.execute(
                    """INSERT INTO traffic (bucket, local_ip, remote_ip, port, proto, app, country, asn,
                           bytes_up, bytes_down, pkts_up, pkts_down, flows)
                       SELECT bucket, ?, remote_ip, port, proto, app, country, asn,
                           bytes_up, bytes_down, pkts_up, pkts_down, flows
                       FROM traffic WHERE local_ip = ?
                       ON CONFLICT DO UPDATE SET
                           bytes_up = bytes_up + excluded.bytes_up,
                           bytes_down = bytes_down + excluded.bytes_down,
                           pkts_up = pkts_up + excluded.pkts_up,
                           pkts_down = pkts_down + excluded.pkts_down,
                           flows = flows + excluded.flows""", (new, old))
                db.execute("DELETE FROM traffic WHERE local_ip = ?", (old,))
                # the other end of local traffic
                db.execute(
                    """INSERT INTO traffic (bucket, local_ip, remote_ip, port, proto, app, country, asn,
                           bytes_up, bytes_down, pkts_up, pkts_down, flows)
                       SELECT bucket, local_ip, ?, port, proto, app, country, asn,
                           bytes_up, bytes_down, pkts_up, pkts_down, flows
                       FROM traffic WHERE remote_ip = ?
                       ON CONFLICT DO UPDATE SET
                           bytes_up = bytes_up + excluded.bytes_up,
                           bytes_down = bytes_down + excluded.bytes_down,
                           pkts_up = pkts_up + excluded.pkts_up,
                           pkts_down = pkts_down + excluded.pkts_down,
                           flows = flows + excluded.flows""", (new, old))
                db.execute("DELETE FROM traffic WHERE remote_ip = ?", (old,))
                # keep a name typed for the IPv6 address only if the device has none
                db.execute("""UPDATE devices SET name = (SELECT name FROM devices WHERE ip = ?)
                              WHERE ip = ? AND name IS NULL""", (old, new))
                db.execute("DELETE FROM devices WHERE ip = ?", (old,))
        db.execute("PRAGMA user_version = 3")
        db.commit()

    def _backfill_lan(self, db):
        """Before version 2, traffic between two of your devices was stored only as the
        sender's upload. Add the receiver's download side to that history, once."""
        if db.execute("PRAGMA user_version").fetchone()[0] >= 2:
            return
        remotes = [r[0] for r in db.execute("SELECT DISTINCT remote_ip FROM traffic WHERE country = 'LAN'")
                   if self.cls.is_local(r[0])]
        if remotes:
            log.info("adding the receiving side of %d local devices' past traffic (one-off)", len(remotes))
            db.execute("CREATE TEMP TABLE lan_remotes (ip TEXT PRIMARY KEY)")
            db.executemany("INSERT INTO lan_remotes VALUES (?)", [(r,) for r in remotes])
            db.execute(
                """INSERT INTO traffic (bucket, local_ip, remote_ip, port, proto, app, country, asn,
                       bytes_up, bytes_down, pkts_up, pkts_down, flows)
                   SELECT bucket, remote_ip, local_ip, port, proto, '', 'LAN', 0,
                       bytes_down, bytes_up, pkts_down, pkts_up, flows
                   FROM traffic WHERE country = 'LAN' AND remote_ip IN (SELECT ip FROM lan_remotes)
                   ON CONFLICT DO UPDATE SET
                       bytes_up = bytes_up + excluded.bytes_up,
                       bytes_down = bytes_down + excluded.bytes_down,
                       pkts_up = pkts_up + excluded.pkts_up,
                       pkts_down = pkts_down + excluded.pkts_down,
                       flows = flows + excluded.flows""")
            db.executemany(
                """INSERT INTO devices (ip, first_seen, last_seen) VALUES (?, NULL, NULL)
                   ON CONFLICT(ip) DO NOTHING""", [(r,) for r in remotes])
            db.execute("DROP TABLE lan_remotes")
        db.execute("PRAGMA user_version = 2")
        db.commit()

    @staticmethod
    def _migrate(db):
        """Databases from before app attribution: add the app column to the key."""
        cols = [r[1] for r in db.execute("PRAGMA table_info(traffic)")]
        if not cols or "app" in cols:
            return
        log.info("upgrading database: adding app column (one-off, may take a moment)")
        db.execute("DROP INDEX IF EXISTS traffic_country")
        db.execute("DROP INDEX IF EXISTS traffic_local")
        db.execute("ALTER TABLE traffic RENAME TO traffic_old")
        db.executescript(SCHEMA)
        db.execute("""INSERT INTO traffic (bucket, local_ip, remote_ip, port, proto, country, asn,
                          bytes_up, bytes_down, pkts_up, pkts_down, flows, app)
                      SELECT bucket, local_ip, remote_ip, port, proto, country, asn,
                          bytes_up, bytes_down, pkts_up, pkts_down, flows, ''
                      FROM traffic_old""")
        db.execute("DROP TABLE traffic_old")
        db.commit()

    def db(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    # ---- ingest ---------------------------------------------------------
    def add_flows(self, flows, now=None):
        now = int(now or time.time())
        bucket = now - now % self.bucket_seconds
        is_local = self.cls.is_local
        attr = self.attribution
        with self._lock:
            for f in flows:
                src, dst = f.src, f.dst
                sport, dport = f.sport, f.dport
                if self.cls.ignored(src) or self.cls.ignored(dst):
                    self.stats["ignored_flows"] += 1
                    continue
                sl, dl = is_local(src), is_local(dst)
                # The router reports addresses as the packet arrived, so the post-NAT
                # destination is who really receives it: a LAN device behind the WAN
                # address, a port-forward target, or with hairpin NAT (a device using
                # your public domain) the device behind the router's own LAN address.
                if f.nat_dst and f.nat_dst != dst and is_local(f.nat_dst):
                    dst, dl = f.nat_dst, True
                    dport = f.nat_dport or dport
                elif not sl and not dl and f.nat_src and is_local(f.nat_src):
                    src, sl = f.nat_src, True
                    sport = f.nat_sport or sport
                # Each side that is one of ours gets its own row: the sender as upload,
                # the receiver as download. Traffic between two of your devices (e.g. a
                # Jellyfin server streaming to a TV) therefore shows on both of them.
                sides = []
                if sl:
                    sides.append((src, dst, sport, dport, True, f.src_mac))
                if dl:
                    # The destination MAC of a routed packet is the router's own, so
                    # only learn MACs from the sending side.
                    sides.append((dst, src, dport, sport, False, None))
                if not sides:
                    self.stats["unclassified_flows"] += 1
                    continue
                if f.proto in (6, 17, 132):  # service port, from the (post-NAT) ports
                    port = min(sport, dport) if sport and dport else (sport or dport)
                else:
                    port = 0
                for local, remote, lport, rport, upload, mac in sides:
                    # agents report the real (IPv6) address, so look the app up first
                    app = attr.lookup(local, f.proto, lport, remote, rport) if attr else ""
                    addr = self.device_ip(local, mac)
                    if addr != local:
                        local, mac = addr, None  # filed under the device's IPv4 address
                    if ":" in remote and is_local(remote):
                        remote = self.device_ip(remote)
                    key = (bucket, local, remote, port, f.proto, app)
                    agg = self._pending.get(key)
                    if agg is None:
                        agg = self._pending[key] = [0, 0, 0, 0, 0]
                    if upload:
                        agg[0] += f.bytes
                        agg[2] += f.packets
                    else:
                        agg[1] += f.bytes
                        agg[3] += f.packets
                    agg[4] += 1
                    prev = self._devices_seen.get(local)
                    self._devices_seen[local] = (mac or (prev[0] if prev else None), now)
                self.stats["stored_flows"] += 1
                self.stats["last_flow"] = now

    def flush(self):
        with self._lock:
            pending, self._pending = self._pending, {}
            devices, self._devices_seen = self._devices_seen, {}
        if not pending and not devices:
            return
        rows = []
        new_asns = []
        for (bucket, local, remote, port, proto, app), (bu, bd, pu, pd, n) in pending.items():
            cc = self.geo.lookup_country(remote)
            asn, org = self.geo.lookup_asn(remote)
            if asn and asn not in self._asn_seen:
                self._asn_seen[asn] = org
                new_asns.append((asn, org))
            rows.append((bucket, local, remote, port, proto, app, cc, asn, bu, bd, pu, pd, n))
        db = self.db()
        with db:
            db.executemany(
                """INSERT INTO traffic (bucket, local_ip, remote_ip, port, proto, app, country,
                       asn, bytes_up, bytes_down, pkts_up, pkts_down, flows)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT DO UPDATE SET
                       bytes_up = bytes_up + excluded.bytes_up,
                       bytes_down = bytes_down + excluded.bytes_down,
                       pkts_up = pkts_up + excluded.pkts_up,
                       pkts_down = pkts_down + excluded.pkts_down,
                       flows = flows + excluded.flows""", rows)
            if new_asns:
                db.executemany("INSERT OR REPLACE INTO asn_names VALUES (?,?)", new_asns)
            db.executemany(
                """INSERT INTO devices (ip, mac, first_seen, last_seen) VALUES (?,?,?,?)
                   ON CONFLICT(ip) DO UPDATE SET
                       last_seen = excluded.last_seen,
                       mac = COALESCE(excluded.mac, devices.mac)""",
                [(ip, mac, ts, ts) for ip, (mac, ts) in devices.items()])

    def prune(self):
        cutoff = int(time.time()) - self.retention_days * 86400
        db = self.db()
        with db:
            n = db.execute("DELETE FROM traffic WHERE bucket < ?", (cutoff,)).rowcount
        if n:
            log.info("pruned %d old rows", n)

    # ---- devices --------------------------------------------------------
    def set_device_name(self, ip, name, source="manual"):
        db = self.db()
        with db:
            if source == "dhcp":
                # never overwrite a name the user typed in
                db.execute(
                    """INSERT INTO devices (ip, name, name_source) VALUES (?,?,?)
                       ON CONFLICT(ip) DO UPDATE SET name = excluded.name,
                           name_source = excluded.name_source
                       WHERE devices.name_source IS NOT 'manual' OR devices.name IS NULL""",
                    (ip, name, source))
            else:
                db.execute(
                    """INSERT INTO devices (ip, name, name_source) VALUES (?,?,?)
                       ON CONFLICT(ip) DO UPDATE SET name = excluded.name,
                           name_source = excluded.name_source""",
                    (ip, name or None, source if name else None))

    def set_device_mac(self, ip, mac):
        db = self.db()
        with db:
            db.execute("""INSERT INTO devices (ip, mac) VALUES (?,?)
                          ON CONFLICT(ip) DO UPDATE SET mac = excluded.mac""", (ip, mac))

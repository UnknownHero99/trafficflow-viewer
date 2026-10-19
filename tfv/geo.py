"""Country and ASN lookups backed by free DB-IP Lite (or GeoLite2) databases."""

import datetime
import functools
import gzip
import ipaddress
import logging
import os
import shutil
import threading
import time
import urllib.request

from .mmdb import Reader

log = logging.getLogger("tfv.geo")

DBIP_URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{ym}.mmdb.gz"
MAX_AGE = 35 * 86400

LAN = "LAN"       # private / local address
UNKNOWN = "??"    # public address with no country in the database


class Geo:
    def __init__(self, data_dir, country_db=None, asn_db=None, auto_download=True):
        self.data_dir = data_dir
        self.country_path = country_db or os.path.join(data_dir, "dbip-country-lite.mmdb")
        self.asn_path = asn_db or os.path.join(data_dir, "dbip-asn-lite.mmdb")
        self.custom = bool(country_db or asn_db)
        self.auto_download = auto_download
        self.country = None
        self.asn = None
        self.lock = threading.Lock()
        self.status = {"country": "not loaded", "asn": "not loaded"}

    def start(self):
        self._load()
        if self.auto_download and not self.custom:
            threading.Thread(target=self._update_loop, daemon=True,
                             name="geo-update").start()

    def _load(self):
        for kind, path in (("country", self.country_path), ("asn", self.asn_path)):
            if not os.path.exists(path):
                continue
            try:
                reader = Reader(path)
            except Exception as e:  # noqa: BLE001 - report any broken file
                self.status[kind] = f"error: {e}"
                log.warning("cannot load %s: %s", path, e)
                continue
            with self.lock:
                setattr(self, kind, reader)
            built = reader.metadata.get("build_epoch")
            when = datetime.datetime.fromtimestamp(built).date() if built else "?"
            self.status[kind] = f"{os.path.basename(path)} (built {when})"
            log.info("loaded %s database %s", kind, path)
        self.lookup_country.cache_clear()
        self.lookup_asn.cache_clear()

    def _update_loop(self):
        while True:
            changed = False
            for kind, path in (("country", self.country_path), ("asn", self.asn_path)):
                fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < MAX_AGE
                if not fresh:
                    changed |= self._download(kind, path)
            if changed:
                self._load()
            time.sleep(86400)

    def _download(self, kind, path):
        os.makedirs(self.data_dir, exist_ok=True)
        today = datetime.date.today()
        prev = (today.replace(day=1) - datetime.timedelta(days=1))
        for d in (today, prev):  # current month's file may not be out yet
            url = DBIP_URL.format(kind=kind, ym=d.strftime("%Y-%m"))
            tmp = path + ".part"
            try:
                log.info("downloading %s", url)
                self.status[kind] = "downloading…"
                req = urllib.request.Request(url, headers={"User-Agent": "tfv/1.0"})
                with urllib.request.urlopen(req, timeout=120) as resp, \
                        gzip.GzipFile(fileobj=resp) as gz, open(tmp, "wb") as out:
                    shutil.copyfileobj(gz, out)
                Reader(tmp)  # validate before replacing
                os.replace(tmp, path)
                return True
            except Exception as e:  # noqa: BLE001 - try previous month, then give up
                log.warning("download of %s failed: %s", url, e)
                if os.path.exists(tmp):
                    os.remove(tmp)
        if not os.path.exists(path):
            self.status[kind] = "download failed (see log)"
        return False

    @functools.lru_cache(maxsize=65536)
    def lookup_country(self, ip):
        addr = ipaddress.ip_address(ip)
        if not addr.is_global:
            return LAN
        reader = self.country
        if reader is None:
            return UNKNOWN
        try:
            rec = reader.get(ip)
        except Exception:  # noqa: BLE001
            return UNKNOWN
        if not rec:
            return UNKNOWN
        c = rec.get("country") or rec.get("registered_country") or {}
        return c.get("iso_code") or UNKNOWN

    @functools.lru_cache(maxsize=65536)
    def lookup_asn(self, ip):
        """Return (asn number, organisation) or (0, '')."""
        reader = self.asn
        if reader is None or not ipaddress.ip_address(ip).is_global:
            return 0, ""
        try:
            rec = reader.get(ip)
        except Exception:  # noqa: BLE001
            return 0, ""
        if not rec:
            return 0, ""
        return (rec.get("autonomous_system_number", 0),
                rec.get("autonomous_system_organization", ""))

"""Optional: pull device names from the router's DHCP leases (RouterOS v7 REST API)."""

import base64
import json
import logging
import ssl
import threading
import time
import urllib.request

log = logging.getLogger("tfv.mikrotik")


class LeaseSync:
    def __init__(self, store, url, user, password, verify_tls=True, interval=300):
        self.store = store
        self.url = url.rstrip("/")
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.ctx = ssl.create_default_context()
        if not verify_tls:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.interval = interval
        self.status = "not run yet"

    def start(self):
        threading.Thread(target=self._loop, daemon=True, name="lease-sync").start()

    def _get(self, path):
        req = urllib.request.Request(self.url + "/rest" + path,
                                     headers={"Authorization": self.auth})
        with urllib.request.urlopen(req, timeout=15, context=self.ctx) as r:
            return json.load(r)

    def sync_once(self):
        leases = self._get("/ip/dhcp-server/lease")
        named = 0
        for lease in leases:
            ip = lease.get("active-address") or lease.get("address")
            if not ip:
                continue
            name = lease.get("comment") or lease.get("host-name")
            mac = lease.get("active-mac-address") or lease.get("mac-address")
            if name:
                self.store.set_device_name(ip, name, source="dhcp")
                named += 1
            if mac:
                self.store.set_device_mac(ip, mac.lower())
        self.status = f"ok: {len(leases)} leases, {named} named ({time.strftime('%H:%M')})"
        log.info("lease sync: %s", self.status)

    def _loop(self):
        while True:
            try:
                self.sync_once()
            except Exception as e:  # noqa: BLE001 - keep retrying
                self.status = f"error: {e}"
                log.warning("lease sync failed: %s", e)
            time.sleep(self.interval)

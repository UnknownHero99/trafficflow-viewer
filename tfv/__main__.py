"""Entry point: python3 -m tfv [-c config.toml]"""

import argparse
import collections
import logging
import os
import signal
import socket
import threading
import time
import tomllib

from .attribution import Attribution
from .geo import Geo
from .mikrotik import LeaseSync
from .netflow import Decoder
from .store import Classifier, Store
from .web import App, serve

log = logging.getLogger("tfv")

DATA_DIR = os.environ.get("TFV_DATA_DIR", "data")

DEFAULTS = {
    "collector": {"listen": "0.0.0.0", "port": 2055},
    "web": {"listen": "0.0.0.0", "port": 8080, "username": "", "password": ""},
    "storage": {"path": os.path.join(DATA_DIR, "tfv.sqlite"), "bucket_seconds": 60, "retention_days": 30},
    "network": {
        "local_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                           "fc00::/7", "fe80::/10"],
        "ignore_networks": ["224.0.0.0/4", "255.255.255.255/32", "ff00::/8"],
    },
    "geoip": {"data_dir": DATA_DIR, "auto_download": True, "country_db": "", "asn_db": ""},
    # Shared secret for agents that report which app owns each connection
    # (tfv/agent.py). Agent reports are refused until this is set.
    "agent": {"token": os.environ.get("TFV_AGENT_TOKEN", "")},
    "mikrotik": {"enabled": False, "url": "", "username": "", "password": "",
                 "verify_tls": True, "interval": 300},
}


def load_config(path):
    cfg = {k: dict(v) for k, v in DEFAULTS.items()}
    if path and os.path.exists(path):
        with open(path, "rb") as fh:
            for section, values in tomllib.load(fh).items():
                cfg.setdefault(section, {}).update(values)
    elif path:
        log.warning("config %s not found, using defaults", path)
    return cfg


class Collector:
    """Receives UDP export packets and hands decoded flows to the store."""

    def __init__(self, host, port, decoder, store):
        self.decoder = decoder
        self.store = store
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        self.sock.bind((host, port))
        self.addr = f"{host}:{port}"
        self.exporters = {}  # ip -> {"packets", "last"}
        self.recent = collections.deque(maxlen=3000)  # (time, Flow) for the debug view

    def info(self):
        return {"listen": self.addr, "exporters": self.exporters}

    def run(self):
        log.info("collecting flows on udp/%s", self.addr)
        while True:
            data, (ip, *_) = self.sock.recvfrom(65535)
            e = self.exporters.setdefault(ip, {"packets": 0, "last": 0})
            e["packets"] += 1
            e["last"] = int(time.time())
            flows = self.decoder.decode(data, ip)
            if flows:
                now = time.time()
                self.recent.extend((now, f) for f in flows)
                self.store.add_flows(flows)


def housekeeping(store, decoder):
    last_prune = 0
    while True:
        time.sleep(5)
        try:
            store.flush()
            if time.time() - last_prune > 3600:
                store.prune()
                decoder.expire_templates()
                last_prune = time.time()
        except Exception:  # noqa: BLE001 - never let the writer die
            log.exception("flush failed")


def main():
    ap = argparse.ArgumentParser(description="MikroTik Traffic Flow viewer")
    ap.add_argument("-c", "--config", default=os.environ.get("TFV_CONFIG", "config.toml"))
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config(args.config)

    st = cfg["storage"]
    os.makedirs(os.path.dirname(os.path.abspath(st["path"])), exist_ok=True)
    g = cfg["geoip"]
    geo = Geo(g["data_dir"], g.get("country_db") or None, g.get("asn_db") or None,
              g["auto_download"])
    geo.start()
    net = cfg["network"]
    attribution = Attribution()
    store = Store(st["path"], geo, Classifier(net["local_networks"], net["ignore_networks"]),
                  st["bucket_seconds"], st["retention_days"], attribution)
    decoder = Decoder()
    c = cfg["collector"]
    collector = Collector(c["listen"], c["port"], decoder, store)

    lease_sync = None
    m = cfg["mikrotik"]
    if m.get("enabled") and m.get("url"):
        lease_sync = LeaseSync(store, m["url"], m["username"], m["password"],
                               m.get("verify_tls", True), m.get("interval", 300))
        lease_sync.start()

    threading.Thread(target=collector.run, daemon=True, name="collector").start()
    threading.Thread(target=housekeeping, args=(store, decoder), daemon=True,
                     name="housekeeping").start()
    w = cfg["web"]
    app = App(store, decoder, collector, geo, lease_sync, w.get("username"), w.get("password"),
              attribution, cfg["agent"].get("token") or os.environ.get("TFV_AGENT_TOKEN", ""))
    # As PID 1 in a container we get SIGTERM on `docker stop` (and on every
    # automatic update); exit promptly and save the last few seconds of flows.
    def on_term(*_):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, on_term)
    try:
        serve(app, w["listen"], w["port"])
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        store.flush()
        log.info("stopped")


if __name__ == "__main__":
    main()

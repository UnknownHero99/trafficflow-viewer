"""HTTP server: JSON API + static dashboard."""

import base64
import concurrent.futures
import csv
import hmac
import io
import ipaddress
import json
import logging
import mimetypes
import os
import socket
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import queries

log = logging.getLogger("tfv.web")
STATIC = os.path.join(os.path.dirname(__file__), "static")


class RDNS:
    def __init__(self):
        self.cache = {}
        self.pool = concurrent.futures.ThreadPoolExecutor(16, thread_name_prefix="rdns")

    @staticmethod
    def _lookup(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return ""

    def resolve(self, ips, timeout=3.0):
        out, todo = {}, {}
        for ip in ips[:100]:
            if ip in self.cache:
                out[ip] = self.cache[ip]
            else:
                todo[ip] = self.pool.submit(self._lookup, ip)
        done, _ = concurrent.futures.wait(todo.values(), timeout=timeout)
        for ip, fut in todo.items():
            if fut in done:
                out[ip] = self.cache[ip] = fut.result()
        if len(self.cache) > 50000:
            self.cache.clear()
        return out


class App:
    def __init__(self, store, decoder, collector, geo, lease_sync=None,
                 username=None, password=None, attribution=None, agent_token=""):
        self.attribution = attribution
        self.agent_token = agent_token
        self.store = store
        self.decoder = decoder
        self.collector = collector
        self.geo = geo
        self.lease_sync = lease_sync
        self.rdns = RDNS()
        self.auth = None
        if username and password:
            self.auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        self.started = time.time()

    def recent_flows(self, params):
        """Last raw flow records as decoded, optionally only those touching an IP."""
        ip = params.get("ip", "")
        limit = min(int(params.get("limit") or 200), 3000)
        out = []
        for ts, f in reversed(self.collector.recent):
            addrs = (f.src, f.dst, f.nat_src, f.nat_dst)
            if ip and ip not in addrs:
                continue
            raw = {}
            for fid, v in (f.raw or {}).items():
                raw[fid] = int.from_bytes(v, "big") if len(v) <= 4 and fid not in (8, 12, 225, 226) \
                    else (str(ipaddress.ip_address(v)) if len(v) in (4, 16) else v.hex(":"))
            out.append({"time": round(ts, 1), "exporter": f.exporter, "src": f.src, "sport": f.sport,
                        "dst": f.dst, "dport": f.dport, "proto": f.proto, "bytes": f.bytes,
                        "packets": f.packets, "in_if": f.in_if, "out_if": f.out_if,
                        "src_mac": f.src_mac, "dst_mac": f.dst_mac,
                        "nat_src": f.nat_src, "nat_dst": f.nat_dst, "raw": raw})
            if len(out) >= limit:
                break
        templates = {f"{k[0]} {k[1]} #{k[2]}": [fid for fid, _ in v[0]]
                     for k, v in self.decoder.templates.items()}
        return {"templates": templates, "flows": out}

    def status(self):
        db_size = sum(os.path.getsize(p) for p in
                      (self.store.path, self.store.path + "-wal") if os.path.exists(p))
        return {
            "uptime": int(time.time() - self.started),
            "version": os.environ.get("TFV_VERSION", "dev")[:12],
            "collector": {**self.collector.info(), **self.decoder.stats,
                          "templates": len(self.decoder.templates)},
            "store": {**self.store.stats, "db_bytes": db_size,
                      "bucket_seconds": self.store.bucket_seconds,
                      "retention_days": self.store.retention_days},
            "geo": self.geo.status,
            "lease_sync": self.lease_sync.status if self.lease_sync else None,
            "agents": dict(self.attribution.info(), token_set=bool(self.agent_token))
                      if self.attribution else None,
        }


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "tfv"

        def log_message(self, fmt, *args):
            log.debug("%s " + fmt, self.address_string(), *args)

        def _authorized(self):
            if not app.auth:
                return True
            got = self.headers.get("Authorization", "")
            if hmac.compare_digest(got, app.auth):
                return True
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="tfv"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False

        def _send(self, code, body, ctype="application/json", extra=None):
            if not isinstance(body, bytes):
                body = json.dumps(body, separators=(",", ":")).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/healthz":
                return self._send(200, b"ok", "text/plain")
            if not self._authorized():
                return
            url = urllib.parse.urlsplit(self.path)
            params = dict(urllib.parse.parse_qsl(url.query))
            path = url.path
            db = app.store.db()
            bs = app.store.bucket_seconds
            try:
                if path == "/api/summary":
                    return self._send(200, queries.summary(db, params, bs))
                if path == "/api/connections":
                    data = queries.connections(db, params, bs)
                    if params.get("format") == "csv":
                        return self._csv(data["rows"])
                    return self._send(200, data)
                if path == "/api/values":
                    return self._send(200, queries.values(db, params, bs))
                if path == "/api/country-timeline":
                    return self._send(200, queries.country_timeline(db, params, bs))
                if path == "/api/devices":
                    return self._send(200, queries.devices(db, params, bs))
                if path == "/api/status":
                    return self._send(200, app.status())
                if path == "/api/debug/flows":
                    return self._send(200, app.recent_flows(params))
                if path == "/api/rdns":
                    ips = [i for i in params.get("ips", "").split(",") if i]
                    return self._send(200, app.rdns.resolve(ips))
            except Exception as e:  # noqa: BLE001
                log.exception("API error")
                return self._send(500, {"error": str(e)})
            return self._static(path)

        def do_POST(self):
            if self.path == "/api/agent/report":
                return self._agent_report()
            if not self._authorized():
                return
            # Requiring JSON forces a CORS preflight, so other sites can't POST here.
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                return self._send(415, {"error": "expected application/json"})
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self._send(400, {"error": "bad json"})
            if self.path == "/api/devices":
                ip = str(body.get("ip", "")).strip()
                if not ip:
                    return self._send(400, {"error": "ip required"})
                name = str(body.get("name", "")).strip()[:100]
                app.store.set_device_name(ip, name, "manual")
                return self._send(200, {"ok": True})
            if self.path == "/api/lease-sync" and app.lease_sync:
                try:
                    app.lease_sync.sync_once()
                except Exception as e:  # noqa: BLE001
                    return self._send(502, {"error": str(e)})
                return self._send(200, {"ok": True, "status": app.lease_sync.status})
            return self._send(404, {"error": "not found"})

        def _agent_report(self):
            """Connection owners from an agent. Uses its own shared token (not the UI login)."""
            token = self.headers.get("X-Agent-Token", "")
            sender = self.client_address[0]
            if not app.agent_token:
                app.attribution.reject(sender, "the viewer has no TFV_AGENT_TOKEN set")
                return self._send(403, {"error": "agent reports are off: set TFV_AGENT_TOKEN on the viewer"})
            if not hmac.compare_digest(token, app.agent_token):
                app.attribution.reject(sender, "wrong token" if token else "no token sent")
                return self._send(401, {"error": "agent token doesn't match the viewer's TFV_AGENT_TOKEN"})
            length = int(self.headers.get("Content-Length") or 0)
            if length > 20_000_000:
                return self._send(413, {"error": "too large"})
            try:
                body = json.loads(self.rfile.read(length))
                app.attribution.report(
                    str(body.get("agent") or self.client_address[0])[:64],
                    [(str(ip), int(p), int(lp), str(rip), int(rp), str(a)[:64])
                     for ip, p, lp, rip, rp, a in body.get("exact", [])],
                    [(str(ip), int(p), int(port), str(a)[:64]) for ip, p, port, a in body.get("bound", [])],
                    {str(ip) for ip in body.get("ips", [])},
                )
            except (ValueError, TypeError) as e:
                return self._send(400, {"error": f"bad report: {e}"})
            return self._send(200, {"ok": True})

        def _csv(self, rows):
            buf = io.StringIO()
            cols = ["local", "name", "app", "remote", "cc", "asn", "org", "port", "proto",
                    "down", "up", "total", "flows", "first", "last"]
            w = csv.writer(buf)
            w.writerow(cols)
            for r in rows:
                w.writerow([r.get(c) for c in cols])
            self._send(200, buf.getvalue().encode(), "text/csv",
                       {"Content-Disposition": 'attachment; filename="connections.csv"'})

        def _static(self, path):
            if path in ("", "/"):
                path = "/index.html"
            full = os.path.normpath(os.path.join(STATIC, path.lstrip("/")))
            if not full.startswith(STATIC + os.sep) or not os.path.isfile(full):
                return self._send(404, b"not found", "text/plain")
            ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
            with open(full, "rb") as fh:
                self._send(200, fh.read(), ctype)

    return Handler


def serve(app, host, port):
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    httpd.daemon_threads = True
    log.info("dashboard on http://%s:%d/", host if host != "0.0.0.0" else "localhost", port)
    httpd.serve_forever()

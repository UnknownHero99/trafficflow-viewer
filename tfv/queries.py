"""Read-side queries used by the web API."""

import time

NICE_STEPS = [60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400]

CONNECTION_SORTS = {
    "total": "total", "down": "down", "up": "up", "flows": "flows",
    "last": "last", "first": "first", "local": "t.local_ip", "remote": "t.remote_ip",
    "country": "t.country", "port": "t.port", "org": "org", "name": "name", "app": "t.app",
}


def _int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


FILTER_COLUMNS = {
    "device": ("t.local_ip", str), "country": ("t.country", str), "remote": ("t.remote_ip", str),
    "port": ("t.port", _int), "proto": ("t.proto", _int), "asn": ("t.asn", _int),
    "app": ("t.app", str),
}


def build_filter(params, bucket_seconds):
    """Turn query parameters into (where sql, args, from, to)."""
    now = int(time.time())
    rng = _int(params.get("range"), 3600)
    to = _int(params.get("to"), now)
    frm = _int(params.get("from"), to - rng)
    frm -= frm % bucket_seconds
    where = ["t.bucket >= ?", "t.bucket <= ?"]
    args = [frm, to]
    # Every dimension can be included ("country=SI,DE") or excluded ("not_country=CN").
    for key, (col, conv) in FILTER_COLUMNS.items():
        for neg in (False, True):
            raw = params.get(("not_" if neg else "") + key, "")
            vals = [conv(v) for v in raw.split(",") if v]
            vals = [v for v in vals if v is not None]
            if vals:
                op = "NOT IN" if neg else "IN"
                where.append(f"{col} {op} ({','.join('?' * len(vals))})")
                args += vals
    if params.get("lan", "0") != "1":
        where.append("t.country != 'LAN'")
    q = params.get("q", "").strip()
    if q:
        like = f"%{q}%"
        where.append("""(t.local_ip LIKE ? OR t.remote_ip LIKE ? OR t.country LIKE ?
                         OR d.name LIKE ? OR a.org LIKE ? OR t.app LIKE ? OR CAST(t.port AS TEXT) = ?)""")
        args += [like, like, like, like, like, like, q]
    return " AND ".join(where), args, frm, to


FROM = """FROM traffic t
          LEFT JOIN devices d ON d.ip = t.local_ip
          LEFT JOIN asn_names a ON a.asn = t.asn"""


def summary(db, params, bucket_seconds):
    where, args, frm, to = build_filter(params, bucket_seconds)
    span = max(to - frm, bucket_seconds)
    step = next((s for s in NICE_STEPS if s >= bucket_seconds and span / s <= 150),
                NICE_STEPS[-1])

    def rows(sql, extra=()):
        return [dict(r) for r in db.execute(sql, (*args, *extra))]

    totals = rows(f"""SELECT COALESCE(SUM(bytes_down),0) down, COALESCE(SUM(bytes_up),0) up,
                         COALESCE(SUM(flows),0) flows,
                         COUNT(DISTINCT t.local_ip) devices,
                         COUNT(DISTINCT t.remote_ip) remotes,
                         COUNT(DISTINCT t.country) countries,
                         COUNT(DISTINCT t.asn) orgs,
                         MIN(t.bucket) first, MAX(t.bucket) last
                      {FROM} WHERE {where}""")[0]
    series = rows(f"""SELECT (t.bucket / {step}) * {step} t, SUM(bytes_down) down, SUM(bytes_up) up
                      {FROM} WHERE {where} GROUP BY 1 ORDER BY 1""")
    countries = rows(f"""SELECT t.country cc, SUM(bytes_down) down, SUM(bytes_up) up,
                            SUM(flows) flows, COUNT(DISTINCT t.local_ip) devices,
                            COUNT(DISTINCT t.remote_ip) remotes,
                            COUNT(DISTINCT t.asn) orgs,
                            COUNT(DISTINCT t.port || '/' || t.proto) services,
                            MIN(t.bucket) first, MAX(t.bucket) last
                         {FROM} WHERE {where} GROUP BY t.country
                         ORDER BY SUM(bytes_down + bytes_up) DESC""")
    # Biggest organisation, device and service inside each country.
    for key, sql in (
        ("top_org", f"""SELECT t.country, a.org, t.asn, SUM(bytes_down + bytes_up) b
                        {FROM} WHERE {where} GROUP BY t.country, t.asn"""),
        ("top_device", f"""SELECT t.country, COALESCE(d.name, t.local_ip), t.local_ip,
                               SUM(bytes_down + bytes_up) b
                           {FROM} WHERE {where} GROUP BY t.country, t.local_ip"""),
        ("top_service", f"""SELECT t.country, t.proto, t.port, SUM(bytes_down + bytes_up) b
                            {FROM} WHERE {where} GROUP BY t.country, t.port, t.proto"""),
    ):
        best = {}
        for cc, label, ident, b in db.execute(sql, args):
            if cc not in best or b > best[cc][2]:
                best[cc] = (label, ident, b)
        for r in countries:
            label, ident, _ = best.get(r["cc"], (None, None, 0))
            r[key] = [label, ident]
    devices = rows(f"""SELECT t.local_ip ip, d.name name, d.mac mac,
                          SUM(bytes_down) down, SUM(bytes_up) up, SUM(flows) flows,
                          COUNT(DISTINCT t.country) countries,
                          COUNT(DISTINCT t.remote_ip) remotes
                       {FROM} WHERE {where} GROUP BY t.local_ip
                       ORDER BY SUM(bytes_down + bytes_up) DESC""")
    remotes = rows(f"""SELECT t.remote_ip ip, t.country cc, t.asn asn, a.org org,
                          SUM(bytes_down) down, SUM(bytes_up) up, SUM(flows) flows,
                          COUNT(DISTINCT t.local_ip) devices,
                          GROUP_CONCAT(DISTINCT t.port) ports
                       {FROM} WHERE {where} GROUP BY t.remote_ip
                       ORDER BY SUM(bytes_down + bytes_up) DESC LIMIT 200""")
    ports = rows(f"""SELECT t.port port, t.proto proto, SUM(bytes_down) down, SUM(bytes_up) up,
                        SUM(flows) flows, COUNT(DISTINCT t.local_ip) devices
                     {FROM} WHERE {where} GROUP BY t.port, t.proto
                     ORDER BY SUM(bytes_down + bytes_up) DESC LIMIT 100""")
    orgs = rows(f"""SELECT t.asn asn, a.org org, SUM(bytes_down) down, SUM(bytes_up) up,
                       SUM(flows) flows, COUNT(DISTINCT t.local_ip) devices,
                       COUNT(DISTINCT t.remote_ip) remotes,
                       GROUP_CONCAT(DISTINCT t.country) countries
                    {FROM} WHERE {where} GROUP BY t.asn
                    ORDER BY SUM(bytes_down + bytes_up) DESC LIMIT 200""")
    apps = rows(f"""SELECT t.app app, SUM(bytes_down) down, SUM(bytes_up) up, SUM(flows) flows,
                       COUNT(DISTINCT t.local_ip) devices, COUNT(DISTINCT t.remote_ip) remotes,
                       COUNT(DISTINCT t.country) countries,
                       GROUP_CONCAT(DISTINCT COALESCE(d.name, t.local_ip)) hosts
                    {FROM} WHERE {where} GROUP BY t.app
                    ORDER BY SUM(bytes_down + bytes_up) DESC LIMIT 300""")
    for r in apps:
        r["hosts"] = sorted(set((r["hosts"] or "").split(",")) - {""})[:6]
    for r in remotes:
        r["ports"] = sorted({int(p) for p in (r["ports"] or "").split(",") if p})[:8]
    for r in orgs:
        r["countries"] = sorted(set((r["countries"] or "").split(",")) - {""})
    return {"from": frm, "to": to, "step": step, "totals": totals, "series": series,
            "countries": countries, "devices": devices, "remotes": remotes,
            "ports": ports, "orgs": orgs, "apps": apps}


def connections(db, params, bucket_seconds):
    where, args, frm, to = build_filter(params, bucket_seconds)
    sort = CONNECTION_SORTS.get(params.get("sort", "total"), "total")
    order = "ASC" if params.get("dir") == "asc" else "DESC"
    limit = min(_int(params.get("limit"), 200), 2000)
    offset = max(_int(params.get("offset"), 0), 0)
    sql = f"""SELECT t.local_ip local, d.name name, t.app app, t.remote_ip remote, t.country cc,
                     t.asn asn, a.org org, t.port port, t.proto proto,
                     SUM(bytes_down) down, SUM(bytes_up) up,
                     SUM(bytes_down + bytes_up) total, SUM(flows) flows,
                     MIN(t.bucket) first, MAX(t.bucket) last
              {FROM} WHERE {where}
              GROUP BY t.local_ip, t.app, t.remote_ip, t.port, t.proto
              ORDER BY {sort} {order} LIMIT ? OFFSET ?"""
    rows = [dict(r) for r in db.execute(sql, (*args, limit, offset))]
    count = db.execute(f"""SELECT COUNT(*) FROM (SELECT 1 {FROM} WHERE {where}
                           GROUP BY t.local_ip, t.app, t.remote_ip, t.port, t.proto)""",
                       args).fetchone()[0]
    return {"from": frm, "to": to, "count": count, "rows": rows}


def devices(db, params, bucket_seconds):
    where, args, frm, to = build_filter({**params, "device": ""}, bucket_seconds)
    usage = {r["ip"]: dict(r) for r in db.execute(
        f"""SELECT t.local_ip ip, SUM(bytes_down) down, SUM(bytes_up) up,
                   COUNT(DISTINCT t.country) countries
            {FROM} WHERE {where} GROUP BY t.local_ip""", args)}
    out = []
    for r in db.execute("SELECT * FROM devices ORDER BY last_seen DESC"):
        d = dict(r)
        u = usage.get(d["ip"], {})
        d["down"], d["up"] = u.get("down", 0), u.get("up", 0)
        d["countries"] = u.get("countries", 0)
        out.append(d)
    return {"devices": out}


def country_timeline(db, params, bucket_seconds):
    """Traffic per country per time bin, for the countries x time heatmap."""
    where, args, frm, to = build_filter(params, bucket_seconds)
    span = max(to - frm, bucket_seconds)
    step = next((s for s in NICE_STEPS if s >= bucket_seconds and span / s <= 72),
                NICE_STEPS[-1])
    rows_limit = min(_int(params.get("rows"), 20), 60)
    top = [r[0] for r in db.execute(
        f"""SELECT t.country {FROM} WHERE {where} GROUP BY t.country
            ORDER BY SUM(bytes_down + bytes_up) DESC LIMIT ?""", (*args, rows_limit))]
    cells = []
    if top:
        cells = [list(r) for r in db.execute(
            f"""SELECT t.country, (t.bucket / {step}) * {step}, SUM(bytes_down), SUM(bytes_up)
                {FROM} WHERE {where} AND t.country IN ({','.join('?' * len(top))})
                GROUP BY 1, 2""", (*args, *top))]
    return {"from": frm, "to": to, "step": step, "countries": top, "cells": cells}


VALUE_QUERIES = {
    "device": ("t.local_ip", "COALESCE(d.name, '')", "t.local_ip LIKE ? OR d.name LIKE ?"),
    "country": ("t.country", "''", "t.country LIKE ?"),
    "asn": ("t.asn", "COALESCE(a.org, '')", "CAST(t.asn AS TEXT) LIKE ? OR a.org LIKE ?"),
    "remote": ("t.remote_ip", "COALESCE(a.org, '')", "t.remote_ip LIKE ? OR a.org LIKE ?"),
    "port": ("t.port", "''", "CAST(t.port AS TEXT) LIKE ?"),
    "proto": ("t.proto", "''", "CAST(t.proto AS TEXT) LIKE ?"),
    "app": ("t.app", "''", "t.app LIKE ?"),
}


def values(db, params, bucket_seconds):
    """Candidate values for one filter field (for the filter picker), busiest first.

    The field's own include/exclude filters are ignored so you can add more values.
    """
    field = params.get("field", "")
    if field not in VALUE_QUERIES:
        return {"values": []}
    p = {k: v for k, v in params.items() if k not in (field, "not_" + field, "q")}
    where, args, _, _ = build_filter(p, bucket_seconds)
    col, label, match = VALUE_QUERIES[field]
    q = params.get("q", "").strip()
    if q and field != "country":  # country names are matched in the browser
        where += f" AND ({match})"
        args = [*args, *([f"%{q}%"] * match.count("?"))]
    rows = db.execute(f"""SELECT {col} v, MAX({label}) label, SUM(bytes_down + bytes_up) total
                          {FROM} WHERE {where} GROUP BY {col}
                          ORDER BY total DESC LIMIT 300""", args)
    return {"values": [{"value": v, "label": l, "total": t} for v, l, t in rows]}

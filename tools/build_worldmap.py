#!/usr/bin/env python3
"""Turn world-atlas TopoJSON into tfv/static/world.json: projected SVG paths
keyed by ISO 3166-1 alpha-2 code, so the browser needs no map library.

    python3 tools/build_worldmap.py countries-110m.json tfv/static/world.json

Source: world-atlas@2.0.2 countries-110m.json (ISC licence, data from
Natural Earth, public domain).
"""

import json
import math
import sys

# ISO 3166-1 numeric -> alpha-2 for every country in the 110m file.
NUMERIC = {
    "004": "AF", "008": "AL", "010": "AQ", "012": "DZ", "024": "AO", "031": "AZ", "032": "AR",
    "036": "AU", "040": "AT", "044": "BS", "050": "BD", "051": "AM", "056": "BE", "064": "BT",
    "068": "BO", "070": "BA", "072": "BW", "076": "BR", "084": "BZ", "090": "SB", "096": "BN",
    "100": "BG", "104": "MM", "108": "BI", "112": "BY", "116": "KH", "120": "CM", "124": "CA",
    "140": "CF", "144": "LK", "148": "TD", "152": "CL", "156": "CN", "158": "TW", "170": "CO",
    "178": "CG", "180": "CD", "188": "CR", "191": "HR", "192": "CU", "196": "CY", "203": "CZ",
    "204": "BJ", "208": "DK", "214": "DO", "218": "EC", "222": "SV", "226": "GQ", "231": "ET",
    "232": "ER", "233": "EE", "238": "FK", "242": "FJ", "246": "FI", "250": "FR", "260": "TF",
    "262": "DJ", "266": "GA", "268": "GE", "270": "GM", "275": "PS", "276": "DE", "288": "GH",
    "300": "GR", "304": "GL", "320": "GT", "324": "GN", "328": "GY", "332": "HT", "340": "HN",
    "348": "HU", "352": "IS", "356": "IN", "360": "ID", "364": "IR", "368": "IQ", "372": "IE",
    "376": "IL", "380": "IT", "384": "CI", "388": "JM", "392": "JP", "398": "KZ", "400": "JO",
    "404": "KE", "408": "KP", "410": "KR", "414": "KW", "417": "KG", "418": "LA", "422": "LB",
    "426": "LS", "428": "LV", "430": "LR", "434": "LY", "440": "LT", "442": "LU", "450": "MG",
    "454": "MW", "458": "MY", "466": "ML", "478": "MR", "484": "MX", "496": "MN", "498": "MD",
    "499": "ME", "504": "MA", "508": "MZ", "512": "OM", "516": "NA", "524": "NP", "528": "NL",
    "540": "NC", "548": "VU", "554": "NZ", "558": "NI", "562": "NE", "566": "NG", "578": "NO",
    "586": "PK", "591": "PA", "598": "PG", "600": "PY", "604": "PE", "608": "PH", "616": "PL",
    "620": "PT", "624": "GW", "626": "TL", "630": "PR", "634": "QA", "642": "RO", "643": "RU",
    "646": "RW", "682": "SA", "686": "SN", "688": "RS", "694": "SL", "703": "SK", "704": "VN",
    "705": "SI", "706": "SO", "710": "ZA", "716": "ZW", "724": "ES", "728": "SS", "729": "SD",
    "732": "EH", "740": "SR", "748": "SZ", "752": "SE", "756": "CH", "760": "SY", "762": "TJ",
    "764": "TH", "768": "TG", "780": "TT", "784": "AE", "788": "TN", "792": "TR", "795": "TM",
    "800": "UG", "804": "UA", "807": "MK", "818": "EG", "826": "GB", "834": "TZ", "840": "US",
    "854": "BF", "858": "UY", "860": "UZ", "862": "VE", "887": "YE", "894": "ZM",
}
# Features without an ISO id: draw them as part of the country IP databases use.
BY_NAME = {"Kosovo": "XK", "N. Cyprus": "CY", "Somaliland": "SO"}
SKIP = {"AQ"}  # Antarctica: lots of pixels, no traffic

WIDTH = 1000


def equal_earth(lon, lat):
    """Equal Earth projection (Šavrič, Patterson & Jenny 2018), unit sphere."""
    a1, a2, a3, a4 = 1.340264, -0.081106, 0.000893, 0.003796
    m = math.sqrt(3) / 2
    lam, phi = math.radians(lon), math.radians(lat)
    t = math.asin(m * math.sin(phi))
    t2 = t * t
    t6 = t2 * t2 * t2
    x = lam * math.cos(t) / (m * (a1 + 3 * a2 * t2 + t6 * (7 * a3 + 9 * a4 * t2)))
    y = t * (a1 + a2 * t2 + t6 * (a3 + a4 * t2))
    return x, y


def decode_arcs(topo):
    sx, sy = topo["transform"]["scale"]
    tx, ty = topo["transform"]["translate"]
    out = []
    for arc in topo["arcs"]:
        x = y = 0
        pts = []
        for dx, dy in arc:
            x += dx
            y += dy
            pts.append((x * sx + tx, y * sy + ty))
        out.append(pts)
    return out


def ring(arcs, idxs):
    pts = []
    for i in idxs:
        a = arcs[i] if i >= 0 else arcs[~i][::-1]
        pts.extend(a if not pts else a[1:])
    return pts


def main(src, dst):
    topo = json.load(open(src))
    arcs = decode_arcs(topo)
    # projection bounds -> scale to WIDTH
    xmax, _ = equal_earth(180, 0)
    _, ymax = equal_earth(0, 90)
    k = WIDTH / (2 * xmax)

    def proj(lon, lat):
        x, y = equal_earth(lon, lat)
        return (x + xmax) * k, (ymax - y) * k

    paths = {}
    ymin_seen, ymax_seen = 1e9, -1e9
    for g in topo["objects"]["countries"]["geometries"]:
        cc = NUMERIC.get(g.get("id")) or BY_NAME.get(g["properties"]["name"])
        if not cc:
            raise SystemExit(f"no code for {g.get('id')} {g['properties']['name']}")
        if cc in SKIP:
            continue
        polys = g["arcs"] if g["type"] == "MultiPolygon" else [g["arcs"]]
        d = []
        rings = []
        for poly in polys:
            for r in poly:
                pts = ring(arcs, r)
                if any(abs(a[0] - b[0]) > 180 for a, b in zip(pts, pts[1:])):
                    # Crosses the antimeridian (Russia, Fiji): unwrap longitudes and
                    # draw it twice, once per side; the viewBox clips the overflow.
                    unwrapped = [(lon + 360 if lon < 0 else lon, lat) for lon, lat in pts]
                    rings.append(unwrapped)
                    rings.append([(lon - 360, lat) for lon, lat in unwrapped])
                else:
                    rings.append(pts)
        for pts in rings:
            prev = None
            seg = []
            for lon, lat in pts:
                p = proj(lon, lat)
                p = (round(p[0], 1), round(p[1], 1))
                if p != prev:
                    seg.append(p)
                    prev = p
                    ymin_seen, ymax_seen = min(ymin_seen, p[1]), max(ymax_seen, p[1])
            if len(seg) >= 3:
                d.append("M" + "L".join(f"{x:g},{y:g}" for x, y in seg) + "Z")
        paths[cc] = paths.get(cc, "") + "".join(d)
    top = math.floor(ymin_seen) - 2
    height = math.ceil(ymax_seen) + 2 - top
    out = {"viewBox": f"0 {top} {WIDTH} {height}", "paths": paths,
           "source": "world-atlas@2.0.2 (Natural Earth 1:110m), Equal Earth projection"}
    with open(dst, "w") as fh:
        json.dump(out, fh, separators=(",", ":"))
    print(f"{len(paths)} countries, viewBox {out['viewBox']}")


if __name__ == "__main__":
    main(*sys.argv[1:3])

# TrafficFlow Viewer

A small self-hosted web dashboard for **MikroTik Traffic Flow** (NetFlow v5 / v9 / IPFIX).
It collects flows from your router and shows where your traffic goes:

- **Filters**: *Add filter* on country, device, organisation, remote host, service port or
  protocol, each as **is** or **is not**, picked from a searchable list that shows each value's
  traffic. Drag across the traffic chart to zoom into a time window. Filters live in the URL, so
  you can bookmark them.
- **Details**: click any country, device, organisation, host or service to open a side panel
  with its own traffic chart and breakdowns. Click through from there (country → device → host),
  or use *Only show this* / *Hide this*.
- **Countries**: a world map heatmap (hover for details, Ctrl + scroll or double-click to zoom,
  drag to pan) plus a table with share, devices, hosts, organisations, top organisation, top
  device, top service and last seen.
- **Country heatmap**: countries × time grid, showing when each country is busy. Click a
  cell to zoom the whole dashboard into that time.
- **My devices**, **Organisations (ASN)**, **Remote hosts** (with reverse DNS), **Services**.
- **Connections**: device ↔ host ↔ port, sortable, paged, **CSV export**.
- **Status**: collector counters, plus the most recent raw flow records for troubleshooting.

Pure Python standard library: no `pip install`. GeoIP uses the free
[DB-IP Lite](https://db-ip.com) databases, downloaded automatically and refreshed monthly.

---

## 1. Deploy on your server

Every push to `main` runs the tests and builds a Docker image (amd64 and arm64) with
GitHub Actions, published as `ghcr.io/<your-github-user>/trafficflow-viewer:latest`
(see [.github/workflows/docker.yml](.github/workflows/docker.yml)). The server only needs
two files, and a Watchtower container installs new images on its own.

On the server:

```bash
mkdir -p ~/trafficflow && cd ~/trafficflow
```

Copy [docker-compose.yml](docker-compose.yml) and [.env.example](.env.example) into that folder
(or `git clone` the repo there), then:

```bash
cp .env.example .env
```

Check `TFV_IMAGE` in `.env` (your GitHub user name, in lower case), then start it:

```bash
docker compose up -d
```

- Web UI: `http://<server-ip>:8080`
- Flow collector: UDP port `2055`
- Everything is stored in `./data` (SQLite database, GeoIP files, optional `config.toml`).
- Watchtower checks for a new image every 5 minutes (`UPDATE_INTERVAL` in `.env`) and restarts
  the app with it. It only touches this app's container, never other containers on the server.

**Private repository?** GitHub publishes the image as private at first. Either make it public
(GitHub → your profile → *Packages* → `trafficflow-viewer` → *Package settings* → *Change
visibility*), or log the server in with a personal access token that has the `read:packages`
scope and uncomment the `config.json` line in `docker-compose.yml`:

```bash
docker login ghcr.io -u <github-user>
```

**Releases:** pushing a tag like `v1.2.0` also publishes `:1.2.0`. To pin the server to a
release instead of following `main`, set `TFV_IMAGE=ghcr.io/<user>/trafficflow-viewer:1.2.0`.

To change settings, copy the example config into the data folder and restart:

```bash
cp config.example.toml data/config.toml
```

```bash
docker compose restart trafficflow
```

> The web UI has **no login by default**. If the server can be reached by people you
> don't trust, set `username` and `password` under `[web]` in `data/config.toml`.

### Build from source instead

```bash
docker compose -f docker-compose.dev.yml up -d --build
```

### Without Docker

Requires Python 3.11 or newer.

```bash
python3 -m tfv -c config.toml
```

## 2. Point your MikroTik at it

In the RouterOS terminal (replace `192.168.88.10` with the IP of the machine running this):

```
/ip traffic-flow set enabled=yes interfaces=all active-flow-timeout=1m inactive-flow-timeout=15s
/ip traffic-flow target add dst-address=192.168.88.10 port=2055 version=ipfix
```

Within a minute the status pill in the top-left should say **Receiving flows**. The
**Status** tab shows how many packets arrived, which router sent them, and what happened to the flows.

Notes:
- **IPFIX is recommended.** It includes the post-NAT address fields, which let the viewer
  attribute download traffic seen on the WAN interface to the right LAN device.
  `version=9` works the same way; `version=5` has no NAT or MAC information.
- A short `active-flow-timeout` (1m) keeps the graph close to real time. Long downloads are
  otherwise only reported when they end.
- Flows where neither side is in your LAN (e.g. the router's own DNS lookups) are skipped and
  counted as *Not LAN-related* in the Status tab.
- Records the router sends more than once (for example because two targets point at the
  viewer) are dropped automatically and counted as *Duplicates dropped* in the Status tab.
  If that number keeps growing, check `/ip traffic-flow target print` for a duplicate target.

## 3. Optional: device names from DHCP leases

With RouterOS v7 the viewer can read DHCP leases over the REST API and name devices from the
lease **comment**, or from the client's host name. Names you type in the UI are never overwritten.

On the router, create a read-only user:

```
/user group add name=tfv-read policy=read,api,rest-api
/user add name=tfv group=tfv-read password=SOMETHING-LONG
```

Then in `config.toml`:

```toml
[mikrotik]
enabled = true
url = "https://192.168.88.1"
username = "tfv"
password = "SOMETHING-LONG"
verify_tls = false
```

`www-ssl` must be enabled under `/ip service` (or use `http://` with the `www` service).

## Configuration

See [config.example.toml](config.example.toml). The most useful settings:

| Setting | Default | Meaning |
|---|---|---|
| `network.local_networks` | RFC1918 + ULA | What counts as "my device". Add your IPv6 prefix for IPv6 devices. |
| `storage.retention_days` | 30 | How long data is kept. |
| `storage.bucket_seconds` | 60 | Time resolution. |
| `web.username` / `web.password` | none | Enables HTTP basic auth. |
| `geoip.country_db` / `asn_db` | DB-IP Lite | Use MaxMind GeoLite2 `.mmdb` files instead. |

Environment variables `TFV_DATA_DIR` and `TFV_CONFIG` override the data folder and config path
(the Docker image sets them to `/data` and `/data/config.toml`).

## How data is stored

Each flow is reduced to: time bucket (1 min) × local device × remote IP × service port ×
protocol, with bytes and packets in each direction. Country and ASN are looked up once, when
the row is written. Size grows with the number of distinct remote hosts your devices talk to;
the Status tab shows the current database size.

The "service port" is the lower of the two ports, so traffic to `:443` is grouped
regardless of the random client port.

## Try it without a router

```bash
python3 tools/fakeflow.py --demo-geo data
```

```bash
python3 -m tfv
```

```bash
python3 tools/fakeflow.py --version ipfix
```

The demo GeoIP files only know the few IP ranges the generator uses. Delete
`data/dbip-*.mmdb` afterwards so the real databases are downloaded.

## Tests

```bash
python3 -m unittest discover tests
```

## Project layout

```
tfv/netflow.py    NetFlow v5 / v9 / IPFIX decoder (template cache per exporter)
tfv/store.py      LAN/remote classification, aggregation, SQLite writes
tfv/queries.py    read queries behind the API
tfv/geo.py        DB-IP / GeoLite2 lookups and automatic monthly download
tfv/mmdb.py       pure-Python MaxMind DB reader
tfv/mikrotik.py   optional DHCP lease → device-name sync (RouterOS REST)
tfv/web.py        HTTP server + JSON API
tfv/static/       dashboard (plain HTML/CSS/JS, no build step)
tools/fakeflow.py fake flow generator for testing
tools/build_worldmap.py  rebuilds tfv/static/world.json from world-atlas
.github/workflows CI: tests, then multi-arch image to ghcr.io
docker-compose.yml       server deployment (published image + auto-update)
docker-compose.dev.yml   build and run from this checkout
```

IP geolocation by [DB-IP](https://db-ip.com), licensed under CC BY 4.0.
Map outlines from [world-atlas](https://github.com/topojson/world-atlas) 2.0.2 (Natural Earth, public domain),
converted with `tools/build_worldmap.py`.

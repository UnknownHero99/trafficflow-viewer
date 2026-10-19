"use strict";

// ---------- helpers ----------
const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
  return (i === 0 ? n.toFixed(0) : n < 10 ? n.toFixed(2) : n < 100 ? n.toFixed(1) : n.toFixed(0)) + " " + u[i];
}
function fmtRate(bps) {
  const u = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"];
  let i = 0;
  while (bps >= 1000 && i < u.length - 1) { bps /= 1000; i++; }
  return (bps < 10 && i ? bps.toFixed(1) : bps.toFixed(0)) + " " + u[i];
}
const fmtNum = (n) => Number(n || 0).toLocaleString();
const fmtPct = (x) => x >= 0.995 ? "100%" : x >= 0.1 ? (x * 100).toFixed(0) + "%" : x >= 0.001 ? (x * 100).toFixed(1) + "%" : "<0.1%";
function fmtAgo(ts) {
  if (!ts) return "never";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 90) return Math.round(s) + "s ago";
  if (s < 5400) return Math.round(s / 60) + "m ago";
  if (s < 172800) return Math.round(s / 3600) + "h ago";
  return Math.round(s / 86400) + "d ago";
}
function fmtTime(ts, withDate) {
  const d = new Date(ts * 1000);
  const t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return withDate ? d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + t : t;
}

const regionNames = (() => { try { return new Intl.DisplayNames(["en"], { type: "region" }); } catch { return null; } })();
function countryName(cc) {
  if (cc === "LAN") return "Local network";
  if (!cc || cc === "??") return "Unknown";
  try { return regionNames?.of(cc) || cc; } catch { return cc; }
}
function flag(cc) {
  if (cc === "LAN") return "🏠";
  if (!cc || cc.length !== 2 || cc === "??") return "🏳️";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0)));
}
const PROTOS = { 1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6", 132: "SCTP" };
const SERVICES = {
  20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
  80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS", 143: "IMAP", 161: "SNMP", 443: "HTTPS",
  445: "SMB", 465: "SMTPS", 500: "IKE", 514: "Syslog", 554: "RTSP", 587: "SMTP submit",
  853: "DNS over TLS", 993: "IMAPS", 995: "POP3S", 1194: "OpenVPN", 1883: "MQTT", 1900: "SSDP",
  1935: "RTMP", 3074: "Xbox Live", 3389: "RDP", 3478: "STUN/TURN", 4500: "IPsec NAT-T",
  5060: "SIP", 5222: "XMPP", 5228: "Google Play", 5353: "mDNS", 5900: "VNC", 6881: "BitTorrent",
  8080: "HTTP alt", 8291: "Winbox", 8443: "HTTPS alt", 8883: "MQTT TLS", 19302: "Google STUN",
  51413: "BitTorrent", 51820: "WireGuard",
};
function serviceName(port, proto) {
  if (!port) return PROTOS[proto] || (proto != null ? "proto " + proto : "");
  if (+port === 443 && +proto === 17) return "QUIC";
  return SERVICES[port] || "";
}
function ipSortKey(ip) {
  if (ip.includes(":")) return "z" + ip;
  return ip.split(".").map((x) => x.padStart(3, "0")).join(".");
}

// ---------- dimensions (things you can filter on and drill into) ----------
const DIMS = {
  country: { label: "Country", plural: "Countries" },
  device: { label: "Device", plural: "My devices" },
  asn: { label: "Organisation", plural: "Organisations" },
  remote: { label: "Remote host", plural: "Remote hosts" },
  port: { label: "Service port", plural: "Services" },
  proto: { label: "Protocol", plural: "Protocols" },
};
const DIM_KEYS = Object.keys(DIMS);
const labels = { device: {}, asn: {}, remote: {} };  // id -> friendly name
const rdns = {};

/** Plain-text name of a value. */
function textLabel(dim, v) {
  switch (dim) {
    case "country": return countryName(v);
    case "device": return labels.device[v] || v;
    case "asn": return +v === 0 ? "Unknown / local" : labels.asn[v] || "AS" + v;
    case "port": return +v === 0 ? "no port" : v + (SERVICES[v] ? " " + SERVICES[v] : "");
    case "proto": return PROTOS[v] || "proto " + v;
    default: return String(v);
  }
}
/** HTML name of a value, with flag where it helps. */
function htmlLabel(dim, v) {
  if (dim === "country") return `<span class="flag">${flag(v)}</span>${esc(countryName(v))}`;
  if (dim === "remote") return `<span class="mono">${esc(v)}</span>`;
  return esc(textLabel(dim, v));
}

// ---------- state ----------
const state = {
  range: 3600, from: null, to: null, lan: false, q: "", tab: "countries",
  inc: Object.fromEntries(DIM_KEYS.map((k) => [k, []])),
  exc: Object.fromEntries(DIM_KEYS.map((k) => [k, []])),
  sort: {},
  conn: { sort: "total", dir: "desc", offset: 0, limit: 100 },
  hideIdle: true,
  heatMetric: "total",
};
let summary = null, status = null, devicesData = null;

function readHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  state.from = +p.get("from") || null;
  state.to = +p.get("to") || null;
  state.range = +p.get("range") || 3600;
  state.lan = p.get("lan") === "1";
  state.q = p.get("q") || "";
  state.tab = p.get("tab") || "countries";
  for (const k of DIM_KEYS) {
    state.inc[k] = (p.get(k) || "").split(",").filter(Boolean);
    state.exc[k] = (p.get("not_" + k) || "").split(",").filter(Boolean);
  }
}
function filterParams(p, skipDim) {
  for (const k of DIM_KEYS) {
    if (k === skipDim) continue;
    if (state.inc[k].length) p.set(k, state.inc[k].join(","));
    if (state.exc[k].length) p.set("not_" + k, state.exc[k].join(","));
  }
  return p;
}
function timeParams(p) {
  if (state.from && state.to) { p.set("from", state.from); p.set("to", state.to); }
  else p.set("range", state.range);
  return p;
}
function writeHash() {
  const p = timeParams(new URLSearchParams());
  if (state.lan) p.set("lan", "1");
  if (state.q) p.set("q", state.q);
  if (state.tab !== "countries") p.set("tab", state.tab);
  filterParams(p);
  history.replaceState(null, "", "#" + p.toString());
}
/** Query string for the API. `skipDim` drops that dimension's filters (used for pickers and drill-downs). */
function apiParams(extra = {}, skipDim = null) {
  const p = timeParams(new URLSearchParams({ lan: state.lan ? "1" : "0" }));
  if (state.q) p.set("q", state.q);
  filterParams(p, skipDim);
  for (const [k, v] of Object.entries(extra)) p.set(k, v);
  return p.toString();
}
async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error((await r.text()) || r.statusText);
  return r.json();
}

/** mode: "inc" (only show) or "exc" (hide). */
function addFilter(dim, value, mode = "inc") {
  value = String(value);
  const other = mode === "inc" ? "exc" : "inc";
  state[other][dim] = state[other][dim].filter((v) => v !== value);
  if (!state[mode][dim].includes(value)) state[mode][dim].push(value);
  state.conn.offset = 0;
  closeDrawer();
  refresh();
}
function setFilter(dim, mode, values) {
  const other = mode === "inc" ? "exc" : "inc";
  state[mode][dim] = values;
  state[other][dim] = state[other][dim].filter((v) => !values.includes(v));
  state.conn.offset = 0;
  refresh();
}
function clearFilter(dim, mode) {
  state[mode][dim] = [];
  state.conn.offset = 0;
  refresh();
}
function setTimeWindow(from, to) {
  state.from = from; state.to = to;
  syncRangeButtons();
  refresh();
}
function syncRangeButtons() {
  document.querySelectorAll("#range button").forEach((x) =>
    x.classList.toggle("active", !state.from && +x.dataset.r === state.range));
}

// ---------- filter bar ----------
function renderChips() {
  const el = $("#chips");
  const chips = [];
  if (state.from && state.to) {
    const wd = state.to - state.from > 86400 || new Date(state.from * 1000).getDate() !== new Date().getDate();
    chips.push(`<span class="chip time"><span class="chip-body" data-time>🕑 ${fmtTime(state.from, wd)} – ${fmtTime(state.to, wd)}</span><button data-clear-time aria-label="Reset time range">×</button></span>`);
  }
  for (const k of DIM_KEYS) for (const mode of ["inc", "exc"]) {
    const vals = state[mode][k];
    if (!vals.length) continue;
    const names = vals.slice(0, 3).map((v) => htmlLabel(k, v)).join(", ") + (vals.length > 3 ? ` +${vals.length - 3}` : "");
    chips.push(`<span class="chip ${mode === "exc" ? "neg" : ""}"><span class="chip-body" data-dim="${k}" data-mode="${mode}" title="Click to edit">
      <span class="chip-field">${DIMS[k].label}</span> <span class="chip-op">${mode === "exc" ? "is not" : "is"}</span> ${names}</span>
      <button data-dim="${k}" data-mode="${mode}" aria-label="Remove filter">×</button></span>`);
  }
  if (chips.length > 1) chips.push(`<button class="link-btn" id="clear-all">Clear all</button>`);
  el.innerHTML = chips.join("");
  el.querySelectorAll(".chip-body[data-dim]").forEach((b) => b.onclick = () => openPicker(b, b.dataset.dim, b.dataset.mode));
  el.querySelectorAll("button[data-dim]").forEach((b) => b.onclick = () => clearFilter(b.dataset.dim, b.dataset.mode));
  const ct = $("[data-clear-time]", el);
  if (ct) ct.onclick = () => setTimeWindow(null, null);
  const ca = $("#clear-all", el);
  if (ca) ca.onclick = () => {
    for (const k of DIM_KEYS) { state.inc[k] = []; state.exc[k] = []; }
    state.from = state.to = null; state.q = ""; $("#search").value = "";
    syncRangeButtons();
    refresh();
  };
}

// ---------- filter picker (popover) ----------
let picker = null;
function closePicker() {
  if (!picker) return;
  picker.el.remove();
  document.removeEventListener("mousedown", picker.outside, true);
  document.removeEventListener("keydown", picker.key, true);
  picker = null;
}
function openPicker(anchor, dim = null, mode = "inc") {
  closePicker();
  const el = document.createElement("div");
  el.className = "popover";
  document.body.appendChild(el);
  picker = {
    el, dim, mode, values: null, query: "",
    selected: new Set(dim ? state[mode][dim] : []),
    outside: (e) => { if (!el.contains(e.target) && !anchor.contains(e.target)) closePicker(); },
    key: (e) => { if (e.key === "Escape") closePicker(); },
  };
  document.addEventListener("mousedown", picker.outside, true);
  document.addEventListener("keydown", picker.key, true);
  const r = anchor.getBoundingClientRect();
  el.style.top = Math.min(r.bottom + 6, innerHeight - 200) + "px";
  el.style.left = Math.max(8, Math.min(r.left, innerWidth - 348)) + "px";
  renderPicker();
}
async function renderPicker() {
  const p = picker;
  if (!p) return;
  if (!p.dim) {
    p.el.innerHTML = `<div class="pop-head">Filter by…</div><div class="pop-fields">${DIM_KEYS.map((k) =>
      `<button data-k="${k}">${DIMS[k].label}</button>`).join("")}</div>`;
    p.el.querySelectorAll("button[data-k]").forEach((b) => b.onclick = () => {
      p.dim = b.dataset.k; p.selected = new Set(state[p.mode][p.dim]); renderPicker();
    });
    return;
  }
  p.el.innerHTML = `<div class="pop-head"><span>${DIMS[p.dim].label}</span>
      <div class="seg small" role="group" aria-label="Match">
        <button data-m="inc" class="${p.mode === "inc" ? "active" : ""}">is</button>
        <button data-m="exc" class="${p.mode === "exc" ? "active" : ""}">is not</button></div></div>
    <input class="pop-search" type="search" placeholder="Search ${esc(DIMS[p.dim].plural.toLowerCase())}…" value="${esc(p.query)}">
    <div class="pop-list"><div class="muted pop-empty">Loading…</div></div>
    <div class="pop-foot"><span class="muted" id="pop-count"></span><span class="grow"></span>
      <button class="btn" data-cancel>Cancel</button><button class="btn primary" data-apply>Apply</button></div>`;
  p.el.querySelectorAll("button[data-m]").forEach((b) => b.onclick = () => {
    p.mode = b.dataset.m; p.selected = new Set(state[p.mode][p.dim]); renderPicker();
  });
  const input = $(".pop-search", p.el);
  input.focus();
  input.oninput = () => { p.query = input.value; renderPickerList(); };
  input.onkeydown = (e) => { if (e.key === "Enter") applyPicker(); };
  $("[data-cancel]", p.el).onclick = closePicker;
  $("[data-apply]", p.el).onclick = applyPicker;
  if (!p.values) {
    try {
      const res = await api("/api/values?" + apiParams({ field: p.dim }, p.dim));
      if (picker !== p) return;
      p.values = res.values;
      for (const v of p.values) {
        if (p.dim === "device" && v.label) labels.device[v.value] = v.label;
        if (p.dim === "asn" && v.label) labels.asn[v.value] = v.label;
      }
    } catch (e) {
      p.values = [];
    }
  }
  renderPickerList();
}
function renderPickerList() {
  const p = picker;
  if (!p || !p.values) return;
  const q = p.query.trim().toLowerCase();
  const items = p.values.map((v) => ({ ...v, value: String(v.value) }));
  // keep already-selected values visible even if they have no traffic in this view
  for (const s of p.selected) if (!items.some((i) => i.value === s)) items.push({ value: s, total: 0 });
  const matches = items.filter((i) => !q || [i.value, i.label, textLabel(p.dim, i.value)].some((x) => String(x || "").toLowerCase().includes(q)));
  const max = Math.max(1, ...items.map((i) => i.total));
  let h = matches.slice(0, 150).map((i) => {
    const sub = p.dim === "device" && i.label ? i.value : p.dim === "remote" && i.label ? i.label : p.dim === "asn" && +i.value ? "AS" + i.value : "";
    return `<label class="pop-item"><input type="checkbox" value="${esc(i.value)}" ${p.selected.has(i.value) ? "checked" : ""}>
      <span class="pop-name">${htmlLabel(p.dim, i.value)}${sub ? ` <span class="muted">${esc(sub)}</span>` : ""}</span>
      <span class="pop-bytes">${i.total ? fmtBytes(i.total) : ""}<i style="width:${(100 * i.total) / max}%"></i></span></label>`;
  }).join("");
  // free entry for values with no traffic yet (an IP, a port…)
  if (q && !items.some((i) => i.value.toLowerCase() === q) && p.dim !== "country" && /^[\w.:-]+$/.test(q)) {
    h += `<button class="pop-add" data-add="${esc(p.query.trim())}">Add “${esc(p.query.trim())}”</button>`;
  }
  $(".pop-list", p.el).innerHTML = h || `<div class="muted pop-empty">Nothing matches.</div>`;
  $(".pop-list", p.el).querySelectorAll("input[type=checkbox]").forEach((c) => c.onchange = () => {
    if (c.checked) p.selected.add(c.value); else p.selected.delete(c.value);
    updatePickerCount();
  });
  const add = $("[data-add]", p.el);
  if (add) add.onclick = () => { p.selected.add(add.dataset.add); applyPicker(); };
  updatePickerCount();
}
function updatePickerCount() {
  const n = picker.selected.size;
  $("#pop-count", picker.el).textContent = n ? `${n} selected` : "";
}
function applyPicker() {
  const p = picker;
  if (!p?.dim) return;
  const vals = [...p.selected];
  closePicker();
  setFilter(p.dim, p.mode, vals);
}

// ---------- KPIs / status ----------
function renderKpis() {
  const t = summary.totals;
  const span = summary.to - summary.from;
  const kpi = (label, value, sub, sw) =>
    `<div class="kpi"><div class="label">${sw ? `<span class="sw ${sw}"></span>` : ""}${label}</div><div class="value">${value}</div><div class="sub">${sub}</div></div>`;
  $("#kpis").innerHTML =
    kpi("Downloaded", fmtBytes(t.down), "avg " + fmtRate((t.down * 8) / span), "down") +
    kpi("Uploaded", fmtBytes(t.up), "avg " + fmtRate((t.up * 8) / span), "up") +
    kpi("Countries", fmtNum(t.countries), fmtNum(t.orgs) + " organisations") +
    kpi("Devices", fmtNum(t.devices), fmtNum(t.remotes) + " remote hosts");
}
function renderStatusPill() {
  const el = $("#status-pill");
  if (!status) return;
  // after a restart the collector's own counter is empty, so also use what's in the database
  const last = Math.max(status.store.last_flow || 0, summary?.totals.last ? summary.totals.last + status.store.bucket_seconds : 0);
  let color, text, icon;
  if (last && Date.now() / 1000 - last < 180) {
    color = "var(--good)"; icon = "●"; text = "Receiving flows";
  } else if (!status.collector.packets) {
    color = "var(--warning)"; icon = "◌"; text = "Waiting for router on udp/" + status.collector.listen.split(":").pop();
  } else if (!last) {
    color = "var(--warning)"; icon = "◌"; text = "Receiving packets, no usable flows yet";
  } else {
    color = "var(--critical)"; icon = "▲"; text = "No flows since " + fmtAgo(last);
  }
  el.innerHTML = `<span style="color:${color}">${icon}</span>${esc(text)}`;
}

// ---------- bar chart (main chart and drawer chart) ----------
function niceMax(v) {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
function roundTop(x, yb, w, h, r) {
  return `M${x},${yb}V${yb - h + r}Q${x},${yb - h} ${x + r},${yb - h}H${x + w - r}Q${x + w},${yb - h} ${x + w},${yb - h + r}V${yb}Z`;
}
function roundBottom(x, yt, w, h, r) {
  return `M${x},${yt}V${yt + h - r}Q${x},${yt + h} ${x + r},${yt + h}H${x + w - r}Q${x + w},${yt + h} ${x + w},${yt + h - r}V${yt}Z`;
}
/** Mirrored bars: download up, upload down. data = {from, to, step, series}. */
function drawBars(el, data, { brush = false, compact = false } = {}) {
  const cs = getComputedStyle(el);
  const W = el.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
  const H = el.clientHeight - parseFloat(cs.paddingTop) - parseFloat(cs.paddingBottom);
  if (W <= 0 || H <= 0) return;
  const step = data.step;
  const start = Math.floor(data.from / step) * step, end = Math.floor(data.to / step) * step;
  const byT = new Map(data.series.map((r) => [r.t, r]));
  const pts = [];
  for (let t = start; t <= end; t += step) {
    const r = byT.get(t) || { down: 0, up: 0 };
    pts.push({ t, down: (r.down * 8) / step, up: (r.up * 8) / step, bdown: r.down, bup: r.up });
  }
  const left = compact ? 58 : 70, right = 6, top = 6, bottom = 20;
  const iw = Math.max(10, W - left - right), ih = Math.max(10, H - top - bottom);
  const maxD = Math.max(0, ...pts.map((p) => p.down)), maxU = Math.max(0, ...pts.map((p) => p.up));
  const tickD = niceMax(maxD), tickU = maxU > 0 ? niceMax(maxU) : 0;
  const total = tickD + tickU || 1;
  const zeroY = top + (ih * tickD) / total;
  const y = (v) => (ih * v) / total;
  const bw = iw / pts.length;
  const gap = bw > 6 ? 2 : bw > 3 ? 1 : 0;
  const withDate = data.to - data.from > 86400;

  let s = `<svg class="bars" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Download and upload rate over time">`;
  s += `<g class="grid axis">`;
  const yticks = compact ? [[tickD, zeroY - y(tickD)]] : [[tickD, zeroY - y(tickD)], [tickD / 2, zeroY - y(tickD / 2)]];
  if (tickU) yticks.push([-tickU, zeroY + y(tickU)]);
  for (const [v, yy] of yticks) {
    s += `<line x1="${left}" x2="${left + iw}" y1="${yy}" y2="${yy}"/>`;
    s += `<text x="${left - 8}" y="${yy + 4}" text-anchor="end">${v < 0 ? "↑ " : "↓ "}${fmtRate(Math.abs(v))}</text>`;
  }
  s += `</g>`;
  for (let i = 0; i < pts.length; i++) {
    const p = pts[i], x = left + i * bw + gap / 2, w = Math.max(0.5, bw - gap);
    const hd = y(p.down), hu = y(p.up), r = Math.min(4, w / 2);
    if (hd > 0.3) s += `<path class="bar-down" d="${roundTop(x, zeroY - 1, w, Math.max(hd - 1, 0.5), Math.min(r, hd))}"/>`;
    if (hu > 0.3) s += `<path class="bar-up" d="${roundBottom(x, zeroY + 1, w, Math.max(hu - 1, 0.5), Math.min(r, hu))}"/>`;
  }
  s += `<line class="zero" x1="${left}" x2="${left + iw}" y1="${zeroY}" y2="${zeroY}"/>`;
  const every = Math.max(1, Math.ceil(pts.length / Math.max(2, Math.floor(iw / (withDate ? 110 : 80)))));
  s += `<g class="axis">`;
  for (let i = 0; i < pts.length; i += every) {
    s += `<text x="${left + i * bw + bw / 2}" y="${H - 4}" text-anchor="middle">${fmtTime(pts[i].t, withDate)}</text>`;
  }
  s += `</g>`;
  s += `<rect class="hover-col" x="0" y="${top}" width="0" height="${ih}"/>`;
  s += `<rect class="brush" x="0" y="${top}" width="0" height="${ih}"/>`;
  s += `<rect class="overlay" x="${left}" y="${top}" width="${iw}" height="${ih}"/>`;
  if (!data.series.length) s += `<text class="empty" x="${left + iw / 2}" y="${top + ih / 2}" text-anchor="middle">No traffic in this time range</text>`;
  s += `</svg>`;
  el.innerHTML = s;

  const svg = el.firstChild, hover = $(".hover-col", svg), br = $(".brush", svg), ov = $(".overlay", svg);
  const idxAt = (e) => {
    const bx = e.clientX - svg.getBoundingClientRect().left;
    return Math.max(0, Math.min(pts.length - 1, Math.floor((bx - left) / bw)));
  };
  let drag = null;
  ov.onpointermove = (e) => {
    const i = idxAt(e), p = pts[i];
    hover.setAttribute("x", left + i * bw); hover.setAttribute("width", bw);
    hover.classList.add("on");
    if (drag != null) {
      const a = Math.min(drag, i), b = Math.max(drag, i);
      br.setAttribute("x", left + a * bw); br.setAttribute("width", (b - a + 1) * bw);
      hideTip();
      return;
    }
    showTip(`<div class="t">${fmtTime(p.t, withDate)} – ${fmtTime(p.t + step)}</div>
      <div class="row"><span><span class="sw down"></span>Download</span><b>${fmtBytes(p.bdown)}</b></div>
      <div class="row muted"><span></span>${fmtRate(p.down)}</div>
      <div class="row"><span><span class="sw up"></span>Upload</span><b>${fmtBytes(p.bup)}</b></div>
      <div class="row muted"><span></span>${fmtRate(p.up)}</div>
      ${brush ? '<div class="muted hint">Drag to zoom in</div>' : ""}`, e);
  };
  ov.onpointerleave = () => { hover.classList.remove("on"); hideTip(); };
  if (brush) {
    ov.onpointerdown = (e) => { drag = idxAt(e); ov.setPointerCapture(e.pointerId); };
    ov.onpointerup = (e) => {
      if (drag == null) return;
      const i = idxAt(e), a = Math.min(drag, i), b = Math.max(drag, i);
      drag = null;
      br.setAttribute("width", 0);
      if (b > a) setTimeWindow(pts[a].t, pts[b].t + step);
    };
  }
}

// ---------- heatmap helpers ----------
const METRICS = { total: "Total", down: "Download", up: "Upload" };
const metricVal = (r) => state.heatMetric === "total" ? (r.down || 0) + (r.up || 0) : r[state.heatMetric] || 0;
function logScale(values) {
  const pos = values.filter((v) => v > 0);
  if (!pos.length) return { bin: () => 0, edges: [] };
  const lo = Math.log10(Math.min(...pos)), hi = Math.log10(Math.max(...pos));
  const n = 5, w = (hi - lo) / n || 1;
  const edges = Array.from({ length: n + 1 }, (_, i) => Math.pow(10, lo + i * w));
  return {
    edges: hi === lo ? [edges[0], edges[0]] : edges,
    bin: (v) => v <= 0 ? 0 : hi === lo ? 5 : Math.min(n, Math.max(1, Math.ceil((Math.log10(v) - lo) / w) || 1)),
  };
}
function heatLegend(scale) {
  let h = `<div class="heat-legend"><span><i class="q0"></i>none</span>`;
  if (scale.edges.length === 2) return h + `<span><i class="q5"></i>${fmtBytes(scale.edges[0])}</span></div>`;
  for (let i = 1; i < scale.edges.length; i++) h += `<span><i class="q${i}"></i>${i === 1 ? "" : "≥ "}${fmtBytes(scale.edges[i - 1])}</span>`;
  return h + `</div>`;
}
function metricSeg() {
  return `<div class="seg small" role="group" aria-label="Metric">${Object.entries(METRICS).map(([k, l]) =>
    `<button data-metric="${k}" class="${state.heatMetric === k ? "active" : ""}">${l}</button>`).join("")}</div>`;
}
function wireMetric(el) {
  el.querySelectorAll("button[data-metric]").forEach((b) => b.onclick = () => { state.heatMetric = b.dataset.metric; renderPanel(); });
}

let ftip;
function showTip(html, e) {
  if (!ftip) { ftip = document.createElement("div"); ftip.className = "tooltip"; document.body.appendChild(ftip); }
  ftip.innerHTML = html;
  ftip.hidden = false;
  const w = ftip.offsetWidth, h = ftip.offsetHeight;
  let x = e.clientX + 14, y = e.clientY + 14;
  if (x + w > innerWidth - 8) x = e.clientX - w - 14;
  if (y + h > innerHeight - 8) y = e.clientY - h - 14;
  ftip.style.left = Math.max(4, x) + "px";
  ftip.style.top = Math.max(4, y) + "px";
}
const hideTip = () => { if (ftip) ftip.hidden = true; };
function tipRows(r) {
  return `<div class="row"><span><span class="sw down"></span>Download</span><b>${fmtBytes(r.down)}</b></div>
    <div class="row"><span><span class="sw up"></span>Upload</span><b>${fmtBytes(r.up)}</b></div>`;
}

let world = null;
async function loadWorld() {
  if (!world) world = await api("/world.json");
  return world;
}
function countryTip(cc, r) {
  if (!r) return `<div class="t">${flag(cc)} ${esc(countryName(cc))}</div><div class="muted">No traffic in this view</div>`;
  const row = (k, v) => `<div class="row"><span>${k}</span><b>${v}</b></div>`;
  return `<div class="t">${flag(cc)} <b>${esc(countryName(cc))}</b> · ${fmtPct(totalOf(r) / (grandTotal() || 1))} of traffic</div>
    ${tipRows(r)}
    ${row("My devices", fmtNum(r.devices))}${row("Remote hosts", fmtNum(r.remotes))}${row("Organisations", fmtNum(r.orgs))}
    ${r.top_org?.[0] ? row("Top organisation", esc(r.top_org[0])) : ""}
    ${r.top_device?.[0] ? row("Top device", esc(labels.device[r.top_device[1]] || r.top_device[0])) : ""}
    ${row("Last seen", fmtAgo(r.last))}
    <div class="muted hint">Click for details</div>`;
}
// Map zoom/pan: we only change the SVG viewBox. Kept across refreshes.
let mapView = null, mapDrag = null;
function wireMapZoom(el, svg) {
  const [fx, fy, fw, fh] = world.viewBox.split(" ").map(Number);
  const full = { x: fx, y: fy, w: fw, h: fh };
  const clamp = (v) => {
    const w = Math.min(full.w, Math.max(full.w / 16, v.w)), h = (w * full.h) / full.w;
    return { w, h, x: Math.min(full.x + full.w - w, Math.max(full.x, v.x)), y: Math.min(full.y + full.h - h, Math.max(full.y, v.y)) };
  };
  const apply = () => {
    const v = mapView || full;
    svg.setAttribute("viewBox", `${v.x} ${v.y} ${v.w} ${v.h}`);
    $(".map-reset", el).disabled = !mapView;
  };
  // zoom by factor k around a point given as fractions (0..1) of the visible map
  const zoom = (k, fxp = 0.5, fyp = 0.5) => {
    const v = mapView || full;
    const w = v.w / k, h = v.h / k;
    const next = clamp({ w, h, x: v.x + (v.w - w) * fxp, y: v.y + (v.h - h) * fyp });
    mapView = next.w >= full.w ? null : next;
    apply();
  };
  const frac = (e) => {
    const r = svg.getBoundingClientRect();
    return [(e.clientX - r.left) / r.width, (e.clientY - r.top) / r.height];
  };
  svg.addEventListener("wheel", (e) => {
    // Plain scrolling keeps scrolling the page; Ctrl+scroll (and trackpad pinch) zooms.
    if (!e.ctrlKey && !e.metaKey) return;
    e.preventDefault();
    zoom(Math.exp(-e.deltaY * 0.01), ...frac(e));
  }, { passive: false });
  svg.ondblclick = (e) => { e.preventDefault(); zoom(2, ...frac(e)); };
  svg.onpointerdown = (e) => {
    if (e.button !== 0) return;
    mapDrag = { x: e.clientX, y: e.clientY, view: mapView || full, moved: false };
  };
  svg.onpointermove = (e) => {
    if (!mapDrag || !(e.buttons & 1)) return;
    const dx = e.clientX - mapDrag.x, dy = e.clientY - mapDrag.y;
    if (!mapDrag.moved && Math.hypot(dx, dy) < 4) return;
    if (!mapDrag.moved) { mapDrag.moved = true; svg.setPointerCapture(e.pointerId); svg.classList.add("panning"); }
    const r = svg.getBoundingClientRect(), v = mapDrag.view;
    const next = clamp({ ...v, x: v.x - (dx * v.w) / r.width, y: v.y - (dy * v.h) / r.height });
    mapView = next.w >= full.w ? null : next;
    apply();
  };
  svg.onpointerup = () => {
    svg.classList.remove("panning");
    // leave `moved` set until the click event has seen it
    setTimeout(() => { mapDrag = null; }, 0);
  };
  $(".map-in", el).onclick = () => zoom(1.6);
  $(".map-out", el).onclick = () => zoom(1 / 1.6);
  $(".map-reset", el).onclick = () => { mapView = null; apply(); };
  apply();
}

function worldMap(rows) {
  const byCc = new Map(rows.map((r) => [r.cc, r]));
  const scale = logScale(rows.filter((r) => world.paths[r.cc]).map(metricVal));
  const sel = new Set(state.inc.country);
  const el = document.createElement("div");
  let svg = `<svg viewBox="${world.viewBox}" role="img" aria-label="World map of traffic by country">`;
  for (const [cc, d] of Object.entries(world.paths)) {
    const r = byCc.get(cc);
    svg += `<path d="${d}" data-cc="${cc}" class="q${r ? scale.bin(metricVal(r)) : 0}${r ? " has" : ""}${sel.has(cc) ? " sel" : ""}"/>`;
  }
  // One outline drawn on top for the hovered country; the country paths themselves never move.
  svg += `<path class="map-hl" d=""/></svg>`;
  const extra = rows.filter((r) => !world.paths[r.cc]);
  el.innerHTML = `<div class="heat-bar"><h3>World map</h3>${metricSeg()}<span class="spacer"></span>${heatLegend(scale)}</div>
    <div class="worldmap">${svg}
      <div class="map-zoom" role="group" aria-label="Map zoom">
        <button class="map-in" title="Zoom in" aria-label="Zoom in">＋</button>
        <button class="map-out" title="Zoom out" aria-label="Zoom out">−</button>
        <button class="map-reset" title="Show whole world" aria-label="Reset zoom">⟲</button>
      </div>
      <div class="map-hint muted">Ctrl + scroll or double-click to zoom · drag to pan</div>
    </div>
    ${extra.length ? `<div class="map-note">Not on the map: ${extra.map((r) =>
      `<button data-cc="${esc(r.cc)}">${flag(r.cc)} ${esc(countryName(r.cc))} · ${fmtBytes(metricVal(r))}</button>`).join("")}</div>` : ""}`;
  wireMetric(el);
  const svgEl = $("svg", el), hl = $(".map-hl", el);
  wireMapZoom(el, svgEl);
  svgEl.onmousemove = (e) => {
    const p = e.target.closest("path[data-cc]");
    if (!p || mapDrag?.moved) { hl.setAttribute("d", ""); hideTip(); return; }
    hl.setAttribute("d", p.getAttribute("d"));
    showTip(countryTip(p.dataset.cc, byCc.get(p.dataset.cc)), e);
  };
  svgEl.onmouseleave = () => { hl.setAttribute("d", ""); hideTip(); };
  svgEl.onclick = (e) => {
    if (mapDrag?.moved) return;  // that was a pan, not a click
    const p = e.target.closest("path[data-cc]");
    if (p && byCc.has(p.dataset.cc)) { hideTip(); openDrawer("country", p.dataset.cc); }
  };
  el.querySelectorAll(".map-note button").forEach((b) => {
    const cc = b.dataset.cc;
    b.onmousemove = (e) => showTip(countryTip(cc, byCc.get(cc)), e);
    b.onmouseleave = hideTip;
    b.onclick = () => { hideTip(); openDrawer("country", cc); };
  });
  return el;
}

// ---------- tables ----------
function shareBar(row, max) {
  const tot = (row.down || 0) + (row.up || 0);
  if (!max || !tot) return "";
  const w = Math.max(1, (100 * tot) / max);
  const d = (100 * row.down) / tot, u = 100 - d;
  return `<div class="sharebar" style="width:${w}%" title="↓ ${fmtBytes(row.down)} / ↑ ${fmtBytes(row.up)}">${
    d > 0.5 ? `<i class="d" style="flex:${d}"></i>` : ""}${u > 0.5 ? `<i class="u" style="flex:${u}"></i>` : ""}</div>`;
}
const totalOf = (r) => (r.down || 0) + (r.up || 0);
const grandTotal = () => (summary.totals.down || 0) + (summary.totals.up || 0);

/**
 * Sortable table. cols: {key, label, num, render(row, max), sort(row), sortable}.
 * dim + id(row): clicking a row opens its detail panel, and an actions column
 * gets "only this" / "hide this" buttons.
 */
function table(tabKey, cols, rows, { dim, id, defaultSort = "total", empty = "Nothing here for these filters." } = {}) {
  const st = state.sort[tabKey] || (state.sort[tabKey] = { key: defaultSort, dir: "desc" });
  if (dim) cols = [...cols, { key: "_act", label: "", sortable: false, cls: "actions-cell", render: (r) => {
    const v = esc(id(r));
    return `<div class="actions"><button class="act" data-f="${dim}" data-v="${v}" title="Only show this">＋</button><button class="act" data-x="${dim}" data-v="${v}" title="Hide this">−</button></div>`;
  } }];
  const col = cols.find((c) => c.key === st.key) || cols[0];
  const sv = col.sort || ((r) => r[col.key]);
  rows = [...rows].sort((a, b) => {
    const x = sv(a), y = sv(b);
    const c = typeof x === "string" || typeof y === "string" ? String(x ?? "").localeCompare(String(y ?? "")) : (x ?? 0) - (y ?? 0);
    return st.dir === "asc" ? c : -c;
  });
  const max = Math.max(0, ...rows.map(totalOf));
  let h = `<table class="data"><thead><tr>`;
  for (const c of cols) {
    const sortable = c.sortable !== false;
    const arrow = st.key === c.key ? `<span class="arrow">${st.dir === "asc" ? " ▲" : " ▼"}</span>` : "";
    h += `<th class="${c.num ? "num " : ""}${sortable ? "sortable " : ""}${c.cls || ""}" ${sortable ? `data-sort="${c.key}"` : ""} ${c.title ? `title="${esc(c.title)}"` : ""}>${c.label}${arrow}</th>`;
  }
  h += `</tr></thead><tbody>`;
  if (!rows.length) h += `<tr><td colspan="${cols.length}" class="empty-state">${empty}</td></tr>`;
  rows.forEach((r, i) => {
    h += `<tr data-i="${i}" class="${dim ? "click" : ""}" style="${r._dim ? "opacity:.5" : ""}">`;
    for (const c of cols) h += `<td class="${c.num ? "num " : ""}${c.cls || ""}">${c.render ? c.render(r, max) : esc(r[c.key])}</td>`;
    h += `</tr>`;
  });
  h += `</tbody></table>`;
  const wrap = document.createElement("div");
  wrap.className = "table-wrap";
  wrap.innerHTML = h;
  wrap.querySelectorAll("th[data-sort]").forEach((th) => th.onclick = () => {
    const k = th.dataset.sort;
    if (st.key === k) st.dir = st.dir === "asc" ? "desc" : "asc";
    else { st.key = k; st.dir = cols.find((c) => c.key === k).num ? "desc" : "asc"; }
    renderPanel();
  });
  if (dim) wrap.querySelectorAll("tbody tr[data-i]").forEach((tr) => tr.onclick = (e) => {
    if (e.target.closest("button, input, a")) return;
    openDrawer(dim, id(rows[+tr.dataset.i]));
  });
  wrap._rows = rows;
  return wrap;
}

const trafficCols = [
  { key: "down", label: "↓ Download", num: true, render: (r) => fmtBytes(r.down) },
  { key: "up", label: "↑ Upload", num: true, render: (r) => fmtBytes(r.up) },
  { key: "total", label: "Share", cls: "share", sort: totalOf, render: (r, max) =>
    `<div class="sharecell">${shareBar(r, max)}<span>${fmtPct(totalOf(r) / (grandTotal() || 1))}</span></div>` },
];
const deviceLabel = (r) => r.name || r.ip;
const countryCell = (cc) => `<span class="flag">${flag(cc)}</span>${esc(countryName(cc))}`;

const TABS = {
  async countries() {
    await loadWorld();
    const el = document.createElement("div");
    el.appendChild(worldMap(summary.countries));
    for (const r of summary.countries) if (r.top_device?.[1]) labels.device[r.top_device[1]] ||= r.top_device[0];
    el.appendChild(table("countries", [
      { key: "cc", label: "Country", sort: (r) => countryName(r.cc), render: (r) => `${countryCell(r.cc)} <span class="muted mono">${esc(r.cc)}</span>` },
      ...trafficCols,
      { key: "devices", label: "Devices", num: true, title: "Your devices that talked to this country", render: (r) => fmtNum(r.devices) },
      { key: "remotes", label: "Hosts", num: true, title: "Distinct remote IPs", render: (r) => fmtNum(r.remotes) },
      { key: "orgs", label: "Orgs", num: true, title: "Distinct organisations (ASNs)", render: (r) => fmtNum(r.orgs) },
      { key: "top_org", label: "Top organisation", sort: (r) => r.top_org?.[0] || "", render: (r) => esc(r.top_org?.[0] || (r.top_org?.[1] ? "AS" + r.top_org[1] : "")) },
      { key: "top_device", label: "Top device", sort: (r) => r.top_device?.[0] || "", render: (r) => esc(r.top_device?.[0] || "") },
      { key: "top_service", label: "Top service", sort: (r) => r.top_service?.[1] ?? 0, render: (r) => {
        const [proto, port] = r.top_service || [];
        return port == null ? "" : `<span class="mono">${port || "—"}</span> <span class="muted">${esc(serviceName(port, proto) || PROTOS[proto] || "")}</span>`;
      } },
      { key: "last", label: "Last seen", num: true, render: (r) => fmtAgo(r.last) },
    ], summary.countries, { dim: "country", id: (r) => r.cc }));
    return el;
  },

  async heatmap() {
    const data = await api("/api/country-timeline?" + apiParams({ rows: 25 }));
    const el = document.createElement("div");
    const step = data.step;
    const start = Math.floor(data.from / step) * step, end = Math.floor(data.to / step) * step;
    const times = [];
    for (let t = start; t <= end; t += step) times.push(t);
    const val = new Map(), totals = new Map();
    for (const [cc, t, down, up] of data.cells) {
      val.set(cc + "|" + t, { down, up });
      const tot = totals.get(cc) || { down: 0, up: 0 };
      tot.down += down; tot.up += up;
      totals.set(cc, tot);
    }
    const scale = logScale([...val.values()].map(metricVal));
    const withDate = data.to - data.from > 86400;
    const every = Math.max(1, Math.ceil(times.length / 8));
    let h = `<div class="heat-bar"><h3>Countries over time</h3>${metricSeg()}<span class="spacer"></span>${heatLegend(scale)}</div>`;
    if (!data.countries.length) {
      h += `<div class="empty-state">No traffic in this time range.</div>`;
    } else {
      h += `<div class="grid-heat"><table><thead><tr><th></th>`;
      for (let i = 0; i < times.length; i += every) {
        h += `<th class="xlab" colspan="${Math.min(every, times.length - i)}">${fmtTime(times[i], withDate)}</th>`;
      }
      h += `<th></th></tr></thead><tbody>`;
      for (const cc of data.countries) {
        h += `<tr><th class="rowh" data-cc="${esc(cc)}">${countryCell(cc)}</th>`;
        for (const t of times) {
          const r = val.get(cc + "|" + t);
          h += `<td class="cell q${r ? scale.bin(metricVal(r)) : 0}" data-cc="${esc(cc)}" data-t="${t}"></td>`;
        }
        h += `<td class="tot">${fmtBytes(metricVal(totals.get(cc) || {}))}</td></tr>`;
      }
      h += `</tbody></table></div>
        <div class="map-note">Top ${data.countries.length} countries, one column per ${step >= 3600 ? step / 3600 + " h" : step / 60 + " min"}.
        Click a country for details, or a cell to zoom into that time.</div>`;
    }
    el.innerHTML = h;
    wireMetric(el);
    el.querySelectorAll("th.rowh").forEach((th) => th.onclick = () => openDrawer("country", th.dataset.cc));
    el.querySelectorAll("td.cell").forEach((td) => {
      const cc = td.dataset.cc, t = +td.dataset.t;
      td.onmousemove = (e) => {
        const r = val.get(cc + "|" + t);
        showTip(`<div class="t">${flag(cc)} ${esc(countryName(cc))}<br>${fmtTime(t, withDate)} – ${fmtTime(t + step)}</div>${
          r ? tipRows(r) : '<div class="muted">No traffic</div>'}`, e);
      };
      td.onmouseleave = hideTip;
      td.onclick = () => { hideTip(); setTimeWindow(t, t + step); };
    });
    return el;
  },

  devices() {
    const known = new Map((devicesData?.devices || []).map((d) => [d.ip, d]));
    const seen = new Set();
    const rows = summary.devices.map((d) => { seen.add(d.ip); return { ...known.get(d.ip), ...d, name: d.name ?? known.get(d.ip)?.name }; });
    if (!state.hideIdle) for (const d of known.values()) if (!seen.has(d.ip)) rows.push({ ...d, down: 0, up: 0, flows: 0, countries: 0, remotes: 0, _dim: true });
    for (const r of rows) labels.device[r.ip] = deviceLabel(r);
    const el = document.createElement("div");
    el.innerHTML = `<div class="panel-bar"><span>Click a device for details. Use <b>rename</b> to give it a friendly name.</span><span class="grow"></span>
      <label class="toggle"><input type="checkbox" id="hide-idle" ${state.hideIdle ? "checked" : ""}> Hide idle devices</label>
      ${status?.lease_sync != null ? `<button class="btn" id="lease-sync">Sync names from router</button>` : ""}</div>`;
    el.appendChild(table("devices", [
      { key: "name", label: "Device", sort: deviceLabel, render: (r) => `<span data-name="${esc(r.ip)}">${esc(r.name || "")}${r.name ? "" : '<span class="muted">unnamed</span>'}</span>${r.name_source === "dhcp" ? '<span class="tag">DHCP</span>' : ""} <button class="act" data-rename="${esc(r.ip)}">rename</button>` },
      { key: "ip", label: "IP", cls: "mono", sort: (r) => ipSortKey(r.ip) },
      { key: "mac", label: "MAC", cls: "mono muted", render: (r) => esc(r.mac || "") },
      ...trafficCols,
      { key: "countries", label: "Countries", num: true, render: (r) => fmtNum(r.countries) },
      { key: "remotes", label: "Hosts", num: true, render: (r) => fmtNum(r.remotes) },
      { key: "last_seen", label: "Last seen", num: true, render: (r) => fmtAgo(r.last_seen) },
    ], rows, { dim: "device", id: (r) => r.ip, empty: "No devices seen yet." }));
    return el;
  },

  orgs() {
    for (const r of summary.orgs) labels.asn[r.asn] = r.org || "AS" + r.asn;
    return table("orgs", [
      { key: "org", label: "Organisation", sort: (r) => r.org || "~", render: (r) => r.asn ? `${esc(r.org || "?")} <span class="muted mono">AS${r.asn}</span>` : `<span class="muted">Unknown / local</span>` },
      { key: "countries", label: "Countries", sortable: false, render: (r) => r.countries.map((c) => `<span class="flag" title="${esc(countryName(c))}">${flag(c)}</span>`).join("") },
      ...trafficCols,
      { key: "devices", label: "Devices", num: true, render: (r) => fmtNum(r.devices) },
      { key: "remotes", label: "Hosts", num: true, render: (r) => fmtNum(r.remotes) },
    ], summary.orgs, { dim: "asn", id: (r) => r.asn });
  },

  remotes() {
    const el = table("remotes", [
      { key: "ip", label: "Remote host", cls: "mono", sort: (r) => ipSortKey(r.ip) },
      { key: "host", label: "Reverse DNS", sortable: false, cls: "muted ellipsis", render: (r) => `<span data-rdns="${esc(r.ip)}">${esc(rdns[r.ip] ?? "…")}</span>` },
      { key: "cc", label: "Country", sort: (r) => countryName(r.cc), render: (r) => countryCell(r.cc) },
      { key: "org", label: "Organisation", render: (r) => esc(r.org || "") },
      { key: "ports", label: "Ports", sortable: false, cls: "mono", render: (r) => esc(r.ports.join(", ")) },
      ...trafficCols,
      { key: "devices", label: "Devices", num: true, render: (r) => fmtNum(r.devices) },
    ], summary.remotes, { dim: "remote", id: (r) => r.ip });
    loadRdns(el._rows.slice(0, 60).map((r) => r.ip));
    return el;
  },

  ports() {
    return table("ports", [
      { key: "port", label: "Port", num: true, render: (r) => r.port ? r.port : "—" },
      { key: "proto", label: "Protocol", render: (r) => esc(PROTOS[r.proto] || r.proto) },
      { key: "svc", label: "Service", sort: (r) => serviceName(r.port, r.proto), render: (r) => esc(serviceName(r.port, r.proto)) },
      ...trafficCols,
      { key: "devices", label: "Devices", num: true, render: (r) => fmtNum(r.devices) },
      { key: "flows", label: "Flows", num: true, render: (r) => fmtNum(r.flows) },
    ], summary.ports, { dim: "port", id: (r) => r.port });
  },

  async connections() {
    const c = state.conn;
    const data = await api("/api/connections?" + apiParams({ sort: c.sort, dir: c.dir, limit: c.limit, offset: c.offset }));
    const el = document.createElement("div");
    const csv = "/api/connections?" + apiParams({ sort: c.sort, dir: c.dir, limit: 2000, format: "csv" });
    el.innerHTML = `<div class="panel-bar"><span>${fmtNum(data.count)} connections (device ↔ host ↔ port). Click any value for details.</span><span class="grow"></span>
      <button class="btn" id="prev" ${c.offset ? "" : "disabled"}>← Prev</button>
      <span>${data.count ? c.offset + 1 : 0}–${Math.min(c.offset + c.limit, data.count)}</span>
      <button class="btn" id="next" ${c.offset + c.limit < data.count ? "" : "disabled"}>Next →</button>
      <a class="btn" href="${csv}">Export CSV</a></div>`;
    const cols = [
      ["name", "Device"], ["remote", "Remote host"], ["country", "Country"], ["org", "Organisation"],
      ["port", "Port", true], ["down", "↓ Download", true], ["up", "↑ Upload", true],
      ["flows", "Flows", true], ["last", "Last seen", true],
    ];
    let h = `<div class="table-wrap"><table class="data"><thead><tr>`;
    for (const [k, label, num] of cols) {
      const arrow = c.sort === k ? `<span class="arrow">${c.dir === "asc" ? " ▲" : " ▼"}</span>` : "";
      h += `<th class="sortable ${num ? "num" : ""}" data-sort="${k}">${label}${arrow}</th>`;
    }
    h += `</tr></thead><tbody>`;
    if (!data.rows.length) h += `<tr><td colspan="${cols.length}" class="empty-state">No connections for these filters.</td></tr>`;
    const open = (dim, id, html) => `<span class="open" data-open-dim="${dim}" data-open-id="${esc(id)}">${html}</span>`;
    for (const r of data.rows) {
      if (r.name) labels.device[r.local] = r.name;
      h += `<tr><td>${open("device", r.local, `${esc(r.name || "")} <span class="mono muted">${esc(r.local)}</span>`)}</td>
        <td class="mono">${open("remote", r.remote, esc(r.remote))}</td>
        <td>${open("country", r.cc, countryCell(r.cc))}</td>
        <td>${r.asn ? open("asn", r.asn, esc(r.org || "AS" + r.asn)) : ""}</td>
        <td class="num mono">${open("port", r.port, `${r.port || "—"} <span class="muted">${esc(PROTOS[r.proto] || r.proto)}</span>`)}</td>
        <td class="num">${fmtBytes(r.down)}</td><td class="num">${fmtBytes(r.up)}</td>
        <td class="num">${fmtNum(r.flows)}</td><td class="num">${fmtAgo(r.last)}</td></tr>`;
    }
    h += `</tbody></table></div>`;
    el.insertAdjacentHTML("beforeend", h);
    el.querySelectorAll("th[data-sort]").forEach((th) => th.onclick = () => {
      const k = th.dataset.sort;
      if (c.sort === k) c.dir = c.dir === "asc" ? "desc" : "asc";
      else { c.sort = k; c.dir = ["name", "remote", "country", "org"].includes(k) ? "asc" : "desc"; }
      c.offset = 0; renderPanel();
    });
    $("#prev", el).onclick = () => { c.offset = Math.max(0, c.offset - c.limit); renderPanel(); };
    $("#next", el).onclick = () => { c.offset += c.limit; renderPanel(); };
    return el;
  },

  status() {
    const s = status;
    const el = document.createElement("div");
    if (!s) { el.innerHTML = `<div class="empty-state">Loading…</div>`; return el; }
    const dl = (o) => `<dl>${Object.entries(o).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
    const ex = Object.entries(s.collector.exporters);
    const port = s.collector.listen.split(":").pop();
    el.innerHTML = `<div class="status">
      <div><h3>Collector</h3>${dl({
        "Listening": `udp/${esc(s.collector.listen)}`,
        "Packets received": fmtNum(s.collector.packets),
        "Flows decoded": fmtNum(s.collector.flows),
        "Duplicates dropped": fmtNum(s.collector.duplicates) + (s.collector.duplicates ? ' <span class="muted">(router sends each record more than once: check for duplicate targets)</span>' : ""),
        "Flows stored": fmtNum(s.store.stored_flows),
        "Not LAN-related (skipped)": fmtNum(s.store.unclassified_flows),
        "Ignored (multicast etc.)": fmtNum(s.store.ignored_flows),
        "Waiting for template": fmtNum(s.collector.no_template),
        "Decode errors": fmtNum(s.collector.errors),
        "Templates": fmtNum(s.collector.templates),
        "Export versions": esc(Object.entries(s.collector.versions).map(([v, n]) => (v === "10" ? "IPFIX" : "v" + v) + ": " + fmtNum(n)).join(", ") || "—"),
        "Last flow": fmtAgo(s.store.last_flow),
      })}</div>
      <div><h3>Routers sending flows</h3>${ex.length ? dl(Object.fromEntries(ex.map(([ip, e]) => [ip, `${fmtNum(e.packets)} packets, last ${fmtAgo(e.last)}`]))) : '<p class="muted">None yet.</p>'}
        <h3>Storage</h3>${dl({
          "Database size": fmtBytes(s.store.db_bytes),
          "Resolution": s.store.bucket_seconds + " s",
          "Retention": s.store.retention_days + " days",
          "Uptime": Math.round(s.uptime / 60) + " min",
        })}</div>
      <div><h3>GeoIP</h3>${dl({ "Country DB": esc(s.geo.country), "ASN DB": esc(s.geo.asn) })}
        <p class="muted"><a href="https://db-ip.com" target="_blank" rel="noopener" style="color:inherit">IP Geolocation by DB-IP</a> (CC BY 4.0)</p>
        <h3>Router DHCP name sync</h3><p class="muted">${s.lease_sync == null ? "Disabled (see <code>[mikrotik]</code> in config.toml)" : esc(s.lease_sync)}</p></div>
      <div style="grid-column:1/-1"><h3>MikroTik setup</h3>
        <p class="muted">Run this in the RouterOS terminal (replace the address with this server's LAN IP if different):</p>
<pre class="setup">/ip traffic-flow set enabled=yes interfaces=all active-flow-timeout=1m inactive-flow-timeout=15s
/ip traffic-flow target add dst-address=${esc(location.hostname)} port=${esc(port)} version=ipfix</pre></div>
      <div style="grid-column:1/-1"><h3>Recent raw flow records</h3>
        <p class="muted">Exactly what the router sent, newest first. Useful for checking NAT and interface fields.</p>
        <button class="btn" id="load-raw">Show last 50</button><div id="raw-flows"></div></div>
    </div>`;
    $("#load-raw", el).onclick = async () => {
      const d = await api("/api/debug/flows?limit=50");
      $("#raw-flows", el).innerHTML = `<div class="table-wrap"><table class="data"><thead><tr>
        <th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th class="num">Bytes</th><th class="num">Pkts</th>
        <th class="num">In if</th><th class="num">Out if</th><th>Post-NAT src</th><th>Post-NAT dst</th></tr></thead><tbody>${
        d.flows.map((f) => `<tr><td>${new Date(f.time * 1000).toLocaleTimeString()}</td>
          <td class="mono">${esc(f.src)}:${f.sport}</td><td class="mono">${esc(f.dst)}:${f.dport}</td>
          <td>${esc(PROTOS[f.proto] || f.proto)}</td><td class="num">${fmtBytes(f.bytes)}</td><td class="num">${fmtNum(f.packets)}</td>
          <td class="num">${f.in_if}</td><td class="num">${f.out_if}</td>
          <td class="mono muted">${esc(f.nat_src || "")}</td><td class="mono muted">${esc(f.nat_dst || "")}</td></tr>`).join("")
      }</tbody></table></div>`;
    };
    return el;
  },
};

async function loadRdns(ips, root = document) {
  const todo = ips.filter((ip) => !(ip in rdns));
  if (todo.length) {
    try { Object.assign(rdns, await api("/api/rdns?ips=" + encodeURIComponent(todo.join(",")))); } catch { /* ignore */ }
  }
  for (const ip of ips) {
    root.querySelectorAll(`[data-rdns="${CSS.escape(ip)}"]`).forEach((el) => el.textContent = rdns[ip] ?? "");
  }
}

// ---------- detail drawer ----------
// What each kind of item shows when you open it: [dimension, summary key, id key].
const DRILL = {
  country: [["device", "devices", "ip"], ["asn", "orgs", "asn"], ["remote", "remotes", "ip"], ["port", "ports", "port"]],
  device: [["country", "countries", "cc"], ["asn", "orgs", "asn"], ["remote", "remotes", "ip"], ["port", "ports", "port"]],
  asn: [["country", "countries", "cc"], ["device", "devices", "ip"], ["remote", "remotes", "ip"], ["port", "ports", "port"]],
  remote: [["device", "devices", "ip"], ["port", "ports", "port"]],
  port: [["country", "countries", "cc"], ["device", "devices", "ip"], ["asn", "orgs", "asn"], ["remote", "remotes", "ip"]],
  proto: [["country", "countries", "cc"], ["device", "devices", "ip"], ["port", "ports", "port"]],
};
const drawerStack = [];
let drawerSeq = 0;

function openDrawer(dim, id) {
  hideTip();
  drawerStack.push([dim, String(id)]);
  renderDrawer();
}
function closeDrawer() {
  drawerStack.length = 0;
  const d = $("#drawer");
  d.classList.remove("open");
  document.body.classList.remove("drawer-open");
}
async function renderDrawer() {
  const d = $("#drawer");
  if (!drawerStack.length) return closeDrawer();
  const [dim, id] = drawerStack[drawerStack.length - 1];
  const seq = ++drawerSeq;
  let data;
  try {
    data = await api("/api/summary?" + apiParams({ [dim]: id }, dim));
  } catch (e) {
    d.innerHTML = `<div class="empty-state">Error: ${esc(e.message)}</div>`;
    return;
  }
  if (seq !== drawerSeq) return;
  for (const r of data.devices) labels.device[r.ip] = deviceLabel(r);
  for (const r of data.orgs) if (r.asn) labels.asn[r.asn] = r.org || "AS" + r.asn;
  const t = data.totals;
  const tot = t.down + t.up;

  let title = htmlLabel(dim, id), sub = DIMS[dim].label, extra = "";
  if (dim === "country") { title = `<span class="flag big">${flag(id)}</span>${esc(countryName(id))}`; sub = `Country · ${esc(id)}`; }
  if (dim === "device") {
    const dev = (devicesData?.devices || []).find((x) => x.ip === id) || {};
    sub = `Device · <span class="mono">${esc(id)}</span>${dev.mac ? ` · <span class="mono">${esc(dev.mac)}</span>` : ""}`;
    extra = `<button class="btn" id="drawer-rename">Rename</button>`;
  }
  if (dim === "asn") sub = +id ? `Organisation · AS${esc(id)}` : "Organisation";
  if (dim === "remote") {
    const r = data.remotes[0] || {};
    sub = `Remote host · <span data-rdns="${esc(id)}">${esc(rdns[id] ?? "…")}</span>`;
    if (r.cc) sub += ` · ${flag(r.cc)} ${esc(countryName(r.cc))}`;
    if (r.org) sub += ` · ${esc(r.org)}`;
  }
  if (dim === "port") sub = `Service port${serviceName(id, data.ports[0]?.proto) ? " · " + esc(serviceName(id, data.ports[0]?.proto)) : ""}`;

  const share = grandTotal() ? ` <span class="muted">(${fmtPct(tot / grandTotal())} of view)</span>` : "";
  const stat = (k, v) => `<div class="dstat"><div class="muted">${k}</div><div>${v}</div></div>`;
  const stats = [
    stat("↓ Download", fmtBytes(t.down)), stat("↑ Upload", fmtBytes(t.up)),
    dim !== "device" ? stat("Devices", fmtNum(t.devices)) : stat("Countries", fmtNum(t.countries)),
    dim !== "remote" ? stat("Remote hosts", fmtNum(t.remotes)) : stat("Services", fmtNum(data.ports.length)),
    stat("First seen", t.first ? fmtAgo(t.first) : "—"), stat("Last seen", t.last ? fmtAgo(t.last) : "—"),
  ].join("");

  const isInc = state.inc[dim]?.includes(id), isExc = state.exc[dim]?.includes(id);
  let h = `<div class="drawer-head">
      ${drawerStack.length > 1 ? `<button class="icon-btn" id="drawer-back" title="Back" aria-label="Back">←</button>` : ""}
      <div class="drawer-title"><h2>${title}</h2><div class="muted">${sub}</div></div>
      <button class="icon-btn" id="drawer-close" title="Close" aria-label="Close">×</button></div>
    <div class="drawer-actions">
      <button class="btn primary" id="drawer-only" ${isInc ? "disabled" : ""}>＋ Only show this</button>
      <button class="btn" id="drawer-hide" ${isExc ? "disabled" : ""}>− Hide this</button>${extra}</div>
    <div class="drawer-body">
      <div class="dtotal">${fmtBytes(tot)}${share}</div>
      <div class="dstats">${stats}</div>
      <div class="dchart"></div>`;
  for (const [sdim, key, idKey] of DRILL[dim] || []) {
    const rows = (data[key] || []).filter((r) => String(r[idKey]) !== id);
    if (!rows.length) continue;
    const max = Math.max(...rows.map(totalOf));
    h += `<h3>${DIMS[sdim].plural} <span class="muted">${rows.length > 8 ? "top 8 of " + rows.length : rows.length}</span></h3><div class="dlist">`;
    for (const r of rows.slice(0, 8)) {
      const rid = r[idKey];
      let name = htmlLabel(sdim, rid), note = "";
      if (sdim === "device") { name = esc(r.name || r.ip); note = r.name ? r.ip : ""; }
      if (sdim === "asn") { name = esc(r.org || (+rid ? "AS" + rid : "Unknown / local")); }
      if (sdim === "remote") note = r.org || "";
      if (sdim === "port") { name = `<span class="mono">${rid || "—"}</span> ${esc(PROTOS[r.proto] || "")}`; note = serviceName(rid, r.proto); }
      h += `<button class="ditem" data-dim="${sdim}" data-id="${esc(rid)}">
        <span class="dname">${name}${note ? ` <span class="muted">${esc(note)}</span>` : ""}</span>
        <span class="dbytes">${fmtBytes(totalOf(r))}</span>${shareBar(r, max)}</button>`;
    }
    h += `</div>`;
  }
  h += `</div>`;
  d.innerHTML = h;
  d.classList.add("open");
  document.body.classList.add("drawer-open");
  requestAnimationFrame(() => drawBars($(".dchart", d), data, { compact: true }));
  $("#drawer-close", d).onclick = closeDrawer;
  const back = $("#drawer-back", d);
  if (back) back.onclick = () => { drawerStack.pop(); renderDrawer(); };
  $("#drawer-only", d).onclick = () => addFilter(dim, id, "inc");
  $("#drawer-hide", d).onclick = () => addFilter(dim, id, "exc");
  const rn = $("#drawer-rename", d);
  if (rn) rn.onclick = async () => {
    const name = prompt("Name for " + id, labels.device[id] !== id ? labels.device[id] || "" : "");
    if (name == null) return;
    await api("/api/devices", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip: id, name }) });
    labels.device[id] = name || id;
    refresh();
  };
  d.querySelectorAll(".ditem").forEach((b) => b.onclick = () => openDrawer(b.dataset.dim, b.dataset.id));
  if (dim === "remote") loadRdns([id], d);
}

// ---------- panel ----------
let panelSeq = 0;
async function renderPanel() {
  const seq = ++panelSeq;
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === state.tab));
  if (!summary) return;
  let el;
  try {
    el = await (TABS[state.tab] || TABS.countries)();
  } catch (e) {
    el = document.createElement("div");
    el.innerHTML = `<div class="empty-state">Error: ${esc(e.message)}</div>`;
  }
  if (seq !== panelSeq) return;
  const panel = $("#panel");
  const scroll = panel.querySelector(".table-wrap")?.scrollLeft || 0;
  hideTip();
  panel.replaceChildren(el);
  const tw = panel.querySelector(".table-wrap");
  if (tw) tw.scrollLeft = scroll;
  wirePanel(panel);
  writeHash();
}

function wirePanel(panel) {
  panel.querySelectorAll("button[data-f]").forEach((b) => b.onclick = () => addFilter(b.dataset.f, b.dataset.v, "inc"));
  panel.querySelectorAll("button[data-x]").forEach((b) => b.onclick = () => addFilter(b.dataset.x, b.dataset.v, "exc"));
  panel.querySelectorAll("button[data-rename]").forEach((b) => b.onclick = () => startRename(b.dataset.rename));
  panel.querySelectorAll("[data-open-dim]").forEach((s) => s.onclick = () => openDrawer(s.dataset.openDim, s.dataset.openId));
  const hi = $("#hide-idle", panel);
  if (hi) hi.onchange = () => { state.hideIdle = hi.checked; renderPanel(); };
  const ls = $("#lease-sync", panel);
  if (ls) ls.onclick = async () => {
    ls.disabled = true; ls.textContent = "Syncing…";
    try { await api("/api/lease-sync", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }); }
    catch (e) { alert("Sync failed: " + e.message); }
    refresh();
  };
}

function startRename(ip) {
  const span = document.querySelector(`#panel [data-name="${CSS.escape(ip)}"]`);
  if (!span) return;
  const current = labels.device[ip] !== ip ? labels.device[ip] || "" : "";
  span.innerHTML = `<input class="name-input" value="${esc(current)}" placeholder="e.g. Living room TV">`;
  const input = span.querySelector("input");
  input.onclick = (e) => e.stopPropagation();
  input.focus(); input.select();
  let done = false;
  const save = async (commit) => {
    if (done) return; done = true;
    if (commit) {
      await api("/api/devices", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, name: input.value }) });
      labels.device[ip] = input.value || ip;
    }
    refresh();
  };
  input.onkeydown = (e) => { if (e.key === "Enter") save(true); if (e.key === "Escape") save(false); };
  input.onblur = () => save(true);
  pauseRefresh = true;
}

// ---------- refresh loop ----------
let pauseRefresh = false, loading = false;
async function refresh() {
  if (loading) { refresh.again = true; return; }
  loading = true;
  pauseRefresh = false;
  renderChips();
  writeHash();
  try {
    const p = apiParams();
    [summary, status, devicesData] = await Promise.all([
      api("/api/summary?" + p), api("/api/status"), api("/api/devices?" + p),
    ]);
    for (const d of devicesData.devices) labels.device[d.ip] = d.name || d.ip;
    for (const r of summary.orgs) if (r.asn) labels.asn[r.asn] = r.org || "AS" + r.asn;
    renderChips();
    renderStatusPill();
    renderKpis();
    drawBars($("#chart"), summary, { brush: true });
    await renderPanel();
    if (drawerStack.length) renderDrawer();
  } catch (e) {
    $("#status-pill").innerHTML = `<span style="color:var(--critical)">▲</span>Can't reach server: ${esc(e.message)}`;
  } finally {
    loading = false;
    if (refresh.again) { refresh.again = false; refresh(); }
  }
}

function init() {
  readHash();
  try { const t = localStorage.getItem("tfv-theme"); if (t) document.documentElement.dataset.theme = t; } catch { /* storage blocked */ }
  $("#theme").onclick = () => {
    const dark = getComputedStyle(document.documentElement).colorScheme.includes("dark");
    const t = dark ? "light" : "dark";
    document.documentElement.dataset.theme = t;
    try { localStorage.setItem("tfv-theme", t); } catch { /* storage blocked */ }
  };
  syncRangeButtons();
  document.querySelectorAll("#range button").forEach((b) => b.onclick = () => {
    state.range = +b.dataset.r;
    state.from = state.to = null;
    syncRangeButtons();
    state.conn.offset = 0;
    refresh();
  });
  $("#add-filter").onclick = (e) => openPicker(e.currentTarget);
  $("#lan").checked = state.lan;
  $("#lan").onchange = (e) => { state.lan = e.target.checked; refresh(); };
  $("#search").value = state.q;
  let t;
  $("#search").oninput = (e) => { clearTimeout(t); t = setTimeout(() => { state.q = e.target.value.trim(); state.conn.offset = 0; refresh(); }, 300); };
  document.querySelectorAll("#tabs button").forEach((b) => b.onclick = () => { state.tab = b.dataset.tab; renderPanel(); });
  let rt;
  window.addEventListener("resize", () => {
    clearTimeout(rt);
    rt = setTimeout(() => {
      if (summary) drawBars($("#chart"), summary, { brush: true });
      if (drawerStack.length) renderDrawer();
    }, 150);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !picker && drawerStack.length) closeDrawer();
    if (e.key === "/" && document.activeElement === document.body) { e.preventDefault(); $("#search").focus(); }
  });
  // pasted / bookmarked links (our own updates use replaceState, which doesn't fire this)
  window.addEventListener("hashchange", () => {
    readHash();
    syncRangeButtons();
    $("#lan").checked = state.lan;
    $("#search").value = state.q;
    refresh();
  });
  setInterval(() => { if ($("#auto").checked && !pauseRefresh && !picker && !document.hidden) refresh(); }, 30000);
  refresh();
}
init();

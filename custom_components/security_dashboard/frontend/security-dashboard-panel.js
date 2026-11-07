// Security Dashboard panel — plain web component, no build step required.
// HA sets `hass`, `narrow`, `route` and `panel` on the element.

const C = {
  high: "var(--error-color, #db4437)",
  medium: "var(--warning-color, #ffa600)",
  low: "var(--info-color, #039be5)",
  ok: "var(--success-color, #43a047)",
};
const SEV_LABEL = { high: "High", medium: "Med", low: "Low" };

const esc = (v) =>
  String(v ?? "—").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const ago = (iso) => {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((Date.now() - new Date(iso)) / 1000));
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
};

const hourLabel = (date) => `${String(date.getHours()).padStart(2, "0")}:00`;
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// Official apps identify themselves with a home-assistant.io URL as client ID
const APP_CLIENTS = {
  "/ios": "Home Assistant iOS app",
  "/android": "Home Assistant Android app",
  "/companion-app": "Home Assistant companion app",
};

// Human label for a token's client.
//   http://homeassistant.lan:8123/ + session → "Browser session · homeassistant.lan"
//   https://home-assistant.io/iOS            → "Home Assistant iOS app"
//   Node-RED + long-lived                    → "Node-RED · long-lived token"
const prettyClient = (client, type) => {
  if (type === "long_lived_access_token") return `${client || "Unnamed"} · long-lived token`;
  if (!client) return type === "system" ? "System" : "Unknown client";
  try {
    const u = new URL(client);
    if (u.protocol.startsWith("http")) {
      if (/(^|\.)home-assistant\.io$/.test(u.hostname)) {
        const app = APP_CLIENTS[u.pathname.toLowerCase().replace(/\/$/, "")];
        return app || `Home Assistant app · ${u.pathname}`;
      }
      return `Browser session · ${u.hostname}`;
    }
  } catch (_) { /* not a URL */ }
  return type === "normal" ? `${client} · session` : client;
};

// Short, readable detail line per event; the raw text goes into the tooltip
const prettyDetail = (e) => {
  if (e.kind === "failed_login") {
    const url = /Requested URL: '([^']*)'/.exec(e.detail);
    let path = url ? url[1].split("?")[0] : null;
    if (path) path = path.replace(/^(\/auth\/login_flow)\/[0-9a-f]+$/i, "$1");
    return path ? `Invalid login · ${path}` : "Invalid login";
  }
  if (e.kind === "banned") return "Banned after too many failed logins";
  if (e.kind === "token_used") {
    const m = /^(.*) \(([a-z_]+)\)$/.exec(e.detail);
    return m ? prettyClient(m[1], m[2]) : e.detail;
  }
  return e.detail;
};

const fmtDateTime = (iso) => {
  if (!iso) return "—";
  const d = new Date(iso);
  const sameDay = d.toDateString() === new Date().toDateString();
  const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return sameDay ? `Today ${time}` : `${d.toLocaleDateString([], { day: "numeric", month: "short" })} ${time}`;
};

const KIND_LABEL = { failed_login: "Failed login", banned: "IP banned", token_used: "Token used" };

class SecurityDashboardPanel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._data = null;
    this._tab = "access";
    this._netView = "now";
    this._running = false;
  }

  // HA calls this on every state change, so it must stay cheap: no re-render here
  set hass(hass) {
    const first = !this._hass;
    this._hass = hass;
    if (first) {
      // Integration titles ("hacs" → "HACS") for the Integration columns
      try { hass.loadBackendTranslation?.("title"); } catch (_) { /* optional */ }
      this._subscribe();
    }
  }

  _integrationName(domain) {
    if (!domain) return null;
    if (domain.startsWith("lib:")) return `${domain.slice(4)} (library)`;
    const title = this._hass?.localize?.(`component.${domain}.title`);
    return title || domain;
  }

  set narrow(v) {
    this._narrow = v;
    this._render();
  }

  connectedCallback() {
    // Keep "x s ago" texts fresh without re-rendering the page
    this._ticker = setInterval(() => {
      this.shadowRoot.querySelectorAll("[data-ago]").forEach((el) => {
        el.textContent = ago(el.dataset.ago);
      });
    }, 5000);
  }

  disconnectedCallback() {
    clearInterval(this._ticker);
    if (this._unsub) this._unsub();
    this._unsub = undefined;
    this._hass = undefined;
  }

  async _subscribe() {
    this._render();
    try {
      this._unsub = await this._hass.connection.subscribeMessage(
        (msg) => {
          this._data = msg;
          this._error = undefined;
          this._render();
        },
        { type: "security_dashboard/subscribe" },
      );
    } catch (err) {
      this._error = err.message || String(err);
      this._render();
    }
  }

  async _runChecks() {
    if (this._running) return;
    this._running = true;
    this._render();
    try {
      this._data = await this._hass.callWS({ type: "security_dashboard/run_checks" });
    } catch (err) {
      this._error = err.message || String(err);
    }
    this._running = false;
    this._render();
  }

  _navigate(path) {
    history.pushState(null, "", path);
    window.dispatchEvent(new CustomEvent("location-changed", { detail: { replace: false } }));
  }

  // ------------------------------------------------------------------ sections

  _header() {
    const d = this._data;
    const status = this._error
      ? `<span class="status err">Disconnected</span>`
      : d && d.network
        ? `<span class="status"><span class="live-dot"></span>Live · last scan <span data-ago="${esc(d.network.scanned_at)}">${ago(d.network.scanned_at)}</span></span>`
        : `<span class="status">Connecting…</span>`;
    return `
      <div class="toolbar">
        ${this._narrow ? `<ha-menu-button></ha-menu-button>` : ""}
        <svg class="shield" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 5 6v5c0 4.5 3 8.3 7 10 4-1.7 7-5.5 7-10V6l-7-3Z"></path><rect x="9.5" y="10.5" width="5" height="4.5" rx="1"></rect><path d="M10.5 10.5V9a1.5 1.5 0 0 1 3 0v1.5"></path></svg>
        <h1>Security</h1>
        <div class="toolbar-right">
          ${status}
          <button class="run" type="button" ${this._running || !d ? "disabled" : ""}>${this._running ? "Checking…" : "Run checks"}</button>
        </div>
      </div>`;
  }

  _tiles(d) {
    const a = d.auth;
    const net = d.network;
    const llat = a.tokens.filter((t) => t.type === "long_lived_access_token");
    const stale = llat.filter((t) => t.stale).length;
    const active = a.users.filter((u) => u.is_active);
    const noMfa = active.filter((u) => !u.mfa_enabled).length;
    const high = d.findings.filter((f) => f.severity === "high").length;
    const scoreColor = d.score >= 80 ? C.ok : d.score >= 50 ? C.medium : C.high;
    const newDest = net ? net.new_destinations_24h : 0;

    const tile = (value, label, sub, color) => `
      <div class="tile">
        <div class="num" style="color:${color || "inherit"}">${value}</div>
        <div class="label">${label}</div>
        <div class="sub">${sub}</div>
      </div>`;

    return `
      <section class="tiles" aria-label="Summary">
        <div class="tile score">
          <div class="ring" style="--c:${scoreColor};--p:${d.score}"><span>${d.score}</span></div>
          <div>
            <div class="label strong">Security score</div>
            <div class="sub">${plural(d.findings.length, "finding", "findings")} · ${high} high</div>
          </div>
        </div>
        ${tile(a.failed_logins_24h, "Failed logins · 24 h",
          a.failed_logins_24h
            ? `${plural(a.failed_sources_24h, "source IP", "source IPs")} · ${a.banned_24h} banned`
            : "No failed attempts",
          a.failed_logins_24h ? C.high : null)}
        ${tile(net ? net.connections.length : "–", "Outbound connections",
          newDest ? `${plural(newDest, "new destination", "new destinations")} in 24 h` : "No new destinations in 24 h")}
        ${tile(llat.length, "Long-lived tokens",
          stale ? `${stale} unused for 90+ days` : "None unused for 90+ days",
          stale ? C.medium : null)}
        ${tile(noMfa, "Users without MFA", `of ${plural(active.length, "active user", "active users")}`,
          noMfa ? C.medium : null)}
      </section>`;
  }

  _chart(d) {
    const a = d.auth;
    const counts = a.failed_hourly || [];
    const start = new Date(a.failed_hourly_start);
    const max = Math.max(1, ...counts);
    const peakIdx = counts.indexOf(Math.max(...counts));
    const at = (i) => new Date(start.getTime() + i * 3600e3);

    let summary = "No failed logins in the last 24 h";
    if (counts[peakIdx] > 0) {
      summary = `Peak ${hourLabel(at(peakIdx))} · ${plural(counts[peakIdx], "attempt", "attempts")}`;
      if (a.top_source_24h) summary += ` · most from ${esc(a.top_source_24h.ip)} (${a.top_source_24h.count})`;
    }

    const bars = counts.map((v, i) => {
      const h = v ? Math.max(6, Math.round((v / max) * 64)) : 3;
      const bg = v === 0 ? "var(--divider-color)" : v >= max * 0.6 ? C.high : `color-mix(in srgb, ${C.high} 65%, transparent)`;
      return `<div class="bar" style="height:${h}px;background:${bg}" title="${hourLabel(at(i))} · ${plural(v, "failed login", "failed logins")}"></div>`;
    }).join("");

    const first = at(0);
    const firstLabel = first.toDateString() === new Date().toDateString() ? hourLabel(first) : `${hourLabel(first)} yesterday`;

    return `
      <div class="chart">
        <div class="chart-head">
          <h2>Failed logins · last 24 h</h2>
          <span class="sub">${summary}</span>
        </div>
        <div class="bars" role="img" aria-label="Failed logins per hour over the last 24 hours, peak ${counts[peakIdx] || 0}">${bars}</div>
        <div class="axis"><span>${firstLabel}</span><span>${hourLabel(at(12))}</span><span>now</span></div>
      </div>`;
  }

  _accessTable(d) {
    const rows = d.auth.events.map((e) => `
      <tr>
        <td class="muted"><span data-ago="${esc(e.timestamp)}">${ago(e.timestamp)}</span></td>
        <td><span class="chip ${e.kind}">${KIND_LABEL[e.kind] || esc(e.kind)}</span></td>
        <td class="mono">${esc(e.ip)}</td>
        <td>${esc(e.user)}</td>
        <td class="detail" title="${esc(e.detail)}">${esc(prettyDetail(e))}</td>
      </tr>`).join("");
    return `<table>
      <thead><tr><th>When</th><th>Event</th><th>Source IP</th><th>User</th><th>Detail</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="5" class="empty">No access events recorded yet.</td></tr>`}</tbody>
    </table>`;
  }

  _networkTable(d) {
    const net = d.network;
    if (!net) return `<div class="empty">Waiting for the first scan…</div>`;
    const views = [["now", "Open now"], ["24h", "Last 24 h"]]
      .map(([id, label]) => `<button type="button" data-netview="${id}" class="seg ${id === this._netView ? "active" : ""}" aria-pressed="${id === this._netView}">${label}</button>`)
      .join("");
    const learning = net.learning_until
      ? `<div class="note">Learning the baseline until ${fmtDateTime(net.learning_until)}. Destinations seen before then aren't flagged as new.</div>`
      : "";
    const body = this._netView === "24h" ? this._network24h(net) : this._networkNow(net);
    return `<div class="segbar"><div class="segs" role="group" aria-label="Connections view">${views}</div></div>${learning}${body}`;
  }

  _integrationCell(name, fallback) {
    return name
      ? esc(this._integrationName(name))
      : `<span class="muted" title="Not made through aiohttp, or from an add-on or the host">${esc(fallback || "Unattributed")}</span>`;
  }

  _networkNow(net) {
    const isNew = new Set(net.destinations_24h.filter((x) => x.new).map((x) => x.host));
    const rows = net.connections.map((c) => {
      const host = c.traced_host || c.hostname || c.remote_ip;
      const rdns = c.traced_host && c.hostname && c.hostname !== c.traced_host
        ? `<div class="sub" title="Reverse DNS">${esc(c.hostname)}</div>` : "";
      return `
      <tr>
        <td>${c.traced_host || c.hostname ? esc(host) : `<span class="muted">(no reverse DNS)</span>`}${rdns}</td>
        <td class="mono">${esc(c.remote_ip)}:${esc(c.remote_port)}</td>
        <td>${this._integrationCell(c.integration, c.process ? `${c.process} · unattributed` : "Unattributed")}</td>
        <td>${isNew.has(host) ? `<span class="chip new">New</span>` : `<span class="chip">Known</span>`}</td>
      </tr>`;
    }).join("");
    return `<table>
      <thead><tr><th>Destination</th><th>Remote</th><th>Integration</th><th>Seen</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="4" class="empty">No external connections right now.</td></tr>`}</tbody>
    </table>
    <div class="foot">${plural(net.connections.length, "established connection", "established connections")} · ${plural(net.listening.length, "listening socket", "listening sockets")}</div>`;
  }

  _network24h(net) {
    const rows = net.destinations_24h.map((x) => {
      const activity = [
        x.requests ? plural(x.requests, "request", "requests") : null,
        x.connections ? plural(x.connections, "connection", "connections") : null,
      ].filter(Boolean).join(" · ");
      const integrations = x.integrations.length
        ? x.integrations.map((i) => esc(this._integrationName(i))).join(", ")
        : this._integrationCell(null);
      return `
      <tr>
        <td>${esc(x.host)}${x.new ? ` <span class="chip new">New</span>` : ""}</td>
        <td>${integrations}</td>
        <td class="muted">${activity}</td>
        <td class="muted">${fmtDateTime(x.first_seen)}</td>
        <td class="muted">${x.last_seen ? `<span data-ago="${esc(x.last_seen)}">${ago(x.last_seen)}</span>` : "—"}</td>
      </tr>`;
    }).join("");
    return `<table>
      <thead><tr><th>Destination</th><th>Integration</th><th>Activity · 24 h</th><th>First seen</th><th>Last seen</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="5" class="empty">No outbound traffic recorded in the last 24 h.</td></tr>`}</tbody>
    </table>
    <div class="foot">Requests are counted by tracing Home Assistant's HTTP client. Connections come from the socket scan. Monitoring since ${fmtDateTime(net.monitoring_since)}.</div>`;
  }

  _tokensTable(d) {
    const rows = d.auth.tokens.map((t) => `
      <tr>
        <td>${esc(t.user)}</td>
        <td>${esc(prettyClient(t.client_name, t.type === "long_lived_access_token" ? null : t.type))}</td>
        <td class="muted">${t.type === "long_lived_access_token" ? "Long-lived" : "Session"}</td>
        <td class="muted">${t.last_used_at ? `<span data-ago="${esc(t.last_used_at)}">${ago(t.last_used_at)}</span>` : "never"}</td>
        <td class="mono">${esc(t.last_used_ip)}</td>
        <td>${t.stale ? `<span class="chip new">Stale · revoke?</span>` : ""}</td>
      </tr>`).join("");
    return `<table>
      <thead><tr><th>User</th><th>Client</th><th>Type</th><th>Last used</th><th>Last IP</th><th><span class="sr">Status</span></th></tr></thead>
      <tbody>${rows || `<tr><td colspan="6" class="empty">No tokens.</td></tr>`}</tbody>
    </table>`;
  }

  _findings(d) {
    const list = d.findings.length
      ? d.findings.map((f) => `
          <div class="finding">
            <span class="sev ${f.severity}">${SEV_LABEL[f.severity] || esc(f.severity)}</span>
            <div><div class="ftitle">${esc(f.title)}</div><div class="sub">${esc(f.detail)}</div></div>
          </div>`).join("")
      : `<div class="empty">No findings. Nice.</div>`;
    return `
      <section class="card" aria-label="Findings">
        <h2>Findings</h2>
        ${list}
        <a class="repairs" href="/config/repairs">Open in Settings › Repairs</a>
      </section>`;
  }

  _destinations(d) {
    const dest = d.network ? d.network.destinations_24h.slice(0, 6) : [];
    const max = Math.max(1, ...dest.map((x) => x.activity));
    const rows = dest.map((x) => {
      const who = x.integrations.length ? this._integrationName(x.integrations[0]) : "unattributed";
      const unit = x.requests ? "requests" : "connections";
      return `
      <div class="dest">
        <div class="dest-row">
          <span class="dest-host" title="${esc(x.host)}">${esc(x.host)}${x.new ? ` <span class="new-tag">· new</span>` : ""}</span>
          <span class="muted" title="${x.requests} requests · ${x.connections} connections">${x.activity}</span>
        </div>
        <div class="track"><div class="fill" style="width:${Math.max(2, (x.activity / max) * 100)}%;background:${x.new ? C.medium : C.low}"></div></div>
        <div class="sub">${esc(who)} · ${unit}</div>
      </div>`;
    }).join("");
    return `
      <section class="card" aria-label="Top destinations">
        <h2>Top destinations · 24 h</h2>
        ${rows || `<div class="empty">No outbound traffic recorded yet.</div>`}
      </section>`;
  }

  // ------------------------------------------------------------------ render

  _render() {
    const d = this._data;
    let body;
    if (this._error && !d) body = `<div class="empty">Couldn't load: ${esc(this._error)}</div>`;
    else if (!d) body = `<div class="empty">Loading…</div>`;
    else {
      const content = { access: this._accessTable(d), network: this._networkTable(d), tokens: this._tokensTable(d) }[this._tab];
      const tabs = [["access", "Access log"], ["network", "Connections"], ["tokens", "Tokens"]]
        .map(([id, label]) => `<button type="button" role="tab" aria-selected="${id === this._tab}" data-tab="${id}" class="${id === this._tab ? "active" : ""}">${label}</button>`)
        .join("");
      body = `
        ${this._tiles(d)}
        <div class="grid">
          <section class="card main" aria-label="Activity">
            ${this._chart(d)}
            <div class="tabs" role="tablist">${tabs}</div>
            <div class="scroll">${content}</div>
          </section>
          <aside class="side">
            ${this._findings(d)}
            ${this._destinations(d)}
          </aside>
        </div>`;
    }

    this.shadowRoot.innerHTML = `
      <style>
        :host { display:block; background:var(--primary-background-color); min-height:100vh; color:var(--primary-text-color); font-size:14px; }
        .toolbar { min-height:56px; display:flex; flex-wrap:wrap; align-items:center; gap:8px 12px; padding:6px 16px; box-sizing:border-box;
          background:var(--app-header-background-color); color:var(--app-header-text-color, white); border-bottom:var(--app-header-border-bottom, none); }
        .toolbar h1 { margin:0; font-size:20px; font-weight:400; flex:1 1 auto; }
        .shield { width:24px; height:24px; flex:none; }
        .toolbar-right { display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
        .status { font-size:13px; opacity:.8; display:inline-flex; align-items:center; gap:6px; }
        .status.err { color:${C.high}; opacity:1; }
        .live-dot { width:8px; height:8px; border-radius:50%; background:${C.ok}; }
        button.run { min-height:40px; padding:0 18px; border-radius:20px; border:1px solid var(--divider-color); background:var(--card-background-color);
          color:var(--primary-text-color); font:inherit; font-weight:500; cursor:pointer; }
        button.run:hover:not([disabled]) { border-color:var(--primary-color); }
        button.run[disabled] { opacity:.6; cursor:default; }
        .content { padding:16px; max-width:1400px; margin:0 auto; display:flex; flex-direction:column; gap:16px; }
        .tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; }
        .tile, .card { background:var(--card-background-color); border:1px solid var(--divider-color); border-radius:var(--ha-card-border-radius,12px); }
        .tile { padding:16px; display:flex; flex-direction:column; gap:4px; }
        .tile.score { flex-direction:row; align-items:center; gap:14px; }
        .ring { width:64px; height:64px; flex:none; border-radius:50%; display:grid; place-items:center;
          background:conic-gradient(var(--c) calc(var(--p)*1%), var(--divider-color) 0); }
        .ring span { width:50px; height:50px; border-radius:50%; background:var(--card-background-color); display:grid; place-items:center; font-weight:600; font-size:18px; }
        .num { font-size:28px; font-weight:600; line-height:1.15; }
        .label { color:var(--primary-text-color); }
        .label.strong { font-weight:500; }
        .sub, .muted { color:var(--secondary-text-color); }
        .sub { font-size:12px; }
        .grid { display:flex; flex-wrap:wrap; gap:16px; align-items:flex-start; }
        .main { flex:999 1 600px; min-width:0; overflow:hidden; }
        .side { flex:1 1 320px; min-width:0; display:flex; flex-direction:column; gap:16px; }
        .side .card { padding:16px; }
        h2 { font-size:16px; font-weight:500; margin:0 0 8px; }
        .chart { padding:16px 16px 4px; }
        .chart-head { display:flex; justify-content:space-between; align-items:baseline; gap:12px; flex-wrap:wrap; }
        .chart-head h2 { margin:0; }
        .bars { height:72px; display:flex; align-items:flex-end; gap:4px; margin-top:12px; border-bottom:1px solid var(--divider-color); }
        .bar { flex:1 1 0; border-radius:3px 3px 0 0; }
        .axis { display:flex; justify-content:space-between; font-size:11px; color:var(--secondary-text-color); padding:4px 0 8px; }
        .tabs { display:flex; gap:4px; padding:0 12px; border-bottom:1px solid var(--divider-color); overflow-x:auto; }
        .tabs button { min-height:44px; background:none; border:0; padding:0 14px; cursor:pointer; color:var(--secondary-text-color); font:inherit; font-weight:500;
          border-bottom:2px solid transparent; white-space:nowrap; }
        .tabs button.active { color:var(--primary-color); border-bottom-color:var(--primary-color); }
        .scroll { overflow-x:auto; }
        table { width:100%; border-collapse:collapse; }
        th { text-align:left; color:var(--secondary-text-color); font-weight:500; font-size:12px; text-transform:uppercase; letter-spacing:.04em;
          padding:12px 8px; border-bottom:1px solid var(--divider-color); white-space:nowrap; }
        td { padding:10px 8px; border-bottom:1px solid var(--divider-color); white-space:nowrap; }
        th:first-child, td:first-child { padding-left:16px; }
        th:last-child, td:last-child { padding-right:16px; }
        tbody tr:last-child td { border-bottom:0; }
        td.detail { white-space:normal; color:var(--secondary-text-color); min-width:220px; }
        .mono { font-family:var(--code-font-family, monospace); font-size:13px; }
        .chip { padding:2px 9px; border-radius:10px; font-size:12px; font-weight:500; background:var(--secondary-background-color); color:var(--secondary-text-color); }
        .chip.failed_login, .chip.banned { background:color-mix(in srgb, ${C.high} 18%, transparent); color:${C.high}; }
        .chip.banned { background:color-mix(in srgb, ${C.high} 30%, transparent); }
        .chip.token_used { background:color-mix(in srgb, ${C.low} 16%, transparent); color:${C.low}; }
        .chip.new { background:color-mix(in srgb, ${C.medium} 18%, transparent); color:${C.medium}; }
        .finding { display:flex; gap:10px; padding:10px 0; border-top:1px solid var(--divider-color); }
        .sev { flex:none; height:fit-content; padding:2px 7px; border-radius:5px; font-size:11px; font-weight:700; text-transform:uppercase; color:#111; }
        .sev.high { background:${C.high}; color:#fff; }
        .sev.medium { background:${C.medium}; }
        .sev.low { background:${C.low}; color:#fff; }
        .ftitle { font-weight:500; margin-bottom:2px; }
        a.repairs { display:inline-flex; align-items:center; min-height:44px; color:var(--primary-color); font-weight:500; font-size:13px; }
        .dest { display:flex; flex-direction:column; gap:6px; margin-top:10px; }
        .dest-row { display:flex; justify-content:space-between; gap:12px; font-size:13px; }
        .dest-host { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
        .new-tag { color:${C.medium}; }
        .track { height:6px; border-radius:3px; background:var(--divider-color); }
        .fill { height:6px; border-radius:3px; }
        .foot { font-size:12px; color:var(--secondary-text-color); padding:10px 16px 12px; }
        .side .foot { padding:12px 0 0; }
        .empty { padding:20px; text-align:center; color:var(--secondary-text-color); }
        .segbar { padding:12px 16px 4px; }
        .segs { display:inline-flex; border:1px solid var(--divider-color); border-radius:18px; overflow:hidden; }
        .seg { min-height:36px; padding:0 14px; background:none; border:0; color:var(--secondary-text-color); font:inherit; font-size:13px; font-weight:500; cursor:pointer; }
        .seg.active { background:color-mix(in srgb, var(--primary-color) 16%, transparent); color:var(--primary-color); }
        .note { margin:8px 16px 4px; padding:8px 12px; border-radius:8px; font-size:12px; color:var(--secondary-text-color);
          background:color-mix(in srgb, ${C.low} 10%, transparent); }
        .dest .sub { margin-top:-2px; }
        .sr { position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0 0 0 0); }
      </style>
      ${this._header()}
      <div class="content">${body}</div>`;

    const menu = this.shadowRoot.querySelector("ha-menu-button");
    if (menu) {
      menu.hass = this._hass;
      menu.narrow = this._narrow;
    }
    this.shadowRoot.querySelector("button.run")?.addEventListener("click", () => this._runChecks());
    this.shadowRoot.querySelectorAll(".tabs button").forEach((b) =>
      b.addEventListener("click", () => {
        this._tab = b.dataset.tab;
        this._render();
      }));
    this.shadowRoot.querySelectorAll("button[data-netview]").forEach((b) =>
      b.addEventListener("click", () => {
        this._netView = b.dataset.netview;
        this._render();
      }));
    this.shadowRoot.querySelector("a.repairs")?.addEventListener("click", (ev) => {
      ev.preventDefault();
      this._navigate("/config/repairs");
    });
  }
}

customElements.define("security-dashboard-panel", SecurityDashboardPanel);

// Security Dashboard panel — plain web component, no build step required.
// HA sets `hass`, `narrow`, `route` and `panel` on the element.

const SEV_COLOR = {
  high: "var(--error-color, #db4437)",
  medium: "var(--warning-color, #ffa600)",
  low: "var(--info-color, #039be5)",
};

const esc = (v) =>
  String(v ?? "—").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const ago = (iso) => {
  if (!iso) return "never";
  const s = Math.round((Date.now() - new Date(iso)) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
};

class SecurityDashboardPanel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._data = null;
    this._tab = "access";
  }

  set hass(hass) {
    const first = !this._hass;
    this._hass = hass;
    if (first) this._subscribe();
  }

  set narrow(v) { this._narrow = v; this._render(); }

  async _subscribe() {
    this._render();
    try {
      this._unsub = await this._hass.connection.subscribeMessage(
        (msg) => { this._data = msg; this._render(); },
        { type: "security_dashboard/subscribe" },
      );
    } catch (err) {
      this._error = err.message || String(err);
      this._render();
    }
  }

  disconnectedCallback() {
    if (this._unsub) this._unsub();
    this._unsub = undefined;
    this._hass = undefined;
  }

  _scoreColor(score) {
    if (score >= 80) return "var(--success-color, #43a047)";
    if (score >= 50) return SEV_COLOR.medium;
    return SEV_COLOR.high;
  }

  _tiles(d) {
    const tokens = d.auth.tokens;
    const llat = tokens.filter((t) => t.type === "long_lived_access_token").length;
    const noMfa = d.auth.users.filter((u) => u.is_active && !u.mfa_enabled).length;
    const out = d.network ? d.network.connections.length : 0;
    return `
      <div class="tiles">
        <div class="tile score">
          <div class="ring" style="--c:${this._scoreColor(d.score)};--p:${d.score}">
            <span>${d.score}</span>
          </div>
          <div><div class="label">Security score</div><div class="sub">${d.findings.length} findings</div></div>
        </div>
        <div class="tile"><div class="num">${d.auth.failed_logins_24h}</div><div class="label">Failed logins · 24h</div></div>
        <div class="tile"><div class="num">${out}</div><div class="label">Outbound connections</div></div>
        <div class="tile"><div class="num">${llat}</div><div class="label">Long-lived tokens</div></div>
        <div class="tile"><div class="num">${noMfa}</div><div class="label">Users without MFA</div></div>
      </div>`;
  }

  _findings(d) {
    if (!d.findings.length) return `<div class="empty">No findings. Nice.</div>`;
    return d.findings
      .map((f) => `
        <div class="finding">
          <span class="sev" style="background:${SEV_COLOR[f.severity]}">${f.severity}</span>
          <div><div class="ftitle">${esc(f.title)}</div><div class="sub">${esc(f.detail)}</div></div>
        </div>`)
      .join("");
  }

  _accessTable(d) {
    const rows = d.auth.events
      .map((e) => `
        <tr class="${e.kind}">
          <td>${ago(e.timestamp)}</td>
          <td><span class="chip ${e.kind}">${e.kind.replace("_", " ")}</span></td>
          <td class="mono">${esc(e.ip)}</td>
          <td>${esc(e.user)}</td>
          <td class="detail">${esc(e.detail)}</td>
        </tr>`)
      .join("");
    return `<table><thead><tr><th>When</th><th>Event</th><th>IP</th><th>User</th><th>Detail</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="5" class="empty">No access events recorded yet.</td></tr>`}</tbody></table>`;
  }

  _networkTable(d) {
    if (!d.network) return `<div class="empty">Waiting for first scan…</div>`;
    const rows = d.network.connections
      .map((c) => `
        <tr>
          <td>${esc(c.hostname)}</td>
          <td class="mono">${esc(c.remote_ip)}:${esc(c.remote_port)}</td>
          <td>${esc(c.process)}</td>
          <td class="mono">${esc(c.local_port)}</td>
        </tr>`)
      .join("");
    return `<table><thead><tr><th>Destination</th><th>Remote</th><th>Process</th><th>Local port</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="4" class="empty">No external connections right now.</td></tr>`}</tbody></table>
      <div class="sub foot">Last scan ${ago(d.network.scanned_at)} · ${d.network.listening.length} listening sockets</div>`;
  }

  _tokensTable(d) {
    const rows = d.auth.tokens
      .map((t) => `
        <tr>
          <td>${esc(t.user)}</td>
          <td>${esc(t.client_name)}</td>
          <td>${t.type === "long_lived_access_token" ? "Long-lived" : "Session"}</td>
          <td>${ago(t.last_used_at)}</td>
          <td class="mono">${esc(t.last_used_ip)}</td>
          <td>${t.stale ? `<span class="chip failed_login">stale</span>` : ""}</td>
        </tr>`)
      .join("");
    return `<table><thead><tr><th>User</th><th>Client</th><th>Type</th><th>Last used</th><th>Last IP</th><th></th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }

  _render() {
    const d = this._data;
    let body;
    if (this._error) body = `<div class="empty">Couldn't load: ${esc(this._error)}</div>`;
    else if (!d) body = `<div class="empty">Loading…</div>`;
    else {
      const tabContent = { access: this._accessTable(d), network: this._networkTable(d), tokens: this._tokensTable(d) }[this._tab];
      body = `
        ${this._tiles(d)}
        <div class="grid">
          <ha-card class="card main">
            <div class="tabs">
              ${["access", "network", "tokens"].map((t) =>
                `<button data-tab="${t}" class="${t === this._tab ? "active" : ""}">${{ access: "Access log", network: "Connections", tokens: "Tokens" }[t]}</button>`).join("")}
            </div>
            <div class="scroll">${tabContent}</div>
          </ha-card>
          <ha-card class="card side"><h2>Findings</h2>${this._findings(d)}</ha-card>
        </div>`;
    }

    this.shadowRoot.innerHTML = `
      <style>
        :host { display:block; background:var(--primary-background-color); min-height:100vh; color:var(--primary-text-color); }
        .toolbar { height:56px; display:flex; align-items:center; gap:12px; padding:0 16px; background:var(--app-header-background-color); color:var(--app-header-text-color, white); font-size:20px; }
        .content { padding:16px; max-width:1400px; margin:0 auto; }
        .tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; margin-bottom:16px; }
        .tile { background:var(--card-background-color); border-radius:var(--ha-card-border-radius,12px); padding:16px; border:1px solid var(--divider-color); }
        .tile.score { display:flex; align-items:center; gap:14px; grid-column:span 2; }
        .ring { width:64px; height:64px; border-radius:50%; display:grid; place-items:center; background:conic-gradient(var(--c) calc(var(--p)*1%), var(--divider-color) 0); }
        .ring span { width:50px; height:50px; border-radius:50%; background:var(--card-background-color); display:grid; place-items:center; font-weight:600; font-size:18px; }
        .num { font-size:28px; font-weight:600; }
        .label { color:var(--secondary-text-color); font-size:13px; margin-top:4px; }
        .sub { color:var(--secondary-text-color); font-size:12px; }
        .grid { display:grid; grid-template-columns:minmax(0,1fr) 340px; gap:16px; }
        @media (max-width:900px) { .grid { grid-template-columns:1fr; } .tile.score { grid-column:auto; } }
        .card { padding:16px; display:block; }
        h2 { font-size:16px; margin:0 0 12px; }
        .tabs { display:flex; gap:4px; border-bottom:1px solid var(--divider-color); margin-bottom:8px; }
        .tabs button { background:none; border:0; padding:10px 14px; cursor:pointer; color:var(--secondary-text-color); font:inherit; border-bottom:2px solid transparent; }
        .tabs button.active { color:var(--primary-color); border-bottom-color:var(--primary-color); }
        .scroll { overflow-x:auto; }
        table { width:100%; border-collapse:collapse; font-size:14px; }
        th { text-align:left; color:var(--secondary-text-color); font-weight:500; padding:8px; border-bottom:1px solid var(--divider-color); }
        td { padding:8px; border-bottom:1px solid var(--divider-color); white-space:nowrap; }
        td.detail { white-space:normal; color:var(--secondary-text-color); }
        .mono { font-family:var(--code-font-family, monospace); font-size:13px; }
        .chip { padding:2px 8px; border-radius:10px; font-size:12px; background:var(--secondary-background-color); }
        .chip.failed_login, .chip.banned { background:color-mix(in srgb, ${SEV_COLOR.high} 18%, transparent); color:${SEV_COLOR.high}; }
        .finding { display:flex; gap:10px; padding:10px 0; border-bottom:1px solid var(--divider-color); }
        .finding:last-child { border:0; }
        .sev { color:white; font-size:11px; text-transform:uppercase; padding:2px 6px; border-radius:4px; height:fit-content; }
        .ftitle { font-weight:500; }
        .empty { padding:24px; text-align:center; color:var(--secondary-text-color); }
        .foot { margin-top:8px; }
      </style>
      <div class="toolbar">
        ${this._narrow ? `<ha-menu-button></ha-menu-button>` : ""}
        <span>Security</span>
      </div>
      <div class="content">${body}</div>`;

    const menu = this.shadowRoot.querySelector("ha-menu-button");
    if (menu) { menu.hass = this._hass; menu.narrow = this._narrow; }
    this.shadowRoot.querySelectorAll(".tabs button").forEach((b) =>
      b.addEventListener("click", () => { this._tab = b.dataset.tab; this._render(); }));
  }
}

customElements.define("security-dashboard-panel", SecurityDashboardPanel);

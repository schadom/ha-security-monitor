// Security Monitor panel — plain web component, no build step required.
// HA sets `hass`, `narrow`, `route` and `panel` on the element.

// ------------------------------------------------------------------ translations
// Panel texts per language. Keep this block strict JSON: tests check that every
// language has the same keys. Values are strings or {"one", "other"} for plurals;
// {name} is a placeholder. To add a language, add a block with all keys.
const TRANSLATIONS = /* translations:start */ {
  "en": {
    "status.disconnected": "Disconnected",
    "status.live": "Live · last scan {ago}",
    "status.connecting": "Connecting…",
    "run.idle": "Run checks",
    "run.busy": "Checking…",
    "summary.aria": "Summary",
    "score.label": "Security score",
    "score.sub": "{findings} · {high} high",
    "count.findings": {
      "one": "{count} finding",
      "other": "{count} findings"
    },
    "tile.failed.label": "Failed logins · 24 h",
    "tile.failed.sub": "{sources} · {banned} banned",
    "count.source_ips": {
      "one": "{count} source IP",
      "other": "{count} source IPs"
    },
    "tile.failed.none": "No failed attempts",
    "tile.outbound.label": "Outbound connections",
    "tile.outbound.sub": {
      "one": "{count} new destination in 24 h",
      "other": "{count} new destinations in 24 h"
    },
    "tile.outbound.none": "No new destinations in 24 h",
    "tile.tokens.label": "Long-lived tokens",
    "tile.tokens.sub": {
      "one": "{count} unused for 90+ days",
      "other": "{count} unused for 90+ days"
    },
    "tile.tokens.none": "None unused for 90+ days",
    "tile.mfa.label": "Users without MFA",
    "tile.mfa.sub": {
      "one": "of {count} active user",
      "other": "of {count} active users"
    },
    "chart.title": "Failed logins · last 24 h",
    "chart.none": "No failed logins in the last 24 h",
    "chart.peak": "Peak {hour} · {attempts}",
    "chart.top": "most from {ip} ({count})",
    "count.attempts": {
      "one": "{count} attempt",
      "other": "{count} attempts"
    },
    "count.failed_logins": {
      "one": "{count} failed login",
      "other": "{count} failed logins"
    },
    "chart.aria": "Failed logins per hour over the last 24 hours, peak {peak}",
    "chart.yesterday": "{hour} yesterday",
    "chart.now": "now",
    "col.when": "When",
    "col.event": "Event",
    "col.source_ip": "Source IP",
    "col.user": "User",
    "col.detail": "Detail",
    "col.destination": "Destination",
    "col.remote": "Remote",
    "col.integration": "Integration",
    "col.seen": "Seen",
    "col.activity": "Activity · 24 h",
    "col.first_seen": "First seen",
    "col.last_seen": "Last seen",
    "col.client": "Client",
    "col.type": "Type",
    "col.last_used": "Last used",
    "col.last_ip": "Last IP",
    "col.status": "Status",
    "pager.aria": "{label} pages",
    "pager.rows": "Rows per page",
    "pager.range": "{start}–{end} of {total}",
    "pager.page": "Page {page} of {pages}",
    "pager.first": "First page",
    "pager.prev": "Previous page",
    "pager.next": "Next page",
    "pager.last": "Last page",
    "tab.access": "Access log",
    "tab.network": "Connections",
    "tab.tokens": "Tokens",
    "label.open_connections": "Open connections",
    "label.destinations": "Destinations",
    "kind.failed_login": "Failed login",
    "kind.banned": "IP banned",
    "kind.token_used": "Token used",
    "access.empty": "No access events recorded yet.",
    "detail.invalid_login": "Invalid login",
    "detail.invalid_login_path": "Invalid login · {path}",
    "detail.banned": "Banned after too many failed logins",
    "client.long_lived": "{client} · long-lived token",
    "client.unnamed": "Unnamed",
    "client.system": "System",
    "client.unknown": "Unknown client",
    "client.app_ios": "Home Assistant iOS app",
    "client.app_android": "Home Assistant Android app",
    "client.app_companion": "Home Assistant companion app",
    "client.app_other": "Home Assistant app · {path}",
    "client.browser": "Browser session · {host}",
    "client.session": "{client} · session",
    "net.waiting": "Waiting for the first scan…",
    "net.view_now": "Open now",
    "net.view_24h": "Last 24 h",
    "net.view_aria": "Connections view",
    "net.learning": "Learning the baseline until {time}. Destinations seen before then aren't flagged as new.",
    "net.unattributed": "Unattributed",
    "net.unattributed_tip": "From an add-on or the host, or opened before monitoring started",
    "net.process_unattributed": "{process} · unattributed",
    "net.rdns": "Reverse DNS",
    "net.no_rdns": "(no reverse DNS)",
    "net.new": "New",
    "net.known": "Known",
    "net.empty_now": "No external connections right now.",
    "count.established": {
      "one": "{count} established connection",
      "other": "{count} established connections"
    },
    "count.listening": {
      "one": "{count} listening socket",
      "other": "{count} listening sockets"
    },
    "count.requests": {
      "one": "{count} request",
      "other": "{count} requests"
    },
    "count.connections": {
      "one": "{count} connection",
      "other": "{count} connections"
    },
    "net.empty_24h": "No outbound traffic recorded in the last 24 h.",
    "net.foot_24h": "Connections from Home Assistant Core are attributed for every library. Requests and exact hostnames come from Home Assistant's HTTP client.",
    "net.foot_no_aiohttp": "HTTP client tracing is unavailable on this version, so some hostnames come from DNS lookups or reverse DNS.",
    "net.monitoring_since": "Monitoring since {time}.",
    "tokens.long_lived": "Long-lived",
    "tokens.session": "Session",
    "tokens.stale": "Stale · revoke?",
    "tokens.empty": "No tokens.",
    "time.never": "never",
    "time.today": "Today {time}",
    "findings.title": "Findings",
    "findings.empty": "No findings. Nice.",
    "findings.repairs": "Open in Settings › Repairs",
    "sev.high": "High",
    "sev.medium": "Med",
    "sev.low": "Low",
    "finding.no_mfa.title": "{user} has no MFA",
    "finding.no_mfa.detail": "Enable TOTP under the user's profile → Security.",
    "finding.stale_tokens.title": {
      "one": "{count} unused long-lived token",
      "other": "{count} unused long-lived tokens"
    },
    "finding.stale_tokens.detail": "Long-lived tokens not used in 90 days. Revoke the ones you don't need.",
    "finding.ip_ban_disabled.title": "IP banning is off",
    "finding.ip_ban_disabled.detail": "Set http: ip_ban_enabled: true and login_attempts_threshold.",
    "finding.external_http.title": "External URL is plain HTTP",
    "finding.external_http.detail": "Remote access without TLS exposes credentials and tokens.",
    "finding.login_burst.title": {
      "one": "{count} failed login in 24 h",
      "other": "{count} failed logins in 24 h"
    },
    "finding.login_burst.detail": "Check the access log for repeated source IPs.",
    "finding.custom_components.title": {
      "one": "{count} custom integration installed",
      "other": "{count} custom integrations installed"
    },
    "finding.custom_components.detail": "Custom code runs with full access to Home Assistant. Keep it updated.",
    "dest.title": "Top destinations · 24 h",
    "dest.empty": "No outbound traffic recorded yet.",
    "dest.unattributed": "unattributed",
    "dest.requests": "requests",
    "dest.connections": "connections",
    "dest.new": "new",
    "lib.suffix": "{name} (library)",
    "load.loading": "Loading…",
    "load.error": "Couldn't load: {error}",
    "section.activity": "Activity"
  },
  "de": {
    "status.disconnected": "Getrennt",
    "status.live": "Live · letzter Scan {ago}",
    "status.connecting": "Verbinde…",
    "run.idle": "Prüfung starten",
    "run.busy": "Prüfe…",
    "summary.aria": "Übersicht",
    "score.label": "Sicherheitsbewertung",
    "score.sub": "{findings} · {high} hoch",
    "count.findings": {
      "one": "{count} Befund",
      "other": "{count} Befunde"
    },
    "tile.failed.label": "Fehlgeschlagene Anmeldungen · 24 h",
    "tile.failed.sub": "{sources} · {banned} gesperrt",
    "count.source_ips": {
      "one": "{count} Quell-IP",
      "other": "{count} Quell-IPs"
    },
    "tile.failed.none": "Keine fehlgeschlagenen Versuche",
    "tile.outbound.label": "Ausgehende Verbindungen",
    "tile.outbound.sub": {
      "one": "{count} neues Ziel in 24 h",
      "other": "{count} neue Ziele in 24 h"
    },
    "tile.outbound.none": "Keine neuen Ziele in 24 h",
    "tile.tokens.label": "Langlebige Zugriffstoken",
    "tile.tokens.sub": {
      "one": "{count} seit über 90 Tagen ungenutzt",
      "other": "{count} seit über 90 Tagen ungenutzt"
    },
    "tile.tokens.none": "Keines seit über 90 Tagen ungenutzt",
    "tile.mfa.label": "Benutzer ohne MFA",
    "tile.mfa.sub": {
      "one": "von {count} aktiven Benutzer",
      "other": "von {count} aktiven Benutzern"
    },
    "chart.title": "Fehlgeschlagene Anmeldungen · letzte 24 h",
    "chart.none": "Keine fehlgeschlagenen Anmeldungen in den letzten 24 h",
    "chart.peak": "Spitze {hour} · {attempts}",
    "chart.top": "die meisten von {ip} ({count})",
    "count.attempts": {
      "one": "{count} Versuch",
      "other": "{count} Versuche"
    },
    "count.failed_logins": {
      "one": "{count} fehlgeschlagene Anmeldung",
      "other": "{count} fehlgeschlagene Anmeldungen"
    },
    "chart.aria": "Fehlgeschlagene Anmeldungen pro Stunde in den letzten 24 Stunden, Spitze {peak}",
    "chart.yesterday": "gestern {hour}",
    "chart.now": "jetzt",
    "col.when": "Zeitpunkt",
    "col.event": "Ereignis",
    "col.source_ip": "Quell-IP",
    "col.user": "Benutzer",
    "col.detail": "Details",
    "col.destination": "Ziel",
    "col.remote": "Gegenstelle",
    "col.integration": "Integration",
    "col.seen": "Status",
    "col.activity": "Aktivität · 24 h",
    "col.first_seen": "Zuerst gesehen",
    "col.last_seen": "Zuletzt gesehen",
    "col.client": "Client",
    "col.type": "Typ",
    "col.last_used": "Zuletzt verwendet",
    "col.last_ip": "Letzte IP",
    "col.status": "Status",
    "pager.aria": "Seiten: {label}",
    "pager.rows": "Zeilen pro Seite",
    "pager.range": "{start}–{end} von {total}",
    "pager.page": "Seite {page} von {pages}",
    "pager.first": "Erste Seite",
    "pager.prev": "Vorherige Seite",
    "pager.next": "Nächste Seite",
    "pager.last": "Letzte Seite",
    "tab.access": "Zugriffsprotokoll",
    "tab.network": "Verbindungen",
    "tab.tokens": "Token",
    "label.open_connections": "Offene Verbindungen",
    "label.destinations": "Ziele",
    "kind.failed_login": "Fehlgeschlagene Anmeldung",
    "kind.banned": "IP gesperrt",
    "kind.token_used": "Token verwendet",
    "access.empty": "Noch keine Zugriffsereignisse aufgezeichnet.",
    "detail.invalid_login": "Ungültige Anmeldung",
    "detail.invalid_login_path": "Ungültige Anmeldung · {path}",
    "detail.banned": "Nach zu vielen fehlgeschlagenen Anmeldungen gesperrt",
    "client.long_lived": "{client} · langlebiges Zugriffstoken",
    "client.unnamed": "Ohne Namen",
    "client.system": "System",
    "client.unknown": "Unbekannter Client",
    "client.app_ios": "Home Assistant iOS-App",
    "client.app_android": "Home Assistant Android-App",
    "client.app_companion": "Home Assistant Companion-App",
    "client.app_other": "Home Assistant-App · {path}",
    "client.browser": "Browser-Sitzung · {host}",
    "client.session": "{client} · Sitzung",
    "net.waiting": "Warte auf den ersten Scan…",
    "net.view_now": "Jetzt offen",
    "net.view_24h": "Letzte 24 h",
    "net.view_aria": "Verbindungsansicht",
    "net.learning": "Die Ausgangslage wird bis {time} erfasst. Ziele, die bis dahin auftauchen, werden nicht als neu markiert.",
    "net.unattributed": "Nicht zugeordnet",
    "net.unattributed_tip": "Von einem Add-on oder dem Host, oder vor Beginn der Überwachung geöffnet",
    "net.process_unattributed": "{process} · nicht zugeordnet",
    "net.rdns": "Reverse-DNS",
    "net.no_rdns": "(kein Reverse-DNS)",
    "net.new": "Neu",
    "net.known": "Bekannt",
    "net.empty_now": "Derzeit keine externen Verbindungen.",
    "count.established": {
      "one": "{count} aufgebaute Verbindung",
      "other": "{count} aufgebaute Verbindungen"
    },
    "count.listening": {
      "one": "{count} lauschender Socket",
      "other": "{count} lauschende Sockets"
    },
    "count.requests": {
      "one": "{count} Anfrage",
      "other": "{count} Anfragen"
    },
    "count.connections": {
      "one": "{count} Verbindung",
      "other": "{count} Verbindungen"
    },
    "net.empty_24h": "Keine ausgehenden Verbindungen in den letzten 24 h aufgezeichnet.",
    "net.foot_24h": "Verbindungen aus Home Assistant Core werden für jede Bibliothek zugeordnet. Anfragen und exakte Hostnamen stammen aus dem HTTP-Client von Home Assistant.",
    "net.foot_no_aiohttp": "Die Nachverfolgung des HTTP-Clients ist in dieser Version nicht verfügbar, daher stammen manche Hostnamen aus DNS-Abfragen oder Reverse-DNS.",
    "net.monitoring_since": "Überwachung seit {time}.",
    "tokens.long_lived": "Langlebig",
    "tokens.session": "Sitzung",
    "tokens.stale": "Veraltet · widerrufen?",
    "tokens.empty": "Keine Token.",
    "time.never": "nie",
    "time.today": "Heute {time}",
    "findings.title": "Befunde",
    "findings.empty": "Keine Befunde. Sehr gut.",
    "findings.repairs": "In Einstellungen › Reparaturen öffnen",
    "sev.high": "Hoch",
    "sev.medium": "Mittel",
    "sev.low": "Niedrig",
    "finding.no_mfa.title": "{user} hat keine MFA",
    "finding.no_mfa.detail": "Aktiviere TOTP im Profil des Benutzers unter Sicherheit.",
    "finding.stale_tokens.title": {
      "one": "{count} ungenutztes langlebiges Zugriffstoken",
      "other": "{count} ungenutzte langlebige Zugriffstoken"
    },
    "finding.stale_tokens.detail": "Langlebige Zugriffstoken, die seit 90 Tagen nicht verwendet wurden. Widerrufe die, die du nicht brauchst.",
    "finding.ip_ban_disabled.title": "IP-Sperre ist aus",
    "finding.ip_ban_disabled.detail": "Setze im Abschnitt http: ip_ban_enabled: true und login_attempts_threshold.",
    "finding.external_http.title": "Externe URL verwendet einfaches HTTP",
    "finding.external_http.detail": "Fernzugriff ohne TLS legt Zugangsdaten und Token offen.",
    "finding.login_burst.title": {
      "one": "{count} fehlgeschlagene Anmeldung in 24 h",
      "other": "{count} fehlgeschlagene Anmeldungen in 24 h"
    },
    "finding.login_burst.detail": "Prüfe das Zugriffsprotokoll auf wiederholte Quell-IPs.",
    "finding.custom_components.title": {
      "one": "{count} benutzerdefinierte Integration installiert",
      "other": "{count} benutzerdefinierte Integrationen installiert"
    },
    "finding.custom_components.detail": "Benutzerdefinierter Code läuft mit vollem Zugriff auf Home Assistant. Halte ihn aktuell.",
    "dest.title": "Häufigste Ziele · 24 h",
    "dest.empty": "Noch keine ausgehenden Verbindungen aufgezeichnet.",
    "dest.unattributed": "nicht zugeordnet",
    "dest.requests": "Anfragen",
    "dest.connections": "Verbindungen",
    "dest.new": "neu",
    "lib.suffix": "{name} (Bibliothek)",
    "load.loading": "Lädt…",
    "load.error": "Konnte nicht geladen werden: {error}",
    "section.activity": "Aktivität"
  }
} /* translations:end */;

let LANG = "en";

// Pick the panel language from HA's profile setting ("de-CH" → "de"), else English
const pickLanguage = (hass) => {
  const wanted = (hass && ((hass.locale && hass.locale.language) || hass.language)) || "en";
  if (TRANSLATIONS[wanted]) return wanted;
  const base = wanted.split("-")[0];
  return TRANSLATIONS[base] ? base : "en";
};

// Translate `key`, filling {placeholders}; a `count` variable picks the plural form
const t = (key, vars = {}) => {
  let text = (TRANSLATIONS[LANG] && TRANSLATIONS[LANG][key]) ?? TRANSLATIONS.en[key] ?? key;
  if (typeof text === "object") {
    let form = "other";
    try { form = new Intl.PluralRules(LANG).select(vars.count ?? 0); } catch (_) { /* default */ }
    text = text[form] ?? text.other;
  }
  return text.replace(/\{(\w+)\}/g, (m, name) => (name in vars ? String(vars[name]) : m));
};

const C = {
  high: "var(--error-color, #db4437)",
  medium: "var(--warning-color, #ffa600)",
  low: "var(--info-color, #039be5)",
  ok: "var(--success-color, #43a047)",
};

const esc = (v) =>
  String(v ?? "—").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// "5 minutes ago" / "vor 5 Minuten", in the panel language
const ago = (iso) => {
  if (!iso) return t("time.never");
  const s = Math.max(0, Math.round((Date.now() - new Date(iso)) / 1000));
  const [value, unit] = s < 60 ? [s, "second"]
    : s < 3600 ? [Math.round(s / 60), "minute"]
    : s < 86400 ? [Math.round(s / 3600), "hour"]
    : [Math.round(s / 86400), "day"];
  try {
    return new Intl.RelativeTimeFormat(LANG, { numeric: "always" }).format(-value, unit);
  } catch (_) {
    return `${value} ${unit}${value === 1 ? "" : "s"} ago`;
  }
};

const hourLabel = (date) => `${String(date.getHours()).padStart(2, "0")}:00`;

// Official apps identify themselves with a home-assistant.io URL as client ID
const APP_CLIENTS = {
  "/ios": "client.app_ios",
  "/android": "client.app_android",
  "/companion-app": "client.app_companion",
};

// Human label for a token's client.
//   http://homeassistant.lan:8123/ + session → "Browser session · homeassistant.lan"
//   https://home-assistant.io/iOS            → "Home Assistant iOS app"
//   Node-RED + long-lived                    → "Node-RED · long-lived token"
const prettyClient = (client, type) => {
  if (type === "long_lived_access_token") return t("client.long_lived", { client: client || t("client.unnamed") });
  if (!client) return type === "system" ? t("client.system") : t("client.unknown");
  try {
    const u = new URL(client);
    if (u.protocol.startsWith("http")) {
      if (/(^|\.)home-assistant\.io$/.test(u.hostname)) {
        const app = APP_CLIENTS[u.pathname.toLowerCase().replace(/\/$/, "")];
        return app ? t(app) : t("client.app_other", { path: u.pathname });
      }
      return t("client.browser", { host: u.hostname });
    }
  } catch (_) { /* not a URL */ }
  return type === "normal" ? t("client.session", { client }) : client;
};

// Short, readable detail line per event; the raw text goes into the tooltip
const prettyDetail = (e) => {
  if (e.kind === "failed_login") {
    const url = /Requested URL: '([^']*)'/.exec(e.detail);
    let path = url ? url[1].split("?")[0] : null;
    if (path) path = path.replace(/^(\/auth\/login_flow)\/[0-9a-f]+$/i, "$1");
    return path ? t("detail.invalid_login_path", { path }) : t("detail.invalid_login");
  }
  if (e.kind === "banned") return t("detail.banned");
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
  const time = d.toLocaleTimeString(LANG, { hour: "2-digit", minute: "2-digit" });
  return sameDay ? t("time.today", { time }) : `${d.toLocaleDateString(LANG, { day: "numeric", month: "short" })} ${time}`;
};

const PAGE_SIZES = [10, 25, 50, 100];
const DEFAULT_PAGE_SIZE = 10;
const PAGE_SIZE_KEY = "security_monitor.page_size";
const chevron = (d) => `<svg aria-hidden="true" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="${d}"></path></svg>`;
const ICON_FIRST = chevron("M17 18l-6-6 6-6M7 6v12");
const ICON_PREV = chevron("M15 18l-6-6 6-6");
const ICON_NEXT = chevron("M9 18l6-6-6-6");
const ICON_LAST = chevron("M7 18l6-6-6-6M17 6v12");

// Default sort per table. "now" keeps the order the scan returns; tokens show
// the most recently used first, never-used ones last.
const SORT_DEFAULTS = {
  access: { key: "when", dir: "desc" },
  now: { key: null, dir: "asc" },
  "24h": { key: "activity", dir: "desc" },
  tokens: { key: "last_used", dir: "desc" },
};
const sortIcon = (d) => `<svg class="sort-icon" aria-hidden="true" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="${d}"></path></svg>`;
const ICON_SORT_ASC = sortIcon("M12 19V5M6 11l6-6 6 6");
const ICON_SORT_DESC = sortIcon("M12 5v14M6 13l6 6 6-6");
const ICON_SORT_NONE = sortIcon("M8 9l4-4 4 4M8 15l4 4 4-4");

// Sort key for an IP: IPv4 numerically, IPv6 after IPv4
const ipSortKey = (ip) => {
  if (!ip) return null;
  const v4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  return v4 ? v4.slice(1).map((n) => n.padStart(3, "0")).join(".") : `~${ip.toLowerCase()}`;
};
const timeSortKey = (iso) => (iso ? new Date(iso).getTime() : null);

const kindLabel = (kind) => (TRANSLATIONS.en[`kind.${kind}`] ? t(`kind.${kind}`) : kind);

class SecurityMonitorPanel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._data = null;
    this._tab = "access";
    this._netView = "now";
    this._pages = { access: 0, now: 0, "24h": 0, tokens: 0 };
    this._sort = JSON.parse(JSON.stringify(SORT_DEFAULTS));
    this._pageSize = DEFAULT_PAGE_SIZE;
    try {
      const saved = parseInt(localStorage.getItem(PAGE_SIZE_KEY), 10);
      if (PAGE_SIZES.includes(saved)) this._pageSize = saved;
    } catch (_) { /* storage unavailable: use the default */ }
    this._running = false;
  }

  // HA calls this on every state change, so it must stay cheap: no re-render here
  set hass(hass) {
    const first = !this._hass;
    this._hass = hass;
    const lang = pickLanguage(hass);
    if (lang !== LANG) {
      LANG = lang;
      if (!first) this._render();  // language changed in the profile
    }
    if (first) {
      // Integration titles ("hacs" → "HACS") for the Integration columns
      try { hass.loadBackendTranslation?.("title"); } catch (_) { /* optional */ }
      this._subscribe();
    }
  }

  _integrationName(domain) {
    if (!domain) return null;
    if (domain.startsWith("lib:")) return t("lib.suffix", { name: domain.slice(4) });
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
        { type: "security_monitor/subscribe" },
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
      this._data = await this._hass.callWS({ type: "security_monitor/run_checks" });
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
      ? `<span class="status err">${t("status.disconnected")}</span>`
      : d && d.network
        ? `<span class="status"><span class="live-dot"></span>${t("status.live", { ago: `<span data-ago="${esc(d.network.scanned_at)}">${ago(d.network.scanned_at)}</span>` })}</span>`
        : `<span class="status">${t("status.connecting")}</span>`;
    return `
      <div class="toolbar">
        ${this._narrow ? `<ha-menu-button></ha-menu-button>` : ""}
        <svg class="shield" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 5 6v5c0 4.5 3 8.3 7 10 4-1.7 7-5.5 7-10V6l-7-3Z"></path><rect x="9.5" y="10.5" width="5" height="4.5" rx="1"></rect><path d="M10.5 10.5V9a1.5 1.5 0 0 1 3 0v1.5"></path></svg>
        <h1>Security Monitor</h1>
        <div class="toolbar-right">
          ${status}
          <button class="run" type="button" ${this._running || !d ? "disabled" : ""}>${this._running ? t("run.busy") : t("run.idle")}</button>
        </div>
      </div>`;
  }

  _tiles(d) {
    const a = d.auth;
    const net = d.network;
    const llat = a.tokens.filter((tok) => tok.type === "long_lived_access_token");
    const stale = llat.filter((tok) => tok.stale).length;
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
      <section class="tiles" aria-label="${t("summary.aria")}">
        <div class="tile score">
          <div class="ring" style="--c:${scoreColor};--p:${d.score}"><span>${d.score}</span></div>
          <div>
            <div class="label strong">${t("score.label")}</div>
            <div class="sub">${t("score.sub", { findings: t("count.findings", { count: d.findings.length }), high })}</div>
          </div>
        </div>
        ${tile(a.failed_logins_24h, t("tile.failed.label"),
          a.failed_logins_24h
            ? t("tile.failed.sub", { sources: t("count.source_ips", { count: a.failed_sources_24h }), banned: a.banned_24h })
            : t("tile.failed.none"),
          a.failed_logins_24h ? C.high : null)}
        ${tile(net ? net.connections.length : "–", t("tile.outbound.label"),
          newDest ? t("tile.outbound.sub", { count: newDest }) : t("tile.outbound.none"))}
        ${tile(llat.length, t("tile.tokens.label"),
          stale ? t("tile.tokens.sub", { count: stale }) : t("tile.tokens.none"),
          stale ? C.medium : null)}
        ${tile(noMfa, t("tile.mfa.label"), t("tile.mfa.sub", { count: active.length }),
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

    let summary = t("chart.none");
    if (counts[peakIdx] > 0) {
      summary = t("chart.peak", { hour: hourLabel(at(peakIdx)), attempts: t("count.attempts", { count: counts[peakIdx] }) });
      if (a.top_source_24h) summary += ` · ${t("chart.top", { ip: esc(a.top_source_24h.ip), count: a.top_source_24h.count })}`;
    }

    const bars = counts.map((v, i) => {
      const h = v ? Math.max(6, Math.round((v / max) * 64)) : 3;
      const bg = v === 0 ? "var(--divider-color)" : v >= max * 0.6 ? C.high : `color-mix(in srgb, ${C.high} 65%, transparent)`;
      return `<div class="bar" style="height:${h}px;background:${bg}" title="${hourLabel(at(i))} · ${t("count.failed_logins", { count: v })}"></div>`;
    }).join("");

    const first = at(0);
    const firstLabel = first.toDateString() === new Date().toDateString() ? hourLabel(first) : t("chart.yesterday", { hour: hourLabel(first) });

    return `
      <div class="chart">
        <div class="chart-head">
          <h2>${t("chart.title")}</h2>
          <span class="sub">${summary}</span>
        </div>
        <div class="bars" role="img" aria-label="${t("chart.aria", { peak: counts[peakIdx] || 0 })}">${bars}</div>
        <div class="axis"><span>${firstLabel}</span><span>${hourLabel(at(12))}</span><span>${t("chart.now")}</span></div>
      </div>`;
  }

  // Columns per table: key, label, type (time/number sort descending first,
  // text/ip ascending) and how to get the sort value from a row.
  _columns(table) {
    const cols = {
      access: [
        { key: "when", label: t("col.when"), type: "time", get: (e) => timeSortKey(e.timestamp) },
        { key: "event", label: t("col.event"), type: "text", get: (e) => kindLabel(e.kind) },
        { key: "ip", label: t("col.source_ip"), type: "ip", get: (e) => ipSortKey(e.ip) },
        { key: "user", label: t("col.user"), type: "text", get: (e) => e.user },
        { key: "detail", label: t("col.detail"), type: "text", get: (e) => prettyDetail(e) },
      ],
      now: [
        { key: "destination", label: t("col.destination"), type: "text", get: (c) => c.traced_host || c.hostname },
        { key: "remote", label: t("col.remote"), type: "ip", get: (c) => ipSortKey(c.remote_ip) },
        { key: "integration", label: t("col.integration"), type: "text", get: (c) => (c.integration ? this._integrationName(c.integration) : null) },
        { key: "seen", label: t("col.seen"), type: "number", get: (c) => (this._newHosts.has(c.traced_host || c.hostname || c.remote_ip) ? 1 : 0) },
      ],
      "24h": [
        { key: "destination", label: t("col.destination"), type: "text", get: (x) => x.host },
        { key: "integration", label: t("col.integration"), type: "text", get: (x) => (x.integrations.length ? this._integrationName(x.integrations[0]) : null) },
        { key: "activity", label: t("col.activity"), type: "number", get: (x) => x.activity },
        { key: "first_seen", label: t("col.first_seen"), type: "time", get: (x) => timeSortKey(x.first_seen) },
        { key: "last_seen", label: t("col.last_seen"), type: "time", get: (x) => timeSortKey(x.last_seen) },
      ],
      tokens: [
        { key: "user", label: t("col.user"), type: "text", get: (tok) => tok.user },
        { key: "client", label: t("col.client"), type: "text", get: (tok) => prettyClient(tok.client_name, tok.type === "long_lived_access_token" ? null : tok.type) },
        { key: "type", label: t("col.type"), type: "text", get: (tok) => (tok.type === "long_lived_access_token" ? t("tokens.long_lived") : t("tokens.session")) },
        // Never used counts as the oldest, not as empty
        { key: "last_used", label: t("col.last_used"), type: "time", get: (tok) => timeSortKey(tok.last_used_at) ?? 0 },
        { key: "last_ip", label: t("col.last_ip"), type: "ip", get: (tok) => ipSortKey(tok.last_used_ip) },
      ],
    };
    return cols[table];
  }

  // Stable sort; empty values always last, whatever the direction
  _sorted(table, items) {
    const { key, dir } = this._sort[table];
    const col = key && this._columns(table).find((c) => c.key === key);
    if (!col) return items;
    const sign = dir === "asc" ? 1 : -1;
    return items
      .map((item, index) => ({ item, index, value: col.get(item) }))
      .sort((a, b) => {
        const av = a.value, bv = b.value;
        const aEmpty = av === null || av === undefined || av === "";
        const bEmpty = bv === null || bv === undefined || bv === "";
        if (aEmpty || bEmpty) return aEmpty === bEmpty ? a.index - b.index : aEmpty ? 1 : -1;
        const cmp = typeof av === "number" && typeof bv === "number"
          ? av - bv
          : String(av).localeCompare(String(bv), undefined, { numeric: true, sensitivity: "base" });
        return cmp ? cmp * sign : a.index - b.index;
      })
      .map((x) => x.item);
  }

  _thead(table, extra = "") {
    const { key, dir } = this._sort[table];
    const ths = this._columns(table).map((c) => {
      const active = c.key === key;
      const ariaSort = active ? (dir === "asc" ? "ascending" : "descending") : "none";
      const icon = active ? (dir === "asc" ? ICON_SORT_ASC : ICON_SORT_DESC) : ICON_SORT_NONE;
      return `<th aria-sort="${ariaSort}"><button type="button" class="sort ${active ? "active" : ""}" data-sort-table="${table}" data-sort-key="${c.key}">${c.label}${icon}</button></th>`;
    }).join("");
    return `<thead><tr>${ths}${extra}</tr></thead>`;
  }

  // Slice `items` for the table `key` and build its pager. The page is clamped,
  // so a list that shrinks (live updates) never leaves you on an empty page.
  _paginate(key, items, label) {
    const size = this._pageSize;
    const total = items.length;
    const pages = Math.max(1, Math.ceil(total / size));
    const page = Math.min(this._pages[key] || 0, pages - 1);
    this._pages[key] = page;
    const start = page * size;
    const slice = items.slice(start, start + size);
    if (total <= PAGE_SIZES[0]) return { slice, pager: "" };

    const btn = (to, icon, text, disabled) =>
      `<button type="button" class="pg" data-pager="${key}" data-to="${to}" aria-label="${text}" title="${text}" ${disabled ? "disabled" : ""}>${icon}</button>`;
    const sizes = PAGE_SIZES.map((n) => `<option value="${n}" ${n === size ? "selected" : ""}>${n}</option>`).join("");
    return {
      slice,
      pager: `
        <nav class="pager" aria-label="${t("pager.aria", { label })}">
          <label class="pg-size">${t("pager.rows")}
            <select data-pagesize>${sizes}</select>
          </label>
          <span class="pg-range">${t("pager.range", { start: start + 1, end: Math.min(start + size, total), total })}</span>
          <span class="pg-buttons">
            ${btn(0, ICON_FIRST, t("pager.first"), page === 0)}
            ${btn(page - 1, ICON_PREV, t("pager.prev"), page === 0)}
            <span class="pg-page">${t("pager.page", { page: page + 1, pages })}</span>
            ${btn(page + 1, ICON_NEXT, t("pager.next"), page >= pages - 1)}
            ${btn(pages - 1, ICON_LAST, t("pager.last"), page >= pages - 1)}
          </span>
        </nav>`,
    };
  }

  _accessTable(d) {
    const { slice, pager } = this._paginate("access", this._sorted("access", d.auth.events), t("tab.access"));
    const rows = slice.map((e) => `
      <tr>
        <td class="muted"><span data-ago="${esc(e.timestamp)}">${ago(e.timestamp)}</span></td>
        <td><span class="chip ${esc(e.kind)}">${esc(kindLabel(e.kind))}</span></td>
        <td class="mono">${esc(e.ip)}</td>
        <td>${esc(e.user)}</td>
        <td class="detail" title="${esc(e.detail)}">${esc(prettyDetail(e))}</td>
      </tr>`).join("");
    return `<table>
      ${this._thead("access")}
      <tbody>${rows || `<tr><td colspan="5" class="empty">${t("access.empty")}</td></tr>`}</tbody>
    </table>${pager}`;
  }

  _networkTable(d) {
    const net = d.network;
    if (!net) return `<div class="empty">${t("net.waiting")}</div>`;
    const views = [["now", t("net.view_now")], ["24h", t("net.view_24h")]]
      .map(([id, label]) => `<button type="button" data-netview="${id}" class="seg ${id === this._netView ? "active" : ""}" aria-pressed="${id === this._netView}">${label}</button>`)
      .join("");
    const learning = net.learning_until
      ? `<div class="note">${t("net.learning", { time: fmtDateTime(net.learning_until) })}</div>`
      : "";
    const body = this._netView === "24h" ? this._network24h(net) : this._networkNow(net);
    return `<div class="segbar"><div class="segs" role="group" aria-label="${t("net.view_aria")}">${views}</div></div>${learning}${body}`;
  }

  _integrationCell(name, fallback) {
    return name
      ? esc(this._integrationName(name))
      : `<span class="muted" title="${t("net.unattributed_tip")}">${esc(fallback || t("net.unattributed"))}</span>`;
  }

  _networkNow(net) {
    const isNew = new Set(net.destinations_24h.filter((x) => x.new).map((x) => x.host));
    this._newHosts = isNew;
    const { slice, pager } = this._paginate("now", this._sorted("now", net.connections), t("label.open_connections"));
    const rows = slice.map((c) => {
      const host = c.traced_host || c.hostname || c.remote_ip;
      const rdns = c.traced_host && c.hostname && c.hostname !== c.traced_host
        ? `<div class="sub" title="${t("net.rdns")}">${esc(c.hostname)}</div>` : "";
      return `
      <tr>
        <td>${c.traced_host || c.hostname ? esc(host) : `<span class="muted">${t("net.no_rdns")}</span>`}${rdns}</td>
        <td class="mono">${esc(c.remote_ip)}:${esc(c.remote_port)}</td>
        <td>${this._integrationCell(c.integration, c.process ? t("net.process_unattributed", { process: c.process }) : t("net.unattributed"))}</td>
        <td>${isNew.has(host) ? `<span class="chip new">${t("net.new")}</span>` : `<span class="chip">${t("net.known")}</span>`}</td>
      </tr>`;
    }).join("");
    return `<table>
      ${this._thead("now")}
      <tbody>${rows || `<tr><td colspan="4" class="empty">${t("net.empty_now")}</td></tr>`}</tbody>
    </table>${pager}
    <div class="foot">${t("count.established", { count: net.connections.length })} · ${t("count.listening", { count: net.listening.length })}</div>`;
  }

  _network24h(net) {
    const { slice, pager } = this._paginate("24h", this._sorted("24h", net.destinations_24h), t("label.destinations"));
    const rows = slice.map((x) => {
      const activity = [
        x.requests ? t("count.requests", { count: x.requests }) : null,
        x.connections ? t("count.connections", { count: x.connections }) : null,
      ].filter(Boolean).join(" · ");
      const integrations = x.integrations.length
        ? x.integrations.map((i) => esc(this._integrationName(i))).join(", ")
        : this._integrationCell(null);
      return `
      <tr>
        <td>${esc(x.host)}${x.new ? ` <span class="chip new">${t("net.new")}</span>` : ""}</td>
        <td>${integrations}</td>
        <td class="muted">${activity}</td>
        <td class="muted">${fmtDateTime(x.first_seen)}</td>
        <td class="muted">${x.last_seen ? `<span data-ago="${esc(x.last_seen)}">${ago(x.last_seen)}</span>` : "—"}</td>
      </tr>`;
    }).join("");
    return `<table>
      ${this._thead("24h")}
      <tbody>${rows || `<tr><td colspan="5" class="empty">${t("net.empty_24h")}</td></tr>`}</tbody>
    </table>${pager}
    <div class="foot">${t("net.foot_24h")}${net.tracing && net.tracing.aiohttp === false ? ` ${t("net.foot_no_aiohttp")}` : ""} ${t("net.monitoring_since", { time: fmtDateTime(net.monitoring_since) })}</div>`;
  }

  _tokensTable(d) {
    const { slice, pager } = this._paginate("tokens", this._sorted("tokens", d.auth.tokens), t("tab.tokens"));
    const rows = slice.map((tok) => `
      <tr>
        <td>${esc(tok.user)}</td>
        <td>${esc(prettyClient(tok.client_name, tok.type === "long_lived_access_token" ? null : tok.type))}</td>
        <td class="muted">${tok.type === "long_lived_access_token" ? t("tokens.long_lived") : t("tokens.session")}</td>
        <td class="muted">${tok.last_used_at ? `<span data-ago="${esc(tok.last_used_at)}">${ago(tok.last_used_at)}</span>` : t("time.never")}</td>
        <td class="mono">${esc(tok.last_used_ip)}</td>
        <td>${tok.stale ? `<span class="chip new">${t("tokens.stale")}</span>` : ""}</td>
      </tr>`).join("");
    return `<table>
      ${this._thead("tokens", `<th><span class="sr">${t("col.status")}</span></th>`)}
      <tbody>${rows || `<tr><td colspan="6" class="empty">${t("tokens.empty")}</td></tr>`}</tbody>
    </table>${pager}`;
  }

  // Translated title/detail when the panel knows the finding, else the backend's English text
  _findingText(f, part) {
    const key = `finding.${f.key}.${part}`;
    if (!f.key || !TRANSLATIONS.en[key]) return f[part];
    const params = {};
    for (const [name, value] of Object.entries(f.params || {})) params[name] = name === "count" ? value : esc(value);
    return t(key, params);
  }

  _findings(d) {
    const list = d.findings.length
      ? d.findings.map((f) => `
          <div class="finding">
            <span class="sev ${esc(f.severity)}">${TRANSLATIONS.en[`sev.${f.severity}`] ? t(`sev.${f.severity}`) : esc(f.severity)}</span>
            <div><div class="ftitle">${f.key ? this._findingText(f, "title") : esc(f.title)}</div><div class="sub">${f.key ? this._findingText(f, "detail") : esc(f.detail)}</div></div>
          </div>`).join("")
      : `<div class="empty">${t("findings.empty")}</div>`;
    return `
      <section class="card" aria-label="${t("findings.title")}">
        <h2>${t("findings.title")}</h2>
        ${list}
        <a class="repairs" href="/config/repairs">${t("findings.repairs")}</a>
      </section>`;
  }

  _destinations(d) {
    const dest = d.network ? d.network.destinations_24h.slice(0, 6) : [];
    const max = Math.max(1, ...dest.map((x) => x.activity));
    const rows = dest.map((x) => {
      const who = x.integrations.length ? this._integrationName(x.integrations[0]) : t("dest.unattributed");
      const unit = x.requests ? t("dest.requests") : t("dest.connections");
      return `
      <div class="dest">
        <div class="dest-row">
          <span class="dest-host" title="${esc(x.host)}">${esc(x.host)}${x.new ? ` <span class="new-tag">· ${t("dest.new")}</span>` : ""}</span>
          <span class="muted" title="${t("count.requests", { count: x.requests })} · ${t("count.connections", { count: x.connections })}">${x.activity}</span>
        </div>
        <div class="track"><div class="fill" style="width:${Math.max(2, (x.activity / max) * 100)}%;background:${x.new ? C.medium : C.low}"></div></div>
        <div class="sub">${esc(who)} · ${unit}</div>
      </div>`;
    }).join("");
    return `
      <section class="card" aria-label="${t("dest.title")}">
        <h2>${t("dest.title")}</h2>
        ${rows || `<div class="empty">${t("dest.empty")}</div>`}
      </section>`;
  }

  // ------------------------------------------------------------------ render

  _render() {
    const d = this._data;
    let body;
    if (this._error && !d) body = `<div class="empty">${t("load.error", { error: esc(this._error) })}</div>`;
    else if (!d) body = `<div class="empty">${t("load.loading")}</div>`;
    else {
      const content = { access: this._accessTable(d), network: this._networkTable(d), tokens: this._tokensTable(d) }[this._tab];
      const tabs = [["access", t("tab.access")], ["network", t("tab.network")], ["tokens", t("tab.tokens")]]
        .map(([id, label]) => `<button type="button" role="tab" aria-selected="${id === this._tab}" data-tab="${id}" class="${id === this._tab ? "active" : ""}">${label}</button>`)
        .join("");
      body = `
        ${this._tiles(d)}
        <div class="grid">
          <section class="card main" aria-label="${t("section.activity")}">
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

    this.setAttribute("lang", LANG);
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
        .pager { display:flex; flex-wrap:wrap; align-items:center; justify-content:flex-end; gap:8px 20px;
          padding:8px 16px; border-top:1px solid var(--divider-color); font-size:13px; color:var(--secondary-text-color); }
        .pg-size { display:inline-flex; align-items:center; gap:8px; }
        .pg-size select { min-height:32px; padding:0 6px; border-radius:6px; border:1px solid var(--divider-color);
          background:var(--card-background-color); color:var(--primary-text-color); font:inherit; }
        .pg-buttons { display:inline-flex; align-items:center; gap:2px; }
        .pg-page { padding:0 8px; white-space:nowrap; }
        button.pg { width:36px; height:36px; display:inline-grid; place-items:center; border:0; border-radius:50%;
          background:none; color:var(--primary-text-color); cursor:pointer; }
        button.pg:hover:not([disabled]) { background:var(--secondary-background-color); }
        button.pg[disabled] { color:var(--disabled-text-color, var(--divider-color)); cursor:default; }
        button.sort { display:inline-flex; align-items:center; gap:4px; padding:0; margin:0; border:0; background:none;
          color:inherit; font:inherit; text-transform:inherit; letter-spacing:inherit; cursor:pointer; white-space:nowrap; }
        button.sort .sort-icon { opacity:.35; transition:opacity .15s; }
        button.sort:hover, button.sort.active { color:var(--primary-text-color); }
        button.sort:hover .sort-icon { opacity:.8; }
        button.sort.active .sort-icon { opacity:1; color:var(--primary-color); }
        button.sort:focus-visible { outline:2px solid var(--primary-color); outline-offset:2px; border-radius:3px; }
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
    this.shadowRoot.querySelectorAll("button[data-sort-table]").forEach((b) =>
      b.addEventListener("click", () => {
        const table = b.dataset.sortTable;
        const key = b.dataset.sortKey;
        const current = this._sort[table];
        if (current.key === key) {
          current.dir = current.dir === "asc" ? "desc" : "asc";
        } else {
          const col = this._columns(table).find((c) => c.key === key);
          this._sort[table] = { key, dir: col.type === "time" || col.type === "number" ? "desc" : "asc" };
        }
        this._pages[table] = 0;
        this._render();
      }));
    this.shadowRoot.querySelectorAll("button[data-pager]").forEach((b) =>
      b.addEventListener("click", () => {
        this._pages[b.dataset.pager] = Math.max(0, parseInt(b.dataset.to, 10) || 0);
        this._render();
      }));
    this.shadowRoot.querySelectorAll("select[data-pagesize]").forEach((sel) =>
      sel.addEventListener("change", () => {
        this._pageSize = parseInt(sel.value, 10) || DEFAULT_PAGE_SIZE;
        try { localStorage.setItem(PAGE_SIZE_KEY, String(this._pageSize)); } catch (_) { /* not persisted */ }
        Object.keys(this._pages).forEach((k) => { this._pages[k] = 0; });
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

customElements.define("security-monitor-panel", SecurityMonitorPanel);

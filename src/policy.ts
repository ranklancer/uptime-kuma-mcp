/**
 * Request-forgery policy for monitor payloads (review finding F1).
 *
 * A Kuma HTTP monitor makes a real request from the Kuma host on every interval. With a free
 * method, body and target, an MCP client could make Kuma send POSTs to internal services
 * (the MCP gateway itself, cloud metadata, localhost admin ports). Two controls:
 *
 *  1. Methods are limited to GET/HEAD and request bodies are refused unless the OPERATOR sets
 *     KUMA_MCP_ALLOW_WRITE_METHODS=1 in the MCP server environment.
 *  2. A target denylist is applied to `url` and `hostname` (and `port` for host:port entries).
 *     Built-ins: loopback, 0.0.0.0, link-local 169.254.0.0/16 (cloud metadata), host.docker.internal
 *     and any host containing "bifrost" or "mcp". KUMA_MCP_DENY_HOSTS (comma-separated) ADDS entries:
 *     exact host, `*` glob (`*.corp.example`), IPv4 CIDR (`10.0.0.0/8`), or `host:port`
 *     (`gateway.internal:8080`). Operators should list the real gateway host:port here.
 *
 * Limits: this checks the literal target. A public DNS name that resolves to an internal address
 * (DNS rebinding / attacker-controlled DNS) is not detected; denylist the resolved names you care about.
 */

export const SAFE_METHODS = ['GET', 'HEAD'] as const;
export const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const;

export function allowWriteMethods(): boolean {
  return process.env.KUMA_MCP_ALLOW_WRITE_METHODS === '1';
}

const BUILTIN_DENY = [
  'localhost', '*.localhost', '127.0.0.0/8', '0.0.0.0/8', '::1', '::', '169.254.0.0/16',
  'fe80::/10', 'fc00::/7', '::/96', '64:ff9b::/96', // link-local, ULA, IPv4-compatible (::127.0.0.1), NAT64
  'host.docker.internal', 'metadata.google.internal', '*bifrost*', '*mcp*',
];

/** Entry grammar: host/glob[:port], IPv4 or IPv6 CIDR, bare IPv6, or [IPv6][:port]. */
function validEntry(e: string): boolean {
  const c4 = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(e);
  if (c4) return ipv4ToInt(c4[1]) !== null && Number(c4[2]) <= 32;
  const c6 = /^([0-9a-f:.]*:[0-9a-f:.]*)\/(\d{1,3})$/i.exec(e);
  if (c6) return ipv6ToBig(c6[1]) !== null && Number(c6[2]) <= 128;
  const b6 = /^\[([0-9a-f:.]+)\](?::(\d{1,5}))?$/i.exec(e);
  if (b6) return ipv6ToBig(b6[1]) !== null;
  if ((e.match(/:/g) ?? []).length >= 2) return ipv6ToBig(e) !== null; // bare IPv6
  return /^[a-z0-9_*.-]+(?::\d{1,5})?$/.test(e);
}

/**
 * Built-ins plus KUMA_MCP_DENY_HOSTS. A malformed operator entry is REFUSED (an error on every
 * add/edit) rather than skipped: a typo must not silently leave a target allowed.
 */
export function denyList(): string[] {
  const extra = (process.env.KUMA_MCP_DENY_HOSTS ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  for (const e of extra) {
    if (!validEntry(e)) throw new Error(`KUMA_MCP_DENY_HOSTS has an invalid entry "${e}"; fix the MCP server environment (IPv6 with a port needs brackets: [2001:db8::5]:8080)`);
  }
  return [...BUILTIN_DENY, ...extra];
}

/** `https://` is the Kuma UI's placeholder url for non-HTTP monitors; it is not a target. */
export function isPlaceholderUrl(u: unknown): boolean {
  return typeof u !== 'string' || u.trim() === '' || u.trim() === 'https://';
}

/** Port the Kuma UI fills in when the monitor type has a conventional one and none was given. */
export const UI_DEFAULT_PORTS: Record<string, number> = { dns: 53, radius: 1812, snmp: 161 };

/** Types whose request target is `url` vs `hostname` (+port). Types in neither set have no network target in those fields. */
export const URL_TYPES = ['http', 'keyword', 'json-query', 'real-browser'];
export const HOST_TYPES = ['port', 'ping', 'dns', 'tailscale-ping', 'smtp', 'snmp', 'steam', 'gamedig', 'mqtt', 'radius'];
const NO_TARGET_TYPES = ['group', 'push', 'docker', 'manual'];

/** The fields of a (merged) monitor that actually make the outgoing request for its type. Unknown types: check both. */
export function effectiveTarget(m: Record<string, any>): { url?: unknown; hostname?: unknown; port?: unknown; dns_resolve_server?: unknown } {
  const t = String(m.type ?? '');
  if (NO_TARGET_TYPES.includes(t)) return {};
  const unknown = !URL_TYPES.includes(t) && !HOST_TYPES.includes(t);
  return {
    url: (URL_TYPES.includes(t) || unknown) && !isPlaceholderUrl(m.url) ? m.url : undefined,
    hostname: HOST_TYPES.includes(t) || unknown ? m.hostname : undefined,
    port: HOST_TYPES.includes(t) || unknown ? m.port : undefined,
    dns_resolve_server: t === 'dns' ? m.dns_resolve_server : undefined,
  };
}

export function assertMethodAndBodyAllowed(f: { method?: unknown; body?: unknown }): void {
  if (allowWriteMethods()) return;
  if (f.method !== undefined && f.method !== null && !(SAFE_METHODS as readonly string[]).includes(String(f.method).toUpperCase())) {
    throw new Error('HTTP method not allowed: only GET/HEAD (operator must set KUMA_MCP_ALLOW_WRITE_METHODS=1 for others)');
  }
  if (f.body !== undefined && f.body !== null && f.body !== '') {
    throw new Error('request body not allowed (operator must set KUMA_MCP_ALLOW_WRITE_METHODS=1)');
  }
}

function ipv4ToInt(h: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((x) => x > 255)) return null;
  return (((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0);
}

/** Normalise a url or bare host the way an HTTP client would (decimal/hex IPs, IPv4-mapped IPv6, case, trailing dot). */
/** Only these URL schemes may be monitored targets (N3). */
const ALLOWED_SCHEMES = ['http', 'https', 'ws', 'wss'];

const DEFAULT_PORTS: Record<string, string> = { http: '80', ws: '80', https: '443', wss: '443' };

function parseTarget(raw: string): { host: string; port: string } | null {
  let s = raw.trim();
  if (!s) return null;
  if ((s.match(/:/g) ?? []).length >= 2 && /^[0-9a-f:.]+$/i.test(s)) s = `[${s}]`; // bare IPv6 literal
  const sch = /^([a-z][a-z0-9+.-]*):(\/\/|(?!\d))/i.exec(s);
  if (sch && !ALLOWED_SCHEMES.includes(sch[1].toLowerCase())) return null; // file:, gopher:, ftp:, javascript:, ...
  try {
    const u = new URL(sch ? s : 'http://' + s);
    // Collapse any run of trailing dots (localhost.. resolves like localhost).
    let host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
    // IPv4-mapped (::ffff:a:b) and IPv4-translated (::ffff:0:a:b) forms embed an IPv4 address.
    const mapped = /^::ffff:(?:0:)?([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
    if (mapped) {
      const a = parseInt(mapped[1], 16), b = parseInt(mapped[2], 16);
      host = `${a >> 8}.${a & 255}.${b >> 8}.${b & 255}`;
    }
    // URL drops the scheme's default port (:80/:443), so a host:port entry would never match: restore it.
    // Scheme-less targets only count a port that was written explicitly.
    let port = u.port;
    if (!port && sch) port = DEFAULT_PORTS[sch[1].toLowerCase()] ?? '';
    if (!port && !sch) { const m = /:(\d+)(?:[/?#]|$)/.exec(s.replace(/^\[[^\]]*\]/, '')); if (m) port = m[1]; }
    return { host, port };
  } catch {
    return null;
  }
}

/** Parse an IPv6 literal (no brackets) to a 128-bit BigInt, or null. Handles `::` and a trailing dotted quad. */
function ipv6ToBig(h: string): bigint | null {
  let s = h;
  const v4 = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  if (v4) {
    const n = ipv4ToInt(v4[2]);
    if (n === null) return null;
    s = v4[1] + ((n >>> 16).toString(16)) + ':' + ((n & 0xffff).toString(16));
  }
  if (!/^[0-9a-f:]+$/i.test(s) || (s.match(/::/g) ?? []).length > 1) return null;
  const [l, r] = s.split('::');
  const left = l ? l.split(':') : [], right = r !== undefined && r ? r.split(':') : [];
  const fill = s.includes('::') ? 8 - left.length - right.length : 0;
  if (fill < 0 || (!s.includes('::') && left.length !== 8)) return null;
  const groups = [...left, ...Array(fill).fill('0'), ...right];
  if (groups.length !== 8 || groups.some((g) => g.length > 4)) return null;
  return groups.reduce((a, g) => (a << 16n) | BigInt(parseInt(g || '0', 16)), 0n);
}

function entryMatches(entry: string, host: string, port: string): boolean {
  const cidr6 = /^([0-9a-f:]*:[0-9a-f:.]*)\/(\d{1,3})$/i.exec(entry);
  if (cidr6) {
    const ip = ipv6ToBig(host), base = ipv6ToBig(cidr6[1]), bits = Number(cidr6[2]);
    if (ip === null || base === null || bits > 128) return false;
    const shift = BigInt(128 - bits);
    return (ip >> shift) === (base >> shift);
  }
  const cidr = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(entry);
  if (cidr) {
    const ip = ipv4ToInt(host), base = ipv4ToInt(cidr[1]), bits = Number(cidr[2]);
    if (ip === null || base === null || bits > 32) return false;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return ((ip & mask) >>> 0) === ((base & mask) >>> 0);
  }
  let pat = entry, wantPort: string | null = null;
  const b6 = /^\[([0-9a-f:.]+)\](?::(\d+))?$/i.exec(entry); // [2001:db8::5]:8080 or [2001:db8::5]
  const pm = /^([^:]+):(\d+)$/.exec(entry); // single colon only: bare IPv6 entries are not host:port
  if (b6) { pat = b6[1]; wantPort = b6[2] ?? null; }
  else if (pm) { pat = pm[1]; wantPort = pm[2]; }
  // IPv6 entries compare numerically so 2001:0db8::5 and 2001:db8::5 are the same host.
  const pBig = pat.includes(':') ? ipv6ToBig(pat) : null;
  if (pBig !== null) {
    const hBig = ipv6ToBig(host);
    return hBig !== null && hBig === pBig && (wantPort === null || wantPort === port);
  }
  const re = new RegExp('^' + pat.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
  if (!re.test(host)) return false;
  return wantPort === null || wantPort === port;
}

/** Throw if url/hostname (optionally with port) hits the denylist or cannot be parsed (fail closed). */
export function assertTargetAllowed(t: { url?: unknown; hostname?: unknown; port?: unknown; dns_resolve_server?: unknown }): void {
  const deny = denyList();
  const port = t.port !== undefined && t.port !== null ? String(t.port) : '';
  for (const [field, raw] of [['url', t.url], ['hostname', t.hostname], ['dns', t.dns_resolve_server]] as const) {
    if (typeof raw !== 'string' || raw === '') continue;
    // A monitor `url` must carry an explicit http/https/ws/wss scheme (no scheme-less or relative forms).
    if (field === 'url' && !/^(https?|wss?):\/\//i.test(raw.trim())) {
      throw new Error('monitor target not allowed: url must start with http://, https://, ws:// or wss://');
    }
    const p = parseTarget(raw);
    if (!p) throw new Error('monitor target not allowed: unparseable url/hostname or scheme not in http/https/ws/wss');
    const eff = p.port || port;
    if (deny.some((e) => entryMatches(e, p.host, eff))) {
      throw new Error('monitor target not allowed: host is on the denylist (loopback, link-local, gateway/MCP or KUMA_MCP_DENY_HOSTS)');
    }
  }
}

/** Redirect cap while write methods are disabled: a followed redirect is a second, unchecked target (N1). */
export const MAX_REDIRECTS_SAFE = 2;

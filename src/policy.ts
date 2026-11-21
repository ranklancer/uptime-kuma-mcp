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
 * Resolve-time check (assertResolvedTargetAllowed): every address a hostname resolves to, from this
 * process's resolver, must also pass the denylist. FAIL CLOSED: a name that cannot be resolved (or times out)
 * is refused unless it matches KUMA_MCP_ALLOW_HOSTS, so a name this process cannot see (a docker service
 * name) must be listed there. Optional KUMA_MCP_DENY_PRIVATE=1 also denies RFC1918 and CGNAT 100.64/10
 * (hosts matching KUMA_MCP_ALLOW_HOSTS are exempt from that range check only).
 *
 * Limits: the check is point-in-time. A record that changes after creation (DNS rebinding / attacker-controlled
 * DNS) is not seen; only a network egress policy on the Kuma host closes that. Redirects are a second,
 * unchecked target, so maxredirects is forced to 0 (KUMA_MCP_ALLOW_REDIRECTS=1 relaxes it to a cap of 2).
 */

import { lookup } from 'node:dns/promises';
import { domainToASCII } from 'node:url';

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

/** Opt-in (KUMA_MCP_DENY_PRIVATE=1): RFC1918 and CGNAT. Default off so existing deployments do not change until the operator opts in. */
const PRIVATE_DENY = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'];

export function denyPrivate(): boolean {
  return process.env.KUMA_MCP_DENY_PRIVATE === '1';
}

/** Redirect cap for monitors: 0 unless the operator sets KUMA_MCP_ALLOW_REDIRECTS=1 (then 2). A redirect is an unchecked second target. */
export function maxRedirectsCap(): number {
  return process.env.KUMA_MCP_ALLOW_REDIRECTS === '1' ? MAX_REDIRECTS_SAFE : 0;
}

function envEntries(name: string): string[] {
  return (process.env[name] ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
}

/** Hosts the operator vouches for (KUMA_MCP_ALLOW_HOSTS): may fail to resolve here and are exempt from the private-range deny. Invalid entries are ignored (fail closed) and listed by invalidAllowEntries(). */
export function allowHosts(): string[] {
  return envEntries('KUMA_MCP_ALLOW_HOSTS').filter(validEntry);
}

export function invalidAllowEntries(): string[] {
  return envEntries('KUMA_MCP_ALLOW_HOSTS').filter((e) => !validEntry(e));
}

function isAllowedHost(host: string, port: string): boolean {
  return allowHosts().some((e) => entryMatches(e, host, port));
}

/** Entry grammar: host/glob[:port], IPv4 or IPv6 CIDR, bare IPv6, or [IPv6][:port]. */
/** Single-label public suffixes a `*.` wildcard must not cover (every site under them). Homelab suffixes (.lan, .local, .home.arpa, .internal) stay allowed. */
const PUBLIC_TLDS = new Set(['com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'name', 'pro', 'io', 'dev', 'app', 'xyz', 'online', 'site', 'tech', 'cloud', 'me', 'tv', 'cc', 'co']);
const PRIVATE_SUFFIXES = new Set(['lan', 'local', 'internal', 'localhost', 'test', 'example', 'corp', 'home', 'localdomain']);
const CCSLD = /^(?:co|com|org|net|gov|edu|ac|or|ne|go|gob|mil|nom|ltd|plc|sch|gv|id|ind|nic)\.[a-z]{2}$/;

/** Why a `*.suffix` host glob is too broad ("public suffix" / "numeric"), or null. Applies to any entry that starts with `*.`; a trailing `:port` is ignored. */
export function wildcardProblem(entry: string): string | null {
  const e = entry.toLowerCase().replace(/:\d{1,5}$/, '');
  if (/[a-z0-9_-]\.$/.test(e)) return 'trailing dot (target hosts never carry one, so this entry would silently never match)';
  if (e.includes('*') && e.replace(/[*.]/g, '').length < 3) return 'glob with fewer than 3 literal characters (matches almost every host)';
  if (/\*\*/.test(e) || /^\*\.[^:]*\*/.test(e)) return 'multi-star wildcard (matches far more than one domain)';
  // `*.suffix`, or a glued form like `*com` / `*o.uk` (a star prefix on the first label): judge the suffix after the star's label.
  const m = /^\*\.([a-z0-9_.-]+)$/.exec(e) ?? (/\*$/.test(e) ? null : /^\*[a-z0-9_-]*(?:\.([a-z0-9_.-]+))?$/.exec(e));
  if (!m) return null;
  const suffix = m[1];
  if (suffix === undefined) return 'single-label glob without a dot (matches every host ending in that text)';
  if (/^[a-z0-9_-]+$/.test(suffix) && !PRIVATE_SUFFIXES.has(suffix)) return `single-label wildcard (covers every host under .${suffix}; only private suffixes such as .lan or .local are accepted)`;
  if (/(^|\.)(nip\.io|sslip\.io|xip\.io)$/.test(suffix)) return 'wildcard over an IP-embedding DNS service (any private IP becomes an allowed name)';
  if (/^[0-9.]+$/.test(suffix)) return 'numeric wildcard (matches IP-address-shaped names, not a domain)';
  if (PUBLIC_TLDS.has(suffix) || CCSLD.test(suffix) || /^[a-z]{2}$/.test(suffix)) return `public suffix wildcard (covers every host under .${suffix})`;
  return null;
}

/** Entries in the three operator host lists that are too-broad wildcards: the server refuses to start with any (see index.ts). */
export function wildcardProblems(): { env: string; entry: string; reason: string }[] {
  const out: { env: string; entry: string; reason: string }[] = [];
  for (const env of ['KUMA_MCP_ALLOW_HOSTS', 'KUMA_MCP_DENY_HOSTS', 'KUMA_MCP_NOTIFICATION_HOSTS']) {
    for (const entry of envEntries(env)) { const reason = wildcardProblem(entry); if (reason) out.push({ env, entry, reason }); }
  }
  return out;
}

function validEntry(e: string): boolean {
  if (wildcardProblem(e)) return false;
  const c4 = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(e);
  if (c4) return ipv4ToInt(c4[1]) !== null && Number(c4[2]) <= 32;
  const c6 = /^([0-9a-f:.]*:[0-9a-f:.]*)\/(\d{1,3})$/i.exec(e);
  if (c6) return ipv6ToBig(c6[1]) !== null && Number(c6[2]) <= 128;
  const b6 = /^\[([0-9a-f:.]+)\](?::(\d{1,5}))?$/i.exec(e);
  if (b6) return ipv6ToBig(b6[1]) !== null && (b6[2] === undefined || validPort(b6[2]));
  if ((e.match(/:/g) ?? []).length >= 2) return ipv6ToBig(e) !== null; // bare IPv6
  const hp = /^[a-z0-9_*.-]+(?::(\d{1,5}))?$/.exec(e);
  return !!hp && (hp[1] === undefined || validPort(hp[1]));
}

function validPort(p: string): boolean {
  const n = Number(p);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}

/** Hosts in ::ffff:0:0/96 (mapped) and ::ffff:0:0:0/96 (translated) are matched as their embedded IPv4 address. */
function embeddedV4(big: bigint): string | null {
  const hi = big >> 32n;
  if (hi !== 0xffffn && hi !== 0xffff0000n) return null;
  const n = Number(big & 0xffffffffn);
  return `${n >>> 24}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
}

/**
 * parseTarget turns mapped IPv6 hosts into dotted IPv4, so an operator entry written in mapped form
 * (::ffff:10.0.0.5, [::ffff:a00:5]:80, ::ffff:10.0.0.0/104) must be converted the same way or it can never match.
 */
function normalizeEntry(entry: string): string {
  const c6 = /^([0-9a-f:.]*:[0-9a-f:.]*)\/(\d{1,3})$/i.exec(entry);
  if (c6) {
    const big = ipv6ToBig(c6[1]), bits = Number(c6[2]);
    const v4 = big !== null && bits >= 96 ? embeddedV4(big) : null;
    return v4 ? `${v4}/${bits - 96}` : entry;
  }
  const b6 = /^\[([0-9a-f:.]+)\](?::(\d+))?$/i.exec(entry);
  const bare = !b6 && (entry.match(/:/g) ?? []).length >= 2 ? entry : null;
  const addr = b6 ? b6[1] : bare;
  const big = addr ? ipv6ToBig(addr) : null;
  const v4 = big !== null ? embeddedV4(big) : null;
  return v4 ? (b6 && b6[2] ? `${v4}:${b6[2]}` : v4) : entry;
}

/** Operator entries that will be refused (for a startup warning). Contains no secrets: entries are host patterns. */
export function invalidDenyEntries(): string[] {
  return envEntries('KUMA_MCP_DENY_HOSTS').filter((e) => !validEntry(e));
}

/**
 * Built-ins plus KUMA_MCP_DENY_HOSTS. A malformed operator entry is REFUSED (an error on every
 * add/edit) rather than skipped: a typo must not silently leave a target allowed.
 */
export function denyList(exemptPrivate = false): string[] {
  const extra = envEntries('KUMA_MCP_DENY_HOSTS');
  for (const e of extra) {
    if (!validEntry(e)) {
      // The entry text stays in the server log; the MCP client only gets a generic message.
      console.error(`KUMA_MCP_DENY_HOSTS has an invalid entry "${e}" (IPv6 with a port needs brackets: [2001:db8::5]:8080)`);
      throw new Error('monitor target not allowed: KUMA_MCP_DENY_HOSTS on the MCP server has an invalid entry; the operator must fix it (see the server log)');
    }
  }
  return [...BUILTIN_DENY, ...extra, ...(denyPrivate() && !exemptPrivate ? PRIVATE_DENY : [])];
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
const DB_TYPES = ['sqlserver', 'postgres', 'mysql', 'mongodb', 'redis'];

/** Host[:port] of a stored DB connection string, or throws (fail closed) when it cannot be read. */
function dbTargetOf(cs: unknown): string | undefined {
  if (typeof cs !== 'string' || cs.trim() === '') return undefined;
  const s = cs.trim();
  try {
    const u = new URL(s);
    if (u.hostname) return u.hostname + (u.port ? ':' + u.port : '');
  } catch { /* not URL-shaped: try key=value forms */ }
  const kv = /(?:server|data source|host|address|addr)\s*=\s*(?:tcp:)?([^,;:\s]+)(?:[,:](\d+))?/i.exec(s);
  if (kv) return kv[1] + (kv[2] ? ':' + kv[2] : '');
  throw new Error('monitor target not allowed: stored database connection string has an unreadable host');
}

/** The fields of a (merged) monitor that actually make the outgoing request for its type. Unknown types: check both. */
export type Target = { url?: unknown; hostname?: unknown; hostPort?: unknown; port?: unknown; dns_resolve_server?: unknown };

export function effectiveTarget(m: Record<string, any>): Target {
  const t = String(m.type ?? '');
  if (NO_TARGET_TYPES.includes(t)) return {};
  // A type change can activate a stale grpcUrl / databaseConnectionString left from an earlier type.
  if (t === 'grpc') return { hostPort: typeof m.grpcUrl === 'string' && m.grpcUrl.trim() ? m.grpcUrl.trim() : undefined };
  if (DB_TYPES.includes(t)) return { hostPort: dbTargetOf(m.databaseConnectionString) };
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
  if (sch && !/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return null; // `http:/\x`, `http:x`: WHATWG repairs these, legacy parsers do not, and the raw-authority check below would look at the wrong text
  if (/^(?:https?|wss?):(?!\/\/)/i.test(s)) return null; // `http:80@host` (the digit lookahead above makes it look scheme-less): legacy parsers read it as protocol http with no host -> localhost
  if (/[\t\r\n]/.test(s)) return null; // the URL parser would delete these, an older one would end the host there: refuse, do not strip
  try {
    // Check the RAW authority too: WHATWG percent-decodes the host (vaultwarden%2eattacker.example -> vaultwarden.attacker.example)
    // while Node's legacy url.parse stops at the `%`, so the host checked would not be the host Kuma connects to.
    const rawAuth = (sch ? s : 'http://' + s).replace(/[\t\r\n]/g, '').replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split(/[/\\?#]/)[0].replace(/^.*@/, '');
    if (!/^(?:[a-z0-9._\u0080-\uffff-]+|\[[0-9a-f:.]+\])(?::\d{0,5})?$/i.test(rawAuth)) return null;
    // Numeric hosts must be plain dotted-decimal: 0x7f.1, 2130706433 and 192.168.1.054 are read differently by different resolvers/OSes.
    const rawHost = rawAuth.replace(/:\d*$/, '');
    if (/^[0-9x.]+$/i.test(rawHost) && !/^(?:(?:0|[1-9]\d{0,2})\.){3}(?:0|[1-9]\d{0,2})$/.test(rawHost)) return null;
    const u = new URL(sch ? s : 'http://' + s);
    // Collapse any run of trailing dots (localhost.. resolves like localhost).
    let host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
    // An address the parser read as IPv4 must have been WRITTEN in canonical dotted-decimal (0xc0.0xa8.0x1.054 parses as 192.168.1.44 but resolvers differ).
    if (ipv4ToInt(host) !== null && rawHost.toLowerCase().replace(/\.+$/, '') !== host) return null;
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
    // WHATWG keeps characters such as `;` `%` `{` in a hostname that Node's legacy url.parse (used by older axios in Kuma)
    // cuts off at, so the name checked here could differ from the host Kuma connects to. Anything but a plain DNS name or an IP literal is refused.
    if (!/^[a-z0-9._-]+$/.test(host) && !(host.includes(':') && ipv6ToBig(host) !== null)) return null;
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

function entryMatches(rawEntry: string, host: string, port: string): boolean {
  const entry = normalizeEntry(rawEntry);
  const cidr6 = /^([0-9a-f:]*:[0-9a-f:.]*)\/(\d{1,3})$/i.exec(entry);
  if (cidr6) {
    // An IPv4 host is also the IPv4-mapped IPv6 address ::ffff:a.b.c.d, so a short prefix such as ::ffff:0:0/80 covers it.
    const v4n = ipv4ToInt(host);
    const ip = ipv6ToBig(host) ?? (v4n !== null ? (0xffffn << 32n) | BigInt(v4n) : null), base = ipv6ToBig(cidr6[1]), bits = Number(cidr6[2]);
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
    return hBig !== null && hBig === pBig && portOk(wantPort, port);
  }
  const re = new RegExp('^' + pat.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
  if (!re.test(host)) return false;
  return portOk(wantPort, port);
}

/** Numeric compare: 08080 and 8080 are the same port. */
function portOk(want: string | null, port: string): boolean {
  return want === null || (port !== '' && Number(want) === Number(port));
}

/**
 * A `hostname` / DNS-server field is a bare host name or IP (L1): no scheme, userinfo, port or path.
 * Parsing it as a URL would let `127.0.0.1@evil.com` be checked as evil.com while the checker connects to 127.0.0.1,
 * and let a port embedded in the name override the port field.
 */
function assertBareHost(raw: string): void {
  let s = raw.trim();
  if (/[^\x00-\x7f]/.test(s)) s = domainToASCII(s); // IDN: validate the punycode form ('' = invalid)
  const ok = /^[a-z0-9_.-]+$/i.test(s) || (s.includes(':') && /^\[?[0-9a-f:.]+\]?$/i.test(s) && ipv6ToBig(s.replace(/^\[|\]$/g, '')) !== null);
  if (!ok) throw new Error('monitor target not allowed: hostname must be a bare host name or IP address (no scheme, credentials, port or path)');
}

/** Throw if url/hostname (optionally with port) hits the denylist or cannot be parsed (fail closed). */
export function assertTargetAllowed(t: Target, opts: { exemptPrivate?: boolean } = {}): void {
  const port = t.port !== undefined && t.port !== null ? String(t.port) : '';
  for (const [field, raw] of [['url', t.url], ['hostname', t.hostname], ['hostPort', t.hostPort], ['dns', t.dns_resolve_server]] as const) {
    if (typeof raw !== 'string' || raw === '') continue;
    if (field === 'hostname' || field === 'dns') assertBareHost(raw);
    // A monitor `url` must carry an explicit http/https/ws/wss scheme (no scheme-less or relative forms).
    if (field === 'url' && !/^(https?|wss?):\/\//i.test(raw.trim())) {
      throw new Error('monitor target not allowed: url must start with http://, https://, ws:// or wss://');
    }
    const p = parseTarget(raw);
    if (!p) throw new Error('monitor target not allowed: unparseable url/hostname or scheme not in http/https/ws/wss');
    const eff = p.port || port;
    // An operator-vouched host is exempt from the opt-in private-range deny only; every other entry still applies.
    const deny = denyList(opts.exemptPrivate === true || isAllowedHost(p.host, eff));
    if (deny.some((e) => entryMatches(e, p.host, eff))) {
      throw new Error('monitor target not allowed: host is on the denylist (loopback, link-local, gateway/MCP or KUMA_MCP_DENY_HOSTS)');
    }
  }
}

/** Redirect cap while write methods are disabled: a followed redirect is a second, unchecked target (N1). */
export const MAX_REDIRECTS_SAFE = 2;

/** Resolver seam (tests inject a fake). Returns every A/AAAA address of `host`, or throws. */
export type Resolver = (host: string) => Promise<string[]>;
const systemResolver: Resolver = async (host) => (await lookup(host, { all: true, verbatim: true })).map((a) => a.address);
const RESOLVE_TIMEOUT_MS = 3000;

function isIpLiteral(h: string): boolean {
  return ipv4ToInt(h) !== null || (h.includes(':') && ipv6ToBig(h) !== null);
}

/**
 * Resolve-time check (closes the "public name -> internal address" gap at add/edit time): every address
 * a monitor hostname resolves to, from THIS process's resolver, must also pass the denylist. A name that
 * does not resolve here (e.g. a Docker-network name only Kuma can see) cannot be verified and is REFUSED unless
 * it matches KUMA_MCP_ALLOW_HOSTS (fail closed).
 * Limit: this is a point-in-time check; a record that changes after creation (DNS rebinding) is not seen.
 * Network-level egress policy on the Kuma host is the control for that.
 */
export async function assertResolvedTargetAllowed(
  t: Target,
  resolve: Resolver = systemResolver,
): Promise<void> {
  const port = t.port !== undefined && t.port !== null ? String(t.port) : '';
  for (const raw of [t.url, t.hostname, t.hostPort, t.dns_resolve_server]) {
    if (typeof raw !== 'string' || raw === '') continue;
    const p = parseTarget(raw);
    if (!p || !p.host || isIpLiteral(p.host)) continue; // unparseable/literal: the literal check already ran
    const allowed = isAllowedHost(p.host, p.port || port);
    let addrs: string[];
    try {
      addrs = await Promise.race([
        resolve(p.host),
        new Promise<string[]>((_, rej) => setTimeout(() => rej(new Error('timeout')), RESOLVE_TIMEOUT_MS).unref()),
      ]);
    } catch {
      // H4: fail closed. A name that does not resolve (or times out) here cannot be verified.
      if (allowed) continue;
      throw new Error('monitor target not allowed: hostname could not be resolved to verify it (the operator can list legitimate internal names in KUMA_MCP_ALLOW_HOSTS)');
    }
    for (const a of addrs) {
      try { assertTargetAllowed({ hostname: a, port: p.port || port }, { exemptPrivate: allowed }); }
      catch { throw new Error('monitor target not allowed: hostname resolves to a denylisted address (loopback, link-local, gateway/MCP or KUMA_MCP_DENY_HOSTS)'); }
    }
  }
}


// ── Notification provider config (H1) ───────────────────────────────────────

/**
 * Hosts a notification provider may send to (KUMA_MCP_NOTIFICATION_HOSTS: exact hosts, `*` globs or CIDRs).
 * DEFAULT EMPTY: every notification destination is refused until the operator lists it. A notification sends
 * agent-influenced content (monitor name/url, heartbeat text) on every status change, so a public destination is an
 * exfiltration channel even when the internal denylist passes it. The denylist still applies on top of this list.
 * A redirect from the destination is an unchecked second hop: keep this list tight (the operator's own ntfy host).
 */
/**
 * Entry grammar for KUMA_MCP_NOTIFICATION_HOSTS, deliberately narrower than the denylist's: an exact host / IPv4 / [IPv6],
 * or `*.suffix` (whole leading labels only), each with an optional `:port`. Bare `*`, other globs and CIDRs are not
 * accepted (they are logged at startup and ignored). A portless entry means the scheme's DEFAULT port only.
 */
function parseNotificationHostEntry(e: string): { host: string; port?: string; glob: boolean } | null {
  const m = /^(?:\[([0-9a-f:.]+)\]|(\*\.)?([a-z0-9_-]+(?:\.[a-z0-9_-]+)*))(?::(\d{1,5}))?$/i.exec(e);
  if (!m) return null;
  if (wildcardProblem(e)) return null;
  if (m[4] !== undefined && !validPort(m[4])) return null;
  const host = (m[1] ?? m[3]).toLowerCase();
  if (m[1] !== undefined && ipv6ToBig(host) === null) return null;
  if (m[2] && host.split('.').length < 2) return null; // `*.com` would match every .com host: a glob needs at least two labels after `*.`
  return { host, port: m[4] === undefined ? undefined : String(Number(m[4])), glob: !!m[2] };
}

export function notificationHosts(): string[] {
  return envEntries('KUMA_MCP_NOTIFICATION_HOSTS').filter((e) => parseNotificationHostEntry(e) !== null);
}

export function invalidNotificationHostEntries(): string[] {
  return envEntries('KUMA_MCP_NOTIFICATION_HOSTS').filter((e) => parseNotificationHostEntry(e) === null);
}

const SCHEME_DEFAULT_PORT: Record<string, string> = { http: '80', ws: '80', https: '443', wss: '443' };

function assertNotificationHostListed(raw: string): void {
  const p = parseTarget(raw);
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(raw.trim())?.[1].toLowerCase();
  const ok = !!p && !!p.host && notificationHosts().some((entry) => {
    const e = parseNotificationHostEntry(entry)!;
    const hostOk = e.glob ? p.host.endsWith('.' + e.host) : (ipv6ToBig(e.host) !== null && ipv6ToBig(p.host) !== null ? ipv6ToBig(e.host) === ipv6ToBig(p.host) : e.host === p.host);
    // A portless entry allows only the scheme's default port; a destination without a scheme needs an entry with a port.
    const portOk = e.port !== undefined ? p.port !== '' && Number(p.port) === Number(e.port) : scheme !== undefined && SCHEME_DEFAULT_PORT[scheme] !== undefined && p.port === SCHEME_DEFAULT_PORT[scheme];
    return hostOk && portOk;
  });
  if (!ok) {
    throw new Error('notification config not allowed: the destination host and port are not listed in KUMA_MCP_NOTIFICATION_HOSTS on the MCP server (default: none; an entry without a port allows only the default http/https port)');
  }
}

/** Destination spec for a provider type: single/multi-value fields holding a URL or host, host+port pairs, and known non-destination fields. */
interface NotifDest { keys?: string[]; multi?: string[]; pair?: [string, string]; skip?: string[] }

/**
 * Operator allow-list of notification provider types that create/update may write (KUMA_MCP_NOTIFICATION_TYPES,
 * comma list, default `ntfy`). Most providers can send an agent-influenced request to an arbitrary destination, so
 * every other type needs an explicit operator opt-in. The per-type table below stays as defence in depth.
 */
export function enabledNotificationTypes(): string[] {
  const raw = process.env.KUMA_MCP_NOTIFICATION_TYPES;
  return (raw === undefined ? 'ntfy' : raw).split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);
}

/**
 * Per-provider-type table of fields that name a network destination. A type that is not listed is REFUSED
 * (fail closed). A field not listed for its type whose value looks like a URL/host is refused too, so a new or
 * unexpected destination field cannot be used to smuggle a target. Keys are Kuma's provider type ids, lower-cased.
 */
const NOTIF_TYPES = new Map<string, NotifDest>(Object.entries({
  webhook: { keys: ['webhookURL'] }, ntfy: { keys: ['ntfyserverurl', 'ntfyIcon'], skip: ['ntfyusername', 'ntfypassword', 'ntfyaccesstoken'] }, gotify: { keys: ['gotifyserverurl'] },
  slack: { keys: ['slackwebhookURL'] }, discord: { keys: ['discordWebhookUrl'] }, teams: { keys: ['webhookUrl'] },
  telegram: { keys: ['telegramServerUrl'] }, smtp: { pair: ['smtpHost', 'smtpPort'], skip: ['smtpDkimDomain', 'smtpDkimKeySelector'] },
  apprise: { keys: ['appriseURL'] },
  matrix: { keys: ['homeserverUrl'] }, mattermost: { keys: ['mattermostWebhookUrl'], skip: ['mattermosticonurl'] }, 'rocket.chat': { keys: ['rocketwebhookURL'] },
  gorush: { keys: ['gorushServerURL'], skip: ['gorushTopic'] }, homeassistant: { keys: ['homeAssistantUrl'] }, signal: { keys: ['signalURL'] },
  googlechat: { keys: ['googleChatWebhookURL'] }, nostr: { multi: ['relays', 'nostrRelays'] },
  onebot: { keys: ['httpAddr'] }, milky: { keys: ['httpAddr'] }, pushdeer: { keys: ['pushdeerServer'] },
  feishu: { keys: ['feishuWebHookUrl'] }, dingding: { keys: ['webHookUrl'] }, bark: { keys: ['barkEndpoint'] },
  pagerduty: { keys: ['pagerdutyIntegrationUrl'] }, alerta: { keys: ['alertaApiEndpoint'] }, splunk: { keys: ['splunkRestURL'] },
  stackfield: { keys: ['stackfieldwebhookURL'] }, zohocliq: { keys: ['webhookUrl'] }, smseagle: { keys: ['smseagleUrl'] },
  grafanaoncall: { keys: ['GrafanaOncallURL'] }, evolution: { keys: ['evolutionApiUrl'] }, wecom: {},
  keep: { keys: ['webhookURL'] }, pagertree: { keys: ['pagertreeIntegrationUrl'] },
  serverchan: {}, // serverChanSendKey is a key, not a host
  pushover: {}, pushbullet: {}, line: {}, linenotify: {}, lunasea: {}, octopush: {}, opsgenie: {}, pushbytechulus: {},
  pushy: {}, threema: {}, twilio: {}, clicksendsms: {},
} as Record<string, NotifDest>));
const NOTIF_RESERVED = new Set(['name', 'type', 'isDefault', 'applyExisting', 'active', 'id', 'userId']);
/** Webhook free-form request shaping: refused unless the operator allows write-style requests. */
const NOTIF_REQUEST_SHAPING_KEYS = ['webhookCustomBody', 'webhookAdditionalHeaders', 'ntfyUseTemplate', 'ntfyCustomTitle', 'ntfyCustomMessage',
  'customSubject', 'customBody', 'telegramUseTemplate', 'telegramTemplate', 'ntfyCall'];
/** apprise schemes that are HTTP requests under the hood: checked exactly like http(s). */
const APPRISE_HTTP_SCHEMES: Record<string, string> = { json: 'http', jsons: 'https', xml: 'http', xmls: 'https', form: 'http', forms: 'https', http: 'http', https: 'https' };
/** apprise schemes whose "host" part is a token/id, not a network host: only the literal denylist applies. Any other scheme is refused. */
const APPRISE_TOKEN_SCHEMES = ['tgram', 'discord', 'slack', 'pover', 'pbul'];

/** Characters a URL client strips or a human cannot see: C0 controls, DEL, NBSP, Unicode spaces, zero-width and bidi/format chars. */
const HIDDEN_CHARS = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u00a0\u1680\u180e\u2000-\u200f\u2028-\u202f\u205f-\u206f\u3000\ufeff]/g;

const HIDDEN_TEST = new RegExp(HIDDEN_CHARS.source);

/** True if a string value reads as a URL, host, host:port or IP literal (so an unlisted key carrying it is suspect). */
function looksTargetLike(v: string): boolean {
  const s = v.replace(/[\t\r\n]/g, '').replace(HIDDEN_CHARS, '').trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return true;
  if (/^\[?[0-9a-f]*:[0-9a-f:.]*:[0-9a-f:.]*\]?(:\d+)?([/?#].*)?$/i.test(s) && (s.match(/:/g) ?? []).length >= 2) return true; // IPv6
  if (/^[a-z0-9_-]+(\.[a-z0-9_-]+)+\.?(:\d{1,5})?([/?#].*)?$/i.test(s) && !/^\d+(\.\d+)?$/.test(s)) return true; // dotted name / IPv4
  const hp = /^([a-z0-9_.-]+):\d{1,5}([/?#].*)?$/i.exec(s);
  return !!hp && !/^\d+$/.test(hp[1]);
}

function* stringLeaves(v: unknown, depth = 0): Generator<string> {
  if (depth > 6 || v === null || v === undefined) return;
  if (typeof v === 'string') yield v;
  else if (Array.isArray(v)) for (const x of v) yield* stringLeaves(x, depth + 1);
  else if (typeof v === 'object') for (const x of Object.values(v as Record<string, unknown>)) yield* stringLeaves(x, depth + 1);
}

async function checkNotificationDestination(raw: string, resolve: Resolver | undefined, opts: { multi?: boolean; apprise?: boolean; schemeOptional?: boolean } = {}): Promise<void> {
  // The URL parser (axios) deletes tab/CR/LF anywhere in a URL and %-encodes other whitespace: a space or
  // line break can hide a different host, so only newline-separated multi-value fields keep their separators.
  // Tab/CR/LF are REFUSED, not stripped: older URL parsers end the host at a tab, so the host checked here could differ from the one Kuma connects to.
  const s = raw.replace(/^ +| +$/g, '');
  if (s === '') return;
  if (/\t/.test(s) || (!opts.multi && /[\r\n]/.test(s))) throw new Error('notification config not allowed: destination contains whitespace or control characters');
  if (/\s/.test(s) || HIDDEN_TEST.test(s)) throw new Error('notification config not allowed: destination contains whitespace or control characters');
  if (opts.apprise) {
    if (s.includes('\\')) throw new Error('notification config not allowed: backslash in an apprise URL');
    // apprise splits one value into several URLs on whitespace, commas and semicolons: only a single URL is accepted.
    if (/[,;]/.test(s) || (s.match(/[a-z][a-z0-9+.-]*:\/\//gi) ?? []).length > 1) throw new Error('notification config not allowed: only one apprise URL is accepted');
    const m = /^([a-z][a-z0-9+.-]*):\/\//i.exec(s);
    if (!m) throw new Error('notification config not allowed: apprise URL must start with a scheme://');
    const sc = m[1].toLowerCase();
    if (APPRISE_HTTP_SCHEMES[sc]) {
      const url = APPRISE_HTTP_SCHEMES[sc] + s.slice(sc.length);
      assertTargetAllowed({ url }); assertNotificationHostListed(url); await assertResolvedTargetAllowed({ url }, resolve); return;
    }
    if (!APPRISE_TOKEN_SCHEMES.includes(sc)) throw new Error(`notification config not allowed: apprise scheme "${sc.slice(0, 20)}" is not supported (its host part is a real network host or unknown)`);
    // The host part of a token scheme is usually a bot token / id (`tgram://123456:ABCdef/987`), which is not a valid
    // authority; only a part that is a valid bare host or bracketed IPv6 literal is run through the denylist.
    const auth = s.slice(m[0].length).split(/[/?#]/)[0].replace(/^.*@/, '');
    const hostOnly = auth.startsWith('[') ? auth.slice(0, auth.indexOf(']') + 1) : auth.split(':')[0];
    if (/^\[[0-9a-f:.]+\]$/i.test(hostOnly) || (/^[a-z0-9_.-]+$/i.test(hostOnly) && !/^\d+$/.test(hostOnly))) assertTargetAllowed({ hostname: hostOnly }); // an all-digit token is not a decimal IP
    return;
  }
  const sch = /^([a-z][a-z0-9+.-]*):\/\//i.exec(s);
  if (sch && !ALLOWED_SCHEMES.includes(sch[1].toLowerCase())) throw new Error('notification config not allowed: destination scheme must be http, https, ws or wss');
  if (!sch && opts.schemeOptional && /^http/i.test(s)) throw new Error('notification config not allowed: a value starting with "http" must be a full http:// or https:// URL (Kuma only adds a scheme to other values)');
  if (!sch && !opts.multi && !opts.schemeOptional && (/[/?#@\\]/.test(s) || /:\d/.test(s))) {
    // Without a scheme Kuma's HTTP client sends the request to localhost:80 (path = the whole value), not to the host written here.
    throw new Error('notification config not allowed: a URL destination must start with http://, https://, ws:// or wss://');
  }
  if (sch) {
    const url = s;
    assertTargetAllowed({ url });
    assertNotificationHostListed(url);
    await assertResolvedTargetAllowed({ url }, resolve);
  } else {
    assertTargetAllowed({ hostPort: s });
    assertNotificationHostListed(s);
    await assertResolvedTargetAllowed({ hostPort: s }, resolve);
  }
}

/**
 * Policy for the full effective notification config (create: the caller's object; update: stored config merged
 * with the changes). The provider type must be enabled (KUMA_MCP_NOTIFICATION_TYPES) AND on the table; every
 * destination field of that type passes the target denylist and the resolve-time check (host+port jointly,
 * multi-value fields split, non-string values refused); no unlisted field may carry a URL/host-like value; a webhook
 * custom body, additional headers or a non-GET method needs KUMA_MCP_ALLOW_WRITE_METHODS=1 (agent-chosen content
 * sent on every status change is an exfiltration channel).
 */
export async function assertNotificationConfigAllowed(config: Record<string, unknown>, resolve?: Resolver): Promise<void> {
  const type = typeof config.type === 'string' ? config.type.toLowerCase() : '';
  if (!enabledNotificationTypes().includes(type)) {
    throw new Error(`notification config not allowed: provider type "${type.slice(0, 40)}" is not enabled; the operator must add it to KUMA_MCP_NOTIFICATION_TYPES on the MCP server (default: ntfy)`);
  }
  const spec = NOTIF_TYPES.get(type);
  if (!spec) throw new Error(`notification config not allowed: provider type "${type.slice(0, 40)}" is not on the supported list`);
  if (!allowWriteMethods()) {
    for (const k of NOTIF_REQUEST_SHAPING_KEYS) {
      const v = config[k];
      if (v !== undefined && v !== null && v !== '' && v !== false && v !== 0) {
        throw new Error('notification config not allowed: a custom/templated body, title or additional headers needs KUMA_MCP_ALLOW_WRITE_METHODS=1 on the MCP server');
      }
    }
    // Kuma's webhook sends POST for a missing httpMethod and for HEAD, so only an explicit GET is read-only.
    if (type === 'webhook' && String(config.httpMethod ?? '').trim().toLowerCase() !== 'get') {
      throw new Error('notification config not allowed: a webhook must set httpMethod to GET unless KUMA_MCP_ALLOW_WRITE_METHODS=1');
    }
  }
  if (type === 'ntfy' && process.env.KUMA_MCP_NTFY_TOPICS !== undefined) {
    const topics = process.env.KUMA_MCP_NTFY_TOPICS.split(',').map((x) => x.trim()).filter(Boolean);
    if (topics.length > 0 && !(typeof config.ntfytopic === 'string' && topics.includes(config.ntfytopic))) {
      throw new Error('notification config not allowed: the ntfy topic is not listed in KUMA_MCP_NTFY_TOPICS on the MCP server');
    }
  }
  if (type === 'ntfy') {
    // Kuma POSTs {topic: ntfytopic, ...} to ntfyserverurl; ntfy only honours that JSON topic at the server ROOT, and a POST
    // to /<topic> publishes to that topic instead. A path, query or fragment would bypass KUMA_MCP_NTFY_TOPICS.
    // An empty/missing value makes Kuma fall back to a default it picks itself (a blind request), so it is refused too.
    // The check is on the RAW text: URL parsing would normalise `/.`, `/..` and `\x` into something that looks like a root.
    const v = typeof config.ntfyserverurl === 'string' ? config.ntfyserverurl.trim() : '';
    if (v === '') throw new Error('notification config not allowed: ntfy needs ntfyserverurl set to the server root (an empty value makes Kuma pick a default)');
    if (!/^[a-z][a-z0-9+.-]*:\/\/[a-z0-9._~:\[\]-]+\/?$/i.test(v)) throw new Error('notification config not allowed: ntfyserverurl must be the server root (no path, query or fragment)');
  }
  const known = new Set<string>([...(spec.keys ?? []), ...(spec.multi ?? []), ...(spec.pair ?? []), ...(spec.skip ?? [])]);
  const notString = (k: string) => new Error(`notification config not allowed: "${k}" must be a plain string`);
  for (const k of spec.keys ?? []) {
    const v = config[k];
    if (v === undefined || v === null) continue;
    if (typeof v !== 'string') throw notString(k);
    await checkNotificationDestination(v, resolve, { apprise: type === 'apprise', schemeOptional: k === 'httpAddr' });
  }
  for (const k of spec.multi ?? []) {
    const v = config[k];
    if (v === undefined || v === null) continue;
    if (!(typeof v === 'string' || (Array.isArray(v) && v.every((x) => typeof x === 'string')))) throw notString(k);
    const parts = Array.isArray(v) ? v.flatMap((x: string) => x.split(/[\r\n,]+/)) : v.split(/[\r\n,]+/);
    for (const part of parts) await checkNotificationDestination(part, resolve, { multi: true });
  }
  if (spec.pair) {
    const host = config[spec.pair[0]], rawPort = config[spec.pair[1]];
    if (host !== undefined && host !== null && typeof host !== 'string') throw notString(spec.pair[0]);
    if (rawPort !== undefined && rawPort !== null && typeof rawPort !== 'string' && typeof rawPort !== 'number') throw notString(spec.pair[1]);
    if (typeof host === 'string' && host.trim() !== '') {
      const port = rawPort === undefined || rawPort === null || rawPort === '' ? undefined : Number(rawPort);
      if (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65535)) throw new Error('notification config not allowed: invalid port');
      assertTargetAllowed({ hostname: host, port }); // host and port are judged together (host:port deny entries)
      assertNotificationHostListed(`${host.includes(':') ? `[${host.replace(/^\[|\]$/g, '')}]` : host}${port !== undefined ? ':' + port : ''}`);
      await assertResolvedTargetAllowed({ hostname: host, port }, resolve);
    }
  }
  for (const [k, v] of Object.entries(config)) {
    if (known.has(k) || NOTIF_RESERVED.has(k) || NOTIF_REQUEST_SHAPING_KEYS.includes(k) || k === 'httpMethod') continue;
    for (const leaf of stringLeaves(v)) {
      if (looksTargetLike(leaf)) throw new Error(`notification config not allowed: field "${k}" holds a URL/host but is not a known destination field for provider type "${type}"`);
    }
  }
}

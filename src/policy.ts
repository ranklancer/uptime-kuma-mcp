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
  'localhost', '*.localhost', '127.0.0.0/8', '::1', '0.0.0.0', '169.254.0.0/16', '::',
  'host.docker.internal', 'metadata.google.internal', '*bifrost*', '*mcp*',
];

export function denyList(): string[] {
  const extra = (process.env.KUMA_MCP_DENY_HOSTS ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  return [...BUILTIN_DENY, ...extra];
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
function parseTarget(raw: string): { host: string; port: string } | null {
  const s = raw.trim();
  if (!s) return null;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : 'http://' + s);
    let host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
    if (mapped) {
      const a = parseInt(mapped[1], 16), b = parseInt(mapped[2], 16);
      host = `${a >> 8}.${a & 255}.${b >> 8}.${b & 255}`;
    }
    return { host, port: u.port };
  } catch {
    return null;
  }
}

function entryMatches(entry: string, host: string, port: string): boolean {
  const cidr = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(entry);
  if (cidr) {
    const ip = ipv4ToInt(host), base = ipv4ToInt(cidr[1]), bits = Number(cidr[2]);
    if (ip === null || base === null || bits > 32) return false;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return ((ip & mask) >>> 0) === ((base & mask) >>> 0);
  }
  let pat = entry, wantPort: string | null = null;
  const pm = /^([^:]+):(\d+)$/.exec(entry); // single colon only: IPv6 entries are not host:port
  if (pm) { pat = pm[1]; wantPort = pm[2]; }
  const re = new RegExp('^' + pat.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
  if (!re.test(host)) return false;
  return wantPort === null || wantPort === port;
}

/** Throw if url/hostname (optionally with port) hits the denylist or cannot be parsed (fail closed). */
export function assertTargetAllowed(t: { url?: unknown; hostname?: unknown; port?: unknown }): void {
  const deny = denyList();
  const port = t.port !== undefined && t.port !== null ? String(t.port) : '';
  for (const raw of [t.url, t.hostname]) {
    if (typeof raw !== 'string' || raw === '') continue;
    const p = parseTarget(raw);
    if (!p) throw new Error('monitor target not allowed: unparseable url/hostname');
    const eff = p.port || port;
    if (deny.some((e) => entryMatches(e, p.host, eff))) {
      throw new Error('monitor target not allowed: host is on the denylist (loopback, link-local, gateway/MCP or KUMA_MCP_DENY_HOSTS)');
    }
  }
}

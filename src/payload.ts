import { createHash, randomInt } from 'node:crypto';
import { allowWriteMethods, assertMethodAndBodyAllowed, assertTargetAllowed, effectiveTarget, isPlaceholderUrl, MAX_REDIRECTS_SAFE, UI_DEFAULT_PORTS } from './policy.js';

/**
 * Monitor payload construction for Kuma's `add` / `editMonitor` socket events.
 *
 * Why this exists: Kuma's server does `bean.import(monitor)` on add and copies named
 * fields on edit. A field that is absent from the payload is stored as NULL, and several
 * monitor columns are NOT NULL (for example `conditions`, which the server fills with
 * JSON.stringify(monitor.conditions); stringify(undefined) is undefined, hence the
 * "NOT NULL constraint failed: monitor.conditions" error). The Kuma web UI avoids this by
 * always sending the full `monitorDefaults` object (src/pages/EditMonitor.vue, Kuma 2.0.x);
 * we mirror those defaults here.
 */

const PUSH_TOKEN_LENGTH = 32; // Kuma EditMonitor.vue: pushTokenLength
const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** Same alphabet and length as Kuma's genSecret(32); uses a CSPRNG with unbiased selection. */
export function genPushToken(length = PUSH_TOKEN_LENGTH): string {
  let out = '';
  for (let i = 0; i < length; i++) out += ALNUM[randomInt(ALNUM.length)];
  return out;
}

/** Short, non-reversible identifier for a secret (first 8 hex of sha256). Safe to show; cannot forge the secret. */
export function fingerprint(secret: string): string {
  return createHash('sha256').update(secret).digest('hex').slice(0, 8);
}

/** Defaults the Kuma UI sends for a new monitor (EditMonitor.vue `monitorDefaults` + init()). */
export function monitorDefaults(): Record<string, any> {
  return {
    type: 'http',
    name: '',
    parent: null,
    url: 'https://',
    method: 'GET',
    ipFamily: null,
    interval: 60,
    retryInterval: 60,
    resendInterval: 0,
    maxretries: 0,
    notificationIDList: {},
    ignoreTls: false,
    upsideDown: false,
    expiryNotification: false,
    maxredirects: 10,
    accepted_statuscodes: ['200-299'],
    dns_resolve_type: 'A',
    dns_resolve_server: '1.1.1.1',
    docker_container: '',
    docker_host: null,
    proxyId: null,
    mqttUsername: '',
    mqttPassword: '',
    mqttTopic: '',
    mqttWebsocketPath: '',
    mqttSuccessMessage: '',
    mqttCheckType: 'keyword',
    authMethod: null,
    oauth_auth_method: 'client_secret_basic',
    httpBodyEncoding: 'json',
    kafkaProducerBrokers: [],
    kafkaProducerSaslOptions: { mechanism: 'None' },
    cacheBust: false,
    kafkaProducerSsl: false,
    kafkaProducerAllowAutoTopicCreation: false,
    gamedigGivenPortOnly: true,
    remote_browser: null,
    rabbitmqNodes: [],
    rabbitmqUsername: '',
    rabbitmqPassword: '',
    conditions: [],
    // added by the UI for new monitors
    ping_count: 3,
    ping_numeric: true,
    packetSize: 56,
    ping_per_request_timeout: 2,
  };
}

/** Columns that are genuinely nullable in Kuma's schema (or null-tolerant on the server): null may be sent for these. */
const NULLABLE_KEYS = new Set([
  'parent', 'ipFamily', 'docker_host', 'proxyId', 'authMethod', 'remote_browser', 'port',
]);

/** Keys the Kuma UI strips before posting (read-only or derived, not columns). */
const READ_ONLY_KEYS = [
  'includeSensitiveData', 'maintenance', 'childrenIDs', 'forceInactive', 'path', 'pathName',
  'screenshot', 'tags', 'humanReadableInterval', 'droppedFields',
];

/** Default check timeout the UI derives: 80% of the interval (ping uses its own 10s default). */
export function deriveTimeout(type: string | undefined, interval: number | undefined): number {
  if (type === 'ping') return 10;
  if (type === 'snmp') return 5;
  const i = typeof interval === 'number' && interval > 0 ? interval : 60;
  return ~~(i * 8) / 10;
}

/** HTTP `headers` / `body` must be JSON strings on the wire (Kuma JSON.parse()s them). */
function toJsonString(v: unknown): unknown {
  if (v !== null && typeof v === 'object') return JSON.stringify(v);
  return v;
}

/** Kuma requires accepted_statuscodes to be an array of STRINGS. Accepts an array, or a comma-separated string. */
export function normalizeStatusCodes(v: unknown): string[] | undefined {
  if (v === undefined || v === null) return undefined;
  const arr = Array.isArray(v) ? v : String(v).split(',');
  const out = arr.map((s) => String(s).trim()).filter((s) => s.length > 0);
  // An explicit but empty value must not silently become a default (it would mask a caller error).
  if (out.length === 0) throw new Error('accepted_statuscodes must contain at least one status code or range');
  return out;
}

/**
 * Explicit ports must be integers in 1-65535. 0 (and null/undefined) means "unset": the caller
 * gets the type's UI default, else null. Port 0 is never a valid check target.
 */
function normalizePort(v: unknown): number | null | undefined {
  if (v === undefined) return undefined;
  if (v === null || v === 0) return null;
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 1 || v > 65535) {
    throw new Error('port must be an integer between 1 and 65535 (0 or omitted = default)');
  }
  return v;
}

/**
 * Fields that belong to one monitor type only. When `edit_monitor` changes the type, those of
 * every group that does not belong to the NEW type are reset, so a stale grpc url, DSN, docker
 * target or MQTT setting is neither sent on nor re-activated by a later type change.
 */
const TYPE_ONLY_FIELDS: Array<{ types: string[]; reset: Record<string, unknown> }> = [
  { types: ['grpc'], reset: { grpcUrl: null, grpcProtobuf: null, grpcBody: null, grpcMetadata: null, grpcMethod: null, grpcServiceName: null, grpcEnableTls: false } },
  { types: ['sqlserver', 'postgres', 'mysql', 'mongodb', 'redis'], reset: { databaseConnectionString: null, databaseQuery: null } },
  { types: ['docker'], reset: { docker_container: '', docker_host: null } },
  { types: ['mqtt'], reset: { mqttUsername: '', mqttPassword: '', mqttTopic: '', mqttSuccessMessage: '', mqttWebsocketPath: '', mqttCheckType: 'keyword' } },
];

/** Keys a caller can never set: the token is server-generated, active/ownership are not tool-controlled. */
const FORBIDDEN_INPUT_KEYS = ['pushToken', 'active', 'user_id', 'id'];

function sanitizeInput(opts: Record<string, any>): Record<string, any> {
  const out = { ...opts };
  for (const k of FORBIDDEN_INPUT_KEYS) delete out[k];
  return out;
}

/** Copy `changes` onto `target`, skipping undefined and skipping null for non-nullable columns. */
function applyChanges(target: Record<string, any>, changes: Record<string, unknown>): void {
  for (const [k, v] of Object.entries(changes)) {
    if (v === undefined) continue;
    if (v === null && !NULLABLE_KEYS.has(k)) continue;
    target[k] = v;
  }
}

function normalizeCommon(m: Record<string, any>): void {
  const sc = normalizeStatusCodes(m.accepted_statuscodes);
  m.accepted_statuscodes = sc ?? ['200-299'];
  if ('headers' in m) m.headers = toJsonString(m.headers);
  if ('body' in m) m.body = toJsonString(m.body);
  if (m.parent === undefined) m.parent = null;
}

/**
 * Build the complete payload for `add`. Every NOT NULL column gets the UI default; a
 * caller value of undefined (or null for a non-nullable column) never overrides it.
 */
export function buildAddPayload(rawOpts: Record<string, any>): Record<string, any> {
  const opts = sanitizeInput(rawOpts);
  if ('port' in opts) opts.port = normalizePort(opts.port);
  assertMethodAndBodyAllowed(opts);
  assertTargetAllowed({
    ...opts,
    url: isPlaceholderUrl(opts.url) ? undefined : opts.url, // a ping/port add may carry the UI placeholder
    port: opts.port ?? UI_DEFAULT_PORTS[String(opts.type ?? '')],
  });
  const m = monitorDefaults();
  if (!allowWriteMethods()) m.maxredirects = 0; // default off; callers may raise it to the cap
  applyChanges(m, opts);
  if ((m.port === undefined || m.port === null) && UI_DEFAULT_PORTS[m.type]) m.port = UI_DEFAULT_PORTS[m.type]; // as the UI does
  if (!allowWriteMethods()) m.maxredirects = Math.min(Number(m.maxredirects) || 0, MAX_REDIRECTS_SAFE);
  if (opts.timeout === undefined || opts.timeout === null || opts.timeout === 0) {
    m.timeout = deriveTimeout(m.type, m.interval);
  }
  normalizeCommon(m);
  // Tokens are generated only here, on creation (never on edit: an edit must not replace a live token).
  if (m.type === 'push') m.pushToken = genPushToken();
  return m;
}

/**
 * Merge `changes` onto the CURRENT (raw) monitor and return the FULL object for `editMonitor`.
 * Kuma's editMonitor overwrites every column from the payload, so a partial object would
 * blank whatever is missing. Also repairs a missing/zero timeout the way the UI does, and
 * keeps an auto-derived timeout (80% of interval) in step when only the interval changes.
 */
export function buildEditPayload(current: Record<string, any>, rawChanges: Record<string, any>, monitorId: number): Record<string, any> {
  return buildEditPayloadWithNotes(current, rawChanges, monitorId).payload;
}

/** As buildEditPayload, plus human-readable notes about values the policy changed (shown to the caller). */
export function buildEditPayloadWithNotes(
  current: Record<string, any>,
  rawChanges: Record<string, any>,
  monitorId: number,
): { payload: Record<string, any>; notes: string[] } {
  const notes: string[] = [];
  const changes = sanitizeInput(rawChanges);
  if ('port' in changes) changes.port = normalizePort(changes.port);
  assertMethodAndBodyAllowed(changes);
  const m: Record<string, any> = { ...current };
  for (const k of READ_ONLY_KEYS) delete m[k];
  if (m.port === 0) m.port = null; // a stored 0 means unset; never forward it
  // Fill NOT NULL columns the server did not return (older/newer Kuma schema differences).
  const defaults = monitorDefaults();
  for (const k of ['conditions', 'kafkaProducerBrokers', 'kafkaProducerSaslOptions', 'rabbitmqNodes']) {
    if (m[k] === undefined || m[k] === null) m[k] = defaults[k];
  }
  const oldInterval = current.interval;
  const oldDerived = deriveTimeout(current.type, oldInterval);
  applyChanges(m, changes);
  if (changes.type !== undefined && changes.type !== current.type) {
    for (const g of TYPE_ONLY_FIELDS) if (!g.types.includes(String(m.type))) Object.assign(m, g.reset);
  }
  if ((m.port === undefined || m.port === null) && UI_DEFAULT_PORTS[m.type]) m.port = UI_DEFAULT_PORTS[m.type]; // as the UI does
  // Re-check the effective target when anything that shapes it changed.
  if (changes.url !== undefined || changes.hostname !== undefined || changes.port !== undefined || changes.dns_resolve_server !== undefined) {
    assertTargetAllowed({
      url: isPlaceholderUrl(changes.url) ? undefined : changes.url,
      hostname: changes.hostname ?? (changes.port !== undefined ? m.hostname : undefined),
      port: m.port,
      dns_resolve_server: changes.dns_resolve_server,
    });
  }
  // B1: the incoming-only check above misses an EXISTING POST/body monitor whose target is being changed.
  // Re-check the merged result whenever anything that shapes the outgoing request changed (N1: also cap redirects).
  const shaping = ['url', 'hostname', 'port', 'type', 'method', 'body', 'headers', 'maxredirects', 'dns_resolve_server',
    'authMethod', 'basic_auth_user', 'basic_auth_pass', 'ignoreTls'];
  const shapingChange = shaping.some((k) => changes[k] !== undefined);
  // The denylist applies even when write methods are enabled: the monitor's EFFECTIVE target for its
  // type must be allowed (a ping->http type change must not activate a stale url aimed at metadata).
  if (shapingChange) assertTargetAllowed(effectiveTarget(m));
  if (!allowWriteMethods() && shapingChange) {
    assertMethodAndBodyAllowed(m);
    const before = Number(m.maxredirects) || 0;
    m.maxredirects = Math.min(before, MAX_REDIRECTS_SAFE);
    if (m.maxredirects !== before) {
      notes.push(`maxredirects was reduced from ${before} to ${m.maxredirects} (policy cap while KUMA_MCP_ALLOW_WRITE_METHODS is off)`);
    }
  }
  m.id = monitorId;
  if (!m.timeout) {
    m.timeout = deriveTimeout(m.type, m.interval);
  } else if (
    changes.timeout === undefined && changes.interval !== undefined &&
    Number(current.timeout) === oldDerived
  ) {
    m.timeout = deriveTimeout(m.type, m.interval);
  }
  normalizeCommon(m);
  // Tokens are generated only in buildAddPayload. An edit must never invent or replace a live token.
  if (m.type === 'push' && !m.pushToken) {
    throw new Error('push monitor has no push token; refusing to edit (repair it in the Kuma UI)');
  }
  return { payload: m, notes };
}

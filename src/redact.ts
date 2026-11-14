/**
 * Monitor redaction for tools that return Uptime Kuma monitor objects.
 *
 * Design: ALLOWLIST projection. Only fields named in MONITOR_SAFE_FIELDS pass
 * through. Fields named in MONITOR_SECRET_FIELDS are replaced by a fixed marker
 * plus a presence boolean (never a hash, prefix, length or any value-derived
 * data). Any other key is dropped and only its NAME is listed, so a field added
 * by a future Kuma release is hidden by default.
 *
 * Field lists are derived from the Uptime Kuma server source, `Monitor.toJSON`
 * in server/model/monitor.js (louislam/uptime-kuma, verified against tags 1.23.16
 * and 2.5.11). MONITOR_SECRET_FIELDS is the union of the fields Kuma itself
 * places behind `includeSensitiveData` in both versions, plus `screenshot`
 * (a JWT-signed URL). MONITOR_SAFE_FIELDS is the union of the remaining keys.
 *
 * NOTE: `getMonitor` (server.js) and the `monitorList` push
 * (uptime-kuma-server.js getMonitorJSONList) both call toJSON with the default
 * includeSensitiveData=true, so the cache behind list_monitors holds the same
 * secrets; only a projection keeps them out of tool output.
 */

export const REDACTED = '***REDACTED***';

/** Secret-bearing monitor fields (camelCase = key as emitted by Monitor.toJSON). */
export const MONITOR_SECRET_FIELDS: readonly string[] = [
  // Kuma's own `includeSensitiveData` block (both 1.23.16 and 2.5.11)
  'headers',                  // monitor.headers: custom HTTP headers, routinely Authorization
  'body',                     // monitor.body: request body, may carry credentials
  'grpcBody',                 // grpc_body
  'grpcMetadata',             // grpc_metadata: gRPC metadata, routinely auth tokens
  'basic_auth_user',          // basic auth identity
  'basic_auth_pass',          // basic auth password
  'oauth_client_id',          // OAuth2 client credentials identity
  'oauth_client_secret',      // OAuth2 client secret
  'oauth_token_url',          // OAuth2 token endpoint (in Kuma's sensitive block)
  'oauth_scopes',             // in Kuma's sensitive block
  'oauth_audience',           // in Kuma's sensitive block (2.x)
  'oauth_auth_method',        // in Kuma's sensitive block
  'pushToken',                // push_token: URL-embedded secret for push/dead-man monitors
  'databaseConnectionString', // database_connection_string: DSN with embedded password
  'radiusUsername',           // radius_username
  'radiusPassword',           // radius_password (also reused as the SNMP community string)
  'radiusSecret',             // radius_secret: RADIUS shared secret
  'mqttUsername',             // mqtt_username
  'mqttPassword',             // mqtt_password
  'authWorkstation',          // NTLM workstation (auth_workstation)
  'authDomain',               // NTLM domain (auth_domain)
  'tlsCa',                    // tls_ca: CA PEM
  'tlsCert',                  // tls_cert: client certificate PEM
  'tlsKey',                   // tls_key: client private key PEM
  'kafkaProducerSaslOptions', // kafka_producer_sasl_options: SASL mechanism, username, password
  // 2.x additions inside the same sensitive block
  'bearer_token',             // bearer_token (2.5.x, migration 2026-05-20-0000-add-bearer-token)
  'gamedigToken',             // gamedig_token (migration 2026-05-25-0000-add-gamedig-token)
  'mqttWebsocketPath',        // mqtt_websocket_path (migration 2025-07-17-0000)
  'rabbitmqUsername',         // rabbitmq_username (migration 2024-10-1315-rabbitmq-monitor)
  'rabbitmqPassword',         // rabbitmq_password
  'sshUsername',              // ssh_username (migration 2026-08-07-0000-add-sftp-monitor)
  'sshPassword',              // ssh_password
  'sshPrivateKey',            // ssh_private_key
  'sshPassphrase',            // ssh_passphrase
  // Outside the sensitive block but secret-shaped
  'screenshot',               // real-browser monitors: "/screenshots/<JWT>.png", a signed access URL
];

/** Non-secret monitor fields allowed through (rest of Monitor.toJSON, 1.23.16 U 2.5.11). */
export const MONITOR_SAFE_FIELDS: readonly string[] = [
  'id', 'name', 'description', 'path', 'pathName', 'parent', 'childrenIDs',
  'url', 'wsIgnoreSecWebsocketAcceptHeader', 'wsSubprotocol', 'method',
  'hostname', 'port', 'location', 'protocol', 'maxretries', 'weight', 'active',
  'forceInactive', 'type', 'subtype', 'timeout', 'interval', 'retryInterval',
  'retryOnlyOnStatusCodeFailure', 'resendInterval', 'keyword', 'invertKeyword',
  'expiryNotification', 'domainExpiryNotification', 'ignoreTls', 'upsideDown',
  'packetSize', 'maxredirects', 'accepted_statuscodes', 'dns_resolve_type',
  'dns_resolve_server', 'dns_last_result', 'docker_container',
  'docker_host',      // numeric id of the docker_host row; its credentials live in another table
  'proxyId',          // numeric id of the proxy row; its credentials live in another table
  'notificationIDList', 'tags', 'maintenance', 'mqttTopic', 'mqttSuccessMessage',
  'mqttCheckType', 'databaseQuery', 'authMethod', 'grpcUrl', 'grpcProtobuf',
  'grpcMethod', 'grpcServiceName', 'grpcEnableTls', 'radiusCalledStationId',
  'radiusCallingStationId', 'game', 'gamedigGivenPortOnly', 'httpBodyEncoding',
  'jsonPath', 'expectedValue', 'system_service_name', 'kafkaProducerTopic',
  'kafkaProducerBrokers', 'kafkaProducerSsl', 'kafkaProducerAllowAutoTopicCreation',
  'kafkaProducerMessage', 'cacheBust',
  'remote_browser',   // numeric id of the remote_browser row
  'screenshot_delay', 'snmpOid', 'jsonPathOperator', 'snmpVersion', 'smtpSecurity',
  'rabbitmqNodes', 'conditions', 'ntpStratumThreshold', 'ntpTimeOffsetThreshold',
  'ntpRootDispersionThreshold', 'ipFamily', 'sftpPath', 'sshAuthMethod',
  'ping_numeric', 'ping_count', 'ping_per_request_timeout', 'saveResponse',
  'saveErrorResponse', 'responseMaxLength',
];

/** Keys dropped silently (they describe the redaction mode of Kuma's own output and would mislead). */
export const MONITOR_IGNORED_FIELDS: readonly string[] = ['includeSensitiveData'];

/** Safe string fields that can still embed credentials when an operator pastes a credentialed URL. */
const URL_SCRUB_FIELDS: readonly string[] = ['url', 'hostname', 'grpcUrl'];
const URL_LIST_FIELDS: readonly string[] = ['rabbitmqNodes', 'kafkaProducerBrokers'];
const IGNORED_SET = new Set(MONITOR_IGNORED_FIELDS);

const SECRET_SET = new Set(MONITOR_SECRET_FIELDS);
const SAFE_SET = new Set(MONITOR_SAFE_FIELDS);

/** Hosts whose webhook URLs carry the secret in the path: any non-root path is masked. */
const WEBHOOK_HOSTS = [
  'hooks.slack.com', 'discord.com', 'discordapp.com', 'api.telegram.org', 'outlook.office.com',
  'webhook.office.com', 'hooks.zapier.com', 'events.pagerduty.com', 'hc-ping.com', 'maker.ifttt.com',
  'chat.googleapis.com', 'api.opsgenie.com', 'api.pushover.net', 'hooks.mattermost.com',
];
/** Path prefixes that conventionally precede an embedded secret. */
const SECRET_PATH_PREFIXES = ['services', 'webhooks', 'webhook', 'hooks', 'push', 'bot', 'send', 'integrations'];

function tokenishSegment(seg: string): boolean {
  let d = seg;
  try { d = decodeURIComponent(seg); } catch { /* keep raw */ }
  if (!/^[A-Za-z0-9_\-.~]+$/.test(d)) return false;
  if (d.length >= 20) return true;
  return d.length >= 12 && /[A-Za-z]/.test(d) && /[0-9]/.test(d);
}

/**
 * Fail-closed URL scrub. Returns REDACTED (the whole value) when the string:
 *  - contains any of `@ ? # ;` (userinfo incl. token-as-username or empty user,
 *    query keys of any shape, fragments, path params, scheme-less user:pass@host);
 *  - is a URL on a known webhook host with a non-root path;
 *  - has a path starting with a secret-bearing prefix followed by more segments;
 *  - has a path segment that looks like a token (>=20 chars, or >=12 with letters and digits).
 * Unparseable strings without the special characters above are returned unchanged
 * (a bare hostname is not a URL). Path secrets in an arbitrary monitor `url` cannot
 * be detected generically; this is a heuristic and is documented as a residual.
 */
export function scrubUrl(val: unknown): unknown {
  if (typeof val !== 'string' || val === '') return val;
  if (/[@?#;]/.test(val)) return REDACTED;
  let u: URL;
  try { u = new URL(val); } catch { return scrubSchemeless(val); }
  if (u.username || u.password || u.search || u.hash) return REDACTED;
  const host = u.hostname.toLowerCase();
  const segs = u.pathname.split('/').filter(Boolean);
  if (segs.length === 0) return val;
  if (WEBHOOK_HOSTS.some((h) => host === h || host.endsWith('.' + h))) return REDACTED;
  const first = segs[0].toLowerCase().replace(/^bot[0-9].*/, 'bot');
  if (segs.length >= 2 && SECRET_PATH_PREFIXES.includes(first)) return REDACTED;
  if (segs.some(tokenishSegment)) return REDACTED;
  return val;
}
/**
 * `new URL()` threw: the value is scheme-less (`host/services/T/B/<token>`, `host:443/<token>`
 * parses, `host/ping/<token>` does not). A bare hostname has no `/` and passes. With a `/`, apply the
 * same webhook-host, secret-prefix and token-segment checks to the pieces after the host.
 */
function scrubSchemeless(val: string): string {
  const parts = val.split('/');
  if (parts.length < 2) return val;
  const host = parts[0].toLowerCase().replace(/:\d+$/, '');
  const rest = parts.slice(1).filter(Boolean);
  if (rest.length === 0) return val;
  if (WEBHOOK_HOSTS.some((h) => host === h || host.endsWith('.' + h))) return REDACTED;
  if (rest.length >= 2 && SECRET_PATH_PREFIXES.includes(rest[0].toLowerCase())) return REDACTED;
  if (rest.some(tokenishSegment)) return REDACTED;
  return val;
}
export const scrubUrlField = scrubUrl;

/** True if scrubUrl would mask the value. */
export function urlEmbedsCreds(val: unknown): boolean {
  return typeof val === 'string' && scrubUrl(val) === REDACTED;
}

function scrubUrlList(v: unknown): unknown {
  return Array.isArray(v) ? v.map(scrubUrl) : v;
}

/** Presence = holds a non-empty value. Never derived from, or leaks, the value itself. */
function isPresent(v: unknown): boolean {
  if (v === undefined || v === null || v === '') return false;
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === 'object') return Object.keys(v as object).length > 0;
  return true;
}

export interface RedactedField {
  value: typeof REDACTED;
  present: boolean;
}

/**
 * Project a raw Kuma monitor object onto the allowlist. Secret fields become
 * `{ value: '***REDACTED***', present }` (emitted only when the key exists on
 * the source object, so version differences carry through). Unknown keys are
 * dropped; their names (never values) are listed in `droppedFields`.
 */
export function redactMonitor(monitor: any): any {
  if (monitor === null || monitor === undefined) return monitor;
  // Fail closed: anything that is not a plain object (JSON string, array, ...) is never passed through.
  if (typeof monitor !== 'object' || Array.isArray(monitor)) return REDACTED;
  const out: Record<string, unknown> = {};
  const dropped: string[] = [];
  for (const [k, v] of Object.entries(monitor)) {
    if (SECRET_SET.has(k)) {
      out[k] = { value: REDACTED, present: isPresent(v) } satisfies RedactedField;
    } else if (SAFE_SET.has(k)) {
      if (URL_SCRUB_FIELDS.includes(k)) out[k] = scrubUrl(v);
      else if (URL_LIST_FIELDS.includes(k)) out[k] = scrubUrlList(v);
      else out[k] = v;
    } else if (IGNORED_SET.has(k)) {
      // dropped silently
    } else {
      dropped.push(k);
    }
  }
  if (dropped.length) out.droppedFields = dropped.sort();
  return out;
}

export const WITHHELD = 'details withheld (Kuma error text can echo stored credentials)';

/**
 * Text safe to show for a failed Kuma call. Kuma validation errors embed the start of the
 * offending stored value (for example `Headers must be valid JSON: ... "X-Api-Key: ..."`),
 * so the free-text `msg` is never echoed; only a short i18n key is.
 */
export function safeFailureText(res: any): string {
  const k = res && typeof res === 'object' ? res.msgi18n : undefined;
  return typeof k === 'string' && /^[A-Za-z0-9_.-]{1,80}$/.test(k) ? k : WITHHELD;
}

/**
 * Project a Kuma Socket.IO ack that may carry a `monitor`. Only ok/msg/msgi18n/
 * monitorID/monitor survive; the monitor goes through redactMonitor; msg of a failed
 * call is replaced (see safeFailureText).
 */
export function redactMonitorAck(res: any): any {
  if (!res || typeof res !== 'object') return res;
  const out: Record<string, unknown> = {};
  for (const k of ['ok', 'msg', 'msgi18n', 'monitorID'] as const) {
    if (k in res) out[k] = res[k];
  }
  if (res.ok === false || res.ok === undefined) {
    if ('msg' in out) out.msg = WITHHELD;
    if ('msgi18n' in out && safeFailureText(res) === WITHHELD) out.msgi18n = WITHHELD;
  }
  if ('monitor' in res) out.monitor = redactMonitor(res.monitor);
  return out;
}

// ── Heartbeats (list_heartbeats) ────────────────────────────────────────────────────────────────

/**
 * Heartbeat `msg` is free text. Kuma writes `"Your JSON body is invalid. " + e.message`
 * (body excerpt) and the same for headers into it, pushers write their own text, and
 * keyword/json-query monitors put response excerpts in it. We (a) withhold any
 * JSON-parse-error text, (b) mask every URL-looking token with scrubUrl. Arbitrary
 * pusher text and response excerpts cannot be detected: documented residual.
 */
/** Heartbeat msg is cut to this many characters before any scan (pusher-controlled length). */
export const HEARTBEAT_MSG_CAP = 1024;

export function sanitizeHeartbeatMsg(input: unknown): unknown {
  if (typeof input !== 'string') return input;
  const msg: string = input.length > HEARTBEAT_MSG_CAP ? input.slice(0, HEARTBEAT_MSG_CAP) + '...[truncated]' : input;
  if (/JSON|Unexpected token|Unexpected end/i.test(msg) && /invalid|valid JSON|Unexpected|position/i.test(msg)) {
    return WITHHELD;
  }
  // Bounded scheme ({0,31}) keeps the scan linear; msg is capped first so row cost is bounded too.
  return msg.replace(/[a-z][a-z0-9+.-]{0,31}:\/\/[^\s"'<>]+/gi, (m) => String(scrubUrl(m)));
}

export function redactHeartbeatAck(res: any): any {
  if (!res || typeof res !== 'object') return res;
  const out: Record<string, unknown> = {};
  for (const k of ['ok', 'msgi18n'] as const) if (k in res) out[k] = res[k];
  if ('msg' in res) out.msg = res.ok === false ? WITHHELD : res.msg;
  if ('data' in res) {
    out.data = Array.isArray(res.data)
      ? res.data.map((row: any) => {
          if (!row || typeof row !== 'object' || Array.isArray(row)) return REDACTED;
          const r: Record<string, unknown> = {};
          for (const [k, v] of Object.entries(row)) {
            if (k === 'msg') r.msg = sanitizeHeartbeatMsg(v);
            else if (v === null || typeof v === 'number' || typeof v === 'boolean' || k === 'time' || k === 'end_time') r[k] = v;
          }
          return r;
        })
      : REDACTED;
  }
  return out;
}

// ── Notification providers (list_notifications) ──────────────────────────────────────────────

/** Config keys shown as-is. Everything else is `{value, present}`. */
const NOTIF_SAFE_CONFIG = new Set(['type', 'name', 'isDefault', 'applyExisting', 'active', 'ntfyPriority', 'ntfyAuthenticationMethod']);
/** Config keys shown only if the value is a host-only URL (no path, query, userinfo, fragment). */
const NOTIF_HOST_ONLY = new Set(['ntfyserverurl']);

function hostOnly(v: unknown): unknown {
  if (typeof v !== 'string' || scrubUrl(v) === REDACTED) return REDACTED;
  try { const u = new URL(v); return u.pathname === '/' || u.pathname === '' ? v : REDACTED; } catch { return REDACTED; }
}

/** Allowlist projection of one notification provider record. */
export function redactNotification(p: any): any {
  if (p === null || p === undefined) return p;
  if (typeof p !== 'object' || Array.isArray(p)) return REDACTED;
  const out: Record<string, unknown> = {};
  for (const k of ['id', 'name', 'active', 'isDefault']) if (k in p) out[k] = p[k];
  let cfg: any = p.config;
  if (typeof cfg === 'string') { try { cfg = JSON.parse(cfg); } catch { cfg = undefined; } }
  if (cfg === undefined && !('config' in p)) return out;
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) { out.config = REDACTED; return out; }
  const c: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(cfg)) {
    if (NOTIF_SAFE_CONFIG.has(k) && (v === null || typeof v !== 'object')) c[k] = v;
    else if (NOTIF_HOST_ONLY.has(k)) c[k] = hostOnly(v);
    else c[k] = { value: REDACTED, present: isPresent(v) };
  }
  out.config = c;
  return out;
}

// ── Write guards (H1) ─────────────────────────────────────────────────────────────────────

/**
 * Monitor fields that, if holding a value, count as a credential for the edit guard.
 * Subset of MONITOR_SECRET_FIELDS: excludes oauth endpoint/scope/audience/method,
 * mqttWebsocketPath and screenshot (not credentials; oauth_auth_method has a non-empty default).
 */
const CREDENTIAL_FIELDS: readonly string[] = [
  'headers', 'body', 'grpcBody', 'grpcMetadata', 'basic_auth_user', 'basic_auth_pass', 'oauth_client_id',
  'oauth_client_secret', 'pushToken', 'databaseConnectionString', 'radiusUsername', 'radiusPassword',
  'radiusSecret', 'mqttUsername', 'mqttPassword', 'authWorkstation', 'authDomain', 'tlsCa', 'tlsCert', 'tlsKey',
  'kafkaProducerSaslOptions', 'bearer_token', 'gamedigToken', 'rabbitmqUsername', 'rabbitmqPassword',
  'sshUsername', 'sshPassword', 'sshPrivateKey', 'sshPassphrase',
];

function credentialPresent(k: string, v: unknown): boolean {
  if (!isPresent(v)) return false;
  if (typeof v === 'string') {
    const t = v.trim();
    if (t === '{}' || t === 'null' || t === '[]') return false;
    if (k === 'kafkaProducerSaslOptions' && /"mechanism"\s*:\s*"none"/i.test(t)) return false;
  }
  if (k === 'kafkaProducerSaslOptions' && typeof v === 'object' && v && String((v as any).mechanism ?? '').toLowerCase() === 'none') return false;
  return true;
}

/** True if the RAW monitor holds any credential. */
export function monitorHoldsCredential(rawMonitor: any): boolean {
  if (!rawMonitor || typeof rawMonitor !== 'object') return true; // unknown shape: assume yes
  if (CREDENTIAL_FIELDS.some((k) => credentialPresent(k, rawMonitor[k]))) return true;
  // A credential carried in the target itself (userinfo, token query, token path) also counts.
  return ['url', 'hostname', 'grpcUrl'].some((k) => urlEmbedsCreds(rawMonitor[k]));
}

/**
 * Destination-shaping monitor fields (where or how Kuma sends a monitor's credentials),
 * from Kuma server source (monitor.js `check()` and monitor-types/*): url, hostname, port,
 * grpcUrl (target); type, subtype, protocol, location, game (which checker/target runs);
 * ignoreTls, tls* (TLS trust); proxyId (traffic relayed through a proxy);
 * docker_host/docker_container, remote_browser (execution target); oauth_token_url
 * (receives the client secret); databaseConnectionString, kafkaProducerBrokers,
 * kafkaProducerSsl, rabbitmqNodes, mqttWebsocketPath, smtpSecurity, authMethod,
 * maxredirects (redirects follow to a new host), dns_resolve_server, sftpPath.
 * The guard is an allowlist (fail closed); this list documents why those are refused.
 */
export const MONITOR_DESTINATION_FIELDS: readonly string[] = [
  'url', 'hostname', 'port', 'grpcUrl', 'type', 'subtype', 'protocol', 'location', 'game', 'ignoreTls',
  'tlsCa', 'tlsCert', 'tlsKey', 'proxyId', 'docker_host', 'docker_container', 'remote_browser',
  'oauth_token_url', 'databaseConnectionString', 'kafkaProducerBrokers', 'kafkaProducerSsl',
  'rabbitmqNodes', 'mqttWebsocketPath', 'smtpSecurity', 'authMethod', 'maxredirects', 'dns_resolve_server', 'sftpPath',
];

/** Edit keys that cannot redirect a credential; allowed even when the monitor holds credentials. */
const MONITOR_EDIT_SAFE_KEYS = new Set([
  'name', 'description', 'interval', 'retryInterval', 'resendInterval', 'maxretries', 'timeout', 'keyword',
  'invertKeyword', 'accepted_statuscodes', 'parent', 'notificationIDList', 'upsideDown', 'weight', 'expiryNotification',
]);

export const DESTINATION_REFUSAL = 'monitor holds credentials; destination change needs an operator';

function sameValue(a: unknown, b: unknown): boolean {
  try { return JSON.stringify(a) === JSON.stringify(b); } catch { return false; }
}

/**
 * Throw if `changes` would alter anything outside MONITOR_EDIT_SAFE_KEYS on a monitor that
 * holds a credential. A key whose new value equals the stored one is a no-op and ignored.
 */
export function assertMonitorEditAllowed(rawMonitor: any, changes: Record<string, unknown>): void {
  if (!monitorHoldsCredential(rawMonitor)) return;
  for (const [k, v] of Object.entries(changes)) {
    if (v === undefined || MONITOR_EDIT_SAFE_KEYS.has(k)) continue;
    if (rawMonitor && typeof rawMonitor === 'object' && k in rawMonitor && sameValue(rawMonitor[k], v)) continue;
    throw new Error(DESTINATION_REFUSAL);
  }
}

/** True if a notification config key name implies a secret (token, password, header, ...). */
export function isSecretFieldName(name: string): boolean {
  const n = name.toLowerCase();
  if (/header/.test(n)) return true;
  if (/(token|password|passwd|pwd|secret|apikey|api_key|accesskey|access_key|privatekey|private_key|credential|signingkey|appkey|authkey)/.test(n)) return true;
  return /key$/.test(n);
}

/** Notification edit keys that cannot redirect a credential. */
const NOTIF_EDIT_SAFE_KEYS = new Set(['name', 'isDefault', 'applyExisting', 'active', 'ntfyPriority']);
export const NOTIF_DESTINATION_REFUSAL = 'notification holds credentials; destination change needs an operator';

/** True if the RAW notification config holds a non-empty secret-named value. */
export function notificationHoldsCredential(cfg: any): boolean {
  if (!cfg || typeof cfg !== 'object') return true;
  // Secret-named keys, and URL-shaped keys (the webhook URL is itself the secret for Slack, Discord,
  // Mattermost, Apprise, ...; for ntfy it is the server that receives the token).
  return Object.entries(cfg).some(([k, v]) => (isSecretFieldName(k) || /url|uri|endpoint|webhook/i.test(k)) && isPresent(v));
}

export function assertNotificationEditAllowed(currentConfig: any, changes: Record<string, unknown>): void {
  if (!notificationHoldsCredential(currentConfig)) return;
  for (const [k, v] of Object.entries(changes)) {
    if (v === undefined || NOTIF_EDIT_SAFE_KEYS.has(k)) continue;
    if (currentConfig && typeof currentConfig === 'object' && k in currentConfig && sameValue(currentConfig[k], v)) continue;
    throw new Error(NOTIF_DESTINATION_REFUSAL);
  }
}

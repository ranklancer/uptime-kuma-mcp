import { io, Socket } from 'socket.io-client';
import type { KumaInstanceConfig, KumaSession, MonitorOpts } from './types.js';
import { buildAddPayload, buildEditPayload, fingerprint } from './payload.js';
import {
  redactMonitorAck, redactHeartbeatAck, redactNotification, safeFailureText,
  assertMonitorEditAllowed, assertNotificationEditAllowed,
} from './redact.js';

/** Kuma's checkLogin() throws "You are not logged in." which handlers return as { ok: false, msg }. */
export function isNotLoggedIn(res: any): boolean {
  return !!res && typeof res === 'object' && res.ok === false && typeof res.msg === 'string' && /not logged in/i.test(res.msg);
}

const TOKEN_TTL_MS = 48 * 60 * 60 * 1000; // re-auth every 48h to be safe

/** Merge desired groups with the existing list so group ids and per-monitor sendUrl/url carry over. */
export function mergeGroups(existing: any[], groups: Array<{ name: string; monitorIds: number[] }>): any[] {
  const byName = new Map<string, any>(existing.map((g) => [g?.name, g]));
  const anyMonitor = new Map<number, any>();
  for (const g of existing) for (const m of g?.monitorList ?? []) anyMonitor.set(m.id, m);
  return groups.map((g) => {
    const old = byName.get(g.name);
    const oldMon = new Map<number, any>((old?.monitorList ?? []).map((m: any) => [m.id, m]));
    const out: Record<string, any> = {
      name: g.name,
      monitorList: g.monitorIds.map((id) => {
        const prev = oldMon.get(id) ?? anyMonitor.get(id);
        const m: Record<string, any> = { id };
        if (prev?.sendUrl !== undefined) m.sendUrl = prev.sendUrl;
        if (prev?.url !== undefined) m.url = prev.url;
        return m;
      }),
    };
    if (old?.id) out.id = old.id;
    return out;
  });
}

export class UptimeKumaClient {
  private socket: Socket | null = null;
  private session: KumaSession | null = null;
  /** True while the socket is connected (reset by socket.io disconnect, set again on every (re)connect). */
  private connected = false;
  /**
   * True only after a successful login/loginByToken on the CURRENT socket connection.
   * Kuma ties authentication to the socket, so every (re)connect starts unauthenticated:
   * this flag is cleared on every 'connect' and 'disconnect' and set by authenticate().
   */
  private authed = false;
  private loginInFlight: Promise<void> | null = null;

  /**
   * Cached monitor list. Uptime Kuma pushes the full list via the
   * 'monitorList' Socket.IO event after login. We store it here
   * and keep it updated as the server pushes changes.
   */
  private monitorCache: Record<string, any> = {};
  private monitorCacheReady = false;
  private monitorCacheWaiters: Array<() => void> = [];

  /**
   * Cached latest heartbeat status per monitor ID.
   * Populated by the 'heartbeat' Socket.IO event that Uptime Kuma
   * pushes continuously after login.
   * Values: 0 = DOWN, 1 = UP, 2 = PENDING, 3 = MAINTENANCE
   */
  private heartbeatStatusCache: Map<number, number> = new Map();

  /**
   * Cached notification provider list. Uptime Kuma pushes the full list via
   * the 'notificationList' Socket.IO event after login — there is NO
   * request/response 'getNotificationList' event, which is why the old
   * emitWithAck('getNotificationList') call always timed out. We mirror the
   * monitorList caching pattern instead for reliable, instant reads.
   */
  private notificationCache: any[] = [];
  private notificationCacheReady = false;
  private notificationCacheWaiters: Array<() => void> = [];

  /** `ioFactory` is injectable so tests can drive the reconnect/re-auth paths with a fake socket. */
  constructor(private cfg: KumaInstanceConfig, private ioFactory: typeof io = io) {}

  // ── Connection management ───────────────────────────────────

  /**
   * Ensure the Socket.IO connection is up AND logged in.
   *
   * Kuma binds auth to the socket. socket.io auto-reconnects after a Kuma restart, but the
   * new server-side socket is unauthenticated, so every reconnect must re-login before the
   * next call (otherwise Kuma replies "You are not logged in.").
   */
  private async ensureConnected(): Promise<Socket> {
    // No socket, or socket.io gave up reconnecting: build a fresh connection (connect() logs in).
    if (!this.socket || (!this.socket.connected && !this.socket.active)) {
      await this.connect();
      return this.socket!;
    }
    // socket.io is mid-reconnect: wait for it rather than emitting into a dead socket.
    if (!this.socket.connected) await this.waitForReconnect();

    const tokenExpired = !!this.session && Date.now() - this.session.obtainedAt >= TOKEN_TTL_MS;
    if (!this.authed || !this.session || tokenExpired) {
      await this.authenticate();
    }
    return this.socket!;
  }

  private waitForReconnect(timeoutMs = 15_000): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const sock = this.socket;
      if (!sock) return reject(new Error(`[${this.cfg.name}] no socket connection`));
      if (sock.connected) return resolve();
      const timer = setTimeout(() => {
        sock.off('connect', onConnect);
        reject(new Error(`[${this.cfg.name}] timeout waiting for Socket.IO reconnect`));
      }, timeoutMs);
      const onConnect = () => { clearTimeout(timer); resolve(); };
      sock.once('connect', onConnect);
    });
  }

  /** Reset per-connection state: the new Kuma socket is unauthenticated and will re-push its lists after login. */
  private markLoggedOut(): void {
    this.authed = false;
    this.loginInFlight = null;
    this.monitorCacheReady = false;
    this.notificationCacheReady = false;
  }

  /** Establish a Socket.IO connection and authenticate. */
  private async connect(): Promise<void> {
    if (this.socket) {
      try { this.socket.removeAllListeners(); this.socket.disconnect(); } catch { /* swallow */ }
    }

    // Reset cache state on new connection
    this.monitorCache = {};
    this.heartbeatStatusCache.clear();
    this.notificationCache = [];
    this.connected = false;
    this.markLoggedOut();

    this.socket = this.ioFactory(this.cfg.baseUrl, {
      path: '/socket.io',
      transports: ['websocket'],
      reconnection: true,
      reconnectionAttempts: Infinity,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 15_000,
      timeout: 10_000,
      rejectUnauthorized: !this.cfg.insecureTLS,
    });

    // Persistent lifecycle handlers, registered BEFORE anything else so they run first on
    // every (re)connect: a new connection is never authenticated.
    this.socket.on('connect', () => { this.connected = true; this.markLoggedOut(); });
    this.socket.on('disconnect', () => { this.connected = false; this.markLoggedOut(); });

    // Listen for monitor list pushes from Uptime Kuma.
    // This event fires after login and on every monitor change.
    this.socket.on('monitorList', (data: Record<string, any>) => {
      this.monitorCache = data;
      if (!this.monitorCacheReady) {
        this.monitorCacheReady = true;
        // Wake up anyone waiting for the initial list
        for (const resolve of this.monitorCacheWaiters) resolve();
        this.monitorCacheWaiters = [];
      }
    });

    // Listen for notification list pushes. Uptime Kuma emits 'notificationList'
    // after login and on every notification change — directly analogous to the
    // monitorList event above. This is the reliable source of truth (there is
    // no ack-based 'getNotificationList' event server-side).
    this.socket.on('notificationList', (data: any[]) => {
      this.notificationCache = Array.isArray(data) ? data : [];
      if (!this.notificationCacheReady) {
        this.notificationCacheReady = true;
        for (const resolve of this.notificationCacheWaiters) resolve();
        this.notificationCacheWaiters = [];
      }
    });

    // Listen for real-time heartbeat events to track monitor status.
    // Uptime Kuma pushes these continuously after login for every check.
    this.socket.on('heartbeat', (heartbeat: any) => {
      if (heartbeat && typeof heartbeat.monitorID === 'number' && typeof heartbeat.status === 'number') {
        this.heartbeatStatusCache.set(heartbeat.monitorID, heartbeat.status);
      }
    });

    // Seed heartbeat status cache from initial heartbeat list push.
    // Uptime Kuma sends 'heartbeatList' per monitor with recent beats after login.
    this.socket.on('heartbeatList', (monitorId: number, beats: any[]) => {
      if (Array.isArray(beats) && beats.length > 0) {
        const latest = beats[beats.length - 1];
        if (latest && typeof latest.status === 'number') {
          this.heartbeatStatusCache.set(monitorId, latest.status);
        }
      }
    });

    await new Promise<void>((resolve, reject) => {
      const sock = this.socket!;
      const timer = setTimeout(() => reject(new Error(
        `[${this.cfg.name}] Socket.IO connection timeout to ${this.cfg.baseUrl}`
      )), 15_000);

      if (sock.connected) { clearTimeout(timer); return resolve(); }
      sock.once('connect', () => { clearTimeout(timer); resolve(); });
      // Only the FIRST connect_error is fatal for this call; socket.io keeps retrying afterwards.
      sock.once('connect_error', (err) => {
        clearTimeout(timer);
        reject(new Error(`[${this.cfg.name}] Socket.IO connect error: ${err.message}`));
      });
    });

    await this.authenticate();
  }

  /** Authenticate via Socket.IO login event (single-flight: concurrent callers share one login). */
  private authenticate(): Promise<void> {
    if (!this.loginInFlight) {
      const p: Promise<void> = this.doAuthenticate().finally(() => {
        if (this.loginInFlight === p) this.loginInFlight = null;
      });
      this.loginInFlight = p;
    }
    return this.loginInFlight;
  }

  private async doAuthenticate(): Promise<void> {
    if (!this.socket) throw new Error(`[${this.cfg.name}] no socket connection`);
    const sock = this.socket;
    this.authed = false;

    // Try loginByToken first if we have a cached token
    if (this.session?.token) {
      const tokenRes = await this.emitWithAck('loginByToken', this.session.token);
      if (tokenRes?.ok) {
        this.session.obtainedAt = Date.now();
        if (this.socket === sock && sock.connected) this.authed = true;
        return;
      }
      this.session = null; // rejected (expired / Kuma restarted with a new secret): fall back to password
    }

    const res = await this.emitWithAck('login', {
      username: this.cfg.username,
      password: this.cfg.password,
      token: '',
    });

    if (!res?.ok) {
      throw new Error(
        `[${this.cfg.name}] auth failed: ${safeFailureText(res)}`
      );
    }

    this.session = {
      token: res.token,
      obtainedAt: Date.now(),
    };
    // Keep the token either way, but only mark THIS connection authenticated if `sock` is still the
    // current, connected socket; a login that finished after a drop or replacement must not vouch for it.
    if (this.socket === sock && sock.connected) this.authed = true;
  }

  /**
   * Emit an authenticated event. If Kuma answers "You are not logged in." (socket was
   * reconnected or the server restarted underneath us), re-login and retry exactly once.
   * Every tool-facing call goes through here; only login events use emitWithAck directly.
   */
  private async request(event: string, ...args: any[]): Promise<any> {
    const res = await this.emitWithAck(event, ...args);
    if (!isNotLoggedIn(res)) return res;
    this.authed = false;
    await this.ensureConnected();
    return this.emitWithAck(event, ...args);
  }

  /** Emit an event and wait for the callback response. */
  private emitWithAck(event: string, ...args: any[]): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.socket) return reject(new Error(`[${this.cfg.name}] no socket`));

      const timer = setTimeout(() => reject(new Error(
        `[${this.cfg.name}] timeout waiting for ${event} response`
      )), 30_000);

      this.socket.emit(event, ...args, (res: any) => {
        clearTimeout(timer);
        resolve(res);
      });
    });
  }

  /**
   * Wait until the monitor list has been pushed at least once.
   * Uptime Kuma sends 'monitorList' shortly after login.
   */
  private async waitForMonitorCache(timeoutMs = 15_000): Promise<void> {
    if (this.monitorCacheReady) return;
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`[${this.cfg.name}] timeout waiting for monitorList event`));
      }, timeoutMs);
      this.monitorCacheWaiters.push(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }

  /**
   * Wait until the notification list has been pushed at least once.
   * Uptime Kuma sends 'notificationList' shortly after login.
   */
  private async waitForNotificationCache(timeoutMs = 15_000): Promise<void> {
    if (this.notificationCacheReady) return;
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`[${this.cfg.name}] timeout waiting for notificationList event`));
      }, timeoutMs);
      this.notificationCacheWaiters.push(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }

  /** Disconnect the Socket.IO client gracefully. */
  async disconnect(): Promise<void> {
    if (this.socket) {
      try { this.socket.disconnect(); } catch { /* swallow */ }
      this.socket = null;
    }
    this.connected = false;
    this.authed = false;
    this.loginInFlight = null;
    this.session = null;
    this.monitorCache = {};
    this.monitorCacheReady = false;
    this.heartbeatStatusCache.clear();
    this.notificationCache = [];
    this.notificationCacheReady = false;
  }

  // ── Read operations ─────────────────────────────────────────

  /** List all monitors from the cached monitorList event data. */
  async listMonitors(): Promise<Record<string, any>> {
    await this.ensureConnected();
    await this.waitForMonitorCache();
    return this.monitorCache;
  }

  /**
   * Get the latest heartbeat status for each monitor.
   * Returns a Map of monitorId → status (0=DOWN, 1=UP, 2=PENDING, 3=MAINTENANCE).
   */
  getHeartbeatStatuses(): Map<number, number> {
    return this.heartbeatStatusCache;
  }

  /**
   * Get a single monitor by ID. REDACTED: Kuma's getMonitor ack carries every
   * monitor credential (push token, basic-auth password, headers, DSN, ...), so
   * the ack is projected through the allowlist in redact.ts. Internal merge
   * paths (editMonitor) must use getMonitorRaw instead.
   */
  async getMonitor(monitorId: number): Promise<any> {
    return redactMonitorAck(await this.getMonitorRaw(monitorId));
  }

  /** INTERNAL / RAW: unredacted ack. Never return this from a tool; editMonitor needs the real values to merge. */
  private async getMonitorRaw(monitorId: number): Promise<any> {
    await this.ensureConnected();
    return this.request('getMonitor', monitorId);
  }

  /**
   * Get heartbeat history for a monitor over the last `periodHours` hours.
   *
   * Uptime Kuma's server-side getMonitorBeats treats the second argument as a
   * POSITIVE number of hours to look back (it binds `-period` into the SQL time
   * window). The previous value of `-1` therefore produced a `+1h` window into
   * the FUTURE, which matched no past beats and always returned empty. Passing a
   * positive hours window (default 24h) returns the expected recent beats.
   */
  async getHeartbeats(monitorId: number, periodHours = 24): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('getMonitorBeats', monitorId, periodHours);
    return redactHeartbeatAck(res);
  }

  /**
   * List notification providers. Returns the list pushed by Uptime Kuma via the
   * 'notificationList' event (cached). Each item: { id, name, active, userId,
   * isDefault, config } where `config` holds the type-specific settings.
   *
   * NOTE: previously this used emitWithAck('getNotificationList'), which has no
   * server-side ack handler and therefore always timed out. The cache approach
   * is reliable and returns instantly once the post-login push has arrived.
   *
   * SECRETS: provider `config` blobs hold live secrets (access tokens, webhook URLs
   * with the secret in the path, auth headers). This read path is an ALLOWLIST
   * projection (redactNotification): only type/name/flags/topic/priority and a
   * host-only ntfy server URL pass; every other config key is { value, present }.
   * The cache is left untouched.
   */
  async listNotifications(): Promise<any[]> {
    await this.ensureConnected();
    await this.waitForNotificationCache();
    return this.notificationCache.map(redactNotification);
  }

  /**
   * Return a single cached notification provider by ID, or undefined.
   *
   * INTERNAL / RAW: this intentionally returns the UNREDACTED provider because
   * it is used by update_notification to fetch-merge-save the existing config —
   * masking here would write '***REDACTED***' back over real secrets. It is not
   * exposed as a read tool. Read-facing output must go through listNotifications
   * (or redactNotification) instead.
   */
  async getNotification(notificationId: number): Promise<any | undefined> {
    await this.ensureConnected();
    await this.waitForNotificationCache();
    return this.notificationCache.find((n: any) => n?.id === notificationId);
  }

  /** List status pages. */
  async listStatusPages(): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('getStatusPageList');
    return res;
  }

  /** List all tags. */
  async listTags(): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('getTags');
    return res;
  }

  /** List maintenance windows. */
  async listMaintenance(): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('getMaintenanceList');
    return res;
  }

  // ── Write operations ────────────────────────────────────────

  /**
   * Add a new monitor. The payload is the full set of defaults the Kuma UI sends
   * (see payload.ts), so no NOT NULL column is left undefined.
   *
   * PUSH MONITORS: a push token is generated client-side (as the UI does) when none is
   * supplied. The token is a bearer secret (anyone holding it can forge heartbeats), so it is
   * NEVER returned: the response carries the monitor id and a token fingerprint only. The
   * operator reads the real push URL from the Kuma UI.
   */
  async addMonitor(opts: MonitorOpts): Promise<any> {
    await this.ensureConnected();
    const monitorData = buildAddPayload(opts);
    const res = await this.request('add', monitorData);
    if (!res?.ok) {
      throw new Error(`[${this.cfg.name}] add monitor failed: ${safeFailureText(res)}`);
    }
    const out = redactMonitorAck(res);
    if (monitorData.type === 'push' && monitorData.pushToken) {
      out.pushTokenFingerprint = fingerprint(String(monitorData.pushToken));
    }
    return out;
  }

  /**
   * Edit an existing monitor: load the current monitor, merge the changes and emit the FULL
   * object (Kuma's editMonitor overwrites every column from the payload, so a partial object
   * would blank or fail to persist the fields it omits).
   */
  async editMonitor(monitorId: number, opts: MonitorOpts): Promise<any> {
    await this.ensureConnected();
    // Fetch current data first to merge
    const current = await this.getMonitorRaw(monitorId);
    if (!current?.monitor) {
      throw new Error(`[${this.cfg.name}] monitor ${monitorId} not found`);
    }
    // H1: a monitor that holds credentials may not be repointed (Kuma would send the stored
    // credentials to the new destination on the next check). Compared against RAW values.
    assertMonitorEditAllowed(current.monitor, opts);
    const merged = buildEditPayload(current.monitor, opts, monitorId);
    const res = await this.request('editMonitor', merged);
    if (!res?.ok) {
      throw new Error(`[${this.cfg.name}] edit monitor failed: ${safeFailureText(res)}`);
    }
    return redactMonitorAck(res);
  }

  /** Delete a monitor by ID. */
  async deleteMonitor(monitorId: number): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('deleteMonitor', monitorId);
    if (!res?.ok) {
      throw new Error(`[${this.cfg.name}] delete monitor failed: ${safeFailureText(res)}`);
    }
    return res;
  }

  /** Pause a monitor by ID. */
  async pauseMonitor(monitorId: number): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('pauseMonitor', monitorId);
    if (!res?.ok) {
      throw new Error(`[${this.cfg.name}] pause monitor failed: ${safeFailureText(res)}`);
    }
    return res;
  }

  /** Resume a monitor by ID. */
  async resumeMonitor(monitorId: number): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('resumeMonitor', monitorId);
    if (!res?.ok) {
      throw new Error(`[${this.cfg.name}] resume monitor failed: ${safeFailureText(res)}`);
    }
    return res;
  }

  // ── Notification provider write operations ──────────────────

  /**
   * Create or update a notification provider.
   * Pass notificationID = null to create, or an existing ID to update.
   * `notification` is a flat config object: { name, type, isDefault,
   * applyExisting, ...type-specific fields }. Uptime Kuma serialises the whole
   * object as the provider's JSON config.
   * Returns { ok, msg, id }.
   */
  async saveNotification(
    notification: Record<string, any>,
    notificationID: number | null = null,
  ): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('addNotification', notification, notificationID ?? null);
    if (!res?.ok) {
      throw new Error(`[${this.cfg.name}] save notification failed: ${safeFailureText(res)}`);
    }
    return res;
  }

  /**
   * Fetch-merge-save update of a notification provider. If the stored config holds any
   * secret, destination-shaping keys (server/webhook URLs, type, ...) cannot be changed
   * (H1): the next alert would send the stored token to the new destination.
   */
  async updateNotification(
    notificationId: number,
    args: { name?: string; type?: string; isDefault?: boolean; applyExisting?: boolean; config?: Record<string, any> },
  ): Promise<any> {
    const existing = await this.getNotification(notificationId);
    if (!existing) throw new Error(`Notification provider ${notificationId} not found`);
    // The cached `config` may be an object or a JSON string depending on the Kuma version.
    let currentConfig: Record<string, any> = {};
    const rawConfig = (existing as any).config;
    if (rawConfig && typeof rawConfig === 'object') currentConfig = rawConfig;
    else if (typeof rawConfig === 'string') {
      try { currentConfig = JSON.parse(rawConfig); } catch { currentConfig = {}; }
    }
    const changes: Record<string, unknown> = {
      ...(args.name !== undefined ? { name: args.name } : {}),
      ...(args.type !== undefined ? { type: args.type } : {}),
      ...(args.isDefault !== undefined ? { isDefault: args.isDefault } : {}),
      ...(args.applyExisting !== undefined ? { applyExisting: args.applyExisting } : {}),
      ...(args.config ?? {}),
    };
    assertNotificationEditAllowed(currentConfig, changes);
    const merged: Record<string, any> = { ...currentConfig, ...changes };
    // Kuma requires name and type to be present on save.
    if (merged.name === undefined) merged.name = (existing as any).name;
    return this.saveNotification(merged, notificationId);
  }

  /** Delete a notification provider by ID. Returns { ok, msg }. */
  async deleteNotification(notificationID: number): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('deleteNotification', notificationID);
    if (!res?.ok) {
      throw new Error(`[${this.cfg.name}] delete notification failed: ${safeFailureText(res)}`);
    }
    return res;
  }

  // ── Monitor ↔ notification assignment ───────────────────────

  /**
   * Replace a monitor's notification assignments with the given map.
   * `notificationIDList` looks like { "1": true, "2": true }. An empty map
   * detaches all notifications. Delegates to editMonitor, which fetches the
   * current monitor and merges, so all other monitor settings are preserved.
   */
  async setMonitorNotifications(
    monitorId: number,
    notificationIDList: Record<string, boolean>,
  ): Promise<any> {
    return this.editMonitor(monitorId, { notificationIDList });
  }

  /**
   * Attach or detach a single notification provider across all monitors,
   * preserving each monitor's other notification assignments.
   *
   * When opts.dryRun is true, returns the planned changes WITHOUT applying them
   * — use this to preview a bulk migration safely. Group monitors are skipped
   * unless opts.includeGroups is true.
   */
  async applyNotificationToAllMonitors(
    notificationId: number,
    enabled: boolean,
    opts: { dryRun?: boolean; includeGroups?: boolean } = {},
  ): Promise<any> {
    await this.ensureConnected();
    const monitors = await this.listMonitors();
    const list = Object.values(monitors) as any[];
    const key = String(notificationId);

    const planned: Array<{ id: number; name: string; from: boolean; to: boolean }> = [];
    for (const m of list) {
      if (!opts.includeGroups && m.type === 'group') continue;
      const current = !!(m.notificationIDList && m.notificationIDList[key]);
      if (current === enabled) continue; // already in desired state — skip
      planned.push({ id: m.id, name: m.name, from: current, to: enabled });
    }

    if (opts.dryRun) {
      return {
        dryRun: true,
        notificationId,
        enabled,
        totalMonitors: list.length,
        toChange: planned.length,
        changes: planned,
      };
    }

    const results: Array<{ id: number; name: string; ok: boolean; error?: string }> = [];
    for (const p of planned) {
      try {
        const m = (monitors as Record<string, any>)[String(p.id)]
          ?? list.find((x: any) => x.id === p.id);
        const newList: Record<string, boolean> = { ...(m?.notificationIDList ?? {}) };
        if (enabled) newList[key] = true;
        else delete newList[key];
        await this.editMonitor(p.id, { notificationIDList: newList });
        results.push({ id: p.id, name: p.name, ok: true });
      } catch (err: any) {
        results.push({ id: p.id, name: p.name, ok: false, error: String(err?.message ?? err) });
      }
    }

    return {
      dryRun: false,
      notificationId,
      enabled,
      totalMonitors: list.length,
      attempted: planned.length,
      succeeded: results.filter((r) => r.ok).length,
      failed: results.filter((r) => !r.ok).length,
      results,
    };
  }

  // ── Tags ────────────────────────────────────────────────────

  /** Create a tag. Returns { ok, tag }. */
  async createTag(name: string, color: string): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('addTag', { name, color });
    if (!res?.ok) throw new Error(`[${this.cfg.name}] create tag failed: ${safeFailureText(res)}`);
    return res;
  }

  /** Attach an existing tag (with optional value) to a monitor. */
  async addMonitorTag(tagId: number, monitorId: number, value = ''): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('addMonitorTag', tagId, monitorId, value);
    if (!res?.ok) throw new Error(`[${this.cfg.name}] add monitor tag failed: ${safeFailureText(res)}`);
    return res;
  }

  /** Detach a tag (matched on tag + monitor + value) from a monitor. */
  async removeMonitorTag(tagId: number, monitorId: number, value = ''): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('deleteMonitorTag', tagId, monitorId, value);
    if (!res?.ok) throw new Error(`[${this.cfg.name}] remove monitor tag failed: ${safeFailureText(res)}`);
    return res;
  }

  // ── Maintenance ─────────────────────────────────────────────

  /**
   * Create a maintenance window (Kuma's Maintenance.jsonToBean shape) and optionally attach
   * monitors. Returns { ok, maintenanceID }.
   */
  async addMaintenance(maintenance: Record<string, any>, monitorIds: number[] = []): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('addMaintenance', maintenance);
    if (!res?.ok) throw new Error(`[${this.cfg.name}] add maintenance failed: ${safeFailureText(res)}`);
    if (monitorIds.length > 0) {
      const att = await this.request('addMonitorMaintenance', res.maintenanceID, monitorIds.map((id) => ({ id })));
      if (!att?.ok) {
        throw new Error(
          `[${this.cfg.name}] maintenance ${res.maintenanceID} created but attaching monitors failed: ${safeFailureText(att)}`);
      }
    }
    return res;
  }

  /** Replace the monitors attached to a maintenance window. */
  async setMaintenanceMonitors(maintenanceId: number, monitorIds: number[]): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('addMonitorMaintenance', maintenanceId, monitorIds.map((id) => ({ id })));
    if (!res?.ok) throw new Error(`[${this.cfg.name}] set maintenance monitors failed: ${safeFailureText(res)}`);
    return res;
  }

  async pauseMaintenance(maintenanceId: number): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('pauseMaintenance', maintenanceId);
    if (!res?.ok) throw new Error(`[${this.cfg.name}] pause maintenance failed: ${safeFailureText(res)}`);
    return res;
  }

  async resumeMaintenance(maintenanceId: number): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('resumeMaintenance', maintenanceId);
    if (!res?.ok) throw new Error(`[${this.cfg.name}] resume maintenance failed: ${safeFailureText(res)}`);
    return res;
  }

  async deleteMaintenance(maintenanceId: number): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('deleteMaintenance', maintenanceId);
    if (!res?.ok) throw new Error(`[${this.cfg.name}] delete maintenance failed: ${safeFailureText(res)}`);
    return res;
  }

  // ── Status pages ────────────────────────────────────────────

  /** Create an (empty) status page. Returns { ok, slug }. */
  async addStatusPage(title: string, slug: string): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('addStatusPage', title, slug);
    if (!res?.ok) throw new Error(`[${this.cfg.name}] add status page failed: ${safeFailureText(res)}`);
    return res;
  }

  /**
   * Save a status page. Kuma's saveStatusPage REPLACES the whole group list, so `groups` is
   * required and is the complete desired list. Page config is loaded, merged with `changes`
   * and re-sent in full; the existing logo path is preserved.
   */
  async saveStatusPage(
    slug: string,
    changes: { title?: string; description?: string; theme?: string; footerText?: string; showPoweredBy?: boolean; showTags?: boolean; autoRefreshInterval?: number },
    groups: Array<{ name: string; monitorIds: number[] }>,
    opts: { confirmPublic?: boolean } = {},
  ): Promise<any> {
    await this.ensureConnected();
    const cur = await this.request('getStatusPage', slug);
    if (!cur?.ok || !cur.config) throw new Error(`[${this.cfg.name}] status page '${slug}' not found`);
    if (cur.config.published && !opts.confirmPublic) {
      throw new Error(
        `[${this.cfg.name}] status page '${slug}' is published: saving puts the listed monitors' names (and URLs, if shown) ` +
        `on a public page. Re-run with confirmPublic=true to proceed.`);
    }
    // Kuma replaces groups wholesale; load the current ones so group ids and per-monitor sendUrl/url survive.
    const existing = await this.fetchPublicGroups(slug);
    const config: Record<string, any> = { ...cur.config };
    for (const [k, v] of Object.entries(changes)) if (v !== undefined) config[k] = v;
    config.slug = slug;
    const publicGroupList = mergeGroups(existing, groups);
    const res = await this.request('saveStatusPage', slug, config, config.icon ?? '', publicGroupList);
    if (!res?.ok) throw new Error(`[${this.cfg.name}] save status page failed: ${safeFailureText(res)}`);
    return { ok: true, slug };
  }

  /** Current public group list of a status page (Kuma serves it over HTTP, not Socket.IO). Fails closed. */
  protected async fetchPublicGroups(slug: string): Promise<any[]> {
    const url = new URL(`/api/status-page/${encodeURIComponent(slug)}`, this.cfg.baseUrl);
    const mod = await import(url.protocol === 'https:' ? 'node:https' : 'node:http');
    const body = await new Promise<string>((resolve, reject) => {
      const req = mod.get(url, { timeout: 10_000, rejectUnauthorized: !this.cfg.insecureTLS } as any, (res: any) => {
        if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode}`)); }
        let data = ''; res.setEncoding('utf8');
        res.on('data', (c: string) => { data += c; if (data.length > 5_000_000) req.destroy(new Error('response too large')); });
        res.on('end', () => resolve(data));
      });
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', reject);
    }).catch((e: any) => { throw new Error(`[${this.cfg.name}] cannot load current groups of '${slug}' (${e?.message}); refusing to overwrite them`); });
    try {
      const list = JSON.parse(body)?.publicGroupList;
      if (!Array.isArray(list)) throw new Error('no publicGroupList');
      return list;
    } catch {
      throw new Error(`[${this.cfg.name}] cannot parse current groups of '${slug}'; refusing to overwrite them`);
    }
  }

  async deleteStatusPage(slug: string): Promise<any> {
    await this.ensureConnected();
    const res = await this.request('deleteStatusPage', slug);
    if (!res?.ok) throw new Error(`[${this.cfg.name}] delete status page failed: ${safeFailureText(res)}`);
    return res;
  }
}

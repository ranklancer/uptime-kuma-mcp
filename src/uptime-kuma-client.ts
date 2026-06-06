import { io, Socket } from 'socket.io-client';
import type { KumaInstanceConfig, KumaSession, MonitorOpts } from './types.js';

const TOKEN_TTL_MS = 48 * 60 * 60 * 1000; // re-auth every 48h to be safe

export class UptimeKumaClient {
  private socket: Socket | null = null;
  private session: KumaSession | null = null;
  private connected = false;

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

  constructor(private cfg: KumaInstanceConfig) {}

  // ── Connection management ───────────────────────────────────

  /** Ensure the Socket.IO connection is established and authenticated. */
  private async ensureConnected(): Promise<Socket> {
    if (this.socket && this.connected && this.session) {
      const age = Date.now() - this.session.obtainedAt;
      if (age < TOKEN_TTL_MS) return this.socket;
      // Token too old — re-auth
      await this.authenticate();
      return this.socket!;
    }

    await this.connect();
    return this.socket!;
  }

  /** Establish a Socket.IO connection and authenticate. */
  private async connect(): Promise<void> {
    if (this.socket) {
      try { this.socket.disconnect(); } catch { /* swallow */ }
    }

    // Reset cache state on new connection
    this.monitorCache = {};
    this.monitorCacheReady = false;
    this.heartbeatStatusCache.clear();
    this.notificationCache = [];
    this.notificationCacheReady = false;

    this.socket = io(this.cfg.baseUrl, {
      path: '/socket.io',
      transports: ['websocket'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      timeout: 10_000,
      rejectUnauthorized: !this.cfg.insecureTLS,
    });

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
      const timer = setTimeout(() => reject(new Error(
        `[${this.cfg.name}] Socket.IO connection timeout to ${this.cfg.baseUrl}`
      )), 15_000);

      this.socket!.on('connect', () => {
        clearTimeout(timer);
        this.connected = true;
        resolve();
      });

      this.socket!.on('connect_error', (err) => {
        clearTimeout(timer);
        reject(new Error(`[${this.cfg.name}] Socket.IO connect error: ${err.message}`));
      });
    });

    this.socket.on('disconnect', () => { this.connected = false; });

    await this.authenticate();
  }

  /** Authenticate via Socket.IO login event. */
  private async authenticate(): Promise<void> {
    if (!this.socket) throw new Error(`[${this.cfg.name}] no socket connection`);

    // Try loginByToken first if we have a cached token
    if (this.session?.token) {
      const tokenRes = await this.emitWithAck('loginByToken', this.session.token);
      if (tokenRes?.ok) {
        this.session.obtainedAt = Date.now();
        return;
      }
    }

    const res = await this.emitWithAck('login', {
      username: this.cfg.username,
      password: this.cfg.password,
      token: '',
    });

    if (!res?.ok) {
      throw new Error(
        `[${this.cfg.name}] auth failed: ${res?.msg ?? 'unknown error'}`
      );
    }

    this.session = {
      token: res.token,
      obtainedAt: Date.now(),
    };
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

  /** Get a single monitor by ID with recent heartbeats. */
  async getMonitor(monitorId: number): Promise<any> {
    await this.ensureConnected();
    const res = await this.emitWithAck('getMonitor', monitorId);
    return res;
  }

  /** Get heartbeat history for a monitor. */
  async getHeartbeats(monitorId: number): Promise<any> {
    await this.ensureConnected();
    const res = await this.emitWithAck('getMonitorBeats', monitorId, -1);
    return res;
  }

  /**
   * List notification providers. Returns the list pushed by Uptime Kuma via the
   * 'notificationList' event (cached). Each item: { id, name, active, userId,
   * isDefault, config } where `config` holds the type-specific settings.
   *
   * NOTE: previously this used emitWithAck('getNotificationList'), which has no
   * server-side ack handler and therefore always timed out. The cache approach
   * is reliable and returns instantly once the post-login push has arrived.
   */
  async listNotifications(): Promise<any[]> {
    await this.ensureConnected();
    await this.waitForNotificationCache();
    return this.notificationCache;
  }

  /** Return a single cached notification provider by ID, or undefined. */
  async getNotification(notificationId: number): Promise<any | undefined> {
    await this.ensureConnected();
    await this.waitForNotificationCache();
    return this.notificationCache.find((n: any) => n?.id === notificationId);
  }

  /** List status pages. */
  async listStatusPages(): Promise<any> {
    await this.ensureConnected();
    const res = await this.emitWithAck('getStatusPageList');
    return res;
  }

  /** List all tags. */
  async listTags(): Promise<any> {
    await this.ensureConnected();
    const res = await this.emitWithAck('getTags');
    return res;
  }

  /** List maintenance windows. */
  async listMaintenance(): Promise<any> {
    await this.ensureConnected();
    const res = await this.emitWithAck('getMaintenanceList');
    return res;
  }

  // ── Write operations ────────────────────────────────────────

  /** Add a new monitor. */
  async addMonitor(opts: MonitorOpts): Promise<any> {
    await this.ensureConnected();
    const monitorData = {
      type: opts.type ?? 'http',
      name: opts.name,
      url: opts.url,
      method: opts.method ?? 'GET',
      interval: opts.interval ?? 60,
      retryInterval: opts.retryInterval ?? 60,
      maxretries: opts.maxretries ?? 0,
      hostname: opts.hostname,
      port: opts.port,
      keyword: opts.keyword,
      accepted_statuscodes: opts.accepted_statuscodes ?? ['200-299'],
      ignoreTls: opts.ignoreTls ?? false,
      expiryNotification: opts.expiryNotification ?? false,
      maxredirects: opts.maxredirects ?? 10,
      dns_resolve_type: opts.dns_resolve_type,
      dns_resolve_server: opts.dns_resolve_server,
      notificationIDList: opts.notificationIDList ?? {},
      description: opts.description ?? '',
      parent: opts.parent,
    };
    const res = await this.emitWithAck('add', monitorData);
    if (!res?.ok) {
      throw new Error(`[${this.cfg.name}] add monitor failed: ${res?.msg ?? 'unknown'}`);
    }
    return res;
  }

  /** Edit an existing monitor. */
  async editMonitor(monitorId: number, opts: MonitorOpts): Promise<any> {
    await this.ensureConnected();
    // Fetch current data first to merge
    const current = await this.emitWithAck('getMonitor', monitorId);
    if (!current?.monitor) {
      throw new Error(`[${this.cfg.name}] monitor ${monitorId} not found`);
    }
    const merged = { ...current.monitor, ...opts, id: monitorId };
    const res = await this.emitWithAck('editMonitor', merged);
    if (!res?.ok) {
      throw new Error(`[${this.cfg.name}] edit monitor failed: ${res?.msg ?? 'unknown'}`);
    }
    return res;
  }

  /** Delete a monitor by ID. */
  async deleteMonitor(monitorId: number): Promise<any> {
    await this.ensureConnected();
    const res = await this.emitWithAck('deleteMonitor', monitorId);
    if (!res?.ok) {
      throw new Error(`[${this.cfg.name}] delete monitor failed: ${res?.msg ?? 'unknown'}`);
    }
    return res;
  }

  /** Pause a monitor by ID. */
  async pauseMonitor(monitorId: number): Promise<any> {
    await this.ensureConnected();
    const res = await this.emitWithAck('pauseMonitor', monitorId);
    if (!res?.ok) {
      throw new Error(`[${this.cfg.name}] pause monitor failed: ${res?.msg ?? 'unknown'}`);
    }
    return res;
  }

  /** Resume a monitor by ID. */
  async resumeMonitor(monitorId: number): Promise<any> {
    await this.ensureConnected();
    const res = await this.emitWithAck('resumeMonitor', monitorId);
    if (!res?.ok) {
      throw new Error(`[${this.cfg.name}] resume monitor failed: ${res?.msg ?? 'unknown'}`);
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
    const res = await this.emitWithAck('addNotification', notification, notificationID ?? null);
    if (!res?.ok) {
      throw new Error(`[${this.cfg.name}] save notification failed: ${res?.msg ?? 'unknown'}`);
    }
    return res;
  }

  /** Delete a notification provider by ID. Returns { ok, msg }. */
  async deleteNotification(notificationID: number): Promise<any> {
    await this.ensureConnected();
    const res = await this.emitWithAck('deleteNotification', notificationID);
    if (!res?.ok) {
      throw new Error(`[${this.cfg.name}] delete notification failed: ${res?.msg ?? 'unknown'}`);
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
}

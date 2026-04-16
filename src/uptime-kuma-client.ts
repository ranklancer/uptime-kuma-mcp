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
  }

  // ── Read operations ─────────────────────────────────────────

  /** List all monitors from the cached monitorList event data. */
  async listMonitors(): Promise<Record<string, any>> {
    await this.ensureConnected();
    await this.waitForMonitorCache();
    return this.monitorCache;
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

  /** List notification channels. */
  async listNotifications(): Promise<any> {
    await this.ensureConnected();
    const res = await this.emitWithAck('getNotificationList');
    return res;
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
}

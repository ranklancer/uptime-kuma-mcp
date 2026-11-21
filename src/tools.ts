import { z } from 'zod';
import { getClient, allInstanceNames } from './instances.js';
import { MONITOR_TYPES } from './types.js';
import { scrubUrlField } from './redact.js';
import { allowWriteMethods, SAFE_METHODS, WRITE_METHODS } from './policy.js';

/**
 * Build an instance selector enum from the configured instance names.
 * Falls back to a free-form string if only one instance is configured.
 */
function instanceSchema() {
  const names = allInstanceNames();
  if (names.length >= 2) {
    return z.enum(names as [string, ...string[]])
      .optional()
      .default(names[0])
      .describe(`Which Uptime Kuma instance to target. Available: ${names.join(', ')}. Defaults to ${names[0]}.`);
  }
  return z.string()
    .optional()
    .default(names[0])
    .describe(`Uptime Kuma instance name. Defaults to ${names[0]}.`);
}

const Instance = instanceSchema();


// ── Shared monitor field schema (add + edit) ────────────────────

const METHODS = (allowWriteMethods() ? [...SAFE_METHODS, ...WRITE_METHODS] : [...SAFE_METHODS]) as [string, ...string[]];

const monitorFields = {
  url:                z.string().optional().describe('URL to monitor (http/keyword types). Loopback, link-local, gateway/MCP hosts and KUMA_MCP_DENY_HOSTS entries are refused.'),
  hostname:           z.string().optional().describe('Hostname for ping/port/dns types'),
  port:               z.number().int().min(1).max(65535).optional().describe('Port number (1-65535)'),
  method:             z.enum(METHODS).optional().describe(
    allowWriteMethods() ? 'HTTP method' : 'HTTP method: GET or HEAD only (the operator can enable others with KUMA_MCP_ALLOW_WRITE_METHODS=1)'),
  interval:           z.number().int().positive().optional().describe('Check interval in seconds (default 60)'),
  retryInterval:      z.number().int().optional().describe('Retry interval in seconds (default 60)'),
  resendInterval:     z.number().int().min(0).optional().describe('Resend notification every N checks while down (0 = off)'),
  maxretries:         z.number().int().min(0).optional().describe('Max retries before marking down (default 0)'),
  timeout:            z.number().min(0).optional().describe('Check timeout in seconds (default: 80% of interval; 10 for ping)'),
  keyword:            z.string().optional().describe('Expected keyword in response (keyword type)'),
  invertKeyword:      z.boolean().optional().describe('Treat the keyword being PRESENT as a failure'),
  accepted_statuscodes: z.union([z.array(z.string()), z.string()]).optional()
    .describe('Accepted HTTP status codes: an array (["200-299","301"]) or a comma-separated string ("200-299,301")'),
  maxredirects:       z.number().int().min(0).optional().describe('Max redirects to follow (default 10)'),
  ignoreTls:          z.boolean().optional().describe('Ignore TLS certificate errors'),
  upsideDown:         z.boolean().optional().describe('Upside-down mode: reachable counts as DOWN'),
  expiryNotification: z.boolean().optional().describe('Notify on TLS certificate expiry'),
  description:        z.string().optional().describe('Monitor description'),
  parent:             z.number().int().nullable().optional().describe('Parent group monitor ID (null to move to root)'),
  dns_resolve_type:   z.string().optional().describe('DNS record type (A, AAAA, MX, ...)'),
  dns_resolve_server: z.string().optional().describe('DNS server to use for resolution'),
  docker_host:        z.number().int().nullable().optional().describe('Numeric ID of the Docker host (docker type)'),
  docker_container:   z.string().optional().describe('Container name (docker type)'),
  headers:            z.union([z.string(), z.record(z.string(), z.string())]).optional().describe('HTTP headers as a JSON object or JSON string. Treated as a credential: never echoed.'),
  body:               z.union([z.string(), z.record(z.string(), z.any())]).optional().describe('HTTP request body (JSON object or string). Refused unless the operator sets KUMA_MCP_ALLOW_WRITE_METHODS=1. Never echoed.'),
  authMethod:         z.enum(['basic', 'ntlm', 'mtls', 'oauth2-cc']).nullable().optional().describe('HTTP authentication method (null = none)'),
  basic_auth_user:    z.string().optional().describe('Basic-auth username. Never echoed.'),
  basic_auth_pass:    z.string().optional().describe('Basic-auth password. Accepted, never echoed.'),
  tags:               z.array(z.object({
    tagId: z.number().int().positive().describe('Existing tag ID (see uptimekuma_list_tags / uptimekuma_create_tag)'),
    value: z.string().optional().default('').describe('Optional tag value'),
  })).optional().describe('Tags to attach after the monitor is saved (additive; use uptimekuma_remove_monitor_tag to detach)'),
};

/** Map tool args to client MonitorOpts (notificationIds -> notificationIDList). */
function toMonitorOpts(args: Record<string, any>): Record<string, any> {
  const { notificationIds, ...opts } = args;
  if (Array.isArray(notificationIds)) {
    opts.notificationIDList = Object.fromEntries(notificationIds.map((id: number) => [String(id), true]));
  }
  return opts;
}

async function attachTags(client: ReturnType<typeof getClient>, monitorId: number, tags: Array<{ tagId: number; value?: string }>) {
  const results: Array<{ tagId: number; ok: boolean; error?: string }> = [];
  for (const t of tags) {
    try {
      await client.addMonitorTag(t.tagId, monitorId, t.value ?? '');
      results.push({ tagId: t.tagId, ok: true });
    } catch (e: any) {
      results.push({ tagId: t.tagId, ok: false, error: String(e?.message ?? e) });
    }
  }
  return results;
}

const CONFIRM_APPLY_DESC = 'Required (true) when isDefault or applyExisting is true: the provider then fires for every new / every existing monitor';

/** isDefault / applyExisting make a provider fire for many monitors at once: same explicit-confirm style as the delete calls. */
export function assertNotificationApplyConfirmed(a: { isDefault?: boolean; applyExisting?: boolean; confirmApply?: boolean }): void {
  if ((a.isDefault === true || a.applyExisting === true) && a.confirmApply !== true) {
    throw new Error('isDefault/applyExisting attach this notification provider to many monitors: pass confirmApply=true to proceed');
  }
}

/** isDefault / applyExisting inside `config` would bypass the confirmApply gate on the top-level fields. */
export function assertNoReservedConfigKeys(config: Record<string, unknown> | undefined): void {
  for (const k of ['isDefault', 'applyExisting', 'name', 'type', 'active', 'id', 'userId']) {
    if (config && k in config) throw new Error(`"${k}" must be passed as a top-level parameter, not inside config`);
  }
}

/** Longest contiguous silence (minutes) that counts as "all day": 23h. Gaps of up to 5 minutes between windows are treated as continuous. */
const LONG_SILENCE_MIN = 23 * 60;
const MERGE_GAP_MIN = 5;

/** Expand one cron field (*, n, a-b, *\/n, a-b/n, comma lists) to a set, or null when it cannot be read. */
function cronField(f: string, lo: number, hi: number): Set<number> | null {
  const out = new Set<number>();
  for (const part of f.split(',')) {
    const m = /^(\*|\d+(?:-\d+)?)(?:\/(\d+))?$/.exec(part);
    if (!m) return null;
    const step = m[2] ? Number(m[2]) : 1;
    if (step < 1) return null;
    let a = lo, b = hi;
    if (m[1] !== '*') { const [x, y] = m[1].split('-').map(Number); a = x; b = y ?? (m[2] ? hi : x); }
    if (a < lo || b > hi || a > b) return null;
    for (let v = a; v <= b; v += step) out.add(v);
  }
  return out;
}

/** True if a cron window of `duration` minutes can silence alerts continuously for 23h+ (simulated over 8 days from a fixed Monday). Unreadable cron: true (fail closed). */
function cronSilencesLong(expr: string, duration: number): boolean {
  const f = expr.trim().split(/\s+/);
  if (f.length !== 5) return true;
  const [mi, h, dom, mon, dow] = [cronField(f[0], 0, 59), cronField(f[1], 0, 23), cronField(f[2], 1, 31), cronField(f[3], 1, 12), cronField(f[4].replace(/7/g, '0'), 0, 6)];
  if (!mi || !h || !dom || !mon || !dow) return true;
  const start = Date.UTC(2030, 0, 7); // a Monday
  const wins: Array<[number, number]> = [];
  for (let t = -duration; t < 8 * 1440; t++) { // start one window early so a window that began before t=0 is counted
    const d = new Date(start + t * 60000);
    if (!mi.has(d.getUTCMinutes()) || !h.has(d.getUTCHours()) || !mon.has(d.getUTCMonth() + 1)) continue;
    const domOk = dom.has(d.getUTCDate()), dowOk = dow.has(d.getUTCDay());
    const domStar = f[2] === '*', dowStar = f[4] === '*';
    if (!(domStar || dowStar ? domOk && dowOk : domOk || dowOk)) continue; // cron: dom OR dow when both restricted
    wins.push([t, t + duration]);
  }
  let cur: [number, number] | null = null;
  for (const w of wins) {
    if (cur && w[0] <= cur[1] + MERGE_GAP_MIN) cur[1] = Math.max(cur[1], w[1]);
    else { if (cur && cur[1] - cur[0] >= LONG_SILENCE_MIN) return true; cur = [w[0], w[1]]; }
  }
  return !!cur && cur[1] - cur[0] >= LONG_SILENCE_MIN;
}

/**
 * A maintenance window silences alerts: confirm when it covers more than 5 monitors, can silence alerts
 * continuously for 23h or more (computed from the effective schedule for every strategy, e.g. a cron that
 * fires every 30 minutes with a 60 minute duration), or has no end. A typo guard, not an agent-proof control.
 */
export function maintenanceNeedsConfirm(a: {
  strategy: string; monitorIds: readonly number[]; dateRange?: readonly (string | null)[]; timeRange?: readonly { hours: number; minutes: number }[];
  durationMinutes?: number; cron?: string;
}): boolean {
  if (a.monitorIds.length > 5) return true;
  const DAY_MS = 24 * 3600 * 1000;
  switch (a.strategy) {
    case 'manual': return true; // active until someone pauses it: always confirm, whatever dateRange says
    case 'single': {
      const [s, e] = a.dateRange ?? [];
      if (!e) return true;
      const span = s ? Date.parse(e.replace(' ', 'T')) - Date.parse(s.replace(' ', 'T')) : Infinity;
      return !(span < DAY_MS); // NaN (unparseable) also needs confirm
    }
    case 'cron': return !a.cron || (a.durationMinutes ?? 60) >= LONG_SILENCE_MIN || cronSilencesLong(a.cron, a.durationMinutes ?? 60);
    default: {
      if (!a.timeRange) return false; // the handler substitutes the 02:00-03:00 default
      const [s, e] = a.timeRange;
      const span = (((e.hours * 60 + e.minutes) - (s.hours * 60 + s.minutes)) + 1440) % 1440 || 1440;
      return span >= LONG_SILENCE_MIN;
    }
  }
}

export interface ToolDef {
  name: string;
  description: string;
  schema: z.ZodType<any>;
  handler: (args: any) => Promise<any>;
}

export const toolDefs: ToolDef[] = [
  // ── Read operations ─────────────────────────────────────────────

  {
    name: 'uptimekuma_list_monitors',
    description:
      'List all monitors from Uptime Kuma with optional filtering by type, status, keyword, or tag.',
    schema: z.object({
      instance: Instance,
      type:    z.enum(MONITOR_TYPES).optional().describe('Filter by monitor type (http, ping, port, etc.)'),
      status:  z.enum(['up', 'down', 'pending', 'maintenance']).optional().describe('Filter by status'),
      keyword: z.string().optional().describe('Filter monitors whose name contains this keyword (case-insensitive)'),
      tag:     z.string().optional().describe('Filter monitors that have this tag name'),
    }),
    handler: async (args) => {
      const client = getClient(args.instance);
      const monitors = await client.listMonitors();
      let list = Object.values(monitors);

      if (args.type) list = list.filter((m: any) => m.type === args.type);
      if (args.status) {
        // Filter on LIVE heartbeat state, not the `active` (paused) flag.
        // 0=DOWN, 1=UP, 2=PENDING, 3=MAINTENANCE. Paused monitors (active=false)
        // have no live status and must never match up/down/pending/maintenance.
        const statusMap: Record<string, number> = { down: 0, up: 1, pending: 2, maintenance: 3 };
        const wanted = statusMap[args.status];
        const heartbeatStatuses = client.getHeartbeatStatuses();
        list = list.filter((m: any) => m.active && heartbeatStatuses.get(m.id) === wanted);
      }
      if (args.keyword) {
        const kw = args.keyword.toLowerCase();
        list = list.filter((m: any) => m.name?.toLowerCase().includes(kw));
      }
      if (args.tag) {
        const tagName = args.tag.toLowerCase();
        list = list.filter((m: any) =>
          m.tags?.some((t: any) => t.name?.toLowerCase() === tagName)
        );
      }

      return {
        total: list.length,
        monitors: list.map((m: any) => ({
          id: m.id,
          name: m.name,
          type: m.type,
          url: scrubUrlField(m.url),
          hostname: scrubUrlField(m.hostname),
          port: m.port,
          interval: m.interval,
          active: m.active,
          description: m.description,
          tags: m.tags,
        })),
      };
    },
  },
  {
    name: 'uptimekuma_get_monitor',
    description:
      'Get detailed information about a single monitor including its configuration. ' +
      'Credential fields (push token, passwords, headers, connection strings, keys) are redacted: ' +
      'each is returned as { value: "***REDACTED***", present: boolean }.',
    schema: z.object({
      instance:  Instance,
      monitorId: z.number().int().positive().describe('The numeric ID of the monitor'),
    }),
    handler: async (args) => getClient(args.instance).getMonitor(args.monitorId),
  },
  {
    name: 'uptimekuma_stats_summary',
    description:
      'Get an overall uptime statistics summary: total monitors, up/down/paused counts, and average uptime.',
    schema: z.object({ instance: Instance }),
    handler: async (args) => {
      const client = getClient(args.instance);
      const monitors = await client.listMonitors();
      const list = Object.values(monitors);
      const heartbeatStatuses = client.getHeartbeatStatuses();

      let up = 0, down = 0, paused = 0, maintenance = 0;
      for (const m of list as any[]) {
        if (!m.active) { paused++; continue; }

        const hbStatus = heartbeatStatuses.get(m.id);
        if (hbStatus === 0)      { down++; }
        else if (hbStatus === 3) { maintenance++; }
        else                     { up++; } // 1 (UP), 2 (PENDING), or no heartbeat yet
      }

      return {
        total: list.length,
        up,
        down,
        paused,
        maintenance,
        instance: args.instance,
      };
    },
  },
  {
    name: 'uptimekuma_list_heartbeats',
    description:
      'Get heartbeat history for a specific monitor over the last N hours. Returns recent up/down events with response times.',
    schema: z.object({
      instance:  Instance,
      monitorId: z.number().int().positive().describe('The numeric ID of the monitor'),
      hours:     z.number().int().positive().optional().default(24).describe('How many hours of heartbeat history to return (default 24).'),
    }),
    handler: async (args) => getClient(args.instance).getHeartbeats(args.monitorId, args.hours),
  },
  {
    name: 'uptimekuma_list_notifications',
    description: 'List all configured notification channels (email, Slack, Discord, Telegram, etc.).',
    schema: z.object({ instance: Instance }),
    handler: async (args) => getClient(args.instance).listNotifications(),
  },
  {
    name: 'uptimekuma_list_status_pages',
    description: 'List all public status pages configured in Uptime Kuma.',
    schema: z.object({ instance: Instance }),
    handler: async (args) => getClient(args.instance).listStatusPages(),
  },
  {
    name: 'uptimekuma_list_tags',
    description: 'List all tags used to organize and categorize monitors.',
    schema: z.object({ instance: Instance }),
    handler: async (args) => getClient(args.instance).listTags(),
  },
  {
    name: 'uptimekuma_list_maintenance',
    description: 'List all scheduled maintenance windows.',
    schema: z.object({ instance: Instance }),
    handler: async (args) => getClient(args.instance).listMaintenance(),
  },

  // ── Write operations ────────────────────────────────────────────

  {
    name: 'uptimekuma_add_monitor',
    description:
      'Create a new monitor. Supports HTTP, ping, port, keyword, DNS, Docker, push, group and more. ' +
      'The full payload Kuma\'s UI sends is built for you (defaults for every NOT NULL column; timeout defaults to 80% of ' +
      'the interval). For type=push a push token is generated server-side and is NEVER returned: the response contains ' +
      'only the monitor id and a token fingerprint (first 8 hex of sha256); read the push URL in the Kuma UI. ' +
      'Credential inputs (basic_auth_pass, headers, body) are accepted but never echoed.',
    schema: z.object({
      instance:           Instance,
      type:               z.enum(MONITOR_TYPES).default('http').describe('Monitor type'),
      name:               z.string().min(1).describe('Display name for the monitor'),
      ...monitorFields,
      notificationIds:    z.array(z.number().int()).optional().describe('Notification provider IDs to attach to this monitor (see uptimekuma_list_notifications for IDs)'),
    }),
    handler: async (args) => {
      const { instance: _i, tags, ...rest } = args;
      const opts = toMonitorOpts(rest);
      const created = await getClient(args.instance).addMonitor(opts);
      if (Array.isArray(tags) && tags.length > 0 && created?.monitorID) {
        created.tags = await attachTags(getClient(args.instance), created.monitorID, tags);
      }
      return created;
    },
  },
  {
    name: 'uptimekuma_edit_monitor',
    description:
      'Update an existing monitor. The current monitor is loaded, your changes are merged, and the FULL object is sent ' +
      '(Kuma replaces every field on edit), so omitted fields are preserved. Credential values are never returned. ' +
      'A monitor that already holds credentials cannot have its destination (url/host/port/docker/auth/...) changed.',
    schema: z.object({
      instance:           Instance,
      monitorId:          z.number().int().positive().describe('The numeric ID of the monitor to edit'),
      name:               z.string().optional().describe('New display name'),
      ...monitorFields,
      notificationIds:    z.array(z.number().int()).optional().describe('Notification provider IDs to attach (replaces the monitor\'s current notification assignments)'),
    }),
    handler: async (args) => {
      const { instance, monitorId, tags, ...rest } = args;
      const client = getClient(instance);
      const result = await client.editMonitor(monitorId, toMonitorOpts(rest));
      if (Array.isArray(tags) && tags.length > 0) {
        result.tags = await attachTags(client, monitorId, tags);
      }
      return result;
    },
  },
  {
    name: 'uptimekuma_delete_monitor',
    description: 'Permanently delete a monitor by ID. This cannot be undone. confirmId must equal monitorId.',
    schema: z.object({
      instance:  Instance,
      monitorId: z.number().int().positive().describe('The numeric ID of the monitor to delete'),
      confirmId: z.number().int().describe('Repeat monitorId to confirm the deletion'),
    }),
    handler: async (args) => {
      if (args.confirmId !== args.monitorId) throw new Error('confirmId must equal monitorId to delete');
      return getClient(args.instance).deleteMonitor(args.monitorId);
    },
  },
  {
    name: 'uptimekuma_pause_monitor',
    description: 'Pause a monitor — it will stop checking until resumed.',
    schema: z.object({
      instance:  Instance,
      monitorId: z.number().int().positive().describe('The numeric ID of the monitor to pause'),
    }),
    handler: async (args) => getClient(args.instance).pauseMonitor(args.monitorId),
  },
  {
    name: 'uptimekuma_resume_monitor',
    description: 'Resume a paused monitor — it will start checking again.',
    schema: z.object({
      instance:  Instance,
      monitorId: z.number().int().positive().describe('The numeric ID of the monitor to resume'),
    }),
    handler: async (args) => getClient(args.instance).resumeMonitor(args.monitorId),
  },

  // ── Notification provider operations ─────────────────────────────

  {
    name: 'uptimekuma_create_notification',
    description:
      'Create a new notification provider (e.g. ntfy, Telegram, Slack, webhook). ' +
      'Provide the provider `type` and a `config` object holding the type-specific ' +
      'fields. For ntfy, config typically includes: ntfyserverurl, ntfytopic, ' +
      'ntfyPriority, ntfyAuthenticationMethod. Returns the new provider id.',
    schema: z.object({
      instance:      Instance,
      name:          z.string().min(1).describe('Display name for the notification provider'),
      type:          z.string().describe('Provider type, e.g. "ntfy", "telegram", "slack", "webhook"'),
      config:        z.record(z.string(), z.any()).optional().describe('Type-specific settings merged into the provider config (e.g. { ntfyserverurl, ntfytopic, ntfyPriority })'),
      isDefault:     z.boolean().optional().default(false).describe('Apply automatically to newly created monitors'),
      applyExisting: z.boolean().optional().default(false).describe('Immediately attach to all existing monitors on save'),
      confirmApply:  z.boolean().optional().describe(CONFIRM_APPLY_DESC),
    }),
    handler: async (args) => {
      assertNotificationApplyConfirmed(args);
      assertNoReservedConfigKeys(args.config);
      const notification = {
        ...(args.config ?? {}),
        name: args.name,
        type: args.type,
        isDefault: args.isDefault ?? false,
        applyExisting: args.applyExisting ?? false,
      };
      return getClient(args.instance).saveNotification(notification, null);
    },
  },
  {
    name: 'uptimekuma_update_notification',
    description:
      'Update an existing notification provider. The current config is fetched and ' +
      'merged with the fields you supply, so you only need to pass what changes.',
    schema: z.object({
      instance:       Instance,
      notificationId: z.number().int().positive().describe('The numeric ID of the notification provider to update'),
      name:           z.string().optional().describe('New display name'),
      type:           z.string().optional().describe('New provider type'),
      config:         z.record(z.string(), z.any()).optional().describe('Type-specific settings to merge into the existing config'),
      isDefault:      z.boolean().optional().describe('Apply automatically to newly created monitors'),
      applyExisting:  z.boolean().optional().describe('Immediately attach to all existing monitors on save'),
      confirmApply:   z.boolean().optional().describe(CONFIRM_APPLY_DESC),
    }),
    handler: async (args) => {
      assertNotificationApplyConfirmed(args);
      assertNoReservedConfigKeys(args.config);
      return getClient(args.instance).updateNotification(args.notificationId, args);
    },
  },
  {
    name: 'uptimekuma_delete_notification',
    description: 'Permanently delete a notification provider by ID. This cannot be undone. confirmId must equal notificationId.',
    schema: z.object({
      instance:       Instance,
      notificationId: z.number().int().positive().describe('The numeric ID of the notification provider to delete'),
      confirmId:      z.number().int().describe('Repeat notificationId to confirm the deletion'),
    }),
    handler: async (args) => {
      if (args.confirmId !== args.notificationId) throw new Error('confirmId must equal notificationId to delete');
      return getClient(args.instance).deleteNotification(args.notificationId);
    },
  },
  {
    name: 'uptimekuma_set_monitor_notifications',
    description:
      'Set exactly which notification providers are attached to a single monitor. ' +
      "Replaces the monitor's current notification assignments with the given list " +
      '(pass an empty array to detach all).',
    schema: z.object({
      instance:        Instance,
      monitorId:       z.number().int().positive().describe('The numeric ID of the monitor'),
      notificationIds: z.array(z.number().int()).describe('Notification provider IDs to attach (replaces existing). Empty array detaches all.'),
    }),
    handler: async (args) => {
      const map: Record<string, boolean> = {};
      for (const id of args.notificationIds) map[String(id)] = true;
      return getClient(args.instance).setMonitorNotifications(args.monitorId, map);
    },
  },
  {
    name: 'uptimekuma_apply_notification_to_all_monitors',
    description:
      'Attach or detach a single notification provider across ALL monitors at once, ' +
      "preserving each monitor's other notification assignments. Strongly recommend " +
      'running with dryRun=true first to preview exactly which monitors would change.',
    schema: z.object({
      instance:       Instance,
      notificationId: z.number().int().positive().describe('The notification provider ID to apply'),
      enabled:        z.boolean().optional().default(true).describe('true = attach to all monitors, false = detach from all'),
      includeGroups:  z.boolean().optional().default(false).describe('Also apply to group monitors (default skips groups)'),
      dryRun:         z.boolean().optional().default(true).describe('Preview the changes without applying them (default true: pass false to apply)'),
      confirmDetach:  z.boolean().optional().describe('Required (true) to apply enabled=false (detach from all monitors, silencing that provider everywhere)'),
    }),
    handler: async (args) => {
      if (!args.dryRun && args.enabled === false && args.confirmDetach !== true) {
        throw new Error('detaching a notification provider from all monitors needs confirmDetach=true (preview first with dryRun=true)');
      }
      return getClient(args.instance).applyNotificationToAllMonitors(args.notificationId, args.enabled, {
        dryRun: args.dryRun,
        includeGroups: args.includeGroups,
      });
    },
  },

  // ── Tags ─────────────────────────────────────────────────────────

  {
    name: 'uptimekuma_create_tag',
    description: 'Create a tag (name + colour). Returns the new tag including its id.',
    schema: z.object({
      instance: Instance,
      name:     z.string().min(1).describe('Tag name'),
      color:    z.string().regex(/^#[0-9a-fA-F]{6}$/).default('#4B5563').describe('Hex colour, e.g. #4B5563'),
    }),
    handler: async (args) => getClient(args.instance).createTag(args.name, args.color),
  },
  {
    name: 'uptimekuma_add_monitor_tag',
    description: 'Attach an existing tag (optionally with a value) to a monitor.',
    schema: z.object({
      instance:  Instance,
      tagId:     z.number().int().positive().describe('Tag ID'),
      monitorId: z.number().int().positive().describe('Monitor ID'),
      value:     z.string().optional().default('').describe('Optional tag value'),
    }),
    handler: async (args) => getClient(args.instance).addMonitorTag(args.tagId, args.monitorId, args.value),
  },
  {
    name: 'uptimekuma_remove_monitor_tag',
    description: 'Detach a tag from a monitor. The value must match the one it was attached with ("" if none).',
    schema: z.object({
      instance:  Instance,
      tagId:     z.number().int().positive().describe('Tag ID'),
      monitorId: z.number().int().positive().describe('Monitor ID'),
      value:     z.string().optional().default('').describe('Tag value it was attached with'),
    }),
    handler: async (args) => getClient(args.instance).removeMonitorTag(args.tagId, args.monitorId, args.value),
  },

  // ── Maintenance ──────────────────────────────────────────────────

  {
    name: 'uptimekuma_add_maintenance',
    description:
      'Create a maintenance window and attach monitors to it. strategy: "manual" (active until paused), ' +
      '"single" (one dateRange window), "recurring-interval" / "recurring-weekday" / "recurring-day-of-month" ' +
      '(need timeRange), or "cron" (needs cron + durationMinutes).',
    schema: z.object({
      instance:       Instance,
      title:          z.string().min(1),
      description:    z.string().optional().default(''),
      strategy:       z.enum(['manual', 'single', 'recurring-interval', 'recurring-weekday', 'recurring-day-of-month', 'cron']).default('manual'),
      active:         z.boolean().optional().default(true),
      monitorIds:     z.array(z.number().int().positive()).optional().default([]).describe('Monitors affected by this window'),
      dateRange:      z.tuple([z.string().nullable(), z.string().nullable()]).optional().describe('[start, end] as "YYYY-MM-DD HH:mm:ss" (single strategy; null = unbounded)'),
      timeRange:      z.tuple([z.object({ hours: z.number().int().min(0).max(23), minutes: z.number().int().min(0).max(59) }), z.object({ hours: z.number().int().min(0).max(23), minutes: z.number().int().min(0).max(59) })]).optional().describe('[start, end] time of day for recurring strategies'),
      weekdays:       z.array(z.number().int().min(1).max(7)).optional().default([]).describe('1=Mon..7=Sun (recurring-weekday)'),
      daysOfMonth:    z.array(z.union([z.number().int().min(1).max(31), z.literal('lastDay1')])).optional().default([]),
      intervalDay:    z.number().int().positive().optional().default(1).describe('Every N days (recurring-interval)'),
      cron:           z.string().optional().describe('Cron expression (cron strategy)'),
      durationMinutes: z.number().int().positive().optional().default(60).describe('Window length in minutes (cron strategy)'),
      timezoneOption: z.string().optional().default('UTC').describe('IANA timezone, or "SAME_AS_SERVER"'),
      confirmOpenEnded: z.boolean().optional().describe('Required (true) for ANY strategy when the window covers more than 5 monitors, runs all day (24h or more), or is open-ended (e.g. a "manual" window with no end in dateRange)'),
    }),
    handler: async (args) => {
      const { instance, monitorIds, confirmOpenEnded, ...rest } = args;
      if (maintenanceNeedsConfirm({ ...rest, monitorIds }) && confirmOpenEnded !== true) {
        throw new Error(
          'this maintenance window silences alerts for a long or broad scope: pass confirmOpenEnded=true ' +
          '(required for any strategy when it covers more than 5 monitors, runs all day, or has no end time)');
      }
      const maintenance = {
        ...rest,
        dateRange: rest.dateRange ?? [null, null],
        timeRange: rest.timeRange ?? [{ hours: 2, minutes: 0 }, { hours: 3, minutes: 0 }],
      };
      return getClient(instance).addMaintenance(maintenance, monitorIds);
    },
  },
  {
    name: 'uptimekuma_pause_maintenance',
    description: 'Pause (deactivate) a maintenance window.',
    schema: z.object({ instance: Instance, maintenanceId: z.number().int().positive() }),
    handler: async (args) => getClient(args.instance).pauseMaintenance(args.maintenanceId),
  },
  {
    name: 'uptimekuma_resume_maintenance',
    description: 'Resume (reactivate) a maintenance window.',
    schema: z.object({ instance: Instance, maintenanceId: z.number().int().positive() }),
    handler: async (args) => getClient(args.instance).resumeMaintenance(args.maintenanceId),
  },
  {
    name: 'uptimekuma_delete_maintenance',
    description: 'Permanently delete a maintenance window. This cannot be undone. confirmId must equal maintenanceId.',
    schema: z.object({
      instance: Instance,
      maintenanceId: z.number().int().positive(),
      confirmId: z.number().int().describe('Repeat maintenanceId to confirm the deletion'),
    }),
    handler: async (args) => {
      if (args.confirmId !== args.maintenanceId) throw new Error('confirmId must equal maintenanceId to delete');
      return getClient(args.instance).deleteMaintenance(args.maintenanceId);
    },
  },

  // ── Status pages ─────────────────────────────────────────────────

  {
    name: 'uptimekuma_add_status_page',
    description: 'Create an empty status page. Use uptimekuma_save_status_page to add groups and monitors.',
    schema: z.object({
      instance: Instance,
      title:    z.string().min(1),
      slug:     z.string().regex(/^[a-z0-9_-]+$/).describe('URL slug (lowercase letters, digits, - and _)'),
    }),
    handler: async (args) => getClient(args.instance).addStatusPage(args.title, args.slug),
  },
  {
    name: 'uptimekuma_save_status_page',
    description:
      'Save a status page. WARNING: Kuma replaces the whole group list, so `groups` is the COMPLETE desired list ' +
      '(an empty array removes all groups); existing group ids and per-monitor sendUrl/url settings are carried over. ' +
      'Page settings you omit are preserved. PUBLIC EXPOSURE: a published status page is visible to anyone who can reach ' +
      'Kuma, and lists monitor names (and URLs where shown). For a published page you must pass confirmPublic=true.',
    schema: z.object({
      instance:    Instance,
      slug:        z.string().min(1),
      title:       z.string().min(1).optional(),
      description: z.string().optional(),
      theme:       z.enum(['auto', 'light', 'dark']).optional(),
      footerText:  z.string().optional(),
      showPoweredBy: z.boolean().optional(),
      showTags:    z.boolean().optional(),
      autoRefreshInterval: z.number().int().min(5).optional(),
      groups:      z.array(z.object({
        name:       z.string().min(1),
        monitorIds: z.array(z.number().int().positive()),
      })).describe('Complete list of monitor groups for the page'),
      confirmPublic: z.boolean().optional().describe('Required when the page is published (publicly visible)'),
    }),
    handler: async (args) => {
      const { instance, slug, groups, confirmPublic, ...changes } = args;
      return getClient(instance).saveStatusPage(slug, changes, groups, { confirmPublic });
    },
  },
  {
    name: 'uptimekuma_delete_status_page',
    description: 'Permanently delete a status page by slug. This cannot be undone. confirmSlug must equal slug.',
    schema: z.object({
      instance: Instance,
      slug: z.string().min(1),
      confirmSlug: z.string().describe('Repeat slug to confirm the deletion'),
    }),
    handler: async (args) => {
      if (args.confirmSlug !== args.slug) throw new Error('confirmSlug must equal slug to delete');
      return getClient(args.instance).deleteStatusPage(args.slug);
    },
  },
];

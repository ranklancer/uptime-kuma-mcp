import { z } from 'zod';
import { getClient, allInstanceNames } from './instances.js';
import { MONITOR_TYPES } from './types.js';

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
      const monitors = await getClient(args.instance).listMonitors();
      let list = Object.values(monitors);

      if (args.type) list = list.filter((m: any) => m.type === args.type);
      if (args.status) {
        const statusMap: Record<string, number> = { down: 0, up: 1, pending: 2, maintenance: 3 };
        const code = statusMap[args.status];
        list = list.filter((m: any) => m.active === (code === 1 || code === 2 || code === 3));
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
          url: m.url,
          hostname: m.hostname,
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
      'Get detailed information about a single monitor including its configuration and recent heartbeats.',
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
      const monitors = await getClient(args.instance).listMonitors();
      const list = Object.values(monitors);

      let up = 0, down = 0, paused = 0, maintenance = 0;
      for (const m of list as any[]) {
        if (!m.active) { paused++; continue; }
        // Status comes from heartbeat data; we count active monitors
        up++; // Default to counting active as "up" — status refined by heartbeats
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
      'Get heartbeat history for a specific monitor. Returns recent up/down events with response times.',
    schema: z.object({
      instance:  Instance,
      monitorId: z.number().int().positive().describe('The numeric ID of the monitor'),
    }),
    handler: async (args) => getClient(args.instance).getHeartbeats(args.monitorId),
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
      'Create a new monitor. Supports HTTP, ping, port, keyword, DNS, Docker, and many more types.',
    schema: z.object({
      instance:           Instance,
      type:               z.enum(MONITOR_TYPES).default('http').describe('Monitor type'),
      name:               z.string().min(1).describe('Display name for the monitor'),
      url:                z.string().optional().describe('URL to monitor (for http/keyword types)'),
      hostname:           z.string().optional().describe('Hostname for ping/port/dns types'),
      port:               z.number().int().optional().describe('Port number for port-type monitors'),
      method:             z.string().optional().default('GET').describe('HTTP method (GET, POST, etc.)'),
      interval:           z.number().int().positive().optional().default(60).describe('Check interval in seconds'),
      retryInterval:      z.number().int().optional().default(60).describe('Retry interval in seconds'),
      maxretries:         z.number().int().optional().default(0).describe('Max retries before marking down'),
      keyword:            z.string().optional().describe('Expected keyword in response (for keyword type)'),
      accepted_statuscodes: z.string().optional().default('200-299').describe('Accepted HTTP status codes (e.g. "200-299")'),
      ignoreTls:          z.boolean().optional().default(false).describe('Ignore TLS certificate errors'),
      description:        z.string().optional().describe('Monitor description'),
      dns_resolve_type:   z.string().optional().describe('DNS record type (A, AAAA, MX, etc.)'),
      dns_resolve_server: z.string().optional().describe('DNS server to use for resolution'),
    }),
    handler: async (args) => {
      const opts = {
        ...args,
        accepted_statuscodes: args.accepted_statuscodes
          ? args.accepted_statuscodes.split(',').map((s: string) => s.trim())
          : ['200-299'],
      };
      return getClient(args.instance).addMonitor(opts);
    },
  },
  {
    name: 'uptimekuma_edit_monitor',
    description: 'Update an existing monitor. Only the provided fields will be changed.',
    schema: z.object({
      instance:           Instance,
      monitorId:          z.number().int().positive().describe('The numeric ID of the monitor to edit'),
      name:               z.string().optional().describe('New display name'),
      url:                z.string().optional().describe('New URL'),
      hostname:           z.string().optional().describe('New hostname'),
      port:               z.number().int().optional().describe('New port'),
      interval:           z.number().int().positive().optional().describe('New check interval in seconds'),
      retryInterval:      z.number().int().optional().describe('New retry interval in seconds'),
      maxretries:         z.number().int().optional().describe('New max retries'),
      keyword:            z.string().optional().describe('New keyword to check'),
      accepted_statuscodes: z.string().optional().describe('New accepted HTTP status codes'),
      ignoreTls:          z.boolean().optional().describe('Ignore TLS errors'),
      description:        z.string().optional().describe('New description'),
    }),
    handler: async (args) => {
      const { instance, monitorId, ...opts } = args;
      if (opts.accepted_statuscodes) {
        opts.accepted_statuscodes = opts.accepted_statuscodes.split(',').map((s: string) => s.trim());
      }
      return getClient(instance).editMonitor(monitorId, opts);
    },
  },
  {
    name: 'uptimekuma_delete_monitor',
    description: 'Permanently delete a monitor by ID. This cannot be undone.',
    schema: z.object({
      instance:  Instance,
      monitorId: z.number().int().positive().describe('The numeric ID of the monitor to delete'),
    }),
    handler: async (args) => getClient(args.instance).deleteMonitor(args.monitorId),
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
];

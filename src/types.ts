/** Configuration for a single Uptime Kuma instance. */
export interface KumaInstanceConfig {
  name: string;
  baseUrl: string;
  username: string;
  password: string;
  insecureTLS: boolean;
}

/** Authenticated session state (JWT token from Socket.IO login). */
export interface KumaSession {
  token: string;
  obtainedAt: number;
}

/** Monitor types supported by Uptime Kuma. */
export const MONITOR_TYPES = [
  'http', 'port', 'ping', 'keyword', 'grpc', 'dns',
  'docker', 'push', 'steam', 'gamedig', 'mqtt',
  'sqlserver', 'postgres', 'mysql', 'mongodb',
  'radius', 'redis', 'group',
] as const;

export type MonitorType = (typeof MONITOR_TYPES)[number];

/** Monitor status values. */
export const MONITOR_STATUS = {
  DOWN: 0,
  UP: 1,
  PENDING: 2,
  MAINTENANCE: 3,
} as const;

/** Options for adding/editing a monitor. */
export interface MonitorOpts {
  type?: MonitorType;
  name?: string;
  url?: string;
  method?: string;
  interval?: number;
  retryInterval?: number;
  maxretries?: number;
  hostname?: string;
  port?: number;
  keyword?: string;
  accepted_statuscodes?: string[];
  ignoreTls?: boolean;
  expiryNotification?: boolean;
  maxredirects?: number;
  dns_resolve_type?: string;
  dns_resolve_server?: string;
  notificationIDList?: Record<string, boolean>;
  description?: string;
  parent?: number;
  [key: string]: unknown;
}

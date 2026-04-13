import { readFileSync, existsSync } from 'node:fs';
import { UptimeKumaClient } from './uptime-kuma-client.js';
import type { KumaInstanceConfig } from './types.js';

/**
 * Dynamic multi-instance loader.
 *
 * Instances are configured via environment variables following these patterns:
 *
 *   KUMA_INSTANCES           — comma-separated list of instance names (e.g. "primary,secondary")
 *                               Defaults to "kuma" if not set.
 *
 * For each instance <NAME> (uppercased):
 *   <NAME>_BASE_URL          — Uptime Kuma base URL  (required, e.g. "http://kuma.example.com:3001")
 *   <NAME>_USERNAME          — Uptime Kuma login username (required)
 *   <NAME>_PASSWORD          — Uptime Kuma login password (or read from Docker secret)
 *   <NAME>_INSECURE_TLS      — set to "true" to skip TLS verification (default: "false")
 *
 * Docker secrets fallback: /run/secrets/<name>_password  (lowercase)
 */

function loadSecret(envVar: string, secretPath: string): string {
  const fromEnv = process.env[envVar];
  if (fromEnv && fromEnv.length > 0) return fromEnv.trim();
  if (existsSync(secretPath)) return readFileSync(secretPath, 'utf8').trim();
  throw new Error(`No value found for ${envVar} (checked env and ${secretPath})`);
}

function parseInstances(): Map<string, KumaInstanceConfig> {
  const raw = process.env.KUMA_INSTANCES ?? 'kuma';
  const names = raw.split(',').map(n => n.trim()).filter(Boolean);

  if (names.length === 0) {
    throw new Error('KUMA_INSTANCES is empty — define at least one instance name');
  }

  const configs = new Map<string, KumaInstanceConfig>();

  for (const name of names) {
    const envPrefix = name.toUpperCase();
    const baseUrl = process.env[`${envPrefix}_BASE_URL`];
    if (!baseUrl) {
      throw new Error(
        `Missing ${envPrefix}_BASE_URL for instance "${name}". ` +
        `Set KUMA_INSTANCES and provide <NAME>_BASE_URL for each.`
      );
    }

    const username = process.env[`${envPrefix}_USERNAME`];
    if (!username) {
      throw new Error(
        `Missing ${envPrefix}_USERNAME for instance "${name}". ` +
        `Set KUMA_INSTANCES and provide <NAME>_USERNAME for each.`
      );
    }

    configs.set(name, {
      name,
      baseUrl,
      username,
      password: loadSecret(
        `${envPrefix}_PASSWORD`,
        `/run/secrets/${name.toLowerCase()}_password`
      ),
      insecureTLS: (process.env[`${envPrefix}_INSECURE_TLS`] ?? 'false') === 'true',
    });
  }

  return configs;
}

const instanceConfigs = parseInstances();
const clients = new Map<string, UptimeKumaClient>();

/** Get an UptimeKumaClient by instance name. Defaults to the first configured instance. */
export function getClient(name?: string): UptimeKumaClient {
  const key = name ?? allInstanceNames()[0];
  if (!instanceConfigs.has(key)) {
    throw new Error(
      `Unknown instance "${key}". Available: ${allInstanceNames().join(', ')}`
    );
  }
  if (!clients.has(key)) {
    clients.set(key, new UptimeKumaClient(instanceConfigs.get(key)!));
  }
  return clients.get(key)!;
}

/** Return all configured instance names. */
export function allInstanceNames(): string[] {
  return [...instanceConfigs.keys()];
}

/** Disconnect all active clients (for graceful shutdown). */
export async function disconnectAll(): Promise<void> {
  for (const client of clients.values()) {
    await client.disconnect();
  }
  clients.clear();
}

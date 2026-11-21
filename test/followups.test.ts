import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertTargetAllowed, effectiveTarget } from '../src/policy.js';
import { buildEditPayload } from '../src/payload.js';
process.env.KUMA_BASE_URL ??= 'http://kuma.test:3001';
process.env.KUMA_USERNAME ??= 'u';
process.env.KUMA_PASSWORD ??= 'p';
const { toolDefs } = await import('../src/tools.js');
const { UptimeKumaClient } = await import('../src/uptime-kuma-client.js');

test('short IPv4-mapped IPv6 CIDR denies the embedded IPv4 host', () => {
  process.env.KUMA_MCP_DENY_HOSTS = '::ffff:0:0/80';
  try { assert.throws(() => assertTargetAllowed({ hostname: '10.1.2.3' }), /denylist/); }
  finally { delete process.env.KUMA_MCP_DENY_HOSTS; }
});

test('built-in ::/96 does not deny ordinary IPv4 hosts', () => {
  assert.doesNotThrow(() => assertTargetAllowed({ hostname: '192.0.2.10' }));
});

test('type change to grpc/db activates a stale target that is then policed', () => {
  assert.throws(() => assertTargetAllowed(effectiveTarget({ type: 'grpc', grpcUrl: '127.0.0.1:50051' })), /denylist/);
  assert.throws(() => assertTargetAllowed(effectiveTarget({ type: 'postgres', databaseConnectionString: 'postgres://u:p@localhost:5432/db' })), /denylist/);
  assert.throws(() => effectiveTarget({ type: 'mysql', databaseConnectionString: 'garbage' }), /unreadable/);
  const cur: any = { id: 1, type: 'http', url: 'https://example.com/', grpcUrl: '169.254.169.254:80', timeout: 48, interval: 60 };
  assert.throws(() => buildEditPayload(cur, { type: 'grpc' }, 1), /denylist/);
});

test('port outside 1-65535 is rejected by the tool schema', () => {
  const add = toolDefs.find((t) => t.name === 'uptimekuma_add_monitor')!;
  for (const port of [0, 65536, -1]) assert.equal(add.schema.safeParse({ name: 'x', port }).success, false);
  assert.equal(add.schema.safeParse({ name: 'x', port: 443 }).success, true);
});

test('monitor cache follows updateMonitorIntoList / deleteMonitorFromList', () => {
  const c: any = Object.create(UptimeKumaClient.prototype);
  const handlers: Record<string, (...a: any[]) => void> = {};
  c.monitorCache = { '1': { id: 1 } };
  c.heartbeatStatusCache = new Map([[2, 1]]);
  c.socket = { on: (e: string, f: any) => { handlers[e] = f; } };
  c.attachCacheHandlers(c.socket);
  if (!handlers.updateMonitorIntoList) return assert.fail('attachCacheHandlers missing');
  handlers.updateMonitorIntoList({ '2': { id: 2, name: 'n' } });
  assert.deepEqual(Object.keys(c.monitorCache).sort(), ['1', '2']);
  handlers.deleteMonitorFromList(2);
  assert.deepEqual(Object.keys(c.monitorCache), ['1']);
  assert.equal(c.heartbeatStatusCache.has(2), false);
});

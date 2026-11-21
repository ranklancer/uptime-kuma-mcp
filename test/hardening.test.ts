import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertTargetAllowed, invalidDenyEntries } from '../src/policy.js';
import { buildAddPayload, buildEditPayload } from '../src/payload.js';

const cur = (o: Record<string, any> = {}): any => ({ id: 1, type: 'port', name: 'n', hostname: 'example.com', port: 443, timeout: 48, interval: 60, ...o });

// ── 1. port validation ──────────────────────────────────────────
test('add: port 0 is unset (default or null), never sent as 0', () => {
  assert.equal(buildAddPayload({ type: 'port', name: 'x', hostname: 'example.com', port: 0 }).port, null);
  assert.equal(buildAddPayload({ type: 'dns', name: 'x', hostname: 'example.com', port: 0 }).port, 53);
});

test('add: explicit port must be an integer in 1-65535', () => {
  for (const port of [-1, 65536, 1.5, NaN, '80' as any]) {
    assert.throws(() => buildAddPayload({ type: 'port', name: 'x', hostname: 'example.com', port }), /port must be an integer between 1 and 65535/);
  }
  assert.equal(buildAddPayload({ type: 'port', name: 'x', hostname: 'example.com', port: 65535 }).port, 65535);
});

test('edit: port 0 clears to unset/default; out-of-range refused; stored port 0 is not forwarded', () => {
  assert.equal(buildEditPayload(cur(), { port: 0 }, 1).port, null);
  assert.equal(buildEditPayload(cur({ type: 'dns', port: 53 }), { port: 0 }, 1).port, 53);
  assert.equal(buildEditPayload(cur({ port: 0 }), { name: 'renamed' }, 1).port, null);
  for (const port of [-1, 65536, 1.5]) assert.throws(() => buildEditPayload(cur(), { port }, 1), /port must be an integer between 1 and 65535/);
});

// ── 2. stale type-specific fields ───────────────────────────────
test('edit type change drops fields of the previous type (grpc/db/docker/mqtt)', () => {
  const grpc = cur({ type: 'grpc', grpcUrl: 'grpc.example.com:50051', grpcServiceName: 'svc', grpcBody: '{"a":1}', grpcMetadata: '{}', grpcProtobuf: 'p', grpcMethod: 'm', grpcEnableTls: true, hostname: null, port: null });
  const p = buildEditPayload(grpc, { type: 'ping', hostname: 'example.com' }, 1);
  for (const k of ['grpcUrl', 'grpcServiceName', 'grpcBody', 'grpcMetadata', 'grpcProtobuf', 'grpcMethod']) assert.ok(p[k] === null || p[k] === '' || p[k] === undefined, k);
  assert.ok(!p.grpcEnableTls);

  const db = cur({ type: 'postgres', databaseConnectionString: 'postgres://u:pw@db.example.com/x', databaseQuery: 'select 1' });
  const p2 = buildEditPayload(db, { type: 'ping', hostname: 'example.com' }, 1);
  assert.ok(!p2.databaseConnectionString && !p2.databaseQuery);

  const dk = cur({ type: 'docker', docker_container: 'c', docker_host: 3 });
  const p3 = buildEditPayload(dk, { type: 'ping', hostname: 'example.com' }, 1);
  assert.equal(p3.docker_container, ''); assert.equal(p3.docker_host, null);

  const mq = cur({ type: 'mqtt', mqttTopic: 't', mqttUsername: 'u', mqttPassword: 'p', mqttSuccessMessage: 'ok' });
  const p4 = buildEditPayload(mq, { type: 'ping', hostname: 'example.com' }, 1);
  assert.equal(p4.mqttTopic, ''); assert.equal(p4.mqttPassword, ''); assert.equal(p4.mqttUsername, '');
});

test('edit without a type change keeps the type\'s own fields', () => {
  const grpc = cur({ type: 'grpc', grpcUrl: 'grpc.example.com:50051', grpcServiceName: 'svc' });
  const p = buildEditPayload(grpc, { name: 'renamed' }, 1);
  assert.equal(p.grpcUrl, 'grpc.example.com:50051'); assert.equal(p.grpcServiceName, 'svc');
});

test('type change to a type that owns the field keeps it and still polices it', () => {
  const stale = cur({ type: 'http', url: 'https://example.com/', grpcUrl: '169.254.169.254:80' });
  assert.throws(() => buildEditPayload(stale, { type: 'grpc' }, 1), /denylist/);
});

test('a stale denylisted field of the old type does not block a type change away from it', () => {
  const db = cur({ type: 'postgres', databaseConnectionString: 'garbage', hostname: 'example.com' });
  assert.doesNotThrow(() => buildEditPayload(db, { type: 'ping' }, 1));
});

// ── 3. denylist: short IPv4-mapped IPv6 CIDRs (regression) ──────
test('mapped IPv6 CIDRs of any prefix length match the embedded IPv4 host; unparseable entries are listed for the startup warning', () => {
  try {
    for (const e of ['::ffff:10.0.0.0/104', '::ffff:a00:0/104', '::ffff:10.0.0.0/100', '::ffff:0:0/80', '0:0:0:0:0:ffff:10.0.0.0/104']) {
      process.env.KUMA_MCP_DENY_HOSTS = e;
      for (const h of ['10.1.2.3', '::ffff:10.1.2.3', '[::ffff:a01:203]']) assert.throws(() => assertTargetAllowed({ hostname: h }), /denylist/, `${e} vs ${h}`);
      if (!e.endsWith('/80')) assert.doesNotThrow(() => assertTargetAllowed({ hostname: '192.0.2.10' }), e); // /80 legitimately covers all IPv4
    }
    process.env.KUMA_MCP_DENY_HOSTS = '::ffff:10.0.0.0/129,::ffff:10.0.0.0/104';
    assert.deepEqual(invalidDenyEntries(), ['::ffff:10.0.0.0/129']);
  } finally { delete process.env.KUMA_MCP_DENY_HOSTS; }
});

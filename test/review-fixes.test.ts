// Tests for the independent-review fixes (F1-F7). Env must be set before tools.ts is imported.
process.env.KUMA_INSTANCES = 'kuma';
process.env.KUMA_BASE_URL = 'http://kuma.test:3001';
process.env.KUMA_USERNAME = 'u';
process.env.KUMA_PASSWORD = 'not-a-real-password';
delete process.env.KUMA_MCP_ALLOW_WRITE_METHODS;
delete process.env.KUMA_MCP_DENY_HOSTS;

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { UptimeKumaClient, mergeGroups } from '../src/uptime-kuma-client.js';
import { buildAddPayload, buildEditPayload, buildEditPayloadWithNotes } from '../src/payload.js';
import { assertTargetAllowed } from '../src/policy.js';
import { DESTINATION_REFUSAL } from '../src/redact.js';

const { toolDefs } = await import('../src/tools.js');
const tool = (n: string) => toolDefs.find((t) => t.name === n)!;

const cur = { id: 5, name: 'm', type: 'http', url: 'https://a.example.test/', method: 'GET', interval: 60, timeout: 48, maxretries: 0,
  accepted_statuscodes: ['200-299'], parent: null, notificationIDList: {}, hostname: null, port: null };

// ── F1: methods, bodies, target denylist ────────────────────────────────────
test('F1 schema: method is GET/HEAD only by default', () => {
  const add = tool('uptimekuma_add_monitor').schema;
  assert.ok(add.safeParse({ name: 'x', method: 'GET' }).success);
  assert.ok(add.safeParse({ name: 'x', method: 'HEAD' }).success);
  for (const m of ['POST', 'PUT', 'DELETE', 'PATCH']) {
    assert.equal(add.safeParse({ name: 'x', method: m }).success, false, m);
    assert.equal(tool('uptimekuma_edit_monitor').schema.safeParse({ monitorId: 1, method: m }).success, false, m);
  }
});

test('F1 payload builders refuse write methods and any body unless the operator opts in', () => {
  assert.throws(() => buildAddPayload({ name: 'x', method: 'POST' }), /method not allowed/);
  assert.throws(() => buildAddPayload({ name: 'x', body: { a: 1 } }), /body not allowed/);
  assert.throws(() => buildEditPayload(cur, { method: 'POST' }, 5), /method not allowed/);
  assert.throws(() => buildEditPayload(cur, { body: 'x' }, 5), /body not allowed/);
  assert.doesNotThrow(() => buildAddPayload({ name: 'x', method: 'head' }));
  process.env.KUMA_MCP_ALLOW_WRITE_METHODS = '1';
  try {
    assert.equal(buildAddPayload({ name: 'x', method: 'POST', body: { a: 1 } }).method, 'POST');
    assert.equal(buildEditPayload(cur, { method: 'POST' }, 5).method, 'POST');
  } finally { delete process.env.KUMA_MCP_ALLOW_WRITE_METHODS; }
  process.env.KUMA_MCP_ALLOW_WRITE_METHODS = 'true'; // only the literal "1" enables
  try { assert.throws(() => buildAddPayload({ name: 'x', method: 'POST' })); } finally { delete process.env.KUMA_MCP_ALLOW_WRITE_METHODS; }
});

test('F1 target denylist: loopback, link-local, metadata, gateway names and obfuscated forms are refused', () => {
  const bad = ['http://localhost:8080/', 'http://127.0.0.1/', 'http://127.1.2.3/', 'http://[::1]/', 'http://169.254.169.254/latest/',
    'http://2130706433/', 'http://0x7f.0.0.1/', 'http://[::ffff:127.0.0.1]/', 'http://LOCALHOST./', 'http://bifrost:8080/mcp',
    'http://my-bifrost.lan/', 'http://mcp.lan/', 'http://host.docker.internal/', 'http://0.0.0.0/', 'https://'];
  for (const u of bad) assert.throws(() => assertTargetAllowed({ url: u }), /not allowed/, u);
  for (const h of ['localhost', '127.0.0.1', '169.254.1.1', 'bifrost', '::1']) assert.throws(() => assertTargetAllowed({ hostname: h }), /not allowed/, h);
  for (const ok of ['https://example.test/', 'http://192.0.2.10:8080/', 'http://nas.lan/health']) assert.doesNotThrow(() => assertTargetAllowed({ url: ok }), ok);
  for (const ok of ['nas.lan', '192.0.2.10']) assert.doesNotThrow(() => assertTargetAllowed({ hostname: ok }), ok);
});

test('F1 KUMA_MCP_DENY_HOSTS adds host, glob, CIDR and host:port entries', () => {
  process.env.KUMA_MCP_DENY_HOSTS = 'gw.lan:8080, *.corp.test, 10.0.0.0/8';
  try {
    assert.throws(() => assertTargetAllowed({ url: 'http://gw.lan:8080/x' }));
    assert.throws(() => assertTargetAllowed({ hostname: 'gw.lan', port: 8080 }));
    assert.doesNotThrow(() => assertTargetAllowed({ url: 'http://gw.lan:9090/x' }));
    assert.throws(() => assertTargetAllowed({ hostname: 'a.corp.test' }));
    assert.throws(() => assertTargetAllowed({ hostname: '10.20.30.40' }));
    assert.doesNotThrow(() => assertTargetAllowed({ hostname: '11.0.0.1' }));
    assert.throws(() => assertTargetAllowed({ hostname: '127.0.0.1' }), 'built-ins stay');
  } finally { delete process.env.KUMA_MCP_DENY_HOSTS; }
});

test('F1 target denylist is enforced in add and edit payload builders', () => {
  assert.throws(() => buildAddPayload({ name: 'x', url: 'http://169.254.169.254/' }), /not allowed/);
  assert.throws(() => buildAddPayload({ name: 'x', type: 'port', hostname: 'localhost', port: 22 }), /not allowed/);
  assert.throws(() => buildEditPayload(cur, { url: 'http://127.0.0.1:9/' }, 5), /not allowed/);
  assert.throws(() => buildEditPayload({ ...cur, type: 'port', hostname: 'localhost' }, { port: 80 }, 5), /not allowed/); // port-only change re-checks host
  // untouched pre-existing target does not block unrelated edits
  assert.doesNotThrow(() => buildEditPayload({ ...cur, url: 'http://localhost:3000/' }, { name: 'renamed' }, 5));
});

// ── schema stripping ────────────────────────────────────────────────────────
test('schema strips pushToken / active / user_id / id on add and edit', () => {
  const evil = { pushToken: 'ATTACKERCHOSENTOKEN', active: false, user_id: 9 };
  const a: any = tool('uptimekuma_add_monitor').schema.parse({ name: 'x', type: 'push', ...evil });
  const e: any = tool('uptimekuma_edit_monitor').schema.parse({ monitorId: 5, ...evil });
  for (const o of [a, e]) for (const k of Object.keys(evil)) assert.ok(!(k in o), k);
  // and the payload builders strip them even if a caller bypasses the schema
  const p = buildAddPayload({ name: 'x', type: 'push', ...evil, id: 3 });
  assert.notEqual(p.pushToken, 'ATTACKERCHOSENTOKEN');
  assert.match(p.pushToken, /^[A-Za-z0-9]{32}$/);
  assert.ok(!('active' in p) && !('user_id' in p) && !('id' in p));
  const m = buildEditPayload({ ...cur, type: 'push', pushToken: 'REALTOKEN' }, { ...evil, id: 99 }, 5);
  assert.equal(m.pushToken, 'REALTOKEN');
  assert.equal(m.id, 5);
  assert.ok(!('active' in m) && !('user_id' in m));
});

// ── F5 + guard on credentialed monitors ─────────────────────────────────────
function editClient(raw: Record<string, any>) {
  const sent: any[] = [];
  const client: any = Object.create(UptimeKumaClient.prototype);
  client.cfg = { name: 't' };
  client.ensureConnected = async () => {};
  client.emitWithAck = async (ev: string, ...a: any[]) => {
    sent.push([ev, ...a]);
    return ev === 'getMonitor' ? { ok: true, monitor: { ...raw } } : { ok: true, msg: 'ok', monitorID: raw.id };
  };
  return { client, sent };
}
const credMon = { ...cur, basic_auth_pass: 'CANARYpw', headers: '{"A":"b"}', authMethod: 'basic', basic_auth_user: 'u' };

test('guard: credentialed monitors refuse method/headers/body/basic_auth/authMethod/upsideDown changes', async () => {
  for (const change of [{ method: 'HEAD' }, { headers: '{"X":"y"}' }, { body: 'x' }, { basic_auth_user: 'other' },
    { basic_auth_pass: 'new' }, { authMethod: 'ntlm' }, { upsideDown: true }]) {
    const { client, sent } = editClient(credMon);
    await assert.rejects(() => client.editMonitor(5, change), { message: DESTINATION_REFUSAL }, JSON.stringify(Object.keys(change)));
    assert.ok(!sent.some((s) => s[0] === 'editMonitor'));
  }
  // control: a safe edit still goes through
  const { client, sent } = editClient(credMon);
  await client.editMonitor(5, { name: 'renamed' });
  assert.ok(sent.some((s) => s[0] === 'editMonitor'));
});

// ── F2 ──────────────────────────────────────────────────────────────────────
test('F2 editMonitor of a push monitor with no token is refused and nothing is sent', async () => {
  const { client, sent } = editClient({ ...cur, type: 'push', pushToken: null });
  await assert.rejects(() => client.editMonitor(5, { name: 'n' }), /no push token/);
  assert.ok(!sent.some((s) => s[0] === 'editMonitor'));
});

// ── F6 ──────────────────────────────────────────────────────────────────────
test('F6 empty accepted_statuscodes is rejected on add and edit', () => {
  for (const v of [[], '', ' , ', ['', ' ']]) {
    assert.throws(() => buildAddPayload({ name: 'x', accepted_statuscodes: v as any }), /at least one/);
    assert.throws(() => buildEditPayload(cur, { accepted_statuscodes: v as any }, 5), /at least one/);
  }
  assert.deepEqual(buildEditPayload(cur, {}, 5).accepted_statuscodes, ['200-299']);
});

// ── timed-out write is not retried ──────────────────────────────────────────
test('a timed-out write is rejected once and never re-emitted (only a not-logged-in reply retries)', async () => {
  let calls = 0;
  const client: any = Object.create(UptimeKumaClient.prototype);
  client.cfg = { name: 't' };
  client.ensureConnected = async () => {};
  client.emitWithAck = async () => { calls++; throw new Error('[t] timeout waiting for add response'); };
  await assert.rejects(() => client.addMonitor({ name: 'x' }), /timeout/);
  assert.equal(calls, 1);
});

// ── F3 ──────────────────────────────────────────────────────────────────────
const existingGroups = [
  { id: 11, name: 'Core', monitorList: [{ id: 7, sendUrl: true, url: 'https://a.example.test/' }, { id: 8, sendUrl: false }] },
  { id: 12, name: 'Other', monitorList: [{ id: 9, sendUrl: true }] },
];

test('F3 mergeGroups carries group ids and per-monitor sendUrl/url; new groups/monitors get none', () => {
  const out = mergeGroups(existingGroups, [{ name: 'Core', monitorIds: [8, 7, 9, 10] }, { name: 'New', monitorIds: [7] }]);
  assert.equal(out[0].id, 11);
  assert.deepEqual(out[0].monitorList, [{ id: 8, sendUrl: false }, { id: 7, sendUrl: true, url: 'https://a.example.test/' }, { id: 9, sendUrl: true }, { id: 10 }]);
  assert.ok(!('id' in out[1]));
  assert.equal(out[1].monitorList[0].sendUrl, true);
});

function pageClient(published: boolean) {
  const sent: any[] = [];
  const client: any = Object.create(UptimeKumaClient.prototype);
  client.cfg = { name: 't' };
  client.ensureConnected = async () => {};
  client.fetchPublicGroups = async () => existingGroups;
  client.emitWithAck = async (ev: string, ...a: any[]) => {
    sent.push([ev, ...a]);
    return ev === 'getStatusPage' ? { ok: true, config: { slug: 's', title: 'T', icon: '/i.png', published, domainNameList: [] } } : { ok: true };
  };
  return { client, sent };
}

test('F3 saveStatusPage on a published page is refused without confirmPublic, and sends nothing', async () => {
  const { client, sent } = pageClient(true);
  await assert.rejects(() => client.saveStatusPage('s', {}, [{ name: 'Core', monitorIds: [7] }]), /confirmPublic/);
  assert.ok(!sent.some((s) => s[0] === 'saveStatusPage'));
});

test('F3 saveStatusPage with confirmPublic preserves group ids and sendUrl/url; unpublished page needs no flag', async () => {
  const { client, sent } = pageClient(true);
  await client.saveStatusPage('s', {}, [{ name: 'Core', monitorIds: [7] }], { confirmPublic: true });
  const save = sent.find((s) => s[0] === 'saveStatusPage');
  assert.deepEqual(save[4], [{ name: 'Core', id: 11, monitorList: [{ id: 7, sendUrl: true, url: 'https://a.example.test/' }] }]);
  const u = pageClient(false);
  await u.client.saveStatusPage('s', {}, []);
  assert.ok(u.sent.some((s) => s[0] === 'saveStatusPage'));
});

test('F3 if the current groups cannot be loaded the save is refused', async () => {
  const { client, sent } = pageClient(false);
  client.fetchPublicGroups = async () => { throw new Error('cannot load current groups'); };
  await assert.rejects(() => client.saveStatusPage('s', {}, []), /cannot load/);
  assert.ok(!sent.some((s) => s[0] === 'saveStatusPage'));
});

test('F3 tool description states the public-exposure risk', () => {
  assert.match(tool('uptimekuma_save_status_page').description, /PUBLIC EXPOSURE/);
});

// ── F4 ──────────────────────────────────────────────────────────────────────
test('F4 delete_status_page / delete_maintenance require matching confirm params', async () => {
  const dsp = tool('uptimekuma_delete_status_page'), dm = tool('uptimekuma_delete_maintenance');
  assert.equal(dsp.schema.safeParse({ slug: 's' }).success, false);
  assert.equal(dm.schema.safeParse({ maintenanceId: 3 }).success, false);
  await assert.rejects(() => dsp.handler(dsp.schema.parse({ slug: 's', confirmSlug: 'other' })), /confirmSlug/);
  await assert.rejects(() => dm.handler(dm.schema.parse({ maintenanceId: 3, confirmId: 4 })), /confirmId/);
});

test('F4 add_maintenance manual window needs confirmOpenEnded when large or without an end time', async () => {
  const am = tool('uptimekuma_add_maintenance');
  const base = { title: 'm', strategy: 'manual' };
  await assert.rejects(() => am.handler(am.schema.parse({ ...base, monitorIds: [1] })), /confirmOpenEnded/);                       // no end time
  await assert.rejects(() => am.handler(am.schema.parse({ ...base, monitorIds: [1, 2, 3, 4, 5, 6], dateRange: [null, '2030-01-01 00:00:00'] })), /confirmOpenEnded/); // >5
  // with the flag (or a small scope with an end time) the guard passes; the call then proceeds to the client, which we stub
  const c: any = (await import('../src/instances.js')).getClient('kuma');
  let added = 0;
  c.addMaintenance = async () => { added++; return { ok: true }; };
  await am.handler(am.schema.parse({ ...base, monitorIds: [1], dateRange: [null, '2030-01-01 00:00:00'] }));
  await am.handler(am.schema.parse({ ...base, monitorIds: [1, 2, 3, 4, 5, 6], confirmOpenEnded: true }));
  await am.handler(am.schema.parse({ title: 'c', strategy: 'cron', cron: '0 3 * * *', monitorIds: [1, 2, 3, 4, 5, 6, 7] })); // non-manual unaffected
  assert.equal(added, 3);
});

// ── Round 2: B1, N1-N5 ──────────────────────────────────────────────────────
test('B1 existing POST/body monitor: a url-only (or host/port/type/headers) edit is refused when write methods are off', () => {
  const post = { ...cur, method: 'POST', body: '{"x":1}' };
  assert.throws(() => buildEditPayload(post, { url: 'https://other.example.test/' }, 5), /not allowed/);
  assert.throws(() => buildEditPayload({ ...post, body: '' }, { url: 'https://other.example.test/' }, 5), /method not allowed/);
  for (const ch of [{ hostname: 'h.example.test' }, { port: 8080 }, { type: 'keyword' }, { headers: '{}' }]) {
    assert.throws(() => buildEditPayload({ ...post, body: '' }, ch, 5), /method not allowed/, JSON.stringify(ch));
  }
  // unrelated edits (rename) and GET monitors are unaffected
  assert.doesNotThrow(() => buildEditPayload(post, { name: 'renamed' }, 5));
  assert.doesNotThrow(() => buildEditPayload(cur, { url: 'https://other.example.test/' }, 5));
  // operator opt-in lifts it
  process.env.KUMA_MCP_ALLOW_WRITE_METHODS = '1';
  try { assert.doesNotThrow(() => buildEditPayload(post, { url: 'https://other.example.test/' }, 5)); } finally { delete process.env.KUMA_MCP_ALLOW_WRITE_METHODS; }
});

test('N1 maxredirects: default 0 and capped at 2 on add; capped on edit when target/redirects change; opt-in restores', () => {
  assert.equal(buildAddPayload({ name: 'x' }).maxredirects, 0);
  assert.equal(buildAddPayload({ name: 'x', maxredirects: 10 }).maxredirects, 2);
  assert.equal(buildAddPayload({ name: 'x', maxredirects: 1 }).maxredirects, 1);
  const c = { ...cur, maxredirects: 10 };
  assert.equal(buildEditPayload(c, { url: 'https://o.example.test/' }, 5).maxredirects, 2);
  assert.equal(buildEditPayload(c, { maxredirects: 9 }, 5).maxredirects, 2);
  assert.equal(buildEditPayload(c, { name: 'n' }, 5).maxredirects, 10); // untouched when nothing request-shaping changed
  process.env.KUMA_MCP_ALLOW_WRITE_METHODS = '1';
  try { assert.equal(buildAddPayload({ name: 'x', maxredirects: 10 }).maxredirects, 10); } finally { delete process.env.KUMA_MCP_ALLOW_WRITE_METHODS; }
});

test('N2 built-in denylist covers IPv6 link-local/ULA, IPv4-compatible, NAT64 and 0.0.0.0/8', () => {
  const bad = ['http://[fe80::1]/', 'http://[febf::1]/', 'http://[fc00::1]/', 'http://[fd12:3456::1]/', 'http://[::127.0.0.1]/', 'http://[::7f00:1]/',
    'http://[64:ff9b::7f00:1]/', 'http://[64:ff9b::a9fe:a9fe]/', 'http://0.1.2.3/', 'http://0.255.255.255/'];
  for (const u of bad) assert.throws(() => assertTargetAllowed({ url: u }), /not allowed/, u);
  for (const h of ['fe80::1', 'fd00::5', '64:ff9b::1']) assert.throws(() => assertTargetAllowed({ hostname: h }), /not allowed/, h);
  for (const ok of ['http://[2001:db8::1]/', 'http://[2606:4700::1111]/', 'http://1.2.3.4/']) assert.doesNotThrow(() => assertTargetAllowed({ url: ok }), ok);
  assert.doesNotThrow(() => assertTargetAllowed({ hostname: '2001:db8::1' }));
});

test('N3 only http/https/ws/wss schemes are accepted', () => {
  for (const u of ['file:///etc/passwd', 'gopher://x.example.test/', 'ftp://x.example.test/', 'javascript:alert(1)', 'data:text/plain,x', 'dict://x.example.test:11211/', 'FILE:///x']) {
    assert.throws(() => assertTargetAllowed({ url: u }), /not allowed/, u);
  }
  for (const u of ['http://x.example.test/', 'https://x.example.test/', 'ws://x.example.test/', 'WSS://x.example.test/']) {
    assert.doesNotThrow(() => assertTargetAllowed({ url: u }), u);
  }
  assert.throws(() => buildAddPayload({ name: 'x', url: 'gopher://x.example.test/' }), /not allowed/);
  assert.throws(() => buildEditPayload(cur, { url: 'file:///etc/passwd' }, 5), /not allowed/);
});

test('N4 dns_resolve_server goes through the denylist on add and edit', () => {
  assert.throws(() => buildAddPayload({ name: 'x', type: 'dns', hostname: 'a.example.test', dns_resolve_server: '127.0.0.1' }), /not allowed/);
  assert.throws(() => buildAddPayload({ name: 'x', type: 'dns', hostname: 'a.example.test', dns_resolve_server: '169.254.169.254' }), /not allowed/);
  assert.throws(() => buildEditPayload(cur, { dns_resolve_server: 'localhost' }, 5), /not allowed/);
  assert.doesNotThrow(() => buildAddPayload({ name: 'x', type: 'dns', hostname: 'a.example.test', dns_resolve_server: '1.1.1.1' }));
});

test('N5 delete_monitor / delete_notification require a matching confirmId', async () => {
  for (const [name, key] of [['uptimekuma_delete_monitor', 'monitorId'], ['uptimekuma_delete_notification', 'notificationId']] as const) {
    const t = tool(name);
    assert.equal(t.schema.safeParse({ [key]: 3 }).success, false, name);
    await assert.rejects(() => t.handler(t.schema.parse({ [key]: 3, confirmId: 4 })), /confirmId/, name);
  }
});

// ── Round 3 ─────────────────────────────────────────────────────────────────
test('R3-1 host:port deny entries match URLs that use the scheme default port', () => {
  process.env.KUMA_MCP_DENY_HOSTS = 'gw.internal:80,gw443.internal:443';
  try {
    for (const u of ['http://gw.internal/', 'http://gw.internal:80/', 'ws://gw.internal/', 'https://gw443.internal/', 'https://gw443.internal:443/x', 'wss://gw443.internal/']) {
      assert.throws(() => assertTargetAllowed({ url: u }), /not allowed/, u);
    }
    assert.throws(() => assertTargetAllowed({ hostname: 'gw.internal:80' }), /not allowed/);
    assert.throws(() => assertTargetAllowed({ hostname: 'gw.internal', port: 80 }), /not allowed/);
    // other ports / the other scheme are not matched by a port-specific entry
    assert.doesNotThrow(() => assertTargetAllowed({ url: 'http://gw443.internal/' }));
    assert.doesNotThrow(() => assertTargetAllowed({ url: 'https://gw.internal/' }));
    assert.doesNotThrow(() => assertTargetAllowed({ url: 'http://gw.internal:8080/' }));
    assert.doesNotThrow(() => assertTargetAllowed({ hostname: 'gw.internal' }));
  } finally { delete process.env.KUMA_MCP_DENY_HOSTS; }
});

test('R3-2 edit re-checks the MERGED target: a monitor already aimed at a denied host cannot take shaping edits', () => {
  const bad = { ...cur, url: 'http://localhost:3000/' };
  for (const ch of [{ headers: '{"A":"b"}' }, { type: 'keyword' }, { ignoreTls: true }, { maxredirects: 1 }]) {
    assert.throws(() => buildEditPayload(bad, ch, 5), /not allowed/, JSON.stringify(ch));
  }
  assert.throws(() => buildEditPayload({ ...cur, type: 'port', hostname: '169.254.169.254', port: 80 }, { ignoreTls: true }, 5), /not allowed/);
  assert.throws(() => buildEditPayload({ ...cur, type: 'dns', hostname: 'a.example.test', dns_resolve_server: '127.0.0.1' }, { type: 'dns', maxretries: 1, ignoreTls: true }, 5), /not allowed/);
  assert.doesNotThrow(() => buildEditPayload(bad, { name: 'renamed' }, 5)); // non-shaping edit still fine
  // placeholder url on ping/port monitors does not block edits; dns server ignored for non-dns types
  assert.doesNotThrow(() => buildEditPayload({ ...cur, type: 'ping', url: 'https://', hostname: 'nas.example.test' }, { hostname: 'nas2.example.test' }, 5));
  assert.doesNotThrow(() => buildEditPayload({ ...cur, type: 'port', url: 'https://', hostname: 'nas.example.test', port: 22, dns_resolve_server: '127.0.0.1' }, { port: 2222 }, 5));
});

test('R3-3 url requires an explicit http/https/ws/wss scheme (hostname stays scheme-optional)', () => {
  for (const u of ['example.test', 'example.test:8080/x', '//example.test/', '/relative/path', 'example.test/health']) {
    assert.throws(() => assertTargetAllowed({ url: u }), /not allowed/, u);
  }
  assert.throws(() => buildAddPayload({ name: 'x', url: 'example.test' }), /not allowed/);
  assert.throws(() => buildEditPayload(cur, { url: 'example.test' }, 5), /not allowed/);
  assert.doesNotThrow(() => assertTargetAllowed({ hostname: 'example.test' }));
});

test('R3-4 auth and TLS changes count as request-shaping for the merged-monitor checks', () => {
  const post = { ...cur, method: 'POST' };
  for (const ch of [{ authMethod: 'basic' }, { basic_auth_user: 'u' }, { basic_auth_pass: 'p' }, { ignoreTls: true }]) {
    assert.throws(() => buildEditPayload(post, ch, 5), /method not allowed/, JSON.stringify(ch));
  }
});

test('R3-5 a clamped maxredirects on edit is reported in notes', () => {
  const r = buildEditPayloadWithNotes({ ...cur, maxredirects: 10 }, { url: 'https://o.example.test/' }, 5);
  assert.equal(r.payload.maxredirects, 2);
  assert.match(r.notes.join(' '), /maxredirects was reduced from 10 to 2/);
  assert.deepEqual(buildEditPayloadWithNotes({ ...cur, maxredirects: 1 }, { url: 'https://o.example.test/' }, 5).notes, []);
});

test('R3-5b editMonitor surfaces the notes in its response', async () => {
  const client: any = Object.create(UptimeKumaClient.prototype);
  client.cfg = { name: 't' };
  client.ensureConnected = async () => {};
  client.emitWithAck = async (ev: string) => ev === 'getMonitor' ? { ok: true, monitor: { ...cur, maxredirects: 10 } } : { ok: true, msg: 'ok', monitorID: 5 };
  const out = await client.editMonitor(5, { url: 'https://o.example.test/' });
  assert.match(out.notes[0], /maxredirects was reduced/);
});

test('R3-6 repeated trailing dots and IPv4-translated IPv6 forms are normalised and refused', () => {
  for (const u of ['http://localhost../', 'http://localhost.../', 'http://127.0.0.1../', 'http://[::ffff:0:7f00:1]/', 'http://[::ffff:7f00:1]/',
    'http://[::ffff:0:a9fe:a9fe]/', 'http://bifrost../']) {
    assert.throws(() => assertTargetAllowed({ url: u }), /not allowed/, u);
  }
  assert.throws(() => assertTargetAllowed({ hostname: 'localhost..' }), /not allowed/);
  assert.doesNotThrow(() => assertTargetAllowed({ url: 'http://example.test../' }));
});

// ── Round 4 ─────────────────────────────────────────────────────────────────
test('R4-1 IPv6 bracket host:port deny entries match URL and hostname+port forms', () => {
  process.env.KUMA_MCP_DENY_HOSTS = '[2001:db8::5]:8080, [2001:db8::6], 2001:db8::7, 2001:db9::/32';
  try {
    assert.throws(() => assertTargetAllowed({ url: 'http://[2001:db8::5]:8080/' }), /not allowed/);
    assert.throws(() => assertTargetAllowed({ url: 'http://[2001:0db8:0:0:0:0:0:5]:8080/' }), /not allowed/);
    assert.throws(() => assertTargetAllowed({ hostname: '2001:db8::5', port: 8080 }), /not allowed/);
    assert.doesNotThrow(() => assertTargetAllowed({ url: 'http://[2001:db8::5]:9090/' }));
    assert.doesNotThrow(() => assertTargetAllowed({ hostname: '2001:db8::5' }));
    assert.throws(() => assertTargetAllowed({ url: 'http://[2001:db8::6]:1/' }), /not allowed/); // no port = any port
    assert.throws(() => assertTargetAllowed({ hostname: '2001:db8::7' }), /not allowed/);       // bare IPv6 entry
    assert.throws(() => assertTargetAllowed({ hostname: '2001:db9::1' }), /not allowed/);       // v6 CIDR
  } finally { delete process.env.KUMA_MCP_DENY_HOSTS; }
});

test('R4-1b a malformed KUMA_MCP_DENY_HOSTS entry is refused loudly, not skipped', () => {
  for (const bad of ['2001:db8::5:8080:zz', 'a b', '10.0.0.0/99', '[zz]:80', 'http://x']) {
    process.env.KUMA_MCP_DENY_HOSTS = 'ok.example.test,' + bad;
    try { assert.throws(() => assertTargetAllowed({ hostname: 'example.test' }), /invalid entry/, bad); } finally { delete process.env.KUMA_MCP_DENY_HOSTS; }
  }
});

test('R4-2 merged target check follows the monitor type: stale unrelated fields do not cause refusals', () => {
  const ping = { ...cur, type: 'ping', url: 'http://localhost/', hostname: 'nas.example.test', port: null };
  assert.doesNotThrow(() => buildEditPayload(ping, { hostname: 'nas2.example.test' }, 5));
  const http = { ...cur, type: 'http', url: 'https://a.example.test/', hostname: 'localhost' };
  assert.doesNotThrow(() => buildEditPayload(http, { url: 'https://b.example.test/' }, 5));
  // but the relevant field is still enforced
  assert.throws(() => buildEditPayload({ ...ping, hostname: 'localhost' }, { ignoreTls: true }, 5), /not allowed/);
  assert.throws(() => buildEditPayload({ ...http, url: 'http://localhost/' }, { ignoreTls: true }, 5), /not allowed/);
  assert.throws(() => buildEditPayload({ ...cur, type: 'weird-new-type', hostname: 'localhost' }, { ignoreTls: true }, 5), /not allowed/); // unknown type: both checked
});

test('R4-3 the https:// placeholder url is accepted on add and edit (ping/port)', () => {
  assert.doesNotThrow(() => buildAddPayload({ name: 'p', type: 'ping', hostname: 'nas.example.test', url: 'https://' }));
  assert.doesNotThrow(() => buildAddPayload({ name: 'p', type: 'port', hostname: 'nas.example.test', port: 22, url: 'https://' }));
  assert.doesNotThrow(() => buildEditPayload({ ...cur, type: 'port', hostname: 'a.example.test' }, { url: 'https://', port: 22 }, 5));
  assert.throws(() => buildAddPayload({ name: 'p', type: 'ping', hostname: 'localhost', url: 'https://' }), /not allowed/);
});

test('R4-4 UI default ports are filled for dns/radius/snmp and used by the denylist', () => {
  assert.equal(buildAddPayload({ name: 'd', type: 'dns', hostname: 'a.example.test' }).port, 53);
  assert.equal(buildAddPayload({ name: 'd', type: 'dns', hostname: 'a.example.test', port: 5353 }).port, 5353);
  process.env.KUMA_MCP_DENY_HOSTS = 'dns.internal:53';
  try { assert.throws(() => buildAddPayload({ name: 'd', type: 'dns', hostname: 'dns.internal' }), /not allowed/); } finally { delete process.env.KUMA_MCP_DENY_HOSTS; }
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactMonitor, redactMonitorAck, MONITOR_SECRET_FIELDS, MONITOR_SAFE_FIELDS, REDACTED, WITHHELD } from '../src/redact.js';
import { UptimeKumaClient } from '../src/uptime-kuma-client.js';

// Synthetic canaries only. Distinct per field so a leak names the field.
const canary = (f: string) => `CANARY_${f}_9f3a`;

function rawMonitor(): Record<string, any> {
  const m: Record<string, any> = {};
  for (const f of MONITOR_SAFE_FIELDS) m[f] = `safe_${f}`;
  m.id = 7; m.name = 'dead-man'; m.type = 'push'; m.active = true; m.interval = 60;
  m.url = 'https://example.test/path'; m.hostname = 'host.example.test'; m.grpcUrl = 'grpc.example.test:443';
  m.tags = [{ tag_id: 1, name: 'security', color: '#fff', value: '' }];
  m.notificationIDList = { '1': true };
  m.rabbitmqNodes = ['http://rabbit.example.test:15672'];
  for (const f of MONITOR_SECRET_FIELDS) m[f] = canary(f);
  m.kafkaProducerSaslOptions = { mechanism: 'plain', username: canary('sasl_user'), password: canary('sasl_pass') };
  return m;
}

test('every secret field is replaced by marker + presence, value never appears', () => {
  const out = redactMonitor(rawMonitor());
  for (const f of MONITOR_SECRET_FIELDS) {
    assert.deepEqual(out[f], { value: REDACTED, present: true }, f);
  }
  const text = JSON.stringify(out);
  assert.ok(!text.includes('CANARY_'), 'a canary value leaked');
});

test('absent / empty secrets report present:false', () => {
  for (const empty of [null, '', undefined, {}, []]) {
    const m = rawMonitor();
    m.pushToken = empty; m.basic_auth_pass = empty;
    const out = redactMonitor(m);
    assert.deepEqual(out.pushToken, { value: REDACTED, present: false });
    assert.deepEqual(out.basic_auth_pass, { value: REDACTED, present: false });
  }
});

test('secret key missing from source (older Kuma) is not invented', () => {
  const m = rawMonitor(); delete m.bearer_token; delete m.sshPassword;
  const out = redactMonitor(m);
  assert.ok(!('bearer_token' in out));
  assert.ok(!('sshPassword' in out));
});

test('redaction output carries no value-derived data (no hash/prefix/length)', () => {
  const m = rawMonitor(); m.pushToken = 'abcdefghijklmnopqrstuvwxyz012345';
  const out = redactMonitor(m);
  assert.deepEqual(Object.keys(out.pushToken).sort(), ['present', 'value']);
  assert.ok(!JSON.stringify(out.pushToken).includes('abcd'));
});

test('non-secret fields still come through unchanged', () => {
  const out = redactMonitor(rawMonitor());
  assert.equal(out.id, 7);
  assert.equal(out.name, 'dead-man');
  assert.equal(out.type, 'push');
  assert.equal(out.active, true);
  assert.equal(out.interval, 60);
  assert.equal(out.url, 'https://example.test/path');
  assert.equal(out.hostname, 'host.example.test');
  assert.deepEqual(out.tags, [{ tag_id: 1, name: 'security', color: '#fff', value: '' }]);
  assert.deepEqual(out.notificationIDList, { '1': true });
  assert.deepEqual(out.rabbitmqNodes, ['http://rabbit.example.test:15672']);
  for (const f of MONITOR_SAFE_FIELDS) {
    if (['url', 'hostname', 'grpcUrl', 'rabbitmqNodes', 'id', 'name', 'type', 'active', 'interval', 'tags', 'notificationIDList'].includes(f)) continue;
    assert.equal(out[f], `safe_${f}`, f);
  }
  assert.ok(!('droppedFields' in out));
});

test('secret and safe lists are disjoint', () => {
  const safe = new Set(MONITOR_SAFE_FIELDS);
  for (const f of MONITOR_SECRET_FIELDS) assert.ok(!safe.has(f), f);
});

test('unknown (future) fields are dropped by default; only the name is reported', () => {
  const m = rawMonitor();
  m.someNewKumaSecret = 'CANARY_new_field'; m.push_token = 'CANARY_snake';
  const out = redactMonitor(m);
  assert.ok(!('someNewKumaSecret' in out));
  assert.ok(!('push_token' in out));
  assert.deepEqual(out.droppedFields, ['push_token', 'someNewKumaSecret']);
  assert.ok(!JSON.stringify(out).includes('CANARY_'));
});

test('credential-bearing url/hostname/grpcUrl/rabbitmqNodes are masked', () => {
  const m = rawMonitor();
  const at = '@'; // built at runtime so secret scanners do not flag synthetic userinfo URLs
  m.url = 'https://user:CANARY_pw' + at + 'example.test/x';
  m.hostname = 'https://h.example.test/?token=CANARY_t';
  m.grpcUrl = 'grpc://u:CANARY_g' + at + 'h:443';
  m.rabbitmqNodes = ['http://a:CANARY_r' + at + 'rabbit.example.test', 'http://clean.example.test'];
  const out = redactMonitor(m);
  assert.equal(out.url, REDACTED);
  assert.equal(out.hostname, REDACTED);
  assert.equal(out.grpcUrl, REDACTED);
  assert.deepEqual(out.rabbitmqNodes, [REDACTED, 'http://clean.example.test']);
  assert.ok(!JSON.stringify(out).includes('CANARY_'));
});

test('ack: only ok/msg/monitorID/monitor survive; monitor is redacted', () => {
  const out = redactMonitorAck({ ok: true, msg: 'saved', monitorID: 7, monitor: rawMonitor(), extra: 'CANARY_extra' });
  assert.equal(out.ok, true);
  assert.equal(out.msg, 'saved');
  assert.equal(out.monitorID, 7);
  assert.ok(!('extra' in out));
  assert.ok(!JSON.stringify(out).includes('CANARY_'));
  assert.equal(redactMonitorAck({ ok: false, msg: 'nope' }).msg, WITHHELD); // failure text is withheld
  assert.equal(redactMonitorAck(undefined), undefined);
});

// Client wiring: get_monitor must redact; editMonitor must still merge RAW values.
function fakeClient(): { client: any; sent: any[] } {
  const client: any = Object.create(UptimeKumaClient.prototype);
  const sent: any[] = [];
  client.cfg = { name: 'test' };
  client.ensureConnected = async () => {};
  client.emitWithAck = async (event: string, ...args: any[]) => {
    sent.push([event, ...args]);
    if (event === 'getMonitor') return { ok: true, monitor: rawMonitor() };
    return { ok: true, msg: 'ok', monitorID: 7, monitor: rawMonitor() };
  };
  return { client, sent };
}

test('client.getMonitor returns a redacted ack', async () => {
  const { client } = fakeClient();
  const res = await client.getMonitor(7);
  assert.equal(res.ok, true);
  assert.deepEqual(res.monitor.pushToken, { value: REDACTED, present: true });
  assert.ok(!JSON.stringify(res).includes('CANARY_'));
  assert.equal(res.monitor.name, 'dead-man');
});

test('client.editMonitor merges RAW secrets upstream (no marker written back) and returns redacted', async () => {
  const { client, sent } = fakeClient();
  const res = await client.editMonitor(7, { name: 'renamed' });
  const edit = sent.find((s) => s[0] === 'editMonitor')![1];
  assert.equal(edit.name, 'renamed');
  assert.equal(edit.pushToken, canary('pushToken'));
  assert.equal(edit.basic_auth_pass, canary('basic_auth_pass'));
  assert.ok(!JSON.stringify(edit).includes(REDACTED));
  assert.ok(!JSON.stringify(res).includes('CANARY_'));
});

test('client.addMonitor ack is redacted', async () => {
  const { client } = fakeClient();
  const res = await client.addMonitor({ name: 'x' });
  assert.ok(!JSON.stringify(res).includes('CANARY_'));
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  scrubUrl, redactMonitor, redactNotification, redactHeartbeatAck, sanitizeHeartbeatMsg,
  assertMonitorEditAllowed, assertNotificationEditAllowed, MONITOR_DESTINATION_FIELDS,
  DESTINATION_REFUSAL, NOTIF_DESTINATION_REFUSAL, REDACTED, WITHHELD,
} from '../src/redact.js';
import { UptimeKumaClient } from '../src/uptime-kuma-client.js';

const at = '@';
const C = 'CANARYr2secret88';

// ── M1: URL scrub, both polarities ─────────────────────────────────────────
test('M1 scrubUrl masks the whole value for every credential-bearing form', () => {
  const bad = [
    'https://' + C + at + 'h.example.test/',                 // token as username
    'https://u:' + C + at + 'h.example.test/',               // user:pw
    'redis://:' + C + at + 'h:6379',                         // empty user
    C + ':x' + at + 'h.example.test',                        // scheme-less userinfo
    'https://h.example.test/x?token=' + C,
    'https://h.example.test/x?auth_token=' + C,
    'https://h.example.test/x?client_secret=' + C,
    'https://h.example.test/x?apiToken=' + C,
    'https://h.example.test/x?key=' + C,
    'https://h.example.test/x?sig=' + C,
    'https://h.example.test/x?whatever=' + C,                // any query value
    'https://h.example.test/x#access_token=' + C,            // fragment
    'https://h.example.test/x;jsessionid=' + C,
    'https://hooks.slack.com/services/T0/B0/' + C,           // known webhook host
    'https://discord.com/api/webhooks/123/' + C,
    'https://api.telegram.org/bot123:' + C + '/sendMessage',
    'https://h.example.test/hooks/' + C,                     // secret-bearing prefix
    'https://h.example.test/a/' + 'Zx9Qw3Er5Ty7' + '/b',     // token-shaped segment
    'http://[fd00::1]:80/?k=' + C,
  ];
  for (const u of bad) assert.equal(scrubUrl(u), REDACTED, u);
});

test('M1 scrubUrl fails closed on parse failure with special chars, passes clean values', () => {
  assert.equal(scrubUrl('not a url ' + at + ' ' + C), REDACTED);
  assert.equal(scrubUrl('%%%?' + C), REDACTED);
  for (const ok of ['https://example.test/', 'https://example.test/health', 'https://example.test/api/v1/status',
    'host.example.test', '10.0.0.5', '', 'http://svc:3001', 'tcp://10.0.0.5:22']) {
    assert.equal(scrubUrl(ok), ok, ok);
  }
  assert.equal(scrubUrl(5 as any), 5);
});

test('M1 monitor fields use the same scrub (url, hostname, grpcUrl, rabbitmqNodes, kafkaProducerBrokers)', () => {
  const out: any = redactMonitor({
    id: 1, url: 'https://' + C + at + 'x.test', hostname: 'https://x.test/p#' + C, grpcUrl: 'g.test:1?t=' + C,
    rabbitmqNodes: ['http://u:' + C + at + 'r.test'], kafkaProducerBrokers: ['k.test:9092?' + C],
  });
  assert.ok(!JSON.stringify(out).includes(C));
  assert.equal(out.url, REDACTED);
});

// ── L1 / nit ────────────────────────────────────────────────────────────────
test('L1 non-object monitor payloads are masked; null passes; includeSensitiveData is silent', () => {
  assert.equal(redactMonitor('{"pushToken":"' + C + '"}'), REDACTED);
  assert.equal(redactMonitor([{ pushToken: C }]), REDACTED);
  assert.equal(redactMonitor(null), null);
  const o: any = redactMonitor({ id: 1, includeSensitiveData: true });
  assert.ok(!('includeSensitiveData' in o) && !('droppedFields' in o));
});

// ── H1: monitor edit guard, both polarities ────────────────────────────────
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
const credMon = { id: 5, name: 'm', type: 'http', url: 'https://a.example.test/', hostname: null, port: null, ignoreTls: false, interval: 60, basic_auth_pass: C };

test('H1 monitor with a credential: every destination-shaping field is refused and nothing is sent', async () => {
  for (const f of MONITOR_DESTINATION_FIELDS) {
    const { client, sent } = editClient(credMon);
    await assert.rejects(() => client.editMonitor(5, { [f]: 'attacker.example.test' }), { message: DESTINATION_REFUSAL }, f);
    assert.ok(!sent.some((s) => s[0] === 'editMonitor'), f);
  }
  for (const [f, v] of [['url', 'https://evil.example.test/'], ['hostname', 'evil.example.test'], ['port', 4444], ['ignoreTls', true]] as const) {
    const { client } = editClient(credMon);
    await assert.rejects(() => client.editMonitor(5, { [f]: v }), { message: DESTINATION_REFUSAL }, f);
  }
  // unknown keys are refused too (allowlist, fail closed)
  const { client } = editClient(credMon);
  await assert.rejects(() => client.editMonitor(5, { someNewField: 1 }), { message: DESTINATION_REFUSAL });
});

test('H1 monitor with a credential: non-destination edits and no-op destination values still work', async () => {
  const { client, sent } = editClient(credMon);
  await client.editMonitor(5, { name: 'renamed', interval: 30, description: 'd', notificationIDList: { '1': true } });
  await client.editMonitor(5, { url: 'https://a.example.test/' }); // unchanged value
  const edits = sent.filter((s) => s[0] === 'editMonitor');
  assert.equal(edits.length, 2);
  assert.equal(edits[0][1].basic_auth_pass, C); // raw merge intact
});

test('H1 monitor with no credential: destination edits are allowed', async () => {
  const { client, sent } = editClient({ id: 6, name: 'p', type: 'ping', hostname: 'a.test', headers: '{}', oauth_auth_method: 'client_secret_basic',
    kafkaProducerSaslOptions: { mechanism: 'None' }, basic_auth_pass: '', pushToken: null });
  await client.editMonitor(6, { hostname: 'b.test', port: 22, ignoreTls: true });
  assert.ok(sent.some((s) => s[0] === 'editMonitor' && s[1].hostname === 'b.test'));
});

test('H1 assertMonitorEditAllowed: unknown shape counts as credentialed', () => {
  assert.throws(() => assertMonitorEditAllowed('x', { url: 'u' }), { message: DESTINATION_REFUSAL });
});

// ── H1: notification edit guard, both polarities ───────────────────────────
function notifClient(cfg: Record<string, any>) {
  const sent: any[] = [];
  const client: any = Object.create(UptimeKumaClient.prototype);
  client.cfg = { name: 't' };
  client.ensureConnected = async () => {};
  client.notificationCacheReady = true;
  client.notificationCache = [{ id: 3, name: 'n', config: JSON.stringify(cfg) }];
  client.emitWithAck = async (ev: string, ...a: any[]) => { sent.push([ev, ...a]); return { ok: true, msg: 'Saved', id: 3 }; };
  return { client, sent };
}
const ntfyCfg = { type: 'ntfy', name: 'n', ntfyserverurl: 'https://ntfy.example.test', ntfytopic: 'alerts', ntfyPriority: 4, ntfyusername: 'u', ntfypassword: C };

test('H1 notification holding a secret: destination changes refused, nothing sent', async () => {
  for (const change of [{ ntfyserverurl: 'https://evil.example.test' }, { webhookURL: 'https://evil.example.test' }, { type: 'webhook' }]) {
    const { client, sent } = notifClient(ntfyCfg);
    await assert.rejects(() => client.updateNotification(3, { config: change }), { message: NOTIF_DESTINATION_REFUSAL });
    await assert.rejects(() => client.updateNotification(3, { type: 'webhook' }), { message: NOTIF_DESTINATION_REFUSAL });
    assert.equal(sent.length, 0);
  }
});

test('H1 notification: safe edits and unchanged values work; secrets are merged raw', async () => {
  const { client, sent } = notifClient(ntfyCfg);
  await client.updateNotification(3, { name: 'renamed', config: { ntfyPriority: 5, ntfyserverurl: 'https://ntfy.example.test' } });
  const saved = sent[0][1];
  assert.equal(saved.ntfypassword, C);
  assert.equal(saved.ntfyPriority, 5);
  assert.equal(saved.name, 'renamed');
});

test('H1 notification with no secret or URL key: edits allowed', async () => {
  const { client, sent } = notifClient({ type: 'pushover', name: 'n', pushoverdevice: 'phone' });
  await client.updateNotification(3, { type: 'pushbullet', config: { pushoverdevice: 'tablet' } });
  assert.equal(sent[0][1].pushoverdevice, 'tablet');
});

test('H1 assertNotificationEditAllowed pure', () => {
  assert.doesNotThrow(() => assertNotificationEditAllowed({ ntfypassword: C }, { name: 'x' }));
  assert.throws(() => assertNotificationEditAllowed({ ntfypassword: C }, { ntfyserverurl: 'x' }));
});

// ── H2: notification projection ─────────────────────────────────────────────
test('H2 redactNotification: allowlist projection, secrets as {value,present}, host-only ntfy url', () => {
  const provs = [
    { id: 1, name: 's', active: true, userId: 9, isDefault: false, config: JSON.stringify({ type: 'slack', slackwebhookURL: 'https://hooks.slack.com/services/T/B/' + C, slackchannel: C }) },
    { id: 2, name: 'd', config: { type: 'discord', discordWebhookUrl: 'https://discord.com/api/webhooks/1/' + C } },
    { id: 3, name: 'a', config: { type: 'apprise', appriseURL: 'tgram://' + C + '/1' } },
    { id: 4, name: 'b', config: { type: 'Bark', barkEndpoint: 'https://bark.example.test/' + C } },
    { id: 5, name: 'w', config: { type: 'webhook', webhookURL: 'https://w.example.test/h/' + C, webhookAdditionalHeaders: '{"Authorization":"' + C + '"}', brandNewProviderKey: C } },
    { id: 6, name: 'bad', config: '{not json ' + C },
    { id: 7, name: 'n', config: { type: 'ntfy', ntfyserverurl: 'https://ntfy.example.test', ntfytopic: 'alerts', ntfyPriority: 4, ntfypassword: C } },
    { id: 8, name: 'n2', config: { type: 'ntfy', ntfyserverurl: 'https://ntfy.example.test/' + C } },
  ];
  const out: any[] = provs.map(redactNotification);
  for (const o of out.slice(0, 6)) assert.ok(!JSON.stringify(o).includes(C), o.name);
  assert.ok(!JSON.stringify(out[7]).includes(C));
  assert.ok(!('userId' in out[0]));
  assert.deepEqual(out[0].config.slackwebhookURL, { value: REDACTED, present: true });
  assert.equal(out[5].config, REDACTED);
  // pass-through polarity
  assert.equal(out[6].config.ntfyserverurl, 'https://ntfy.example.test');
  assert.deepEqual(out[6].config.ntfytopic, { value: REDACTED, present: true }); // L3: topic is the alert path
  assert.equal(out[6].config.ntfyPriority, 4);
  assert.equal(out[6].config.type, 'ntfy');
  assert.deepEqual(out[6].config.ntfypassword, { value: REDACTED, present: true });
  assert.equal(out[7].config.ntfyserverurl, REDACTED);
  assert.equal(out[0].name, 's'); assert.equal(out[0].active, true); assert.equal(out[0].id, 1);
});

// ── L2: error text ──────────────────────────────────────────────────────────
test('L2 failed add/delete/pause/resume/save errors do not echo Kuma msg', async () => {
  const client: any = Object.create(UptimeKumaClient.prototype);
  client.cfg = { name: 't' };
  client.ensureConnected = async () => {};
  client.emitWithAck = async () => ({ ok: false, msg: 'bad "X-Api-Key: ' + C + '" is not valid JSON' });
  for (const call of [() => client.addMonitor({ name: 'x' }), () => client.deleteMonitor(1), () => client.pauseMonitor(1),
    () => client.resumeMonitor(1), () => client.saveNotification({ name: 'x' }), () => client.deleteNotification(1)]) {
    await assert.rejects(call, (e: any) => { assert.ok(!e.message.includes(C)); assert.ok(e.message.includes(WITHHELD)); return true; });
  }
  client.emitWithAck = async () => ({ ok: false, msg: 'x ' + C, msgi18n: 'invalidJSON' });
  await assert.rejects(() => client.deleteMonitor(1), (e: any) => e.message.includes('invalidJSON') && !e.message.includes(C));
});

// ── L3: heartbeats ──────────────────────────────────────────────────────────
test('L3 heartbeat msg: JSON-parse excerpts withheld, URLs scrubbed, plain text kept', () => {
  assert.equal(sanitizeHeartbeatMsg('Your JSON body is invalid. Unexpected token \'x\', "{' + C + '" is not valid JSON'), WITHHELD);
  assert.equal(sanitizeHeartbeatMsg('push to https://h.test/api/push/' + C + ' ok'), 'push to ' + REDACTED + ' ok');
  assert.equal(sanitizeHeartbeatMsg('200 - OK'), '200 - OK');
  const out: any = redactHeartbeatAck({ ok: true, data: [{ id: 1, status: 1, msg: 'OK', time: '2026-01-01 00:00:00', ping: 5, junk: 'S' + C }, 'str'] });
  assert.deepEqual(out.data[0], { id: 1, status: 1, msg: 'OK', time: '2026-01-01 00:00:00', ping: 5 });
  assert.equal(out.data[1], REDACTED);
  assert.ok(!JSON.stringify(out).includes(C));
});

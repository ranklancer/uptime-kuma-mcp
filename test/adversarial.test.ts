import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactMonitor, redactMonitorAck, scrubUrlField, REDACTED } from '../src/redact.js';
import { UptimeKumaClient } from '../src/uptime-kuma-client.js';

const at = '@';
const C = 'CANARYsecret77';
// Each case: a string that embeds a credential; secure behaviour = masked.
const urlCases: Record<string, string> = {
  redis_empty_user: 'redis://:' + C + at + 'cache.example.test:6379/0',
  token_as_username: 'https://' + C + at + 'git.example.test/repo.git',
  fragment_token: 'https://app.example.test/cb#access_token=' + C,
  auth_token_param: 'https://api.example.test/x?auth_token=' + C,
  client_secret_param: 'https://api.example.test/x?client_id=a&client_secret=' + C,
  apiToken_param: 'https://api.example.test/x?apiToken=' + C,
  path_secret_slack_style: 'https://hooks.example.test/services/T000/B000/' + C,
  ipv6_userinfo: 'http://u:' + C + at + '[fd00::1]:8080/',
  mongodb_srv: 'mongodb+srv://u:' + C + at + 'cluster.example.test/db',
  pct_userinfo: 'https://u:' + C + '%40x' + at + 'h.example.test/',
  semicolon_param: 'https://h.example.test/x;jsessionid=' + C,
};

test('ADV-1 url scrub: every credential-bearing URL form is masked', () => {
  const missed: string[] = [];
  for (const [name, u] of Object.entries(urlCases)) {
    const out = scrubUrlField(u);
    if (typeof out === 'string' && out.includes(C)) missed.push(name);
  }
  assert.deepEqual(missed, [], 'unmasked forms: ' + missed.join(','));
});

test('ADV-2 fail closed: non-object monitor payload (string / array) is not passed through raw', () => {
  const asString = JSON.stringify({ id: 1, pushToken: C });
  const asArray = [{ id: 1, pushToken: C }];
  const leaks: string[] = [];
  if (JSON.stringify(redactMonitor(asString)).includes(C)) leaks.push('string');
  if (JSON.stringify(redactMonitor(asArray)).includes(C)) leaks.push('array');
  if (JSON.stringify(redactMonitorAck({ ok: true, monitor: asString })).includes(C)) leaks.push('ack-string');
  assert.deepEqual(leaks, [], 'raw pass-through: ' + leaks.join(','));
});

test('ADV-3 list_notifications masks path-embedded webhook secrets (Slack/Discord/Mattermost)', async () => {
  const client: any = Object.create(UptimeKumaClient.prototype);
  client.cfg = { name: 't' };
  client.ensureConnected = async () => {};
  client.notificationCacheReady = true;
  client.notificationCache = [
    { id: 1, name: 's', config: JSON.stringify({ type: 'slack', slackwebhookURL: 'https://hooks.example.test/services/T/B/' + C }) },
    { id: 2, name: 'd', config: JSON.stringify({ type: 'discord', discordWebhookUrl: 'https://discord.example.test/api/webhooks/1/' + C }) },
    { id: 3, name: 'a', config: { type: 'apprise', appriseURL: 'tgram://' + C + '/12345' } },
  ];
  const out = await client.listNotifications();
  const leaked = out.filter((n: any) => JSON.stringify(n).includes(C)).map((n: any) => n.name);
  assert.deepEqual(leaked, [], 'leaked providers: ' + leaked.join(','));
});

test('ADV-4 edit failure message from Kuma is not echoed verbatim to the tool caller', async () => {
  const client: any = Object.create(UptimeKumaClient.prototype);
  client.cfg = { name: 't' };
  client.ensureConnected = async () => {};
  client.emitWithAck = async (ev: string) => ev === 'getMonitor'
    ? { ok: true, monitor: { id: 1, headers: 'X-Api-Key: ' + C } }
    : { ok: false, msg: 'Headers must be valid JSON: Unexpected token \'X\', "X-Api-Key: ' + C + '" is not valid JSON' };
  let msg = '';
  try { await client.editMonitor(1, { name: 'n' }); } catch (e: any) { msg = String(e.message); }
  assert.ok(msg.length > 0);
  assert.ok(!msg.includes(C), 'Kuma error text echoed secret to caller');
});

test('ADV-5 (control) prototype keys and a spoofed droppedFields key cannot smuggle values', () => {
  const m = JSON.parse('{"id":1,"__proto__":{"x":"' + C + '"},"droppedFields":["' + C + '"],"constructor":"' + C + '"}');
  const out = redactMonitor(m);
  assert.ok(!JSON.stringify(out).includes(C));
  assert.deepEqual(out.droppedFields, ['__proto__', 'constructor', 'droppedFields']);
});

test('ADV-6 (control) headers as JSON string and SASL object are redacted whole', () => {
  const out = redactMonitor({ id: 1, headers: JSON.stringify({ Authorization: 'Bearer ' + C }), kafkaProducerSaslOptions: { mechanism: 'plain', password: C }, accepted_statuscodes: ['200-299'] });
  assert.ok(!JSON.stringify(out).includes(C));
  assert.deepEqual(out.accepted_statuscodes, ['200-299']);
});

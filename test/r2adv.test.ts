import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scrubUrl, sanitizeHeartbeatMsg, assertMonitorEditAllowed, assertNotificationEditAllowed, redactNotification, redactMonitor, REDACTED } from '../src/redact.js';
const C = 'CANARYsecret77zzQ';
const at = '@';

test('R2-1 scheme-less path secret in url/grpcUrl/brokers is masked', () => {
  const cases: Record<string, string> = {
    schemeless_slack: 'hooks.example.test/services/T000/B000/' + C + 'abcdefgh',
    schemeless_token_seg: 'host.example.test/ping/' + C + '1234567890',
    hostport_path: 'grpc.example.test:443/' + C + '1234567890',
    opaque_scheme: 'tgram:' + C + '1234567890/12345',
    ws_token_path: 'wss://h.example.test/socket/' + C + '1234567890',
  };
  const missed = Object.entries(cases).filter(([, v]) => String(scrubUrl(v)).includes(C)).map(([k]) => k);
  assert.deepEqual(missed, [], 'unmasked: ' + missed.join(','));
});

test('R2-2 heartbeat URL regex is linear (no quadratic blowup on long msg)', () => {
  const s = 'a'.repeat(200_000);
  const t0 = process.hrtime.bigint(); sanitizeHeartbeatMsg(s); const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.ok(ms < 500, `sanitizeHeartbeatMsg took ${ms.toFixed(0)} ms on 200k chars`);
});

test('R2-3 monitor whose ONLY credential is in the url cannot be weakened (ignoreTls/hostname)', () => {
  const raw = { id: 1, type: 'http', url: 'https://u:' + C + at + 'h.example.test/', ignoreTls: false };
  assert.throws(() => assertMonitorEditAllowed(raw, { ignoreTls: true }));
});

test('R2-4 notification whose secret is its webhook URL: type/URL change refused (alert reroute)', () => {
  const cfg = { type: 'slack', slackwebhookURL: 'https://hooks.example.test/services/T/B/' + C };
  assert.throws(() => assertNotificationEditAllowed(cfg, { type: 'webhook', webhookURL: 'https://evil.example.test/' }));
});

test('R2-5 ntfytopic is not disclosed by list_notifications', () => {
  const out = redactNotification({ id: 1, name: 'n', config: { type: 'ntfy', ntfytopic: 'alerts-' + C, ntfyserverurl: 'https://ntfy.example.test' } });
  assert.ok(!JSON.stringify(out).includes(C));
});

test('R2-6 (control) aliasing: changes with __proto__/constructor keys are refused on credentialed monitor', () => {
  const raw = { id: 1, basic_auth_pass: C, url: 'https://h.example.test/' };
  const ch = JSON.parse('{"__proto__":{"url":"https://evil.example.test/"}}');
  assert.throws(() => assertMonitorEditAllowed(raw, ch));
  assert.throws(() => assertMonitorEditAllowed(raw, { constructor: 'x' } as any));
  assert.throws(() => assertMonitorEditAllowed(raw, { active: false }));
  assert.throws(() => assertMonitorEditAllowed(raw, { type: 'keyword' }));
  assert.ok(!JSON.stringify(redactMonitor(raw)).includes(C));
});

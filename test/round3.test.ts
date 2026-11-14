import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeHeartbeatMsg, redactHeartbeatAck, assertMonitorEditAllowed, assertNotificationEditAllowed, scrubUrl, redactNotification, HEARTBEAT_MSG_CAP, REDACTED, DESTINATION_REFUSAL, NOTIF_DESTINATION_REFUSAL } from '../src/redact.js';

const C = 'CANARYr3secret55';
const ms = (f: () => void) => { const t = process.hrtime.bigint(); f(); return Number(process.hrtime.bigint() - t) / 1e6; };

test('R2-M1 timing: 200k-char msgs of several shapes are fast', () => {
  for (const s of ['a'.repeat(200_000), 'a.'.repeat(100_000), 'ab+'.repeat(70_000), 'x://'.repeat(50_000), ('a'.repeat(31) + ':/').repeat(6000)]) {
    const t = ms(() => sanitizeHeartbeatMsg(s));
    assert.ok(t < 100, `took ${t.toFixed(0)} ms`);
  }
});

test('R2-M1 timing: 1440 rows x 8 KB through redactHeartbeatAck is bounded', () => {
  const rows = Array.from({ length: 1440 }, (_, i) => ({ id: i, status: 1, msg: 'a'.repeat(8192), time: 't', ping: 1 }));
  const t = ms(() => redactHeartbeatAck({ ok: true, data: rows }));
  assert.ok(t < 1000, `took ${t.toFixed(0)} ms`);
});

test('R2-M1 msg is truncated to the cap before scanning; behaviour on short msgs unchanged', () => {
  const out = sanitizeHeartbeatMsg('ok ' + 'b'.repeat(5000)) as string;
  assert.ok(out.length <= HEARTBEAT_MSG_CAP + 20);
  assert.equal(sanitizeHeartbeatMsg('push to https://h.test/api/push/' + C + 'abcd ok'), 'push to ' + REDACTED + ' ok');
  assert.equal(sanitizeHeartbeatMsg('200 - OK'), '200 - OK');
});

test('L1 URL-only credential: ignoreTls/type refused; unchanged url allowed; credential-free monitor allowed', () => {
  const at = '@';
  for (const url of ['https://u:' + C + at + 'h.test/', 'https://h.test/x?token=' + C, 'h.test/hooks/T/B/' + C + 'zz']) {
    const raw = { id: 1, type: 'http', url, ignoreTls: false };
    assert.throws(() => assertMonitorEditAllowed(raw, { ignoreTls: true }), { message: DESTINATION_REFUSAL });
    assert.throws(() => assertMonitorEditAllowed(raw, { hostname: 'evil.test' }), { message: DESTINATION_REFUSAL });
    assert.doesNotThrow(() => assertMonitorEditAllowed(raw, { url, name: 'n' }));
  }
  assert.doesNotThrow(() => assertMonitorEditAllowed({ id: 1, type: 'http', url: 'https://h.test/health', ignoreTls: false }, { ignoreTls: true }));
});

test('L2 URL-secret provider: type and URL changes refused; credential-free provider free', () => {
  const cfg = { type: 'slack', slackwebhookURL: 'https://hooks.example.test/services/T/B/' + C };
  assert.throws(() => assertNotificationEditAllowed(cfg, { type: 'webhook' }), { message: NOTIF_DESTINATION_REFUSAL });
  assert.throws(() => assertNotificationEditAllowed(cfg, { slackwebhookURL: 'https://evil.test/' }), { message: NOTIF_DESTINATION_REFUSAL });
  assert.throws(() => assertNotificationEditAllowed({ type: 'ntfy', ntfyserverurl: 'https://n.test', ntfytopic: 't' }, { ntfytopic: 'other' }), { message: NOTIF_DESTINATION_REFUSAL });
  assert.doesNotThrow(() => assertNotificationEditAllowed(cfg, { name: 'renamed' }));
  assert.doesNotThrow(() => assertNotificationEditAllowed({ type: 'pushover', pushoverdevice: 'a' }, { type: 'x', pushoverdevice: 'b' }));
});

test('L3 ntfytopic is masked', () => {
  const o: any = redactNotification({ id: 1, name: 'n', config: { type: 'ntfy', ntfytopic: 'alerts-' + C, ntfyPriority: 3 } });
  assert.ok(!JSON.stringify(o).includes(C));
  assert.equal(o.config.ntfyPriority, 3);
});

test('L4 scheme-less path tokens are masked; bare hosts and clean paths are not', () => {
  for (const u of ['hooks.example.test/services/T000/B000/' + C, 'host.example.test/ping/' + C + '12345', 'grpc.example.test:443/' + C + '12345', 'hooks.slack.com/x']) {
    assert.equal(scrubUrl(u), REDACTED, u);
  }
  for (const ok of ['very-long-service-hostname.example.test', 'host.example.test/health', 'host:8080', '10.0.0.5/ping']) {
    assert.equal(scrubUrl(ok), ok, ok);
  }
});

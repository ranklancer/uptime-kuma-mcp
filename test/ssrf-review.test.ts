import { test } from 'node:test';
import assert from 'node:assert/strict';
process.env.KUMA_INSTANCES = 'kuma';
process.env.KUMA_BASE_URL = 'http://kuma.test:3001';
process.env.KUMA_USERNAME ??= 'u';
process.env.KUMA_PASSWORD ??= 'p';
const { assertTargetAllowed, assertResolvedTargetAllowed, assertNotificationConfigAllowed, denyList } = await import('../src/policy.js');
const { buildAddPayload, buildEditPayload } = await import('../src/payload.js');
const { sanitizeHeartbeatMsg } = await import('../src/redact.js');
const { toolDefs, maintenanceNeedsConfirm } = await import('../src/tools.js');
const tool = (n: string) => toolDefs.find((t) => t.name === n)!;
const res = (m: Record<string, string[] | 'fail'>) => async (h: string) => { const v = m[h]; if (!v || v === 'fail') throw new Error('ENOTFOUND'); return v; };
const withEnv = async (env: Record<string, string>, f: () => unknown | Promise<unknown>) => {
  const old: Record<string, string | undefined> = {};
  for (const k of Object.keys(env)) { old[k] = process.env[k]; process.env[k] = env[k]; }
  try { await f(); } finally { for (const k of Object.keys(env)) { if (old[k] === undefined) delete process.env[k]; else process.env[k] = old[k]; } }
};

// H1 ── notification config policy
test('H1 notification config: URL/host-shaped values (recursive) go through the denylist and resolve check', async () => {
  for (const cfg of [
    { webhookURL: 'http://127.0.0.1:8015/hook' },
    { webhookURL: 'http://bifrost:8080/x' },
    { ntfyserverurl: 'http://169.254.169.254/' },
    { nested: { deep: { smtpHost: 'localhost' } } },
    { list: [{ endpoint: 'http://[::1]/x' }] },
    { appriseURL: 'json://127.0.0.1:9000/x' },
  ]) await assert.rejects(assertNotificationConfigAllowed(cfg), /not allowed/, JSON.stringify(cfg));
  await assert.rejects(assertNotificationConfigAllowed({ webhookURL: 'https://evil.example/h' }, res({ 'evil.example': ['127.0.0.1'] })), /denylisted/);
  await assert.rejects(assertNotificationConfigAllowed({ webhookURL: 'https://nx.example/h' }, res({})), /could not be resolved/);
  await assertNotificationConfigAllowed({ webhookURL: 'https://ok.example/h', slackchannel: 'general', appriseURL: 'tgram://tok/123' }, res({ 'ok.example': ['203.0.113.9'] }));
});

test('H1 webhook custom body / additional headers refused unless KUMA_MCP_ALLOW_WRITE_METHODS=1', async () => {
  await assert.rejects(assertNotificationConfigAllowed({ webhookURL: 'https://203.0.113.9/h', webhookCustomBody: '{"a":"{{msg}}"}' }), /ALLOW_WRITE_METHODS/);
  await assert.rejects(assertNotificationConfigAllowed({ webhookURL: 'https://203.0.113.9/h', webhookAdditionalHeaders: '{"X":"y"}' }), /ALLOW_WRITE_METHODS/);
  await withEnv({ KUMA_MCP_ALLOW_WRITE_METHODS: '1' }, () => assertNotificationConfigAllowed({ webhookURL: 'https://203.0.113.9/h', webhookCustomBody: '{}' }));
});

test('H1 create/update_notification with isDefault or applyExisting need confirmApply', async () => {
  for (const [n, extra] of [['uptimekuma_create_notification', {}], ['uptimekuma_update_notification', { notificationId: 1 }]] as const) {
    const t = tool(n);
    for (const flag of [{ isDefault: true }, { applyExisting: true }]) {
      await assert.rejects(() => t.handler(t.schema.parse({ name: 'n', type: 'ntfy', ...extra, ...flag })), /confirmApply/, n);
    }
  }
});

test('H1 the client policy runs on create and on the incoming changes of an update', async () => {
  const { UptimeKumaClient } = await import('../src/uptime-kuma-client.js');
  const c: any = Object.create(UptimeKumaClient.prototype);
  c.cfg = { name: 't' }; c.ensureConnected = async () => {};
  let sent = 0; c.emitWithAck = async () => { sent++; return { ok: true, id: 1 }; };
  await assert.rejects(c.saveNotification({ name: 'n', type: 'webhook', webhookURL: 'http://127.0.0.1:8015/x' }, null), /not allowed/);
  assert.equal(sent, 0);
  c.getNotification = async () => ({ id: 1, name: 'n', config: { type: 'ntfy', ntfytopic: 't' } });
  await assert.rejects(c.updateNotification(1, { config: { ntfyserverurl: 'http://localhost:2586' } }), /not allowed/);
  assert.equal(sent, 0);
});

// H2 ── redirects
test('H2 maxredirects is forced to 0 even with write methods on', () => {
  withEnv({ KUMA_MCP_ALLOW_WRITE_METHODS: '1' }, () => {
    assert.equal(buildAddPayload({ name: 'x', url: 'https://203.0.113.9/', maxredirects: 10 }).maxredirects, 0);
    assert.equal(buildEditPayload({ id: 1, type: 'http', url: 'https://203.0.113.9/', maxredirects: 10, timeout: 48, interval: 60 }, { maxredirects: 5 }, 1).maxredirects, 0);
  });
});

// H3 ── opt-in private ranges
test('H3 KUMA_MCP_DENY_PRIVATE=1 denies RFC1918/CGNAT unless the host is allow-listed; default is unchanged', () => {
  for (const h of ['10.1.2.3', '172.16.5.5', '172.31.255.1', '192.168.1.54', '100.64.0.1', '100.127.255.254']) {
    assert.doesNotThrow(() => assertTargetAllowed({ hostname: h }), `${h} default allowed`);
  }
  assert.ok(!denyList().includes('10.0.0.0/8'));
  withEnv({ KUMA_MCP_DENY_PRIVATE: '1', KUMA_MCP_ALLOW_HOSTS: 'nas.lan,192.168.1.60' }, () => {
    for (const h of ['10.1.2.3', '172.16.5.5', '172.31.255.1', '192.168.1.54', '100.64.0.1', '100.127.255.254']) {
      assert.throws(() => assertTargetAllowed({ hostname: h }), /denylist/, h);
    }
    assert.doesNotThrow(() => assertTargetAllowed({ hostname: '172.32.0.1' }));
    assert.doesNotThrow(() => assertTargetAllowed({ hostname: '192.168.1.60' })); // allow-listed
    assert.throws(() => assertTargetAllowed({ url: 'http://[::ffff:10.1.2.3]/' }), /denylist/);
  });
});

test('H3 a name resolving to a private address is refused under DENY_PRIVATE unless allow-listed (loopback never exempt)', async () => {
  await withEnv({ KUMA_MCP_DENY_PRIVATE: '1', KUMA_MCP_ALLOW_HOSTS: 'grafana' }, async () => {
    await assert.rejects(assertResolvedTargetAllowed({ hostname: 'other.example' }, res({ 'other.example': ['172.18.0.5'] })), /denylisted/);
    await assertResolvedTargetAllowed({ hostname: 'grafana' }, res({ grafana: ['172.18.0.5'] }));
    await assert.rejects(assertResolvedTargetAllowed({ hostname: 'grafana' }, res({ grafana: ['127.0.0.1'] })), /denylisted/);
  });
});

// H4 ── fail closed on resolve failure / timeout
test('H4 an unresolvable or timed-out name is refused unless allow-listed', async () => {
  await assert.rejects(assertResolvedTargetAllowed({ hostname: 'svc' }, res({})), /could not be resolved/);
  await assert.rejects(assertResolvedTargetAllowed({ url: 'http://svc.example/' }, async () => { throw new Error('timeout'); }), /could not be resolved/);
  await withEnv({ KUMA_MCP_ALLOW_HOSTS: 'svc,*.svc.example' }, async () => {
    await assertResolvedTargetAllowed({ hostname: 'svc' }, res({}));
    await assertResolvedTargetAllowed({ url: 'http://a.svc.example/' }, res({}));
  });
  await assertResolvedTargetAllowed({ url: 'https://public.example/' }, res({ 'public.example': ['203.0.113.9'] }));
});

// L1 ── strict hostname grammar
test('L1 hostname fields must be bare hosts: userinfo, port and path forms are refused', () => {
  for (const h of ['127.0.0.1@evil.example.com', 'evil.example.com:80', 'a.example/x', 'http://example.com', 'a b', 'x#y', 'a?b']) {
    assert.throws(() => assertTargetAllowed({ hostname: h }), /bare host name/, h);
    assert.throws(() => assertTargetAllowed({ dns_resolve_server: h }), /bare host name/, h);
  }
  for (const h of ['example.com', 'my_host.lan', '203.0.113.9', '2001:db8::5', '[2001:db8::5]', 'localhost.']) {
    if (h === 'localhost.') assert.throws(() => assertTargetAllowed({ hostname: h }), /denylist/);
    else assert.doesNotThrow(() => assertTargetAllowed({ hostname: h }), h);
  }
  assert.throws(() => buildAddPayload({ name: 'x', type: 'port', hostname: '127.0.0.1@evil.example.com', port: 80 }), /bare host name/);
  // grpc / DB targets are host:port, not bare hosts
  assert.doesNotThrow(() => assertTargetAllowed({ hostPort: 'grpc.example.com:50051' }));
});

// M1 ── keyword response excerpt
test('M1 heartbeat msg drops the response excerpt after the keyword marker', () => {
  const m = sanitizeHeartbeatMsg('Status 200 - But the keyword is not in [secret-token-abc123 internal page body here...]') as string;
  assert.ok(!m.includes('secret-token-abc123'), m);
  assert.match(m, /keyword is not in/);
  const inv = sanitizeHeartbeatMsg('But the keyword is in [admin panel text]') as string;
  assert.ok(!inv.includes('admin panel'), inv);
});

// M2 ── routing headers
test('M2 Host / X-Forwarded-Host / X-Original-URL / X-Rewrite-URL / X-HTTP-Method-Override headers are refused', () => {
  for (const name of ['Host', 'x-forwarded-host', 'X-Original-Url', 'X-REWRITE-URL', 'x-http-method-override']) {
    assert.throws(() => buildAddPayload({ name: 'x', url: 'https://203.0.113.9/', headers: { [name]: 'internal' } }), /not allowed/, name);
    assert.throws(() => buildAddPayload({ name: 'x', url: 'https://203.0.113.9/', headers: JSON.stringify({ [name]: 'internal' }) }), /not allowed/, name);
    assert.throws(() => buildEditPayload({ id: 1, type: 'http', url: 'https://203.0.113.9/', timeout: 48, interval: 60 }, { headers: { [` ${name}`]: 'x' } }, 1), /not allowed/, name);
  }
  assert.doesNotThrow(() => buildAddPayload({ name: 'x', url: 'https://203.0.113.9/', headers: { Accept: 'application/json' } }));
});

// M3 ── maintenance / bulk detach
test('M3 every maintenance strategy is confirm-gated for >5 monitors or all-day/open-ended windows', async () => {
  const mk = (o: any) => ({ monitorIds: [1], ...o });
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'single', dateRange: ['2030-01-01 00:00:00', '2030-01-01 02:00:00'] })), false);
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'single', dateRange: ['2030-01-01 00:00:00', null] })), true);
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'single', dateRange: ['2030-01-01 00:00:00', '2030-01-09 00:00:00'] })), true);
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'recurring-weekday', timeRange: [{ hours: 0, minutes: 0 }, { hours: 23, minutes: 59 }] })), true);
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'recurring-interval', timeRange: [{ hours: 2, minutes: 0 }, { hours: 3, minutes: 0 }] })), false);
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'cron', durationMinutes: 1440 })), true);
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'cron', durationMinutes: 60 })), false);
  assert.equal(maintenanceNeedsConfirm({ strategy: 'recurring-day-of-month', monitorIds: [1, 2, 3, 4, 5, 6] }), true);
  const am = tool('uptimekuma_add_maintenance');
  await assert.rejects(() => am.handler(am.schema.parse({ title: 't', strategy: 'recurring-weekday', monitorIds: [1, 2, 3, 4, 5, 6, 7] })), /confirmOpenEnded/);
});

test('M3 apply_notification_to_all_monitors: dryRun defaults to true; detaching for real needs confirmDetach', async () => {
  const t = tool('uptimekuma_apply_notification_to_all_monitors');
  assert.equal(t.schema.parse({ notificationId: 1 }).dryRun, true);
  await assert.rejects(() => t.handler(t.schema.parse({ notificationId: 1, enabled: false, dryRun: false })), /confirmDetach/);
});

// denyList message
test('a malformed KUMA_MCP_DENY_HOSTS entry is not echoed to the MCP client', () => {
  withEnv({ KUMA_MCP_DENY_HOSTS: 'sup3r-secret entry' }, () => {
    const orig = console.error; let logged = '';
    console.error = (m: string) => { logged += m; };
    try { assert.throws(() => assertTargetAllowed({ hostname: 'example.com' }), (e: Error) => !/sup3r/.test(e.message) && /invalid entry/.test(e.message)); }
    finally { console.error = orig; }
    assert.match(logged, /sup3r-secret entry/); // operator log keeps it
  });
});

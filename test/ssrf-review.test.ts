import { test } from 'node:test';
import assert from 'node:assert/strict';
process.env.KUMA_INSTANCES = 'kuma';
process.env.KUMA_BASE_URL = 'http://kuma.test:3001';
process.env.KUMA_USERNAME ??= 'u';
process.env.KUMA_PASSWORD ??= 'p';
process.env.KUMA_MCP_NOTIFICATION_TYPES = 'ntfy,webhook,smtp,apprise,onebot,milky,nostr,pushover,serverchan,telegram,gotify,matrix,gorush,keep,pagertree,mattermost,brandnew,twilio';
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

// Fail fast: if a gate is removed the handler must hit this stub, not a real Kuma connection.
const REACHED = 'REACHED_CLIENT';
const stubClient = async () => {
  const c: any = (await import('../src/instances.js')).getClient('kuma');
  for (const m of ['addMaintenance', 'saveNotification', 'updateNotification', 'applyNotificationToAllMonitors']) c[m] = async () => { throw new Error(REACHED); };
  return c;
};
await stubClient();

// H1 ── notification config policy
test('H1 notification config: destination fields of the provider type go through the denylist and resolve check', async () => {
  for (const cfg of [
    { type: 'webhook', httpMethod: 'GET', webhookURL: 'http://127.0.0.1:8015/hook' },
    { type: 'webhook', httpMethod: 'GET', webhookURL: 'http://bifrost:8080/x' },
    { type: 'ntfy', ntfyserverurl: 'http://169.254.169.254/' },
    { type: 'smtp', smtpHost: 'localhost', smtpPort: 25 },
    { type: 'apprise', appriseURL: 'json://127.0.0.1:9000/x' },
  ]) await assert.rejects(assertNotificationConfigAllowed(cfg), /not allowed/, JSON.stringify(cfg));
  await assert.rejects(assertNotificationConfigAllowed({ type: 'webhook', httpMethod: 'GET', webhookURL: 'https://evil.example/h' }, res({ 'evil.example': ['127.0.0.1'] })), /denylisted/);
  await assert.rejects(assertNotificationConfigAllowed({ type: 'webhook', httpMethod: 'GET', webhookURL: 'https://nx.example/h' }, res({})), /could not be resolved/);
  await assertNotificationConfigAllowed({ type: 'webhook', httpMethod: 'GET', webhookURL: 'https://ok.example/h' }, res({ 'ok.example': ['203.0.113.9'] }));
  await assertNotificationConfigAllowed({ type: 'apprise', appriseURL: 'tgram://tok/123' });
});

test('H1 webhook custom body / additional headers / non-GET method refused unless KUMA_MCP_ALLOW_WRITE_METHODS=1', async () => {
  const base = { type: 'webhook', httpMethod: 'GET', webhookURL: 'https://203.0.113.9/h' };
  await assert.rejects(assertNotificationConfigAllowed({ ...base, webhookCustomBody: '{"a":"{{msg}}"}' }), /ALLOW_WRITE_METHODS/);
  await assert.rejects(assertNotificationConfigAllowed({ ...base, webhookAdditionalHeaders: '{"X":"y"}' }), /ALLOW_WRITE_METHODS/);
  for (const m of ['PUT', 'delete', 'POST', 'HEAD']) await assert.rejects(assertNotificationConfigAllowed({ ...base, httpMethod: m }), /httpMethod to GET/, m);
  await assert.rejects(assertNotificationConfigAllowed({ type: 'webhook', webhookURL: 'https://203.0.113.9/h' }), /httpMethod to GET/); // missing = POST in Kuma
  await assertNotificationConfigAllowed({ ...base, httpMethod: 'get' });
  await withEnv({ KUMA_MCP_ALLOW_WRITE_METHODS: '1' }, () => assertNotificationConfigAllowed({ ...base, webhookCustomBody: '{}', httpMethod: 'PUT' }));
});

// review round 2, blocking 1: whitespace
test('R2-1 tab/CR/LF inside a destination is stripped before the check (the URL parser deletes them); other whitespace is refused', async () => {
  for (const v of ['http://127.0.0.1\t:8015/', 'http://127.0.\n0.1/', 'http://local\rhost/', 'http://127.0.0.1\t/x'])
    await assert.rejects(assertNotificationConfigAllowed({ type: 'webhook', httpMethod: 'GET', webhookURL: v }), /denylist|not allowed/, JSON.stringify(v));
  await assert.rejects(assertNotificationConfigAllowed({ type: 'webhook', httpMethod: 'GET', webhookURL: 'http://203.0.113.9/a b' }), /whitespace/);
});

// blocking 2: per-type table
test('R2-2 per-type destination table: httpAddr, nostr relays, unknown types and unlisted URL-like fields', async () => {
  await assert.rejects(assertNotificationConfigAllowed({ type: 'onebot', httpAddr: '127.0.0.1:8200/v1/x?' }), /not allowed|denylist/);
  await assert.rejects(assertNotificationConfigAllowed({ type: 'milky', httpAddr: 'http://bifrost:8080' }), /not allowed|denylist/);
  await assert.rejects(assertNotificationConfigAllowed({ type: 'nostr', relays: 'wss://203.0.113.9/r\nws://127.0.0.1:8015' }), /denylist/);
  await assert.rejects(assertNotificationConfigAllowed({ type: 'nostr', nostrRelays: 'ws://127.0.0.1:8015,wss://203.0.113.9' }), /denylist/);
  await assert.rejects(assertNotificationConfigAllowed({ type: 'brandnew', foo: 'x' }), /not on the supported list/);
  for (const t of ['__proto__', 'constructor', 'toString']) await assert.rejects(assertNotificationConfigAllowed({ type: t }), /not enabled/, t);
  await assert.rejects(assertNotificationConfigAllowed({ type: 'pushover', somethingElse: 'http://127.0.0.1:8015/' }), /not a known destination field/);
  await assert.rejects(assertNotificationConfigAllowed({ type: 'pushover', nested: { deep: ['grafana:3000'] } }), /not a known destination field/);
  // ServerChan: a send key is not a host
  await assertNotificationConfigAllowed({ type: 'serverchan', serverChanSendKey: 'SCT123abcDEF456' });
  await assertNotificationConfigAllowed({ type: 'telegram', telegramBotToken: '123456:ABC-def_GHI', telegramChatID: '-100123' });
});

// blocking 3: apprise schemes
test('R2-3 apprise http-backed schemes resolve and fail closed like http; IPv6 brackets are kept', async () => {
  await assert.rejects(assertNotificationConfigAllowed({ type: 'apprise', appriseURL: 'json://rebind.example:8015/' }, res({ 'rebind.example': ['127.0.0.1'] })), /denylisted/);
  await assert.rejects(assertNotificationConfigAllowed({ type: 'apprise', appriseURL: 'jsons://nx.example/' }, res({})), /could not be resolved/);
  for (const sc of ['json', 'jsons', 'xml', 'xmls', 'form', 'forms'])
    await assert.rejects(assertNotificationConfigAllowed({ type: 'apprise', appriseURL: `${sc}://127.0.0.1:80/` }), /denylist/, sc);
  await assert.rejects(assertNotificationConfigAllowed({ type: 'apprise', appriseURL: 'json://[::ffff:127.0.0.1]:80/' }), /denylist/);
  await assert.rejects(assertNotificationConfigAllowed({ type: 'apprise', appriseURL: 'tgram://[::1]:80/x' }), /denylist/);
});

// blocking 4: applyExisting/isDefault inside config
test('R2-4 isDefault/applyExisting/name/type inside config are refused (they would bypass confirmApply)', async () => {
  for (const [n, extra] of [['uptimekuma_create_notification', {}], ['uptimekuma_update_notification', { notificationId: 1 }]] as const) {
    const t = tool(n);
    for (const k of ['applyExisting', 'isDefault']) {
      await assert.rejects(() => t.handler(t.schema.parse({ name: 'n', type: 'ntfy', ...extra, config: { [k]: true, ntfyserverurl: 'https://203.0.113.9/' } })), /top-level parameter/, `${n} ${k}`);
    }
  }
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
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'cron', cron: '0 3 * * *', durationMinutes: 1440 })), true);
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'cron', cron: '0 3 * * *', durationMinutes: 60 })), false);
  assert.equal(maintenanceNeedsConfirm({ strategy: 'recurring-day-of-month', monitorIds: [1, 2, 3, 4, 5, 6] }), true);
  const am = tool('uptimekuma_add_maintenance');
  await assert.rejects(() => am.handler(am.schema.parse({ title: 't', strategy: 'recurring-weekday', monitorIds: [1, 2, 3, 4, 5, 6, 7] })), /confirmOpenEnded/);
  // review round 2, #8: effective coverage, not special cases
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'cron', cron: '*/30 * * * *', durationMinutes: 60 })), true);   // fires every 30 min, 60 min long: permanent
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'cron', cron: '0 3 * * *', durationMinutes: 60 })), false);
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'cron', cron: '0 * * * *', durationMinutes: 65 })), true);
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'cron', cron: 'not a cron', durationMinutes: 5 })), true);     // unreadable: fail closed
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'recurring-weekday', timeRange: [{ hours: 0, minutes: 0 }, { hours: 23, minutes: 58 }] })), true);
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'recurring-interval', timeRange: [{ hours: 5, minutes: 0 }, { hours: 5, minutes: 0 }] })), true); // start == end: 24h
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'recurring-interval' })), false); // default 02:00-03:00 window
  await assert.rejects(() => am.handler(am.schema.parse({ title: 't', strategy: 'cron', cron: '*/30 * * * *', durationMinutes: 60, monitorIds: [1] })), /confirmOpenEnded/);
});

test('M3 apply_notification_to_all_monitors: dryRun defaults to true; detaching for real needs confirmDetach', async () => {
  const t = tool('uptimekuma_apply_notification_to_all_monitors');
  assert.equal(t.schema.parse({ notificationId: 1 }).dryRun, true);
  await assert.rejects(() => t.handler(t.schema.parse({ notificationId: 1, enabled: false, dryRun: false })), /confirmDetach/);
  await assert.rejects(() => t.handler(t.schema.parse({ notificationId: 1, enabled: false, dryRun: false, confirmDetach: true })), new RegExp(REACHED)); // the stub proves the gate is the only thing in the way
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

// blocking 5: M1 patterns
test('R2-5 heartbeat msg: invert-keyword and json-query response excerpts are withheld', () => {
  const inv = sanitizeHeartbeatMsg('Status 200 - but keyword is present in [admin-secret-xyz page text...]') as string;
  assert.ok(!inv.includes('admin-secret-xyz'), inv);
  const jq = sanitizeHeartbeatMsg('JSON query does not pass (comparing {"token":"tok-abc-123"} == ok)') as string;
  assert.ok(!jq.includes('tok-abc-123'), jq);
  const jq2 = sanitizeHeartbeatMsg('JSON query passes (comparing 42-secret >= 3)') as string;
  assert.ok(!jq2.includes('42-secret'), jq2);
});

// blocking 6: host+port jointly
test('R2-6 SMTP host and port are judged together against host:port deny entries', async () => {
  await withEnv({ KUMA_MCP_DENY_HOSTS: '192.168.1.54:8015' }, async () => {
    await assert.rejects(assertNotificationConfigAllowed({ type: 'smtp', smtpHost: '192.168.1.54', smtpPort: 8015 }), /denylist/);
    await assert.rejects(assertNotificationConfigAllowed({ type: 'smtp', smtpHost: '192.168.1.54', smtpPort: '8015' }), /denylist/);
    await assertNotificationConfigAllowed({ type: 'smtp', smtpHost: '192.168.1.54', smtpPort: 587 });
    await assert.rejects(assertNotificationConfigAllowed({ type: 'smtp', smtpHost: '192.168.1.54', smtpPort: 70000 }), /invalid port/);
  });
});

// should-fix 9: headers
test('R2-9 more routing/spoofing headers and non-object header shapes are refused', () => {
  const add = (headers: any) => buildAddPayload({ name: 'x', url: 'https://203.0.113.9/', headers });
  for (const n of ['X-Forwarded-For', 'x-real-ip', 'Forwarded', 'X-Original-Host']) assert.throws(() => add({ [n]: '10.0.0.1' }), /not allowed/, n);
  assert.throws(() => add([{ name: 'Host', value: 'internal' }]), /not allowed/);
  assert.throws(() => add(['X-Forwarded-Host: internal']), /not allowed/);
  assert.throws(() => add({ Wrapper: { Host: 'internal' } }), /not allowed/);
  assert.throws(() => add('Host: internal'), /not allowed/);
  assert.doesNotThrow(() => add({ Accept: 'x' }));
});

// should-fix 10: merged effective config
test('R2-10 update_notification polices the stored config merged with the changes', async () => {
  const { UptimeKumaClient } = await import('../src/uptime-kuma-client.js');
  const c: any = Object.create(UptimeKumaClient.prototype);
  c.cfg = { name: 't' }; c.ensureConnected = async () => {};
  let sent = 0; c.emitWithAck = async () => { sent++; return { ok: true, id: 1 }; };
  c.getNotification = async () => ({ id: 1, name: 'n', config: { type: 'ntfy', ntfyserverurl: 'http://127.0.0.1:2586' } });
  await assert.rejects(c.updateNotification(1, { name: 'renamed' }), /not allowed/); // stored destination is bad; a rename must not re-arm it
  assert.equal(sent, 0);
});

// should-fix 12: IDN
test('R2-12 IDN hostnames are validated in punycode form', () => {
  assert.doesNotThrow(() => assertTargetAllowed({ hostname: 'bücher.example' }));
  assert.doesNotThrow(() => assertTargetAllowed({ hostname: 'xn--bcher-kva.example' }));
  assert.throws(() => assertTargetAllowed({ hostname: 'bü cher.example' }), /bare host name/);
});

// reviewer note: the allow-list can never un-deny loopback / built-ins / operator deny entries
test('allow-list never un-denies loopback, built-in names or KUMA_MCP_DENY_HOSTS entries', async () => {
  await withEnv({ KUMA_MCP_ALLOW_HOSTS: '*', KUMA_MCP_DENY_HOSTS: 'gw.lan:8080', KUMA_MCP_DENY_PRIVATE: '1' }, async () => {
    for (const t of [{ hostname: 'localhost' }, { hostname: '127.0.0.1' }, { hostname: 'bifrost' }, { url: 'http://mcp-gateway/' }, { hostname: '169.254.169.254' }, { url: 'http://gw.lan:8080/' }])
      assert.throws(() => assertTargetAllowed(t), /denylist/, JSON.stringify(t));
    await assert.rejects(assertResolvedTargetAllowed({ hostname: 'svc' }, res({ svc: ['127.0.0.1'] })), /denylisted/);
  });
});

// ── review round 3 ──────────────────────────────────────────────────────────
test('R3 type allow-list: default is ntfy only; other types and type changes need KUMA_MCP_NOTIFICATION_TYPES', async () => {
  await withEnv({ KUMA_MCP_NOTIFICATION_TYPES: '' }, async () => { delete process.env.KUMA_MCP_NOTIFICATION_TYPES; // unset = default
    await assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl: 'https://203.0.113.9/', ntfyAuthenticationMethod: 'none', ntfyIcon: 'https://x.example/i.png' });
    for (const t of ['webhook', 'apprise', 'gotify', 'smtp', 'slack']) await assert.rejects(assertNotificationConfigAllowed({ type: t }), /KUMA_MCP_NOTIFICATION_TYPES/, t);
  });
  const { UptimeKumaClient } = await import('../src/uptime-kuma-client.js');
  const c: any = Object.create(UptimeKumaClient.prototype);
  c.cfg = { name: 't' }; c.ensureConnected = async () => {};
  let sent = 0; c.emitWithAck = async () => { sent++; return { ok: true, id: 1 }; };
  c.getNotification = async () => ({ id: 1, name: 'n', config: { type: 'ntfy', ntfytopic: 't' } });
  await withEnv({ KUMA_MCP_NOTIFICATION_TYPES: 'ntfy' }, async () => {
    await assert.rejects(c.updateNotification(1, { type: 'webhook' }), /KUMA_MCP_NOTIFICATION_TYPES/); // type change to a disabled type
  });
  assert.equal(sent, 0);
});

test('N1 a listed destination field must be a plain string (arrays/objects cannot hide a URL)', async () => {
  for (const cfg of [
    { type: 'gotify', gotifyserverurl: ['http://192.168.1.54:8015'] }, { type: 'matrix', homeserverUrl: ['http://127.0.0.1'] },
    { type: 'gorush', gorushServerURL: { a: 'http://127.0.0.1' } }, { type: 'smtp', smtpHost: ['127.0.0.1'], smtpPort: 25 },
    { type: 'smtp', smtpHost: 'mail.example.com', smtpPort: [25] }, { type: 'nostr', relays: ['wss://203.0.113.9', 7] },
  ]) await assert.rejects(assertNotificationConfigAllowed(cfg), /plain string/, JSON.stringify(cfg));
  await assert.rejects(assertNotificationConfigAllowed({ type: 'nostr', relays: ['wss://203.0.113.9', 'ws://127.0.0.1:8015'] }), /denylist/);
});

test('R1 apprise: one URL only; ,/; and second scheme:// refused; unknown schemes refused; token schemes literal-checked', async () => {
  const a = (appriseURL: string, r?: any) => assertNotificationConfigAllowed({ type: 'apprise', appriseURL }, r);
  await assert.rejects(a('json://203.0.113.9/,json://192.168.1.54:8015/'), /only one apprise URL/);
  await assert.rejects(a('tgram://123abc/456;json://192.168.1.54:8015/'), /only one apprise URL/);
  await assert.rejects(a('tgram://123abc/456 json://192.168.1.54:8015/'), /whitespace/);
  await assert.rejects(a('ntfy://nas.nip.io:8015/t'), /not supported/);
  await assert.rejects(a('apprise://localtest.me:8015/x'), /not supported/);
  await assert.rejects(a('mailto://u:p@127.0.0.1'), /not supported/);
  await assert.rejects(a('json://nx.example/', res({})), /could not be resolved/);
  await a('tgram://123abc/456');
  await a('discord://webhook-id/token');
});

test('R2 keep/pagertree destination keys; control and hidden characters in a destination are refused', async () => {
  await assert.rejects(assertNotificationConfigAllowed({ type: 'keep', webhookURL: 'http://127.0.0.1:8015/' }), /denylist/);
  await assert.rejects(assertNotificationConfigAllowed({ type: 'pagertree', pagertreeIntegrationUrl: 'http://127.0.0.1:8015/' }), /denylist/);
  for (const v of ['\u0000http://192.168.1.54:8015/', '\u0001http://127.0.0.1:8015/x', ' http://127.0.0.1/', 'http://127.0.0.1​/', 'http://127.0.0.1 /', '﻿http://127.0.0.1/']) {
    await assert.rejects(assertNotificationConfigAllowed({ type: 'webhook', httpMethod: 'GET', webhookURL: v }), /control characters|whitespace|denylist/, JSON.stringify(v));
  }
  // an unlisted free-text field hiding a URL behind a control char is still seen as target-like
  await assert.rejects(assertNotificationConfigAllowed({ type: 'pushover', note: '\u0000http://127.0.0.1:8015/' }), /not a known destination field/);
  await assertNotificationConfigAllowed({ type: 'pushover', note: 'Disk space is low on the NAS' });
});

test('N2/N3 ntfy defaults work (ntfyAuthenticationMethod is not a method); known non-destination keys are skipped', async () => {
  await assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl: 'https://203.0.113.9/', ntfyAuthenticationMethod: 'usernamePassword', ntfyIcon: 'https://x.example/i.png', ntfytopic: 'alerts', ntfyPriority: 5 });
  await assertNotificationConfigAllowed({ type: 'mattermost', mattermostWebhookUrl: 'https://203.0.113.9/h', mattermosticonurl: 'https://x.example/i.png' });
  await assertNotificationConfigAllowed({ type: 'smtp', smtpHost: '203.0.113.9', smtpPort: 587, smtpDkimDomain: 'example.com' });
  await assertNotificationConfigAllowed({ type: 'gorush', gorushServerURL: 'https://203.0.113.9/', gorushTopic: 'com.example.app' });
});

test('N4 heartbeat msg is withheld for monitor types that echo received data', async () => {
  const { redactHeartbeatAck } = await import('../src/redact.js');
  const rows = { ok: true, data: [{ status: 0, time: '2030-01-01 00:00:00', msg: 'Topic: t; Message: secret-payload-1' }] };
  for (const t of ['mqtt', 'grpc-keyword', 'mysql', 'sqlserver', 'postgres', 'mongodb', 'redis', 'sip-options']) {
    assert.ok(!JSON.stringify(redactHeartbeatAck(rows, t)).includes('secret-payload-1'), t);
  }
  assert.ok(JSON.stringify(redactHeartbeatAck({ ok: true, data: [{ status: 0, msg: 'timeout' }] }, 'http')).includes('timeout'));
});

test('N6 more forwarding/client-address headers refused', () => {
  for (const n of ['X-Forwarded-Proto', 'X-Forwarded-Port', 'X-Forwarded-Prefix', 'X-Forwarded-Server', 'True-Client-IP', 'CF-Connecting-IP', 'X-Client-IP'])
    assert.throws(() => buildAddPayload({ name: 'x', url: 'https://203.0.113.9/', headers: { [n]: 'v' } }), /not allowed/, n);
});

test('R4 maintenance: long cron windows, manual always, durationMinutes >= 1380, zod time bounds', async () => {
  const mk = (o: any) => ({ monitorIds: [1], ...o });
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'cron', cron: '0 0 1 * *', durationMinutes: 44640 })), true);
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'cron', cron: '0 0 1 1 *', durationMinutes: 525600 })), true);
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'cron', cron: '0 3 * * *', durationMinutes: 1380 })), true);
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'cron', cron: '0 22 * * *', durationMinutes: 600 })), false);
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'cron', cron: '0 23 * * *', durationMinutes: 1000 })), false); // window began before the horizon start still counted, but 1000 min < 23h
  assert.equal(maintenanceNeedsConfirm(mk({ strategy: 'manual', dateRange: [null, '2030-01-01 00:00:00'] })), true);
  const am = tool('uptimekuma_add_maintenance');
  for (const bad of [{ hours: 24, minutes: 0 }, { hours: 1, minutes: 60 }, { hours: -1, minutes: 0 }])
    assert.equal(am.schema.safeParse({ title: 't', strategy: 'recurring-weekday', timeRange: [bad, { hours: 3, minutes: 0 }] }).success, false);
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
process.env.KUMA_INSTANCES = 'kuma';
process.env.KUMA_BASE_URL = 'http://kuma.test:3001';
process.env.KUMA_USERNAME ??= 'u';
process.env.KUMA_PASSWORD ??= 'p';
process.env.KUMA_MCP_NOTIFICATION_HOSTS = '203.0.113.9,203.0.113.9:80,203.0.113.9:25,203.0.113.9:587,ok.example,evil.example,nx.example,x.example,other.example,*.example.com,ntfy.test,n.test,h.test,rebind.example:8015,192.168.1.54:587'; // tests of the host list itself override this
process.env.KUMA_MCP_NOTIFICATION_TYPES = 'ntfy,webhook,smtp,apprise,onebot,milky,nostr,pushover,serverchan,telegram,gotify,matrix,gorush,keep,pagertree,mattermost,brandnew,twilio';
const { assertTargetAllowed, assertResolvedTargetAllowed, assertNotificationConfigAllowed, denyList, invalidNotificationHostEntries, effectiveTarget } = await import('../src/policy.js');
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
test('H2 maxredirects is forced to 0 even with write methods on', async () => {
  await withEnv({ KUMA_MCP_ALLOW_WRITE_METHODS: '1' }, () => {
    assert.equal(buildAddPayload({ name: 'x', url: 'https://203.0.113.9/', maxredirects: 10 }).maxredirects, 0);
    assert.equal(buildEditPayload({ id: 1, type: 'http', url: 'https://203.0.113.9/', maxredirects: 10, timeout: 48, interval: 60 }, { maxredirects: 5 }, 1).maxredirects, 0);
  });
});

// H3 ── opt-in private ranges
test('H3 KUMA_MCP_DENY_PRIVATE=1 denies RFC1918/CGNAT unless the host is allow-listed; default is unchanged', async () => {
  for (const h of ['10.1.2.3', '172.16.5.5', '172.31.255.1', '192.168.1.54', '100.64.0.1', '100.127.255.254']) {
    assert.doesNotThrow(() => assertTargetAllowed({ hostname: h }), `${h} default allowed`);
  }
  assert.ok(!denyList().includes('10.0.0.0/8'));
  await withEnv({ KUMA_MCP_DENY_PRIVATE: '1', KUMA_MCP_ALLOW_HOSTS: 'nas.lan,192.168.1.60' }, () => {
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
test('a malformed KUMA_MCP_DENY_HOSTS entry is not echoed to the MCP client', async () => {
  await withEnv({ KUMA_MCP_DENY_HOSTS: 'sup3r-secret entry' }, () => {
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
  await withEnv({ KUMA_MCP_ALLOW_HOSTS: '*.test,*.example,*.lan,*.local,*.internal,*.example.com', KUMA_MCP_DENY_HOSTS: 'gw.lan:8080', KUMA_MCP_DENY_PRIVATE: '1' }, async () => {
    for (const t of [{ hostname: 'localhost' }, { hostname: '127.0.0.1' }, { hostname: 'bifrost' }, { url: 'http://mcp-gateway/' }, { hostname: '169.254.169.254' }, { url: 'http://gw.lan:8080/' }])
      assert.throws(() => assertTargetAllowed(t), /denylist/, JSON.stringify(t));
    await assert.rejects(assertResolvedTargetAllowed({ hostname: 'svc' }, res({ svc: ['127.0.0.1'] })), /denylisted/);
  });
});

// ── review round 3 ──────────────────────────────────────────────────────────
test('R3 type allow-list: default is ntfy only; other types and type changes need KUMA_MCP_NOTIFICATION_TYPES', async () => {
  await withEnv({ KUMA_MCP_NOTIFICATION_TYPES: '' }, async () => { delete process.env.KUMA_MCP_NOTIFICATION_TYPES; // unset = default
    await assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl: 'https://203.0.113.9/', ntfyAuthenticationMethod: 'none', ntfyIcon: 'https://203.0.113.9/i.png' });
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
  await assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl: 'https://203.0.113.9/', ntfyAuthenticationMethod: 'usernamePassword', ntfyIcon: 'https://203.0.113.9/i.png', ntfytopic: 'alerts', ntfyPriority: 5 });
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

// ── review round 4 ──────────────────────────────────────────────────────────
test('R4-H1 KUMA_MCP_NOTIFICATION_HOSTS: default empty refuses every destination; listed hosts pass; denylist still wins', async () => {
  await withEnv({ KUMA_MCP_NOTIFICATION_HOSTS: '' }, async () => {
    delete process.env.KUMA_MCP_NOTIFICATION_HOSTS; // unset = default (none)
    await assert.rejects(assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl: 'https://ntfy.sh' }, res({ 'ntfy.sh': ['203.0.113.9'] })), /KUMA_MCP_NOTIFICATION_HOSTS/);
    await assert.rejects(assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl: 'http://192.168.1.54:8015/' }), /KUMA_MCP_NOTIFICATION_HOSTS/);
    await assert.rejects(assertNotificationConfigAllowed({ type: 'smtp', smtpHost: 'mail.example.com', smtpPort: 587 }, res({ 'mail.example.com': ['203.0.113.9'] })), /KUMA_MCP_NOTIFICATION_HOSTS/);
    await assert.rejects(assertNotificationConfigAllowed({ type: 'apprise', appriseURL: 'json://203.0.113.9/x' }), /KUMA_MCP_NOTIFICATION_HOSTS/);
    await assertNotificationConfigAllowed({ type: 'apprise', appriseURL: 'tgram://123456:ABCdef/987' }); // fixed external service: exempt
    await assert.rejects(assertNotificationConfigAllowed({ type: 'ntfy', ntfytopic: 't' }), /ntfyserverurl/); // R7-a: ntfy must name its server
    await assertNotificationConfigAllowed({ type: 'gotify', gotifyserverurl: '' }); // no destination field set: nothing to list
  });
  await withEnv({ KUMA_MCP_NOTIFICATION_HOSTS: 'ntfy.lan.example, 192.168.1.60:8080', KUMA_MCP_ALLOW_HOSTS: 'ntfy.lan.example' }, async () => {
    await assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl: 'https://ntfy.lan.example/' }, res({}));
    await assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl: 'http://192.168.1.60:8080/' });
    await assert.rejects(assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl: 'https://ntfy.sh' }, res({ 'ntfy.sh': ['203.0.113.9'] })), /KUMA_MCP_NOTIFICATION_HOSTS/);
    await assert.rejects(assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl: 'http://192.168.1.60:9999/' }), /KUMA_MCP_NOTIFICATION_HOSTS/);
  });
  // the list can never un-deny loopback / built-ins / operator deny entries
  await withEnv({ KUMA_MCP_NOTIFICATION_HOSTS: '*', KUMA_MCP_DENY_HOSTS: 'gw.lan:8080' }, async () => {
    for (const u of ['http://127.0.0.1:8015/', 'http://localhost/', 'http://bifrost:8080/', 'http://gw.lan:8080/', 'http://169.254.169.254/'])
      await assert.rejects(assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl: u }), /denylist/, u);
  });
});

test('R4-H1 templated ntfy/smtp/telegram body and title fields refused unless write methods are enabled (false/empty is fine)', async () => {
  const base = { type: 'ntfy', ntfyserverurl: 'https://203.0.113.9/' };
  for (const extra of [{ ntfyUseTemplate: true, ntfyCustomMessage: '{{ msg }} {{ monitorJSON.url }}' }, { ntfyCustomTitle: '{{ name }}' }, { ntfyCustomMessage: 'x' }, { ntfyUseTemplate: true }])
    await assert.rejects(assertNotificationConfigAllowed({ ...base, ...extra }), /templated|ALLOW_WRITE_METHODS/, JSON.stringify(extra));
  await assertNotificationConfigAllowed({ ...base, ntfyUseTemplate: false, ntfyCustomMessage: '', ntfyCustomTitle: '' });
  await assert.rejects(assertNotificationConfigAllowed({ type: 'smtp', smtpHost: '203.0.113.9', smtpPort: 25, customBody: '{{ msg }}' }), /ALLOW_WRITE_METHODS/);
  await withEnv({ KUMA_MCP_ALLOW_WRITE_METHODS: '1' }, () => assertNotificationConfigAllowed({ ...base, ntfyUseTemplate: true, ntfyCustomMessage: '{{ msg }}' }));
});

test('R4-L1 cron confirm simulates a full year: month / day-of-month restricted every-minute windows are caught', () => {
  const mk = (cron: string, durationMinutes = 1) => ({ monitorIds: [1], strategy: 'cron', cron, durationMinutes });
  for (const c of ['* * * 6 *', '* * 1 * *', '* * 20 * *', '* * 29 2 *', '*/30 * 15 * *'])
    assert.equal(maintenanceNeedsConfirm(mk(c, c.startsWith('*/30') ? 60 : 1)), true, c);
  for (const c of ['0 3 * * *', '0 3 1 * *', '0 3 * 6 *', '*/5 3 * * 1']) assert.equal(maintenanceNeedsConfirm(mk(c, 30)), false, c);
});

test('R4-L1b cron windows >= 23h are confirmed without simulation (long durations, including monthly/yearly)', () => {
  const mk = (cron: string, durationMinutes: number) => ({ monitorIds: [1], strategy: 'cron', cron, durationMinutes });
  assert.equal(maintenanceNeedsConfirm(mk('0 3 * * *', 1380)), true);
  assert.equal(maintenanceNeedsConfirm(mk('0 3 * * *', 1379)), false);
  assert.equal(maintenanceNeedsConfirm(mk('0 0 1 * *', 44640)), true);
});

test('R4-L2 ntfy credential fields are not mistaken for hosts; real apprise token shapes parse', async () => {
  await assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl: 'https://203.0.113.9/', ntfyusername: 'john.doe', ntfypassword: 'Correct.Horse9', ntfyaccesstoken: 'tk_abc.def' });
  await assertNotificationConfigAllowed({ type: 'apprise', appriseURL: 'tgram://123456:ABCdef/987' });
  await assertNotificationConfigAllowed({ type: 'apprise', appriseURL: 'discord://1234567890/abc-DEF_ghi' });
  await assert.rejects(assertNotificationConfigAllowed({ type: 'apprise', appriseURL: 'tgram://[::1]:80/x' }), /denylist/);
  await assert.rejects(assertNotificationConfigAllowed({ type: 'apprise', appriseURL: 'slack://localhost/T/B/C' }), /denylist/);
});

test('R4 getHeartbeats: msg is withheld when the monitor type lookup fails (fail closed) and for echo types', async () => {
  const { UptimeKumaClient } = await import('../src/uptime-kuma-client.js');
  const mkClient = (monitor: () => any) => {
    const c: any = Object.create(UptimeKumaClient.prototype);
    c.cfg = { name: 't' }; c.ensureConnected = async () => {};
    c.emitWithAck = async (ev: string) => {
      if (ev === 'getMonitorBeats') return { ok: true, data: [{ status: 0, time: '2030-01-01 00:00:00', msg: 'Message: secret-payload-9' }] };
      return monitor();
    };
    return c;
  };
  const failed = await mkClient(() => { throw new Error('socket gone'); }).getHeartbeats(1);
  assert.ok(!JSON.stringify(failed).includes('secret-payload-9'), 'lookup failure must withhold msg');
  const mqtt = await mkClient(() => ({ ok: true, monitor: { id: 1, type: 'mqtt' } })).getHeartbeats(1);
  assert.ok(!JSON.stringify(mqtt).includes('secret-payload-9'));
  const http = await mkClient(() => ({ ok: true, monitor: { id: 1, type: 'http' } })).getHeartbeats(1);
  assert.ok(JSON.stringify(http).includes('secret-payload-9')); // ordinary types keep msg
});

// ── review round 5 ──────────────────────────────────────────────────────────
test('R5-1 NOTIFICATION_HOSTS: a portless entry allows only the scheme default port; globs are whole labels; no bare * or CIDR', async () => {
  const ntfy = (u: string) => assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl: u }, res({}));
  await withEnv({ KUMA_MCP_NOTIFICATION_HOSTS: 'ntfy.lan.example,192.168.1.60,*.svc.example,192.168.1.0/24,*lan.example,*', KUMA_MCP_ALLOW_HOSTS: '*.example,192.168.1.60,192.168.1.54' }, async () => {
    await ntfy('https://ntfy.lan.example/');                                       // portless entry: scheme default port
    await ntfy('https://ntfy.lan.example:443/');
    await ntfy('http://ntfy.lan.example/');                                        // (80 for http)
    await assert.rejects(ntfy('http://ntfy.lan.example:8015/'), /NOTIFICATION_HOSTS/);
    await assert.rejects(ntfy('https://ntfy.lan.example:9999/'), /NOTIFICATION_HOSTS/);
    await assert.rejects(ntfy('http://192.168.1.60:8015/'), /NOTIFICATION_HOSTS/);
    await ntfy('http://192.168.1.60/');
    await assert.rejects(ntfy('http://192.168.1.54:8015/'), /NOTIFICATION_HOSTS/);  // bare CIDR entry is ignored
    await assert.rejects(ntfy('https://evillan.example/'), /NOTIFICATION_HOSTS/);   // *lan.example is not accepted
    await assert.rejects(ntfy('https://other.example/'), /NOTIFICATION_HOSTS/);     // bare * is not accepted
    await ntfy('https://a.svc.example/');                                           // *.suffix still works
    await assert.rejects(ntfy('https://svc.example/'), /NOTIFICATION_HOSTS/);       // needs at least one label before the suffix
    await assert.rejects(ntfy('https://x.evil-svc.example/'), /NOTIFICATION_HOSTS/);
  });
  await withEnv({ KUMA_MCP_NOTIFICATION_HOSTS: '*,192.168.1.0/24,*lan.example,ok.example:70000,ok.example,*.ok.example:8080,[2001:db8::5]:443' }, () => {
    assert.deepEqual(invalidNotificationHostEntries(), ['*', '192.168.1.0/24', '*lan.example', 'ok.example:70000']);
  });
});

test('R5-5 a scheme-less host:port destination (hostPort branch) must be listed WITH its port; portless entries do not match it', async () => {
  const gotify = (v: string) => assertNotificationConfigAllowed({ type: 'onebot', httpAddr: v }, res({})); // httpAddr is the one URL field a provider prefixes itself, so it may be scheme-less
  await withEnv({ KUMA_MCP_NOTIFICATION_HOSTS: 'g.example:8080,h.example', KUMA_MCP_ALLOW_HOSTS: '*.example' }, async () => {
    await gotify('g.example:8080');
    await assert.rejects(gotify('g.example:9090'), /NOTIFICATION_HOSTS/);
    await assert.rejects(gotify('other.example:8080'), /NOTIFICATION_HOSTS/);
    await assert.rejects(gotify('h.example'), /NOTIFICATION_HOSTS/);          // no scheme, no port: no default to rely on
    await assert.rejects(gotify('h.example:8080'), /NOTIFICATION_HOSTS/);      // portless entry only covers a scheme's default port
  });
});

test('R5-2 KUMA_MCP_NTFY_TOPICS (optional) restricts the ntfy topic; unset = no restriction', async () => {
  const t = (ntfytopic?: string) => assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl: 'https://203.0.113.9/', ...(ntfytopic === undefined ? {} : { ntfytopic }) });
  await t('anything');
  await withEnv({ KUMA_MCP_NTFY_TOPICS: 'kuma-alerts, kuma-info' }, async () => {
    await t('kuma-alerts'); await t('kuma-info');
    await assert.rejects(t('someone-elses-topic'), /KUMA_MCP_NTFY_TOPICS/);
    await assert.rejects(t(), /KUMA_MCP_NTFY_TOPICS/);
  });
});

test('R5-4 ntfyIcon goes through the host list and denylist; ntfyCall needs write methods', async () => {
  const base = { type: 'ntfy', ntfyserverurl: 'https://203.0.113.9/' };
  await assert.rejects(assertNotificationConfigAllowed({ ...base, ntfyIcon: 'http://127.0.0.1:8015/i.png' }), /denylist/);
  await assert.rejects(assertNotificationConfigAllowed({ ...base, ntfyIcon: 'https://tracker.example.net/i.png' }, res({ 'tracker.example.net': ['203.0.113.7'] })), /NOTIFICATION_HOSTS/);
  await assertNotificationConfigAllowed({ ...base, ntfyIcon: 'https://203.0.113.9/i.png' });
  await assertNotificationConfigAllowed({ ...base, ntfyIcon: '' });
  await assert.rejects(assertNotificationConfigAllowed({ ...base, ntfyCall: '+15551234567' }), /ALLOW_WRITE_METHODS/);
  await assertNotificationConfigAllowed({ ...base, ntfyCall: '' });
  await withEnv({ KUMA_MCP_ALLOW_WRITE_METHODS: '1' }, () => assertNotificationConfigAllowed({ ...base, ntfyCall: '+15551234567' }));
});

// ── review round 6 ──────────────────────────────────────────────────────────
test('R6-M1 ntfyserverurl must be the server root: a path, query or fragment would bypass KUMA_MCP_NTFY_TOPICS', async () => {
  const ntfy = (ntfyserverurl: string) => assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl, ntfytopic: 'kuma-alerts' });
  await withEnv({ KUMA_MCP_NTFY_TOPICS: 'kuma-alerts' }, async () => {
    for (const u of ['https://203.0.113.9/attacker-topic', 'https://203.0.113.9/?x=1', 'https://203.0.113.9?x=1', 'https://203.0.113.9/#t', 'https://203.0.113.9/?', 'https://203.0.113.9//x', 'https://203.0.113.9/\tattacker'])
      await assert.rejects(ntfy(u), /server root/, u);
    await ntfy('https://203.0.113.9'); await ntfy('https://203.0.113.9/');
  });
  await assert.rejects(assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl: 'https://203.0.113.9/t' }), /server root/); // always, not only with NTFY_TOPICS
});

test('R6-L1 a *. glob in NOTIFICATION_HOSTS needs at least two labels after the star', async () => {
  await withEnv({ KUMA_MCP_NOTIFICATION_HOSTS: '*.com,*.example,*.lan.example,*.co.uk' }, () => {
    assert.deepEqual(invalidNotificationHostEntries(), ['*.com', '*.example', '*.co.uk']);
  });
});

// ── review round 7 (Low items) ──────────────────────────────────────────────
test('R7-a ntfy needs a non-empty ntfyserverurl (Kuma would otherwise make a blind request to a default)', async () => {
  for (const cfg of [{ type: 'ntfy', ntfytopic: 't' }, { type: 'ntfy', ntfytopic: 't', ntfyserverurl: '' }, { type: 'ntfy', ntfytopic: 't', ntfyserverurl: '   ' }, { type: 'ntfy', ntfytopic: 't', ntfyserverurl: null }, { type: 'ntfy', ntfytopic: 't', ntfyserverurl: 5 }])
    await assert.rejects(assertNotificationConfigAllowed(cfg as any), /ntfyserverurl/, JSON.stringify(cfg));
  await assertNotificationConfigAllowed({ type: 'ntfy', ntfytopic: 't', ntfyserverurl: 'https://203.0.113.9' });
});

test('R7-b the server-root check rejects dot-segment and encoded paths that URL parsing would normalise away', async () => {
  const ntfy = (ntfyserverurl: string) => assertNotificationConfigAllowed({ type: 'ntfy', ntfyserverurl, ntfytopic: 't' });
  for (const u of ['https://203.0.113.9/.', 'https://203.0.113.9/..', 'https://203.0.113.9/./', 'https://203.0.113.9/a/..', 'https://203.0.113.9/%2e', 'https://203.0.113.9/%2E%2E', 'https://203.0.113.9\\x', 'https://203.0.113.9\\', 'https://203.0.113.9/\\x'])
    await assert.rejects(ntfy(u), /server root/, u);
  await ntfy('https://203.0.113.9'); await ntfy('https://203.0.113.9/');
});

test('R7-c public-suffix and numeric wildcards are rejected in ALLOW/DENY/NOTIFICATION host env parsing', async () => {
  const { invalidAllowEntries, invalidDenyEntries, wildcardProblems } = await import('../src/policy.js');
  const bad = ['*.co.uk', '*.com.au', '*.com', '*.org.uk', '*.1.2.3', '*.10', '*.192.168.1:80'];
  const good = ['*.lan.example', '*.example.com', '*.lan', '*.home.arpa', '*bifrost*', '*.localhost'];
  await withEnv({ KUMA_MCP_ALLOW_HOSTS: [...bad, ...good].join(','), KUMA_MCP_DENY_HOSTS: [...bad, ...good].join(','), KUMA_MCP_NOTIFICATION_HOSTS: [...bad, ...good].join(',') }, async () => {
    for (const fn of [invalidAllowEntries, invalidDenyEntries]) for (const b of bad) assert.ok(fn().includes(b), `${fn.name} should reject ${b}`);
    for (const b of bad) assert.ok(invalidNotificationHostEntries().includes(b), `notification should reject ${b}`);
    for (const g of good) assert.ok(!invalidAllowEntries().includes(g) && !invalidDenyEntries().includes(g), g);
    const p = wildcardProblems();
    for (const env of ['KUMA_MCP_ALLOW_HOSTS', 'KUMA_MCP_DENY_HOSTS', 'KUMA_MCP_NOTIFICATION_HOSTS']) for (const b of bad) assert.ok(p.some((x) => x.env === env && x.entry === b && x.reason.length > 0), `${env} ${b}`);
    assert.ok(!p.some((x) => good.includes(x.entry)));
  });
  await withEnv({ KUMA_MCP_DENY_HOSTS: '*.co.uk' }, async () => { assert.throws(() => denyList(), /invalid entry/); }); // refused, never silently skipped
});

test('R7-c the server refuses to start with such an entry and says why', async () => {
  const { spawnSync } = await import('node:child_process');
  const r = spawnSync(process.execPath, [new URL('../src/index.js', import.meta.url).pathname], { env: { ...process.env, KUMA_MCP_ALLOW_HOSTS: '*.co.uk', PORT: '0' }, encoding: 'utf8', timeout: 15000 });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /KUMA_MCP_ALLOW_HOSTS.*\*\.co\.uk.*public suffix/i);
});

// ── review round 7 follow-ups (opus findings) ───────────────────────────────
test('R7-d a hostname that WHATWG and legacy url.parse split differently is refused (name checked != host connected)', async () => {
  await withEnv({ KUMA_MCP_NOTIFICATION_HOSTS: '*.lan.example', KUMA_MCP_ALLOW_HOSTS: '*.lan.example', KUMA_MCP_DENY_HOSTS: 'vaultwarden,192.168.1.54' }, async () => {
    for (const u of ['https://vaultwarden;.lan.example', 'https://192.168.1.54%2a.lan.example', 'https://a{b}.lan.example', 'https://a|b.lan.example'])
      await assert.rejects(assertNotificationConfigAllowed({ type: 'ntfy', ntfytopic: 't', ntfyserverurl: u }, res({})), /not allowed/, u);
    for (const u of ['http://192.168.1.54;.lan.example:8015/', 'http://vaultwarden;.lan.example/'])
      await assert.rejects(async () => { const t = { url: u }; assertTargetAllowed(t); await assertResolvedTargetAllowed(t, res({})); }, /not allowed/, u);
    await assertNotificationConfigAllowed({ type: 'ntfy', ntfytopic: 't', ntfyserverurl: 'https://ntfy.lan.example' }, res({}));
  });
});

test('R7-e multi-star, single-label and IP-embedding wildcards are rejected; private suffixes stay', async () => {
  const { invalidAllowEntries } = await import('../src/policy.js');
  const bad = ['**.com', '*.*.uk', '*.*', '*.xn--p1ai', '*.museum', '*.nip.io', '*.sslip.io', '*.192-168-1-54.nip.io'];
  const good = ['*.lan', '*.local', '*.home.arpa', '*.internal', '*.lan.example', '*bifrost*', '*mcp*', '*.localhost', 'n8n', '192.168.1.0/24'];
  await withEnv({ KUMA_MCP_ALLOW_HOSTS: [...bad, ...good].join(',') }, async () => {
    for (const b of bad) assert.ok(invalidAllowEntries().includes(b), b);
    for (const g of good) assert.ok(!invalidAllowEntries().includes(g), g);
  });
});

// ── review round 8 ──────────────────────────────────────────────────────────
test('R8-B1 percent-encoded host characters are refused (WHATWG decodes, legacy url.parse stops at %)', async () => {
  await withEnv({ KUMA_MCP_ALLOW_HOSTS: '*.rebhahnomicon.com,*.attacker.example', KUMA_MCP_DENY_HOSTS: 'vaultwarden,dockge,localhost', KUMA_MCP_DENY_PRIVATE: '1' }, async () => {
    for (const u of ['http://vaultwarden%2erebhahnomicon.com/admin', 'http://vaultwarden%2eattacker.example/admin', 'https://dockge%2eattacker.example/', 'http://%6cocalhost.attacker.example/', 'http://a%2db.rebhahnomicon.com/'])
      await assert.rejects(async () => { const t = { url: u }; assertTargetAllowed(t); await assertResolvedTargetAllowed(t, res({})); }, /not allowed/, u);
    await assert.rejects(assertNotificationConfigAllowed({ type: 'gotify', gotifyserverurl: 'http://vaultwarden%2elan.example/' }, res({})), /not allowed/);
    const t = { url: 'https://grafana.rebhahnomicon.com/x?q=%2e' }; assertTargetAllowed(t); await assertResolvedTargetAllowed(t, res({})); // % in the path/query is fine
  });
});

test('R8-S1 bare * and glued/trailing-dot ALLOW/DENY entries are rejected; legit homelab entries stay', async () => {
  const { invalidAllowEntries, invalidDenyEntries } = await import('../src/policy.js');
  const bad = ['*', '*com', '*o.uk', '*.co.uk.', 'vaultwarden.', '*.com.'];
  const good = ['*.rebhahnomicon.com', '*.lan', '*bifrost*', '*mcp*', '*.localhost', '192.168.1.0/24', 'n8n', 'n8n:5678', '[2001:db8::1]:8080'];
  await withEnv({ KUMA_MCP_ALLOW_HOSTS: [...bad, ...good].join(','), KUMA_MCP_DENY_HOSTS: [...bad, ...good].join(',') }, async () => {
    for (const b of bad) { assert.ok(invalidAllowEntries().includes(b), `allow ${b}`); assert.ok(invalidDenyEntries().includes(b), `deny ${b}`); }
    for (const g of good) { assert.ok(!invalidAllowEntries().includes(g), g); assert.ok(!invalidDenyEntries().includes(g), g); }
  });
});

test('R8 legit hosts still pass parseTarget: underscore name, IDN, IPv6 with port, bare host:port', async () => {
  await withEnv({ KUMA_MCP_ALLOW_HOSTS: 'my_svc,xn--bcher-kva.example.com,[2001:db8::1],db' }, async () => {
    for (const t of [{ url: 'http://my_svc:8080/' }, { url: 'https://bücher.example.com/' }, { url: 'http://[2001:db8::1]:8080/' }, { hostPort: 'db:5432' }])
      { try { assertTargetAllowed(t); await assertResolvedTargetAllowed(t, res({})); } catch (e: any) { assert.fail(JSON.stringify(t) + ' ' + e.message); } }
  });
});

// ── review round 9 ──────────────────────────────────────────────────────────
test('R9-B1 an empty host in the raw authority is refused (legacy url.parse gives hostname "" which http.request turns into localhost)', async () => {
  await withEnv({ KUMA_MCP_ALLOW_HOSTS: '*.rebhahnomicon.com,grafana' }, async () => {
    for (const u of ['http:///grafana:3000/', 'http://\\grafana:3000/', 'https:///hass.rebhahnomicon.com', 'http://:80/', 'http://@/x'])
      await assert.rejects(async () => { const t = { url: u }; assertTargetAllowed(t); await assertResolvedTargetAllowed(t, res({})); }, /not allowed/, u);
  });
});

test('R9-S1 tab/CR/LF inside a host is refused, not stripped (monitor url and notification destinations)', async () => {
  await withEnv({ KUMA_MCP_ALLOW_HOSTS: '*.rebhahnomicon.com', KUMA_MCP_DENY_HOSTS: 'vaultwarden', KUMA_MCP_NOTIFICATION_HOSTS: '192.168.1.54:8088,*.rebhahnomicon.com' }, async () => {
    for (const u of ['http://vaultwarden\t.rebhahnomicon.com/', 'http://vaultwarden\n.rebhahnomicon.com/', 'http://a.rebhahnomicon.com/\t'.replace('/\t', '\t/x')])
      assert.throws(() => assertTargetAllowed({ url: u }), /not allowed/, JSON.stringify(u));
    await assert.rejects(assertNotificationConfigAllowed({ type: 'ntfy', ntfytopic: 't', ntfyserverurl: 'http://192.168.1.54\t:8088' }, res({})), /not allowed/);
    await assert.rejects(assertNotificationConfigAllowed({ type: 'webhook', httpMethod: 'GET', webhookURL: 'https://vaultwarden\t.rebhahnomicon.com/' }, res({})), /whitespace|not allowed/);
  });
});

test('R9-N ntfyserverurl userinfo is refused; very short globs (*e*, a*) are invalid host entries', async () => {
  const { invalidAllowEntries } = await import('../src/policy.js');
  await assert.rejects(assertNotificationConfigAllowed({ type: 'ntfy', ntfytopic: 't', ntfyserverurl: 'https://x@ntfy.example' }), /server root/);
  await withEnv({ KUMA_MCP_ALLOW_HOSTS: '*e*,a*,*com*,*,*x*.com,*mcp*,*bifrost*,*.lan' }, async () => {
    for (const b of ['*e*', 'a*', '*']) assert.ok(invalidAllowEntries().includes(b), b);
    for (const g of ['*mcp*', '*bifrost*', '*.lan']) assert.ok(!invalidAllowEntries().includes(g), g);
  });
});

// ── review round 10 ─────────────────────────────────────────────────────────
test('R10-S1 a scheme-less URL destination is refused (Kuma would send it to localhost:80)', async () => {
  await withEnv({ KUMA_MCP_NOTIFICATION_TYPES: 'webhook,gotify', KUMA_MCP_NOTIFICATION_HOSTS: 'hooks.rebhahnomicon.com,hooks.rebhahnomicon.com:8080', KUMA_MCP_ALLOW_HOSTS: '*.rebhahnomicon.com' }, async () => {
    for (const v of ['hooks.rebhahnomicon.com/x', 'evil@hooks.rebhahnomicon.com', 'hooks.rebhahnomicon.com?x', 'hooks.rebhahnomicon.com:8080/x', 'hooks.rebhahnomicon.com\\x'])
      await assert.rejects(assertNotificationConfigAllowed({ type: 'webhook', httpMethod: 'GET', webhookURL: v }, res({})), /scheme|not allowed/, v);
    await assert.rejects(assertNotificationConfigAllowed({ type: 'gotify', gotifyserverurl: 'hooks.rebhahnomicon.com#' }, res({})), /scheme|not allowed/);
    await assertNotificationConfigAllowed({ type: 'webhook', httpMethod: 'GET', webhookURL: 'https://hooks.rebhahnomicon.com/x' }, res({}));
  });
});

test('R10-N1 non-canonical IPv4 spellings are refused in hosts (resolvers disagree on octal/hex/decimal)', async () => {
  await withEnv({ KUMA_MCP_DENY_HOSTS: '192.168.1.54:8015' }, async () => {
    for (const u of ['http://192.168.1.054:8015/', 'http://0xc0.0xa8.1.54:8015/', 'http://3232235830:8015/', 'http://192.168.1.54.:8015/x'.replace('54.', '054')])
      assert.throws(() => assertTargetAllowed({ url: u }), /not allowed/, u);
    assertTargetAllowed({ url: 'http://192.168.1.55:8015/' });
  });
});

test('R10-N3/N4 backslash in an apprise URL refused; post-parse hostname charset still guards fullwidth characters', async () => {
  await withEnv({ KUMA_MCP_NOTIFICATION_TYPES: 'apprise', KUMA_MCP_NOTIFICATION_HOSTS: 'ntfy.rebhahnomicon.com:443', KUMA_MCP_ALLOW_HOSTS: '*.rebhahnomicon.com' }, async () => {
    await assert.rejects(assertNotificationConfigAllowed({ type: 'apprise', appriseURL: 'jsons://ntfy.rebhahnomicon.com:443\\@192.168.1.54:8015/' }, res({})), /backslash|not allowed/);
  });
  for (const u of ['http://n8n＊/', 'http://a＄b/']) assert.throws(() => assertTargetAllowed({ url: u }), /not allowed/, u);
});

// ── review round 11 ─────────────────────────────────────────────────────────
test('R11-S1 an address the parser reads as IPv4 must be written canonically, hex letters included', async () => {
  await withEnv({ KUMA_MCP_DENY_HOSTS: '192.168.1.54:8015' }, async () => {
    for (const u of ['http://0xc0.0xa8.0x1.054:8015/', 'http://0xa.0.0.1/', 'http://0xc0.0xa8.1.54:8088/'])
      assert.throws(() => assertTargetAllowed({ url: u }), /not allowed/, u);
    for (const t of [{ hostname: '0xa.0.0.1' }, { hostPort: '0xc0.0xa8.1.54:25' }]) assert.throws(() => assertTargetAllowed(t), /not allowed/, JSON.stringify(t));
    assertTargetAllowed({ url: 'http://cafe.face:80/' }); assertTargetAllowed({ url: 'http://192.168.1.55/' }); // names that merely look hex stay fine
  });
});

test('R11-S2 scheme-less host:port in a single-value URL field is refused (legacy parser reads the host as the protocol)', async () => {
  await withEnv({ KUMA_MCP_NOTIFICATION_TYPES: 'webhook,gotify,ntfy', KUMA_MCP_NOTIFICATION_HOSTS: '192.168.1.54:8088,ntfy.rebhahnomicon.com:443', KUMA_MCP_ALLOW_HOSTS: '*.rebhahnomicon.com,192.168.1.54' }, async () => {
    await assert.rejects(assertNotificationConfigAllowed({ type: 'webhook', httpMethod: 'GET', webhookURL: '192.168.1.54:8088' }, res({})), /must start with http/);
    await assert.rejects(assertNotificationConfigAllowed({ type: 'gotify', gotifyserverurl: 'ntfy.rebhahnomicon.com:443' }, res({})), /must start with http/);
    await assert.rejects(assertNotificationConfigAllowed({ type: 'ntfy', ntfytopic: 't', ntfyserverurl: 'https://ntfy.rebhahnomicon.com', ntfyIcon: '192.168.1.54:8088' }, res({})), /must start with http/);
  });
});

// ── review round 12 ─────────────────────────────────────────────────────────
test('R12 a scheme not followed by // is refused (http:/\\host%2e... slipped past the raw-authority check via httpAddr)', async () => {
  await withEnv({ KUMA_MCP_NOTIFICATION_TYPES: 'onebot', KUMA_MCP_NOTIFICATION_HOSTS: '*.rebhahnomicon.com:443', KUMA_MCP_ALLOW_HOSTS: '*.rebhahnomicon.com', KUMA_MCP_DENY_HOSTS: 'vaultwarden' }, async () => {
    for (const v of ['http:/\\vaultwarden%2erebhahnomicon.com:443', 'http:\\\\vaultwarden%2erebhahnomicon.com:443', 'https:/\\vaultwarden%2erebhahnomicon.com:443', 'http:vaultwarden.rebhahnomicon.com:443', 'http:80@x.rebhahnomicon.com:443', 'https:443@x.rebhahnomicon.com:443', 'http:1@x.rebhahnomicon.com:443/a', 'httpbin.rebhahnomicon.com:443'])
      await assert.rejects(assertNotificationConfigAllowed({ type: 'onebot', httpAddr: v }, res({})), /not allowed/, v);
    await assertNotificationConfigAllowed({ type: 'onebot', httpAddr: 'x.rebhahnomicon.com:443' }, res({}));
    await assertNotificationConfigAllowed({ type: 'onebot', httpAddr: 'https://x.rebhahnomicon.com' }, res({}));
  });
  for (const u of ['http:/\\x.example/', 'http:x.example/', 'http:80@x.example/', 'https:443@x.example']) assert.throws(() => assertTargetAllowed({ url: u }), /not allowed/, u);
});

test('R13 httpAddr with a non-lowercase-http scheme is refused (Kuma prefixes http:// to it); parseTarget rule on hostPort/relays', async () => {
  await withEnv({ KUMA_MCP_NOTIFICATION_TYPES: 'onebot,nostr', KUMA_MCP_NOTIFICATION_HOSTS: 'x.example,x.example:443', KUMA_MCP_ALLOW_HOSTS: '*.example,x.example' }, async () => {
    for (const v of ['ws://x.example/', 'wss://x.example:443/', 'Http://x.example/', 'HTTPS://x.example:443', 'WS://x.example'])
      await assert.rejects(assertNotificationConfigAllowed({ type: 'onebot', httpAddr: v }, res({})), /lowercase http/, v);
    await assertNotificationConfigAllowed({ type: 'onebot', httpAddr: 'https://x.example' }, res({}));
    await assertNotificationConfigAllowed({ type: 'onebot', httpAddr: 'x.example:443' }, res({}));
    for (const t of [{ hostPort: 'http:80@x.example:443' }, { hostPort: 'wss:443@x.example:443' }]) assert.throws(() => assertTargetAllowed(t), /not allowed/, JSON.stringify(t));
    await assert.rejects(assertNotificationConfigAllowed({ type: 'nostr', relays: 'wss:443@x.example:443' }, res({})), /not allowed/);
  });
});

test('R13-B1 leading/trailing whitespace on a destination is refused (Kuma gets the raw value: " http://x" gets http:// prefixed -> localhost)', async () => {
  await withEnv({ KUMA_MCP_NOTIFICATION_TYPES: 'onebot,webhook', KUMA_MCP_NOTIFICATION_HOSTS: 'x.example,x.example:5700,192.168.1.54:5700', KUMA_MCP_ALLOW_HOSTS: '*.example,192.168.1.54' }, async () => {
    for (const v of [' http://x.example:5700', '  https://x.example', ' 192.168.1.54:5700', '192.168.1.54:5700 ', 'https://x.example\u00a0'])
      await assert.rejects(assertNotificationConfigAllowed({ type: 'onebot', httpAddr: v }, res({})), /whitespace|not allowed/, JSON.stringify(v));
    await assert.rejects(assertNotificationConfigAllowed({ type: 'webhook', httpMethod: 'GET', webhookURL: ' https://x.example/h' }, res({})), /whitespace/);
    await assertNotificationConfigAllowed({ type: 'onebot', httpAddr: '192.168.1.54:5700' }, res({}));
  });
  await assert.rejects(assertNotificationConfigAllowed({ type: 'ntfy', ntfytopic: 't', ntfyserverurl: ' https://x.example' }), /whitespace|server root|not allowed/);
});

test('R13-B2 a :port written after / ? # in a scheme-less target is path text, not the port', async () => {
  await withEnv({ KUMA_MCP_NOTIFICATION_TYPES: 'onebot', KUMA_MCP_NOTIFICATION_HOSTS: '192.168.1.54:5700,x.example:5700', KUMA_MCP_ALLOW_HOSTS: '*.example,192.168.1.54' }, async () => {
    for (const v of ['192.168.1.54/:5700', '192.168.1.54?:5700', '192.168.1.54#:5700', 'x.example/:5700'])
      await assert.rejects(assertNotificationConfigAllowed({ type: 'onebot', httpAddr: v }, res({})), /not allowed/, v);
    await assertNotificationConfigAllowed({ type: 'onebot', httpAddr: 'x.example:5700/path' }, res({}));
  });
  await withEnv({ KUMA_MCP_DENY_HOSTS: '192.168.1.54:5700' }, async () => { assert.throws(() => assertTargetAllowed({ hostPort: '192.168.1.54:5700' }), /not allowed/); assertTargetAllowed({ hostPort: '192.168.1.54/:5700' }); });
});

test('R14-A1 a monitor target padded with Unicode whitespace is refused (JS trim() strips U+3000, legacy url.parse does not -> localhost:80)', () => {
  for (const u of ['　https://example.com/', 'https://example.com/　', ' http://a.example/', ' https://a.example/', ' https://a.example/', ' https://a.example/', 'https://a.example/​'])
    assert.throws(() => assertTargetAllowed({ url: u }), /whitespace|not allowed/, JSON.stringify(u));
  assert.throws(() => assertTargetAllowed({ hostname: ' a.example' }), /not allowed|whitespace/);
  assertTargetAllowed({ url: 'https://a.example/' });
});

test('R14-B1 an http-type monitor without a real url (empty/placeholder/padded) is refused: Kuma would send it to localhost', () => {
  assert.throws(() => buildAddPayload({ type: 'http', name: 'x' }), /explicit http/);
  for (const u of ['', ' ', ' ', '﻿', ' https://', 'https:// '])
    assert.throws(() => buildAddPayload({ type: 'http', name: 'x', url: u }), /not allowed/, JSON.stringify(u));
  assert.throws(() => effectiveTarget({ type: 'keyword', url: 'https://' }), /explicit http/);
  assert.throws(() => effectiveTarget({ type: 'http', url: undefined }), /explicit http/);
  buildAddPayload({ type: 'ping', name: 'x', hostname: 'a.example' });
  buildAddPayload({ type: 'http', name: 'x', url: 'https://a.example/' });
});

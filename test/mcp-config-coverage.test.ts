import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { UptimeKumaClient, isNotLoggedIn } from '../src/uptime-kuma-client.js';
import { buildAddPayload, buildEditPayload, genPushToken, fingerprint, deriveTimeout, normalizeStatusCodes } from '../src/payload.js';

const CFG = { name: 't', baseUrl: 'http://kuma.test', username: 'u', password: 'P_NOT_A_REAL_SECRET', insecureTLS: false };

// ── Fake socket.io socket ───────────────────────────────────────────────────
class FakeSocket extends EventEmitter {
  connected = false;
  active = true;
  /** per-connection auth state, like Kuma's server-side socket */
  loggedIn = false;
  log: string[] = [];
  handlers: Record<string, (...a: any[]) => any> = {};
  emit(event: string, ...args: any[]): boolean {
    const cb = args[args.length - 1];
    if (typeof cb === 'function' && !['connect', 'disconnect', 'connect_error'].includes(event)) {
      this.log.push(event);
      const h = this.handlers[event];
      queueMicrotask(() => cb(h ? h.call(this, ...args.slice(0, -1)) : { ok: true }));
      return true;
    }
    return super.emit(event, ...args);
  }
  serverConnect() { this.connected = true; this.loggedIn = false; super.emit('connect'); }
  serverDrop() { this.connected = false; super.emit('disconnect', 'transport close'); }
  disconnect() { this.connected = false; return this; }
}

function mkClient() {
  const sock = new FakeSocket();
  sock.handlers.login = function (this: FakeSocket) { this.loggedIn = true; return { ok: true, token: 'jwt-1' }; };
  sock.handlers.loginByToken = function (this: FakeSocket, tok: string) {
    this.loggedIn = tok === 'jwt-1'; return { ok: this.loggedIn, msg: this.loggedIn ? undefined : 'Invalid token' };
  };
  sock.handlers.getTags = function (this: FakeSocket) {
    return this.loggedIn ? { ok: true, tags: [] } : { ok: false, msg: 'You are not logged in.' };
  };
  const factory: any = () => { queueMicrotask(() => sock.serverConnect()); return sock; };
  const client = new UptimeKumaClient(CFG, factory);
  return { client, sock };
}

// ── 1. Re-auth after reconnect ──────────────────────────────────────────────
test('isNotLoggedIn matches only the Kuma not-logged-in reply', () => {
  assert.equal(isNotLoggedIn({ ok: false, msg: 'You are not logged in.' }), true);
  assert.equal(isNotLoggedIn({ ok: true, msg: 'not logged in' }), false);
  assert.equal(isNotLoggedIn({ ok: false, msg: 'other' }), false);
  assert.equal(isNotLoggedIn(null), false);
});

test('initial connect logs in once', async () => {
  const { client, sock } = mkClient();
  const r = await client.listTags();
  assert.equal(r.ok, true);
  assert.equal(sock.log.filter((e) => e === 'login').length, 1);
});

test('socket.io auto-reconnect re-runs login before the next call (the "You are not logged in." bug)', async () => {
  const { client, sock } = mkClient();
  await client.listTags();
  sock.serverDrop();            // Kuma restarts
  sock.serverConnect();         // socket.io auto-reconnects: new server-side socket, NOT logged in
  assert.equal(sock.loggedIn, false);
  sock.log.length = 0;
  const r = await client.listTags();
  assert.equal(r.ok, true, 'call after reconnect must be authenticated');
  // proactive path: login happens BEFORE the call, so Kuma never sees an unauthenticated getTags
  assert.deepEqual(sock.log, ['loginByToken', 'getTags']);
});

test('reconnect with a rejected token falls back to password login', async () => {
  const { client, sock } = mkClient();
  await client.listTags();
  sock.handlers.loginByToken = () => ({ ok: false, msg: 'Invalid token' }); // new Kuma JWT secret
  sock.serverDrop(); sock.serverConnect();
  const r = await client.listTags();
  assert.equal(r.ok, true);
  assert.equal(sock.log.filter((e) => e === 'login').length, 2);
});

test('call that races the reconnect: waits for the socket then logs in', async () => {
  const { client, sock } = mkClient();
  await client.listTags();
  sock.serverDrop();
  const p = client.listTags();            // issued while disconnected, socket.io still active
  setTimeout(() => sock.serverConnect(), 20);
  assert.equal((await p).ok, true);
});

test('server-side "not logged in" reply triggers exactly one re-login and one retry', async () => {
  const { client, sock } = mkClient();
  await client.listTags();
  sock.loggedIn = false;                  // server forgot us without a disconnect event
  const r = await client.listTags();
  assert.equal(r.ok, true);
  assert.equal(sock.log.filter((e) => e === 'getTags').length, 3); // 1st ok, 2nd rejected, 3rd retry
  // a permanent not-logged-in reply is retried once, not forever
  sock.handlers.getTags = () => ({ ok: false, msg: 'You are not logged in.' });
  sock.log.length = 0;
  const r2 = await client.listTags();
  assert.equal(r2.ok, false);
  assert.equal(sock.log.filter((e) => e === 'getTags').length, 2);
});

test('concurrent calls after a reconnect share a single login', async () => {
  const { client, sock } = mkClient();
  await client.listTags();
  sock.log.length = 0;
  sock.serverDrop(); sock.serverConnect();
  await Promise.all([client.listTags(), client.listTags(), client.listTags()]);
  assert.equal(sock.log.filter((e) => e === 'loginByToken' || e === 'login').length, 1);
});

test('failed login error never echoes Kuma msg', async () => {
  const { client, sock } = mkClient();
  sock.handlers.login = () => ({ ok: false, msg: 'bad creds P_NOT_A_REAL_SECRET' });
  await assert.rejects(() => client.listTags(), (e: any) => !e.message.includes('P_NOT_A_REAL_SECRET'));
});

// ── 2. add payload defaults ─────────────────────────────────────────────────
test('add payload carries every NOT NULL default the UI sends', () => {
  const p = buildAddPayload({ type: 'http', name: 'x', url: 'https://a.test/' });
  assert.deepEqual(p.conditions, []);
  assert.deepEqual(p.accepted_statuscodes, ['200-299']);
  assert.equal(p.timeout, 48);                 // 60 * 0.8
  assert.equal(p.retryInterval, 60);
  assert.equal(p.maxretries, 0);
  assert.equal(p.resendInterval, 0);
  assert.equal(p.maxredirects, 10);
  assert.deepEqual(p.notificationIDList, {});
  assert.deepEqual(p.kafkaProducerBrokers, []);
  assert.deepEqual(p.kafkaProducerSaslOptions, { mechanism: 'None' });
  assert.deepEqual(p.rabbitmqNodes, []);
  assert.equal(p.parent, null);
});

test('add payload: undefined/null never override NOT NULL defaults; nullable columns may be null', () => {
  const p = buildAddPayload({ name: 'x', conditions: undefined, maxretries: null, interval: undefined, method: null, parent: null, docker_host: null });
  assert.deepEqual(p.conditions, []);
  assert.equal(p.maxretries, 0);
  assert.equal(p.interval, 60);
  assert.equal(p.method, 'GET');
  assert.equal(p.parent, null);
  assert.ok(Object.values(p).every((v) => v !== undefined));
});

test('add payload: timeout derives from interval, explicit timeout wins, ping defaults to 10', () => {
  assert.equal(buildAddPayload({ name: 'x', interval: 30 }).timeout, 24);
  assert.equal(buildAddPayload({ name: 'x', interval: 30, timeout: 5 }).timeout, 5);
  assert.equal(buildAddPayload({ name: 'x', type: 'ping', hostname: 'h' }).timeout, 10);
  assert.equal(deriveTimeout('http', 0), 48);
});

test('add payload: accepted_statuscodes accepts array and comma string; always string array', () => {
  assert.deepEqual(buildAddPayload({ name: 'x', accepted_statuscodes: ['200-299', '301'] }).accepted_statuscodes, ['200-299', '301']);
  assert.deepEqual(buildAddPayload({ name: 'x', accepted_statuscodes: '200-299, 404' }).accepted_statuscodes, ['200-299', '404']);
  assert.deepEqual(buildAddPayload({ name: 'x', accepted_statuscodes: [200, 301] as any }).accepted_statuscodes, ['200', '301']);
  assert.deepEqual(buildAddPayload({ name: 'x', accepted_statuscodes: [] }).accepted_statuscodes, ['200-299']);
  assert.equal(normalizeStatusCodes(undefined), undefined);
});

test('add payload: headers/body objects become JSON strings; auth + docker + parent pass through', () => {
  const p = buildAddPayload({ name: 'x', headers: { A: 'b' }, body: { k: 1 }, authMethod: 'basic', basic_auth_user: 'u', docker_host: 2, docker_container: 'c', parent: 7 });
  assert.equal(p.headers, '{"A":"b"}');
  assert.equal(p.body, '{"k":1}');
  assert.equal(p.authMethod, 'basic');
  assert.equal(p.docker_host, 2);
  assert.equal(p.parent, 7);
});

test('push token: generated 32-char alphanumeric for type=push, not for others', () => {
  const p = buildAddPayload({ name: 'x', type: 'push' });
  assert.match(p.pushToken, /^[A-Za-z0-9]{32}$/);
  assert.notEqual(genPushToken(), genPushToken());
  assert.equal(buildAddPayload({ name: 'x', type: 'http' }).pushToken, undefined);
});

function addClient(res: any = { ok: true, msg: 'Added Successfully.', monitorID: 9 }) {
  const sent: any[] = [];
  const client: any = Object.create(UptimeKumaClient.prototype);
  client.cfg = { name: 't' };
  client.ensureConnected = async () => {};
  client.emitWithAck = async (ev: string, ...a: any[]) => { sent.push([ev, ...a]); return res; };
  return { client, sent };
}

test('addMonitor(push) returns id + fingerprint only; the token goes to Kuma but never back to the caller', async () => {
  const { client, sent } = addClient();
  const out = await client.addMonitor({ name: 'p', type: 'push' });
  const token = sent[0][1].pushToken;
  assert.match(token, /^[A-Za-z0-9]{32}$/);
  assert.equal(out.monitorID, 9);
  assert.equal(out.pushTokenFingerprint, fingerprint(token));
  assert.ok(!JSON.stringify(out).includes(token));
  assert.equal(out.pushTokenFingerprint.length, 8);
});

test('addMonitor: sent payload is complete and failure text is withheld', async () => {
  const { client, sent } = addClient();
  await client.addMonitor({ name: 'x', url: 'https://a.test/' });
  assert.deepEqual(sent[0][1].conditions, []);
  const bad = addClient({ ok: false, msg: 'NOT NULL constraint failed: monitor.conditions' });
  await assert.rejects(() => bad.client.addMonitor({ name: 'x' }), (e: any) => !e.message.includes('monitor.conditions'));
});

// ── 3. edit merge ───────────────────────────────────────────────────────────
const current = {
  id: 5, name: 'm', type: 'http', url: 'https://a.test/', method: 'GET', interval: 60, retryInterval: 60, resendInterval: 0,
  maxretries: 2, timeout: 48, keyword: 'hello', invertKeyword: false, accepted_statuscodes: ['200-299', '301'],
  maxredirects: 10, notificationIDList: { '1': true }, parent: 3, description: 'd', upsideDown: false, ignoreTls: false,
  tags: [{ tag_id: 1 }], path: ['a'], pathName: 'a / m', childrenIDs: [], maintenance: false, forceInactive: false, includeSensitiveData: true,
};

test('edit merge: unchanged fields are preserved, read-only keys dropped, full object emitted', () => {
  const m = buildEditPayload(current, { name: 'renamed' }, 5);
  assert.equal(m.name, 'renamed');
  assert.equal(m.keyword, 'hello');
  assert.deepEqual(m.accepted_statuscodes, ['200-299', '301']);
  assert.equal(m.parent, 3);
  assert.equal(m.id, 5);
  for (const k of ['tags', 'path', 'pathName', 'childrenIDs', 'maintenance', 'forceInactive', 'includeSensitiveData']) assert.ok(!(k in m), k);
  assert.deepEqual(m.conditions, []); // NOT NULL column missing from older getMonitor ack is filled
  assert.deepEqual(m.kafkaProducerSaslOptions, { mechanism: 'None' });
});

test('edit merge: keyword and accepted_statuscodes changes persist; string form is normalised; undefined ignored', () => {
  const m = buildEditPayload(current, { keyword: 'bye', accepted_statuscodes: '200-299,404', description: undefined, interval: undefined }, 5);
  assert.equal(m.keyword, 'bye');
  assert.deepEqual(m.accepted_statuscodes, ['200-299', '404']);
  assert.equal(m.description, 'd');
  assert.equal(m.interval, 60);
});

test('edit merge: parent may be set to null (root) but non-nullable columns ignore null', () => {
  const m = buildEditPayload(current, { parent: null, maxretries: null, keyword: null } as any, 5);
  assert.equal(m.parent, null);
  assert.equal(m.maxretries, 2);
  assert.equal(m.keyword, 'hello');
});

test('edit merge: auto-derived timeout follows an interval change; custom or explicit timeout is kept', () => {
  assert.equal(buildEditPayload(current, { interval: 100 }, 5).timeout, 80);
  assert.equal(buildEditPayload({ ...current, timeout: 5 }, { interval: 100 }, 5).timeout, 5);
  assert.equal(buildEditPayload(current, { interval: 100, timeout: 30 }, 5).timeout, 30);
  assert.equal(buildEditPayload({ ...current, timeout: 0 }, {}, 5).timeout, 48); // zeroed timeout repaired like the UI
});

test('edit merge: switching a monitor to push generates a token; existing token is kept', () => {
  assert.match(buildEditPayload(current, { type: 'push' }, 5).pushToken, /^[A-Za-z0-9]{32}$/);
  assert.equal(buildEditPayload({ ...current, type: 'push', pushToken: 'EXISTINGTOKEN' }, { name: 'n' }, 5).pushToken, 'EXISTINGTOKEN');
});

test('editMonitor end to end: loads current via getMonitor, emits editMonitor with the full object, redacts the ack', async () => {
  const sent: any[] = [];
  const client: any = Object.create(UptimeKumaClient.prototype);
  client.cfg = { name: 't' };
  client.ensureConnected = async () => {};
  client.emitWithAck = async (ev: string, ...a: any[]) => {
    sent.push([ev, ...a]);
    return ev === 'getMonitor' ? { ok: true, monitor: { ...current } } : { ok: true, msg: 'Saved.', monitorID: 5, monitor: { id: 5, pushToken: 'SECRETTOKEN123' } };
  };
  const out = await client.editMonitor(5, { keyword: 'bye' });
  assert.deepEqual(sent.map((s) => s[0]), ['getMonitor', 'editMonitor']);
  const payload = sent[1][1];
  assert.equal(payload.keyword, 'bye');
  assert.equal(payload.name, 'm');
  assert.deepEqual(payload.accepted_statuscodes, ['200-299', '301']);
  assert.ok(!JSON.stringify(out).includes('SECRETTOKEN123'));
});

// ── 4. new tools hit the right Kuma events ──────────────────────────────────
test('tag / maintenance / status page methods emit the expected Kuma events and args', async () => {
  const { client, sent } = addClient({ ok: true, maintenanceID: 4, config: { slug: 's', title: 'T', icon: '/i.png', domainNameList: [] } });
  await client.createTag('t', '#112233');
  await client.addMonitorTag(1, 2, 'v');
  await client.removeMonitorTag(1, 2, 'v');
  await client.addMaintenance({ title: 'm' }, [7, 8]);
  await client.pauseMaintenance(4);
  await client.resumeMaintenance(4);
  await client.deleteMaintenance(4);
  await client.addStatusPage('T', 's');
  await client.saveStatusPage('s', { title: 'New' }, [{ name: 'g', monitorIds: [7] }]);
  await client.deleteStatusPage('s');
  assert.deepEqual(sent.map((s) => s[0]), ['addTag', 'addMonitorTag', 'deleteMonitorTag', 'addMaintenance', 'addMonitorMaintenance',
    'pauseMaintenance', 'resumeMaintenance', 'deleteMaintenance', 'addStatusPage', 'getStatusPage', 'saveStatusPage', 'deleteStatusPage']);
  assert.deepEqual(sent[2].slice(1), [1, 2, 'v']);
  assert.deepEqual(sent[4].slice(1), [4, [{ id: 7 }, { id: 8 }]]);
  const save = sent[10];
  assert.equal(save[2].title, 'New');
  assert.equal(save[3], '/i.png');
  assert.deepEqual(save[4], [{ name: 'g', monitorList: [{ id: 7 }] }]);
});

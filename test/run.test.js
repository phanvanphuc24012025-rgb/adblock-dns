const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const Module = require('module');
const { execSync } = require('child_process');

const DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'adblock-test-'));
process.env.ADBLOCK_DATA_DIR = DATA;
process.env.DASHBOARD_PASSWORD = 'secret123';

const origLoad = Module._load;
Module._load = function (request, ...rest) {
  return request === 'dns2' ? origLoad.call(this, path.join(__dirname, 'stub-dns2.js'), ...rest) : origLoad.call(this, request, ...rest);
};

const root = path.join(__dirname, '..');
const config = require(path.join(root, 'config'));
const lists = require(path.join(root, 'lists'));
const engine = require(path.join(root, 'engine'));
const { parseDomains } = require(path.join(root, 'list-utils'));
const stats = require(path.join(root, 'stats'));
const notify = require(path.join(root, 'notify'));
const admin = require(path.join(root, 'admin'));
const app = require(path.join(root, 'index'));

fs.mkdirSync(lists.LISTS_DIR, { recursive: true });
fs.writeFileSync(lists.listPath('ads'), 'ads.example.com\ntracker.net\n');
fs.writeFileSync(lists.listPath('malware'), 'evil.test\n');
fs.writeFileSync(lists.listPath('social'), 'social.test\n');
fs.writeFileSync(lists.listPath('porn'), 'adult.test\n');
engine.reloadLists();

const at = (day, hh, mm) => { // 2026-10-18 is a Sunday (day 0)
  const d = new Date(2026, 9, 18 + day, hh, mm); return d;
};

test('normalizeDomain', () => {
  assert.equal(config.normalizeDomain(' HTTPS://Sub.Example.com/path?x '), 'sub.example.com');
  assert.equal(config.normalizeDomain('*.example.com'), 'example.com');
  assert.equal(config.normalizeDomain('not a domain'), null);
  assert.equal(config.normalizeDomain('<script>.com'), null);
  assert.equal(config.normalizeDomain('localhost'), null);
});

test('parseDomains handles hosts, plain, wildcard and adblock formats', () => {
  const s = parseDomains('# c\n! c\n127.0.0.1 localhost\n0.0.0.0 A.com B.com # x\nplain.org\n*.wild.net\n||adb.io^\n||adb2.io^$third-party\n[Adblock]\n');
  assert.deepEqual([...s].sort(), ['a.com', 'adb.io', 'adb2.io', 'b.com', 'plain.org', 'wild.net']);
});

test('schedules: same-day and overnight windows', () => {
  const night = { days: [5], start: '22:00', end: '06:00', categories: [] }; // Friday night
  assert.equal(engine.scheduleActive(night, at(5, 23, 0)), true);  // Fri 23:00
  assert.equal(engine.scheduleActive(night, at(6, 5, 59)), true);  // Sat 05:59 (belongs to Fri)
  assert.equal(engine.scheduleActive(night, at(6, 6, 0)), false);
  assert.equal(engine.scheduleActive(night, at(5, 5, 0)), false);  // Fri 05:00 belongs to Thu
  const day = { days: [1], start: '08:00', end: '09:30', categories: [] };
  assert.equal(engine.scheduleActive(day, at(1, 9, 29)), true);
  assert.equal(engine.scheduleActive(day, at(1, 9, 30)), false);
  assert.equal(engine.scheduleActive({ days: [1], start: 'x', end: '1:00' }, at(1, 9, 0)), false);
});

test('engine: categories, whitelist, blacklist, subdomains', () => {
  assert.equal(engine.decide('x.ads.example.com', '10.0.0.2').category, 'ads');
  assert.equal(engine.decide('evil.test', '10.0.0.2').category, 'malware');
  assert.equal(engine.decide('social.test', '10.0.0.2').blocked, false); // social off by default
  admin.actions.whitelist({ add: 'ads.example.com' });
  assert.equal(engine.decide('x.ads.example.com', '10.0.0.2').blocked, false);
  admin.actions.whitelist({ remove: 'ads.example.com' });
  admin.actions.blacklist({ add: 'blocked.me' });
  assert.deepEqual(engine.decide('a.blocked.me', '10.0.0.2'), { blocked: true, category: 'custom' });
  admin.actions.blacklist({ remove: 'blocked.me' });
});

test('engine: per-device always/exempt/schedule and pause', () => {
  admin.actions.devices({
    devices: {
      '192.168.1.50': { name: 'Con', always: ['social'], exempt: [], schedules: [] },
      '192.168.1.60': { name: 'Bố', always: [], exempt: ['porn', 'malware'], schedules: [] },
      '192.168.1.70': { name: 'Máy lịch', always: [], exempt: [], schedules: [{ days: [0], start: '22:00', end: '23:00', categories: ['social'] }] }
    },
    globalSchedules: []
  });
  assert.equal(engine.decide('social.test', '192.168.1.50').category, 'social');
  assert.equal(engine.decide('social.test', '192.168.1.51').blocked, false);
  assert.equal(engine.decide('adult.test', '192.168.1.60').blocked, false);   // exempt
  assert.equal(engine.decide('adult.test', '192.168.1.61').category, 'porn');
  assert.equal(engine.decide('evil.test', '192.168.1.60').category, 'malware'); // essential can't be exempted
  assert.equal(engine.decide('social.test', '192.168.1.70', at(0, 22, 30)).category, 'social');
  assert.equal(engine.decide('social.test', '192.168.1.70', at(0, 21, 0)).blocked, false);
  assert.equal(engine.decide('social.test', '::ffff:192.168.1.50').category, 'social');
  engine.pause(10);
  assert.equal(engine.decide('x.ads.example.com', '10.0.0.2').blocked, false);
  assert.equal(engine.decide('evil.test', '10.0.0.2').category, 'malware'); // essential survives pause
  engine.pause(0);
  assert.equal(engine.decide('x.ads.example.com', '10.0.0.2').category, 'ads');
});

test('admin validation', () => {
  assert.throws(() => admin.actions.whitelist({ add: 'bad domain' }), admin.BadRequest);
  assert.throws(() => admin.actions.devices({ devices: { 'not-an-ip': {} } }), admin.BadRequest);
  assert.throws(() => admin.actions.devices({ devices: { '1.2.3.4': { schedules: [{ days: [], start: '22:00', end: '06:00', categories: ['ads'] }] } } }), admin.BadRequest);
  assert.throws(() => admin.actions.source({ id: 'ads', add: 'http://example.com/x' }), admin.BadRequest);
  assert.throws(() => admin.actions.source({ id: 'ads', add: 'https://127.0.0.1/x' }), admin.BadRequest);
  assert.throws(() => admin.actions['category-delete']({ id: 'ads' }), admin.BadRequest);
  assert.throws(() => admin.actions.pause({ minutes: -5 }), admin.BadRequest);
  admin.actions['category-create']({ id: 'games', label: 'Game' });
  admin.actions['category-domains']({ id: 'games', add: 'game.test' });
  admin.actions.category({ id: 'games', enabled: true });
  assert.equal(engine.decide('x.game.test', '10.0.0.2').category, 'games');
  admin.actions['category-delete']({ id: 'games' });
  assert.equal(engine.decide('x.game.test', '10.0.0.2').blocked, false);
});

const req = (domain, type = 1) => ({ questions: [{ name: domain, type }] });

test('handleRequest: record types, passthrough, NXDOMAIN, beaconing, malware notify', async () => {
  const sent = [];
  notify._setTransport(async (url, body) => { sent.push({ url, body }); });
  admin.actions.notify({ telegramToken: '123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', telegramChatId: '42', events: ['malware', 'beacon'] });

  let r = await app.handleRequest(req('x.ads.example.com', 1), '10.0.0.9');
  assert.equal(r.answers[0].address, '0.0.0.0');
  r = await app.handleRequest(req('x.ads.example.com', 28), '10.0.0.9');
  assert.equal(r.answers[0].address, '::');
  r = await app.handleRequest(req('x.ads.example.com', 65), '10.0.0.9');
  assert.deepEqual(r.answers, []);
  r = await app.handleRequest(req('good.com', 28), '10.0.0.9');
  assert.equal(r.answers[0].type, 28);

  await app.handleRequest(req('evil.test'), '10.0.0.9');
  await app.handleRequest(req('evil.test'), '10.0.0.9'); // deduped
  await new Promise((r2) => setTimeout(r2, 20));
  assert.equal(sent.filter((s) => s.url.includes('api.telegram.org')).length, 1);
  assert.match(sent[0].body.text, /MÃ ĐỘC/);

  for (let i = 0; i < 20; i++) r = await app.handleRequest(req(`nx${i}.com`), '10.0.0.77');
  assert.equal(r.header.rcode, 3);
  await new Promise((r2) => setTimeout(r2, 20));
  assert.ok(sent.some((s) => /beaconing/.test(s.body.text)));
  notify._setTransport(null);
});

test('notify validation', () => {
  assert.equal(notify.validateDiscord('https://discord.com/api/webhooks/123/abc-DEF_1'), true);
  assert.equal(notify.validateDiscord('https://evil.com/api/webhooks/123/abc'), false);
  assert.equal(notify.validateTelegram('bad', '1'), false);
  assert.throws(() => admin.actions.notify({ discordWebhook: 'http://169.254.169.254/' }), admin.BadRequest);
});

test('stats persist to disk and reload', () => {
  stats.recordBlocked('ads', 'persist.test', '10.0.0.3');
  stats.flush();
  const file = JSON.parse(fs.readFileSync(path.join(DATA, 'stats.json'), 'utf8'));
  assert.equal(file.days[stats.dayKey()].top['persist.test'], 1);
  const snap = stats.snapshot();
  assert.ok(snap.history.length >= 1 && snap.clients.some((c) => c.ip === '10.0.0.3'));
});

function call(port, method, p, { body, auth, headers } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const r = http.request({ port, method, path: p, host: '127.0.0.1', headers: {
      ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
      ...(auth ? { Authorization: 'Basic ' + Buffer.from(auth).toString('base64') } : {}), ...headers } }, (res) => {
      let b = ''; res.on('data', (c) => (b += c)); res.on('end', () => resolve({ status: res.statusCode, body: b, headers: res.headers }));
    });
    r.on('error', reject); r.end(data);
  });
}

test('dashboard HTTP: auth, CSRF header, actions, secret masking', async () => {
  const { startDashboard } = require(path.join(root, 'dashboard'));
  const server = startDashboard(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const port = server.address().port;
  const H = { 'X-Requested-With': 'adblock-dashboard' };
  try {
    assert.equal((await call(port, 'GET', '/api/state')).status, 401); // password set => view needs it
    assert.equal((await call(port, 'GET', '/api/state', { auth: 'admin:secret123' })).status, 200);
    assert.equal((await call(port, 'POST', '/api/whitelist', { body: { add: 'a.com' }, headers: H })).status, 401);
    assert.equal((await call(port, 'POST', '/api/whitelist', { body: { add: 'a.com' }, auth: 'admin:wrong', headers: H })).status, 401);
    assert.equal((await call(port, 'POST', '/api/whitelist', { body: { add: 'a.com' }, auth: 'admin:secret123' })).status, 403); // no CSRF header
    const ok = await call(port, 'POST', '/api/whitelist', { body: { add: 'a.com' }, auth: 'admin:secret123', headers: H });
    assert.equal(ok.status, 200);
    assert.equal((await call(port, 'POST', '/api/whitelist', { body: { add: 'bad domain' }, auth: 'admin:secret123', headers: H })).status, 400);
    assert.equal((await call(port, 'POST', '/api/constructor', { body: {}, auth: 'admin:secret123', headers: H })).status, 404);
    const st = JSON.parse((await call(port, 'GET', '/api/state', { auth: 'admin:secret123' })).body);
    assert.ok(st.whitelist.includes('a.com'));
    assert.ok(!JSON.stringify(st).includes('AAAAAAAAAAAAAAAA')); // token masked
    const page = await call(port, 'GET', '/', { auth: 'admin:secret123' });
    assert.match(page.body, /Adblock DNS/);
    assert.match(page.headers['content-security-policy'], /default-src 'none'/);
  } finally { server.close(); }
});

test('DoH server answers GET and POST (self-signed cert)', async (t) => {
  try { execSync('openssl version', { stdio: 'ignore' }); } catch { return t.skip('openssl not available'); }
  const certDir = path.join(DATA, 'certs');
  fs.mkdirSync(certDir, { recursive: true });
  execSync(`openssl req -x509 -newkey rsa:2048 -nodes -keyout ${certDir}/key.pem -out ${certDir}/cert.pem -days 1 -subj /CN=localhost`, { stdio: 'ignore' });
  const secure = require(path.join(root, 'secure-servers'));
  const { Packet } = require(path.join(__dirname, 'stub-dns2.js'));
  const s = secure.start(app.handleRequest, Packet, '127.0.0.1');
  await new Promise((r) => s.doh.once('listening', r));
  const port = s.doh.address().port;
  const ask = (method, p, body) => new Promise((resolve, reject) => {
    const r = https.request({ port, host: '127.0.0.1', method, path: p, rejectUnauthorized: false, headers: body ? { 'Content-Type': 'application/dns-message' } : {} }, (res) => {
      let b = ''; res.on('data', (c) => (b += c)); res.on('end', () => resolve({ status: res.statusCode, body: b }));
    });
    r.on('error', reject); r.end(body);
  });
  try {
    const q = JSON.stringify({ questions: [{ name: 'x.ads.example.com', type: 1 }] });
    const post = await ask('POST', '/dns-query', q);
    assert.equal(post.status, 200);
    assert.equal(JSON.parse(post.body).answers[0].address, '0.0.0.0');
    const get = await ask('GET', '/dns-query?dns=' + Buffer.from(q).toString('base64url'));
    assert.equal(JSON.parse(get.body).answers[0].address, '0.0.0.0');
    assert.equal((await ask('GET', '/other')).status, 404);
    assert.equal((await ask('GET', '/dns-query')).status, 400);
  } finally { s.doh.close(); s.dot.close(); }
});

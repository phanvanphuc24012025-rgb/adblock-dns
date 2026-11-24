// DNS ad/malware blocker with per-device rules, schedules, dashboard,
// notifications, and optional DNS-over-TLS / DNS-over-HTTPS.
//
// Settings live in data/config.json (edited from the dashboard); only ports
// and bind addresses are constants below.

const fs = require('fs');
const path = require('path');
const dns2 = require('dns2');
const { Packet } = dns2;

const config = require('./config');
const lists = require('./lists');
const engine = require('./engine');
const stats = require('./stats');
const dga = require('./dga-detector');
const { notify } = require('./notify');

const ALERT_LOG_PATH = path.join(__dirname, 'security-alerts.log');
const LISTEN_PORT = 53;
const LISTEN_ADDR = '0.0.0.0';
const DASHBOARD_PORT = 8053;
const DASHBOARD_ADDR = '0.0.0.0';

const CACHE_TTL_MS = 5 * 60 * 1000;
const CACHE_MAX_ENTRIES = 5000;
// Beaconing: one device failing this many distinct lookups within the window.
const BEACON_FAIL_THRESHOLD = 20;
const BEACON_WINDOW_MS = 60 * 1000;
const ALERT_COOLDOWN_MS = 10 * 60 * 1000;

config.load();

const cache = new Map(); // `${name}:${type}` -> { answers, expires }
const clientFailures = new Map(); // ip -> { domains:Set, windowStart, alerted }
const recentAlerts = new Map(); // message -> last time logged

function logAlert(message, notifyType) {
  const now = Date.now();
  const last = recentAlerts.get(message);
  if (last && now - last < ALERT_COOLDOWN_MS) return;
  recentAlerts.set(message, now);
  if (recentAlerts.size > 2000) {
    for (const [k, t] of recentAlerts) if (now - t > ALERT_COOLDOWN_MS) recentAlerts.delete(k);
  }
  const line = `[${new Date(now).toISOString()}] ${message}`;
  console.warn(line);
  fs.appendFile(ALERT_LOG_PATH, line + '\n', () => {});
  if (notifyType) notify(notifyType, message);
}

function deviceLabel(ip) {
  const dev = config.get().devices[ip];
  return dev && dev.name ? `${dev.name} (${ip})` : ip;
}

function recordFailure(clientIp, name) {
  const now = Date.now();
  let entry = clientFailures.get(clientIp);
  if (!entry || now - entry.windowStart > BEACON_WINDOW_MS) {
    entry = { domains: new Set(), windowStart: now, alerted: false };
    clientFailures.set(clientIp, entry);
  }
  entry.domains.add(name.toLowerCase());
  if (!entry.alerted && entry.domains.size >= BEACON_FAIL_THRESHOLD) {
    entry.alerted = true;
    logAlert(
      `Nghi ngờ mã độc beaconing: ${deviceLabel(clientIp)} tra cứu thất bại ${BEACON_FAIL_THRESHOLD}+ domain khác nhau trong chưa đầy 1 phút`,
      'beacon'
    );
    stats.recordBeaconAlert(clientIp);
  }
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of clientFailures) if (now - e.windowStart > BEACON_WINDOW_MS) clientFailures.delete(ip);
}, BEACON_WINDOW_MS).unref();

const TYPE_NAMES = {};
for (const [k, v] of Object.entries(Packet.TYPE)) TYPE_NAMES[v] = k;

// 0.0.0.0 for A, :: for AAAA, empty NOERROR for other record types.
function answerBlocked(response, name, type) {
  if (type === Packet.TYPE.A) {
    response.answers.push({ name, type, class: Packet.CLASS.IN, ttl: 300, address: '0.0.0.0' });
  } else if (type === Packet.TYPE.AAAA) {
    response.answers.push({ name, type, class: Packet.CLASS.IN, ttl: 300, address: '::' });
  }
}

function cacheSet(key, answers) {
  if (cache.size >= CACHE_MAX_ENTRIES) {
    const now = Date.now();
    for (const [k, v] of cache) if (v.expires <= now) cache.delete(k);
    if (cache.size >= CACHE_MAX_ENTRIES) cache.delete(cache.keys().next().value);
  }
  const ttls = answers.map((a) => a.ttl).filter((t) => Number.isFinite(t));
  const ttlMs = ttls.length ? Math.min(CACHE_TTL_MS, Math.max(30, Math.min(...ttls)) * 1000) : 60 * 1000;
  cache.set(key, { answers, expires: Date.now() + ttlMs });
}

let upstreamClient = null;
let upstreamKey = '';
function upstream() {
  const servers = config.get().upstream;
  const key = servers.join(',');
  if (key !== upstreamKey) {
    upstreamClient = new dns2({ nameServers: servers });
    upstreamKey = key;
  }
  return upstreamClient;
}

// Core resolver shared by UDP/TCP, DoT and DoH. Returns the response packet.
async function handleRequest(request, rawClientIp) {
  const response = Packet.createResponseFromRequest(request);
  const [question] = request.questions;
  if (!question) return response;
  const { name, type } = question;
  const clientIp = config.normalizeIp(rawClientIp) || 'unknown';

  const decision = engine.decide(name, clientIp);
  if (decision.blocked) {
    const cat = decision.category;
    stats.recordBlocked(cat, name, clientIp);
    if (cat === 'malware') {
      logAlert(`Chặn domain MÃ ĐỘC: ${name} (thiết bị ${deviceLabel(clientIp)})`, 'malware');
    } else if (cat === 'doh') {
      logAlert(`Chặn DoH endpoint: ${name} (thiết bị ${deviceLabel(clientIp)})`);
    } else {
      console.log(`BLOCKED [${cat}]  ${name}`);
    }
    answerBlocked(response, name, type);
    return response;
  }

  const dgaResult = dga.analyze(name);
  if (dgaResult.suspicious) {
    logAlert(
      `Domain nghi vấn (giống DGA): ${name} (thiết bị ${deviceLabel(clientIp)}, ${dgaResult.reasons.join(', ')})`,
      'dga'
    );
    stats.recordSuspiciousDga(name, clientIp);
    if (config.get().blockSuspectedDga) {
      stats.recordBlocked('dga', name, clientIp);
      answerBlocked(response, name, type);
      return response;
    }
  }

  const cacheKey = `${name.toLowerCase()}:${type}`;
  const cached = cache.get(cacheKey);
  if (cached && cached.expires > Date.now()) {
    response.answers = cached.answers;
    stats.recordAllowed(name, clientIp);
    return response;
  }

  try {
    const typeName = TYPE_NAMES[type];
    const client = upstream();
    const result = typeName ? await client.resolve(name, typeName) : await client.resolveA(name);
    response.answers = result.answers || [];
    if (result.header && result.header.rcode) {
      response.header.rcode = result.header.rcode; // pass NXDOMAIN etc. through
      recordFailure(clientIp, name);
    } else {
      cacheSet(cacheKey, response.answers);
    }
    stats.recordAllowed(name, clientIp);
    console.log(`ALLOWED  ${name}`);
  } catch (err) {
    console.error(`Failed to resolve ${name}: ${err.message}`);
    recordFailure(clientIp, name);
    response.header.rcode = 2; // SERVFAIL
  }
  return response;
}

function onListsChanged() {
  engine.reloadLists();
  const sizes = engine.listSizes();
  console.log('Danh sách đã nạp:', Object.entries(sizes).map(([k, v]) => `${k}=${v}`).join(', '));
}

function main() {
  const { startDashboard } = require('./dashboard');
  const { startScheduler } = require('./scheduler');
  const secure = require('./secure-servers');

  stats.start();
  onListsChanged();
  config.onChange(() => cache.clear()); // upstream servers may have changed

  const server = dns2.createServer({
    udp: true,
    tcp: true,
    handle: async (request, send, rinfo) => {
      try {
        send(await handleRequest(request, rinfo && rinfo.address));
      } catch (err) {
        console.error('Handler error:', err.message);
      }
    }
  });
  server.on('error', (err) => console.error('DNS server error:', err.message));
  server.on('requestError', (err) => console.error('Bad DNS request:', err.message));
  process.on('unhandledRejection', (err) => console.error('Unhandled rejection:', err));

  Promise.resolve(server.listen({
    udp: { port: LISTEN_PORT, address: LISTEN_ADDR },
    tcp: { port: LISTEN_PORT, address: LISTEN_ADDR }
  })).catch((err) => {
    if (err && err.code === 'EACCES') console.error('Không mở được port 53: hãy chạy bằng quyền Administrator.');
    else if (err && err.code === 'EADDRINUSE') console.error('Port 53 đang được dùng (dịch vụ DNS khác, hoặc đang chạy 2 bản).');
    else console.error('Không khởi động được DNS server:', err);
    process.exit(1);
  });
  console.log(`DNS ad-blocker listening on ${LISTEN_ADDR}:${LISTEN_PORT} (UDP+TCP)`);

  secure.start(handleRequest, Packet, LISTEN_ADDR);
  startDashboard(DASHBOARD_PORT, DASHBOARD_ADDR);

  // Reload when list files are refreshed by something else.
  const watch = () => {
    for (const id of Object.keys(config.get().categories)) {
      fs.watchFile(lists.listPath(id), { interval: 30000 }, (cur, prev) => {
        if (cur.mtimeMs !== prev.mtimeMs) onListsChanged();
      });
    }
  };
  watch();

  // First run: download any category that has sources but no file yet.
  const missing = Object.entries(config.get().categories)
    .filter(([id, c]) => c.enabled && lists.needsDownload(id, c)).map(([id]) => id);
  if (missing.length) {
    console.log(`Lần đầu chạy: đang tải danh sách (${missing.join(', ')})...`);
    lists.updateAll(missing).then(onListsChanged);
  }

  startScheduler(config.get().autoUpdateHours, onListsChanged);
}

module.exports = { handleRequest, answerBlocked };

if (require.main === module) main();

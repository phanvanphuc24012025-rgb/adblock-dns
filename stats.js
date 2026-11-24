// Live counters + per-day history. History is saved to data/stats.json so it
// survives restarts (kept 90 days).

const fs = require('fs');
const path = require('path');
const config = require('./config');

const STATS_PATH = path.join(config.DATA_DIR, 'stats.json');
const MAX_RECENT = 200;
const MAX_TOP_DOMAINS = 15;
const MAX_TOP_PER_DAY = 500;
const KEEP_DAYS = 90;

const live = {
  startedAt: Date.now(),
  suspiciousDga: 0,
  beaconAlerts: 0,
  recentEvents: [] // { time, type, domain, client }
};
let days = {}; // 'YYYY-MM-DD' -> { queries, allowed, blocked:{cat:n}, top:{domain:n}, clients:{ip:{q,b}} }
let dirty = false;

function dayKey(d = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function today() {
  const k = dayKey();
  if (!days[k]) days[k] = { queries: 0, allowed: 0, blocked: {}, top: {}, clients: {} };
  return days[k];
}

function client(day, ip) {
  if (!day.clients[ip]) day.clients[ip] = { q: 0, b: 0 };
  return day.clients[ip];
}

function pushEvent(type, domain, ip) {
  live.recentEvents.unshift({ time: Date.now(), type, domain, client: ip });
  if (live.recentEvents.length > MAX_RECENT) live.recentEvents.pop();
}

function load() {
  try {
    if (fs.existsSync(STATS_PATH)) days = JSON.parse(fs.readFileSync(STATS_PATH, 'utf8')).days || {};
  } catch (err) {
    console.error(`Could not read stats.json (${err.message}); starting fresh.`);
    days = {};
  }
}

function prune() {
  const keys = Object.keys(days).sort();
  while (keys.length > KEEP_DAYS) delete days[keys.shift()];
  for (const d of Object.values(days)) {
    const entries = Object.entries(d.top);
    if (entries.length > MAX_TOP_PER_DAY) {
      d.top = Object.fromEntries(entries.sort((a, b) => b[1] - a[1]).slice(0, MAX_TOP_PER_DAY));
    }
  }
}

function flush() {
  if (!dirty) return;
  try {
    prune();
    fs.mkdirSync(config.DATA_DIR, { recursive: true });
    const tmp = STATS_PATH + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ days }), 'utf8');
    fs.renameSync(tmp, STATS_PATH);
    dirty = false;
  } catch (err) {
    console.error(`Could not save stats: ${err.message}`);
  }
}

function start() {
  load();
  setInterval(flush, 60 * 1000).unref();
  process.on('exit', flush);
}

const sum = (o) => Object.values(o).reduce((a, b) => a + b, 0);

const stats = {
  start, flush, dayKey,
  recordAllowed(domain, ip) {
    const d = today();
    d.queries += 1; d.allowed += 1;
    client(d, ip).q += 1;
    dirty = true;
  },
  recordBlocked(category, domain, ip) {
    const d = today();
    d.queries += 1;
    d.blocked[category] = (d.blocked[category] || 0) + 1;
    d.top[domain] = (d.top[domain] || 0) + 1;
    const c = client(d, ip);
    c.q += 1; c.b += 1;
    dirty = true;
    pushEvent(category, domain, ip);
  },
  recordSuspiciousDga(domain, ip) {
    live.suspiciousDga += 1;
    pushEvent('dga', domain, ip);
  },
  recordBeaconAlert(ip) {
    live.beaconAlerts += 1;
    pushEvent('beacon', '(nhiều domain lỗi)', ip);
  },
  snapshot() {
    const t = today();
    const topBlocked = Object.entries(t.top)
      .sort((a, b) => b[1] - a[1]).slice(0, MAX_TOP_DOMAINS)
      .map(([domain, count]) => ({ domain, count }));
    const history = Object.keys(days).sort().slice(-7).map((date) => ({
      date, queries: days[date].queries, blocked: sum(days[date].blocked)
    }));
    return {
      startedAt: live.startedAt,
      uptimeSeconds: Math.floor((Date.now() - live.startedAt) / 1000),
      today: { date: dayKey(), queries: t.queries, allowed: t.allowed, blocked: t.blocked },
      suspiciousDga: live.suspiciousDga,
      beaconAlerts: live.beaconAlerts,
      clients: Object.entries(t.clients)
        .map(([ip, v]) => ({ ip, queries: v.q, blocked: v.b }))
        .sort((a, b) => b.queries - a.queries).slice(0, 20),
      topBlocked,
      history,
      recentEvents: live.recentEvents.slice(0, 50)
    };
  }
};

module.exports = stats;

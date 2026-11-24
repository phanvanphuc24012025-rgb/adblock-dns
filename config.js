// Central configuration, stored as JSON in data/config.json so the dashboard
// can edit it. Missing keys fall back to DEFAULTS, so upgrading is safe.

const fs = require('fs');
const path = require('path');
const net = require('net');

const DATA_DIR = process.env.ADBLOCK_DATA_DIR || path.join(__dirname, 'data');
const CONFIG_PATH = path.join(DATA_DIR, 'config.json');

const SB = 'https://raw.githubusercontent.com/StevenBlack/hosts/master';
const DEFAULTS = {
  upstream: ['1.1.1.1', '8.8.8.8'],
  autoUpdateHours: 24,
  // If true, domains that look DGA-generated are blocked, not just logged.
  blockSuspectedDga: false,
  // essential categories ignore "pause" and device exemptions.
  categories: {
    ads: {
      label: 'Quảng cáo & tracker', enabled: true, minExpected: 10000,
      sources: [`${SB}/hosts`], domains: []
    },
    malware: {
      label: 'Mã độc / phishing', enabled: true, essential: true, minExpected: 10,
      sources: ['https://urlhaus.abuse.ch/downloads/hostfile/'], domains: []
    },
    doh: {
      label: 'DNS-over-HTTPS (né lọc)', enabled: true, essential: true,
      file: 'doh-blocklist.txt', sources: [], domains: []
    },
    gambling: {
      label: 'Cờ bạc', enabled: true, minExpected: 50,
      sources: [`${SB}/alternates/gambling-only/hosts`], domains: []
    },
    porn: {
      label: 'Web 18+', enabled: true, minExpected: 1000,
      sources: [`${SB}/alternates/porn-only/hosts`], domains: []
    },
    social: {
      label: 'Mạng xã hội', enabled: false, minExpected: 20,
      sources: [`${SB}/alternates/social-only/hosts`], domains: []
    }
  },
  whitelist: [],
  blacklist: [],
  // Per-device rules, keyed by the device's LAN IP:
  // { "192.168.1.50": { name, always: [cat], exempt: [cat], schedules: [Schedule] } }
  devices: {},
  // Schedule: { days:[0-6 (0=Sunday)], start:"22:00", end:"06:00", categories:[cat] }
  globalSchedules: [],
  notify: {
    events: ['malware', 'beacon'],
    telegram: { token: '', chatId: '' },
    discord: { webhook: '' }
  },
  secure: {
    dot: { port: 853 },
    doh: { port: 8443, path: '/dns-query' }
  }
};

let cfg = null;
const listeners = new Set();

const clone = (o) => JSON.parse(JSON.stringify(o));
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);

function deepMerge(base, over) {
  if (!isObj(base) || !isObj(over)) return over === undefined ? clone(base) : over;
  const out = clone(base);
  for (const [k, v] of Object.entries(over)) {
    out[k] = isObj(v) && isObj(out[k]) ? deepMerge(out[k], v) : v;
  }
  return out;
}

function load() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  let saved = {};
  if (fs.existsSync(CONFIG_PATH)) {
    try {
      saved = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    } catch (err) {
      const bak = CONFIG_PATH + '.broken-' + Date.now();
      fs.copyFileSync(CONFIG_PATH, bak);
      console.error(`config.json is invalid (${err.message}); backed up to ${bak}, using defaults.`);
    }
  }
  cfg = deepMerge(DEFAULTS, saved);
  return cfg;
}

function save() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = CONFIG_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2), 'utf8');
  fs.renameSync(tmp, CONFIG_PATH);
}

function get() {
  if (!cfg) load();
  return cfg;
}

// Mutate through update() so the file is saved and listeners are told.
function update(mutator) {
  mutator(get());
  save();
  for (const fn of listeners) fn(cfg);
}

function onChange(fn) {
  listeners.add(fn);
}

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/;

// Accepts "Example.com", "https://example.com/path", "*.example.com"; returns
// a clean lowercase domain or null when invalid.
function normalizeDomain(input) {
  if (typeof input !== 'string') return null;
  let d = input.trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/[/?#].*$/, '');
  d = d.replace(/^\*\./, '').replace(/^\./, '').replace(/\.$/, '');
  return DOMAIN_RE.test(d) ? d : null;
}

function isValidIp(ip) {
  return typeof ip === 'string' && net.isIP(ip) !== 0;
}

// Strips IPv6-mapped prefix so "::ffff:192.168.1.5" equals "192.168.1.5".
function normalizeIp(ip) {
  return typeof ip === 'string' ? ip.replace(/^::ffff:/i, '') : ip;
}

module.exports = {
  DATA_DIR, CONFIG_PATH, DEFAULTS,
  load, get, save, update, onChange,
  normalizeDomain, isValidIp, normalizeIp
};

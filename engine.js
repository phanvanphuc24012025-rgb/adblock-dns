// Decides whether a DNS name is blocked for a given device right now.
// Inputs: category lists, global whitelist/blacklist, per-device rules,
// schedules, and the temporary "pause" switch.

const fs = require('fs');
const path = require('path');
const config = require('./config');
const lists = require('./lists');

const LEGACY_WHITELIST = path.join(__dirname, 'whitelist.txt');

let fileSets = new Map();   // category id -> Set from list files
let inlineSets = new Map(); // category id -> Set of manually added domains
let whitelist = new Set();
let blacklist = new Set();
let pausedUntil = 0;

function toSet(arr) {
  return new Set((arr || []).map((d) => String(d).toLowerCase()));
}

// Rebuilds the small, config-derived sets (cheap; called on every change).
function rebuildPolicy() {
  const cfg = config.get();
  whitelist = toSet(cfg.whitelist);
  if (fs.existsSync(LEGACY_WHITELIST)) {
    for (const line of fs.readFileSync(LEGACY_WHITELIST, 'utf8').split(/\r?\n/)) {
      const t = line.split('#')[0].trim().toLowerCase();
      if (t) whitelist.add(t);
    }
  }
  blacklist = toSet(cfg.blacklist);
  inlineSets = new Map();
  for (const [id, cat] of Object.entries(cfg.categories)) {
    if (cat.domains && cat.domains.length) inlineSets.set(id, toSet(cat.domains));
  }
}

// Re-reads list files from disk (slow for big lists; call when files change).
function reloadLists() {
  const cfg = config.get();
  fileSets = new Map();
  for (const [id, cat] of Object.entries(cfg.categories)) {
    fileSets.set(id, lists.loadFileSet(id, cat));
  }
  rebuildPolicy();
}

function listSizes() {
  const out = {};
  for (const id of Object.keys(config.get().categories)) {
    out[id] = (fileSets.get(id) || new Set()).size + (inlineSets.get(id) || new Set()).size;
  }
  return out;
}

// Checks the name and every parent domain ("a.b.com" -> "b.com" -> "com").
function matches(domain, set) {
  if (!set || set.size === 0) return false;
  const parts = domain.toLowerCase().replace(/\.$/, '').split('.');
  for (let i = 0; i < parts.length; i++) {
    if (set.has(parts.slice(i).join('.'))) return true;
  }
  return false;
}

function toMinutes(hhmm) {
  const m = /^(\d{1,2}):(\d{2})$/.exec(hhmm || '');
  if (!m) return null;
  const h = +m[1], min = +m[2];
  return h > 23 || min > 59 ? null : h * 60 + min;
}

// True if `now` falls inside the schedule's window. Overnight windows
// (start > end, e.g. 22:00-06:00) belong to the day they start on.
function scheduleActive(sch, now) {
  const start = toMinutes(sch.start), end = toMinutes(sch.end);
  if (start === null || end === null || !Array.isArray(sch.days)) return false;
  const day = now.getDay();
  const mins = now.getHours() * 60 + now.getMinutes();
  if (start === end) return sch.days.includes(day); // whole day
  if (start < end) return sch.days.includes(day) && mins >= start && mins < end;
  if (mins >= start) return sch.days.includes(day);
  return sch.days.includes((day + 6) % 7) && mins < end;
}

function pause(minutes) {
  pausedUntil = minutes > 0 ? Date.now() + minutes * 60 * 1000 : 0;
  return pausedUntil;
}

function pausedUntilTs() {
  if (pausedUntil && pausedUntil <= Date.now()) pausedUntil = 0;
  return pausedUntil;
}

// Categories that apply to this device at this moment.
function activeCategories(clientIp, now = new Date()) {
  const cfg = config.get();
  const ids = new Set();
  for (const [id, cat] of Object.entries(cfg.categories)) if (cat.enabled) ids.add(id);

  const addSchedules = (schedules) => {
    for (const sch of schedules || []) {
      if (scheduleActive(sch, now)) for (const c of sch.categories || []) ids.add(c);
    }
  };
  addSchedules(cfg.globalSchedules);

  const dev = cfg.devices[config.normalizeIp(clientIp)];
  if (dev) {
    for (const c of dev.always || []) ids.add(c);
    addSchedules(dev.schedules);
    for (const c of dev.exempt || []) {
      if (!(cfg.categories[c] && cfg.categories[c].essential)) ids.delete(c);
    }
  }
  if (pausedUntilTs()) {
    for (const id of [...ids]) if (!(cfg.categories[id] && cfg.categories[id].essential)) ids.delete(id);
  }
  // Only categories that exist.
  return [...ids].filter((id) => cfg.categories[id]);
}

// Returns { blocked:false } or { blocked:true, category }.
function decide(domain, clientIp, now = new Date()) {
  if (matches(domain, whitelist)) return { blocked: false };
  if (matches(domain, blacklist)) return { blocked: true, category: 'custom' };
  const cfg = config.get();
  // Essential categories first so malware is reported as malware.
  const ids = activeCategories(clientIp, now).sort(
    (a, b) => Number(!!cfg.categories[b].essential) - Number(!!cfg.categories[a].essential)
  );
  for (const id of ids) {
    if (matches(domain, fileSets.get(id)) || matches(domain, inlineSets.get(id))) {
      return { blocked: true, category: id };
    }
  }
  return { blocked: false };
}

module.exports = {
  reloadLists, rebuildPolicy, listSizes, decide, activeCategories,
  scheduleActive, pause, pausedUntil: pausedUntilTs, matches
};

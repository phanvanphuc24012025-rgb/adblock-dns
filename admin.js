// All dashboard write actions live here (validated, saved, applied). The HTTP
// layer in dashboard.js only routes requests to these functions.

const config = require('./config');
const engine = require('./engine');
const lists = require('./lists');
const notify = require('./notify');
const net = require('net');

class BadRequest extends Error {}
const bad = (msg) => { throw new BadRequest(msg); };

const MAX_ENTRIES = 5000;

function domainOrBad(d) {
  const n = config.normalizeDomain(d);
  return n || bad(`Domain không hợp lệ: ${String(d).slice(0, 80)}`);
}

function listAction(key, { add, remove }) {
  config.update((cfg) => {
    if (add !== undefined) {
      const d = domainOrBad(add);
      if (!cfg[key].includes(d)) {
        if (cfg[key].length >= MAX_ENTRIES) bad('Danh sách quá dài');
        cfg[key].push(d);
      }
    }
    if (remove !== undefined) cfg[key] = cfg[key].filter((x) => x !== String(remove).toLowerCase());
  });
  engine.rebuildPolicy();
}

function setCategory({ id, enabled }) {
  const cat = config.get().categories[id];
  if (!cat) bad('Danh mục không tồn tại');
  config.update((cfg) => { cfg.categories[id].enabled = !!enabled; });
}

function createCategory({ id, label }) {
  if (!lists.validId(id)) bad('Mã danh mục chỉ gồm a-z, 0-9, - _ (tối đa 24 ký tự)');
  if (config.get().categories[id]) bad('Danh mục đã tồn tại');
  const clean = String(label || id).trim().slice(0, 40) || id;
  config.update((cfg) => {
    cfg.categories[id] = { label: clean, enabled: false, minExpected: 1, sources: [], domains: [] };
  });
}

function deleteCategory({ id }) {
  const cat = config.get().categories[id];
  if (!cat) bad('Danh mục không tồn tại');
  if (cat.essential || ['ads', 'malware', 'doh', 'gambling', 'porn', 'social'].includes(id)) {
    bad('Không xóa được danh mục có sẵn (chỉ tắt được)');
  }
  config.update((cfg) => {
    delete cfg.categories[id];
    for (const dev of Object.values(cfg.devices)) {
      for (const k of ['always', 'exempt']) dev[k] = (dev[k] || []).filter((c) => c !== id);
      dev.schedules = (dev.schedules || []).map((s) => ({ ...s, categories: s.categories.filter((c) => c !== id) }));
    }
  });
  engine.reloadLists();
}

function editSource({ id, add, remove }) {
  if (!config.get().categories[id]) bad('Danh mục không tồn tại');
  if (add !== undefined) {
    let u;
    try { u = new URL(add); } catch { bad('URL không hợp lệ'); }
    if (u.protocol !== 'https:') bad('Chỉ hỗ trợ nguồn https://');
    const host = u.hostname;
    if (host === 'localhost' || net.isIP(host) || !host.includes('.')) bad('Nguồn phải là tên miền công khai');
  }
  config.update((cfg) => {
    const cat = cfg.categories[id];
    if (add !== undefined && !cat.sources.includes(add)) {
      if (cat.sources.length >= 20) bad('Tối đa 20 nguồn mỗi danh mục');
      cat.sources.push(add);
    }
    if (remove !== undefined) cat.sources = cat.sources.filter((s) => s !== remove);
  });
}

function editCategoryDomains({ id, add, remove }) {
  if (!config.get().categories[id]) bad('Danh mục không tồn tại');
  config.update((cfg) => {
    const cat = cfg.categories[id];
    if (add !== undefined) {
      const d = domainOrBad(add);
      if (!cat.domains.includes(d)) cat.domains.push(d);
    }
    if (remove !== undefined) cat.domains = cat.domains.filter((x) => x !== remove);
  });
  engine.rebuildPolicy();
}

function validateSchedules(schedules, cats) {
  if (!Array.isArray(schedules) || schedules.length > 20) bad('Lịch không hợp lệ');
  return schedules.map((s) => {
    const days = Array.isArray(s.days) ? [...new Set(s.days.map(Number))].filter((d) => d >= 0 && d <= 6) : [];
    if (!days.length) bad('Mỗi lịch cần chọn ít nhất 1 ngày');
    const hhmm = /^([01]?\d|2[0-3]):[0-5]\d$/;
    if (!hhmm.test(s.start) || !hhmm.test(s.end)) bad('Giờ phải dạng HH:MM');
    const categories = (s.categories || []).filter((c) => cats[c]);
    if (!categories.length) bad('Mỗi lịch cần chọn ít nhất 1 danh mục');
    return { days, start: s.start, end: s.end, categories };
  });
}

function setDevices({ devices, globalSchedules }) {
  const cats = config.get().categories;
  const out = {};
  if (!devices || typeof devices !== 'object' || Array.isArray(devices)) bad('Dữ liệu thiết bị không hợp lệ');
  const entries = Object.entries(devices);
  if (entries.length > 200) bad('Tối đa 200 thiết bị');
  for (const [ip, d] of entries) {
    if (!config.isValidIp(ip)) bad(`IP không hợp lệ: ${ip.slice(0, 50)}`);
    out[config.normalizeIp(ip)] = {
      name: String(d.name || '').trim().slice(0, 40),
      always: (d.always || []).filter((c) => cats[c]),
      exempt: (d.exempt || []).filter((c) => cats[c]),
      schedules: validateSchedules(d.schedules || [], cats)
    };
  }
  const gs = globalSchedules === undefined ? undefined : validateSchedules(globalSchedules, cats);
  config.update((cfg) => {
    cfg.devices = out;
    if (gs !== undefined) cfg.globalSchedules = gs;
  });
}

function setPause({ minutes }) {
  const m = Number(minutes);
  if (!Number.isFinite(m) || m < 0 || m > 24 * 60) bad('Số phút phải từ 0 đến 1440');
  return { pausedUntil: engine.pause(m) };
}

function setNotify({ telegramToken, telegramChatId, discordWebhook, events }) {
  const n = config.get().notify;
  const token = telegramToken === undefined ? n.telegram.token : String(telegramToken).trim();
  const chat = telegramChatId === undefined ? n.telegram.chatId : String(telegramChatId).trim();
  const hook = discordWebhook === undefined ? n.discord.webhook : String(discordWebhook).trim();
  if ((token || chat) && !notify.validateTelegram(token, chat)) bad('Telegram token hoặc chat id không hợp lệ');
  if (hook && !notify.validateDiscord(hook)) bad('Discord webhook không hợp lệ');
  const allowed = ['malware', 'beacon', 'dga'];
  config.update((cfg) => {
    cfg.notify.telegram = { token, chatId: chat };
    cfg.notify.discord = { webhook: hook };
    if (Array.isArray(events)) cfg.notify.events = events.filter((e) => allowed.includes(e));
  });
}

async function testNotify() {
  return notify.test();
}

function updateLists() {
  if (lists.status.running) return { started: false, running: true };
  lists.updateAll().then(() => engine.reloadLists()).catch((e) => console.error(e));
  return { started: true };
}

const mask = (s) => (s ? s.slice(0, 4) + '…' + s.slice(-3) : '');

// State for the UI. Secrets are masked.
function getState() {
  const cfg = config.get();
  const sizes = engine.listSizes();
  const categories = {};
  for (const [id, c] of Object.entries(cfg.categories)) {
    categories[id] = {
      label: c.label, enabled: c.enabled, essential: !!c.essential,
      sources: c.sources, domains: c.domains, size: sizes[id] || 0
    };
  }
  return {
    categories,
    whitelist: cfg.whitelist,
    blacklist: cfg.blacklist,
    devices: cfg.devices,
    globalSchedules: cfg.globalSchedules,
    pausedUntil: engine.pausedUntil(),
    notify: {
      events: cfg.notify.events,
      telegram: { token: mask(cfg.notify.telegram.token), chatId: cfg.notify.telegram.chatId, set: !!cfg.notify.telegram.token },
      discord: { webhook: cfg.notify.discord.webhook ? mask(cfg.notify.discord.webhook) : '', set: !!cfg.notify.discord.webhook }
    },
    update: { running: lists.status.running, last: lists.status.last },
    now: Date.now()
  };
}

module.exports = {
  BadRequest, getState,
  actions: {
    whitelist: (b) => listAction('whitelist', b),
    blacklist: (b) => listAction('blacklist', b),
    category: setCategory,
    'category-create': createCategory,
    'category-delete': deleteCategory,
    source: editSource,
    'category-domains': editCategoryDomains,
    devices: setDevices,
    pause: setPause,
    notify: setNotify,
    'notify-test': testNotify,
    'update-lists': updateLists
  }
};

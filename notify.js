// Sends security alerts to Telegram and/or a Discord webhook.

const https = require('https');
const config = require('./config');

const MAX_PER_MINUTE = 10;
let sentTimes = [];

function postJson(urlStr, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = https.request(urlStr, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
    }, (res) => {
      res.resume();
      res.on('end', () => (res.statusCode < 300 ? resolve(res.statusCode) : reject(new Error(`HTTP ${res.statusCode}`))));
    });
    req.setTimeout(10000, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end(data);
  });
}

let transport = postJson; // swapped in tests

const TOKEN_RE = /^\d{5,}:[A-Za-z0-9_-]{20,}$/;
const DISCORD_RE = /^https:\/\/(discord(app)?\.com)\/api\/webhooks\/\d+\/[\w-]+$/;

function validateTelegram(token, chatId) {
  return TOKEN_RE.test(token) && /^-?\d+$|^@\w+$/.test(String(chatId));
}
function validateDiscord(url) {
  return DISCORD_RE.test(url);
}

function targets() {
  const n = config.get().notify;
  const out = [];
  if (n.telegram && n.telegram.token && n.telegram.chatId && validateTelegram(n.telegram.token, n.telegram.chatId)) {
    out.push({
      name: 'telegram',
      url: `https://api.telegram.org/bot${n.telegram.token}/sendMessage`,
      body: (text) => ({ chat_id: n.telegram.chatId, text })
    });
  }
  if (n.discord && n.discord.webhook && validateDiscord(n.discord.webhook)) {
    out.push({ name: 'discord', url: n.discord.webhook, body: (text) => ({ content: text }) });
  }
  return out;
}

async function deliver(text) {
  const results = {};
  for (const t of targets()) {
    try {
      await transport(t.url, t.body(text));
      results[t.name] = 'ok';
    } catch (err) {
      results[t.name] = `lỗi: ${err.message.replace(t.url, '[url]')}`;
      console.error(`[notify] ${t.name} failed: ${results[t.name]}`);
    }
  }
  return results;
}

// Fire-and-forget alert for an event type ('malware', 'beacon', ...).
function notify(type, text) {
  if (!config.get().notify.events.includes(type)) return;
  const now = Date.now();
  sentTimes = sentTimes.filter((t) => now - t < 60000);
  if (sentTimes.length >= MAX_PER_MINUTE) return;
  sentTimes.push(now);
  deliver(`🛡️ Adblock DNS: ${text}`).catch(() => {});
}

function test() {
  if (!targets().length) return Promise.resolve({ error: 'Chưa cấu hình Telegram/Discord hợp lệ' });
  return deliver('🛡️ Adblock DNS: tin nhắn thử — thông báo đã hoạt động.');
}

module.exports = {
  notify, test, validateTelegram, validateDiscord,
  _setTransport(fn) { transport = fn || postJson; }
};

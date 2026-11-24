// Dependency-free web dashboard.
//
// Security model:
//  - Viewing (/, /api/stats, /api/state) is open to the LAN unless
//    DASHBOARD_PASSWORD is set, in which case everything needs the password.
//  - Changing anything (POST /api/*) ALWAYS needs a password (HTTP Basic,
//    user "admin" or DASHBOARD_USER). If DASHBOARD_PASSWORD isn't set, a random
//    one is generated into data/dashboard-password.txt on first start.
//  - POSTs must be JSON with an X-Requested-With header, which blocks
//    cross-site request forgery from other web pages.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('./config');
const stats = require('./stats');
const admin = require('./admin');

const PAGE = fs.readFileSync(path.join(__dirname, 'dashboard.html'));
const PASSWORD_FILE = path.join(config.DATA_DIR, 'dashboard-password.txt');
const MAX_BODY = 256 * 1024;

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy':
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:"
};

function adminPassword() {
  if (process.env.DASHBOARD_PASSWORD) return process.env.DASHBOARD_PASSWORD;
  try {
    return fs.readFileSync(PASSWORD_FILE, 'utf8').trim();
  } catch {
    const pw = crypto.randomBytes(9).toString('base64url');
    fs.mkdirSync(config.DATA_DIR, { recursive: true });
    fs.writeFileSync(PASSWORD_FILE, pw + '\n', { mode: 0o600 });
    console.log(`Mật khẩu chỉnh sửa dashboard (user "admin"): ${pw}  (lưu trong ${PASSWORD_FILE})`);
    return pw;
  }
}

function passwordOk(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Basic ')) return false;
  const given = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const expected = Buffer.from(`${process.env.DASHBOARD_USER || 'admin'}:${adminPassword()}`);
  const a = Buffer.from(given);
  return a.length === expected.length && crypto.timingSafeEqual(a, expected);
}

function send(res, status, body, extra = {}) {
  const isJson = typeof body === 'object' && !Buffer.isBuffer(body);
  res.writeHead(status, {
    'Content-Type': isJson ? 'application/json' : 'text/html; charset=utf-8',
    'Cache-Control': 'no-store', ...SECURITY_HEADERS, ...extra
  });
  res.end(isJson ? JSON.stringify(body) : body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new admin.BadRequest('Dữ liệu quá lớn')); req.destroy(); } else chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(size ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch { reject(new admin.BadRequest('JSON không hợp lệ')); }
    });
    req.on('error', reject);
  });
}

async function handle(req, res) {
  const requireAll = !!process.env.DASHBOARD_PASSWORD;
  const url = (req.url || '/').split('?')[0];
  const challenge = { 'WWW-Authenticate': 'Basic realm="Adblock DNS"' };

  if (req.method === 'POST') {
    if (!url.startsWith('/api/')) return send(res, 404, { error: 'Not found' });
    if (!passwordOk(req)) return send(res, 401, { error: 'Cần đăng nhập để chỉnh sửa' }, challenge);
    if (req.headers['x-requested-with'] !== 'adblock-dashboard' ||
        !String(req.headers['content-type'] || '').startsWith('application/json')) {
      return send(res, 403, { error: 'Yêu cầu không hợp lệ' });
    }
    const action = admin.actions[url.slice(5)];
    if (!Object.prototype.hasOwnProperty.call(admin.actions, url.slice(5)) || !action) {
      return send(res, 404, { error: 'Không có hành động này' });
    }
    try {
      const out = await action(await readJson(req));
      return send(res, 200, out === undefined ? { ok: true } : out);
    } catch (err) {
      if (err instanceof admin.BadRequest) return send(res, 400, { error: err.message });
      console.error('Dashboard action failed:', err);
      return send(res, 500, { error: 'Lỗi server' });
    }
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'Method not allowed' });
  if (requireAll && !passwordOk(req)) return send(res, 401, 'Authentication required', challenge);

  if (url === '/api/stats') return send(res, 200, stats.snapshot());
  if (url === '/api/state') return send(res, 200, admin.getState());
  if (url === '/favicon.ico') { res.writeHead(204); return res.end(); }
  if (url === '/' || url === '/index.html') return send(res, 200, PAGE);
  return send(res, 404, { error: 'Not found' });
}

function startDashboard(port, address) {
  adminPassword(); // generate on first start so it is printed in the console
  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      console.error('Dashboard error:', err);
      if (!res.headersSent) send(res, 500, { error: 'Lỗi server' });
    });
  });
  server.on('error', (err) => console.error('Dashboard error:', err.message));
  server.listen(port, address, () => {
    console.log(`Dashboard: http://${address === '0.0.0.0' ? 'localhost' : address}:${port}`);
  });
  return server;
}

module.exports = { startDashboard, handle, adminPassword };

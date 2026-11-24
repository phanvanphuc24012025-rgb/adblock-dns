// Optional encrypted DNS front-ends so phones can use this server away from
// home: DNS-over-TLS (port 853) and DNS-over-HTTPS (port 8443, /dns-query).
// They start only if data/certs/cert.pem and data/certs/key.pem exist.
// A DNS name pointing at your home IP + a real certificate (e.g. Let's
// Encrypt) is required for phones to trust them.

const fs = require('fs');
const path = require('path');
const tls = require('tls');
const https = require('https');
const config = require('./config');

const CERT_DIR = path.join(config.DATA_DIR, 'certs');
const MAX_MSG = 4096;

function readCerts() {
  const cert = path.join(CERT_DIR, 'cert.pem');
  const key = path.join(CERT_DIR, 'key.pem');
  if (!fs.existsSync(cert) || !fs.existsSync(key)) return null;
  return { cert: fs.readFileSync(cert), key: fs.readFileSync(key) };
}

function startDot(handle, Packet, opts, port, address) {
  const server = tls.createServer(opts, (sock) => {
    const ip = config.normalizeIp(sock.remoteAddress);
    let buf = Buffer.alloc(0);
    sock.setTimeout(30000, () => sock.destroy());
    sock.on('error', () => {});
    sock.on('data', async (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length > 2 * (MAX_MSG + 2)) return sock.destroy();
      while (buf.length >= 2) {
        const len = buf.readUInt16BE(0);
        if (len === 0 || len > MAX_MSG) return sock.destroy();
        if (buf.length < 2 + len) break;
        const msg = buf.subarray(2, 2 + len);
        buf = buf.subarray(2 + len);
        try {
          const out = (await handle(Packet.parse(msg), ip)).toBuffer();
          const frame = Buffer.alloc(2 + out.length);
          frame.writeUInt16BE(out.length, 0);
          out.copy(frame, 2);
          if (!sock.destroyed) sock.write(frame);
        } catch (err) {
          console.error(`[DoT] bad query from ${ip}: ${err.message}`);
        }
      }
    });
  });
  server.on('error', (err) => console.error('[DoT] error:', err.message));
  server.listen(port, address, () => console.log(`DNS-over-TLS listening on ${address}:${port}`));
  return server;
}

function startDoh(handle, Packet, opts, port, address, urlPath) {
  const server = https.createServer(opts, (req, res) => {
    const ip = config.normalizeIp(req.socket.remoteAddress);
    const url = new URL(req.url, 'https://x');
    if (url.pathname !== urlPath) { res.writeHead(404); return res.end(); }
    const respond = async (msg) => {
      try {
        const out = (await handle(Packet.parse(msg), ip)).toBuffer();
        res.writeHead(200, { 'Content-Type': 'application/dns-message', 'Cache-Control': 'no-store' });
        res.end(out);
      } catch (err) {
        res.writeHead(400); res.end();
      }
    };
    if (req.method === 'GET') {
      const q = url.searchParams.get('dns');
      if (!q || q.length > MAX_MSG * 2) { res.writeHead(400); return res.end(); }
      return respond(Buffer.from(q, 'base64url'));
    }
    if (req.method === 'POST') {
      const chunks = []; let size = 0;
      req.on('data', (c) => {
        size += c.length;
        if (size > MAX_MSG) { res.writeHead(413); res.end(); req.destroy(); } else chunks.push(c);
      });
      return req.on('end', () => size <= MAX_MSG && respond(Buffer.concat(chunks)));
    }
    res.writeHead(405); res.end();
  });
  server.on('error', (err) => console.error('[DoH] error:', err.message));
  server.listen(port, address, () => console.log(`DNS-over-HTTPS listening on https://${address}:${port}${urlPath}`));
  return server;
}

function start(handle, Packet, address) {
  const certs = readCerts();
  if (!certs) {
    console.log(`DoT/DoH off (no certificate in ${CERT_DIR}). See README to enable.`);
    return null;
  }
  const { dot, doh } = config.get().secure;
  return {
    dot: startDot(handle, Packet, certs, dot.port, address),
    doh: startDoh(handle, Packet, certs, doh.port, address, doh.path)
  };
}

module.exports = { start, CERT_DIR };

// Shared helpers for downloading and parsing blocklists.

const https = require('https');
const fs = require('fs');

const TIMEOUT_MS = 60 * 1000;
const MAX_REDIRECTS = 5;
const MAX_BYTES = 80 * 1024 * 1024;

function download(url, headers = {}, redirects = 0) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        if (redirects >= MAX_REDIRECTS) return reject(new Error('Too many redirects'));
        const next = new URL(res.headers.location, url).toString();
        return download(next, headers, redirects + 1).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`Request failed (${res.statusCode}) for ${url}`));
      }
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_BYTES) return req.destroy(new Error(`Response too large: ${url}`));
        chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });
    req.setTimeout(TIMEOUT_MS, () => req.destroy(new Error(`Timeout after ${TIMEOUT_MS / 1000}s: ${url}`)));
    req.on('error', reject);
  });
}

const SKIP = new Set(['localhost', 'localhost.localdomain', 'local', 'broadcasthost',
  'ip6-localhost', 'ip6-loopback', 'ip6-allnodes', 'ip6-allrouters', '0.0.0.0']);
const DOMAIN_RE = /^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?\.[a-z0-9-]{2,63}$/;

function addDomain(set, raw) {
  const d = raw.toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
  if (!SKIP.has(d) && DOMAIN_RE.test(d)) set.add(d);
}

// Understands the common list formats:
//   hosts:    0.0.0.0 example.com
//   domains:  example.com   or   *.example.com
//   adblock:  ||example.com^
function parseDomains(text, into = new Set()) {
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line[0] === '#' || line[0] === '!' || line[0] === '[') continue;
    let m = line.match(/^\|\|([a-z0-9._-]+)\^(\$.*)?$/i);
    if (m) { addDomain(into, m[1]); continue; }
    const parts = line.split(/\s+/);
    if (parts[0] === '0.0.0.0' || parts[0] === '127.0.0.1') {
      for (const tok of parts.slice(1)) {
        if (tok[0] === '#') break;
        addDomain(into, tok);
      }
    } else if (parts.length === 1 || parts[1][0] === '#') {
      addDomain(into, parts[0]);
    }
  }
  return into;
}

// Writes atomically; refuses to replace a good list with a suspiciously
// small one (e.g. an error page parsed as 0 domains).
function saveList(outputPath, domains, minExpected) {
  if (domains.size < minExpected) {
    throw new Error(
      `Only ${domains.size} domains parsed (expected at least ${minExpected}); keeping the old list.`
    );
  }
  const sorted = Array.from(domains).sort();
  const tmp = outputPath + '.tmp';
  fs.writeFileSync(tmp, sorted.join('\n') + '\n', 'utf8');
  fs.renameSync(tmp, outputPath);
  return sorted.length;
}

module.exports = { download, parseDomains, parseHostsFile: parseDomains, saveList };

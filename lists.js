// Downloads and loads the per-category domain lists (data/lists/<id>.txt).

const fs = require('fs');
const path = require('path');
const config = require('./config');
const { download, parseDomains, saveList } = require('./list-utils');

const LISTS_DIR = path.join(config.DATA_DIR, 'lists');
const status = { running: false, last: null }; // last: { time, results }

function listPath(id) {
  return path.join(LISTS_DIR, `${id}.txt`);
}

function validId(id) {
  return typeof id === 'string' && /^[a-z0-9_-]{1,24}$/.test(id);
}

// Reads one category's file(s) into a Set (does not include inline domains).
function loadFileSet(id, cat) {
  const set = new Set();
  const files = [listPath(id)];
  if (cat.file) files.push(path.join(__dirname, cat.file));
  for (const f of files) {
    if (!fs.existsSync(f)) continue;
    try {
      for (const line of fs.readFileSync(f, 'utf8').split(/\r?\n/)) {
        const t = line.split('#')[0].trim().toLowerCase().replace(/\.$/, '');
        if (t) set.add(t);
      }
    } catch (err) {
      console.error(`Could not read ${f}: ${err.message}`);
    }
  }
  return set;
}

function needsDownload(id, cat) {
  return cat.sources.length > 0 && !fs.existsSync(listPath(id));
}

async function updateCategory(id) {
  const cat = config.get().categories[id];
  if (!cat) throw new Error(`Unknown category: ${id}`);
  if (!cat.sources.length) return 0;
  fs.mkdirSync(LISTS_DIR, { recursive: true });
  const headers = process.env.ABUSECH_AUTH_KEY && id === 'malware'
    ? { 'Auth-Key': process.env.ABUSECH_AUTH_KEY } : {};
  const domains = new Set();
  const errors = [];
  for (const url of cat.sources) {
    try {
      console.log(`[${id}] downloading ${url} ...`);
      parseDomains(await download(url, headers), domains);
    } catch (err) {
      errors.push(err.message);
      console.error(`[${id}] ${err.message}`);
    }
  }
  if (errors.length === cat.sources.length) throw new Error(errors.join('; '));
  const n = saveList(listPath(id), domains, cat.minExpected || 1);
  console.log(`[${id}] saved ${n} domains`);
  return n;
}

// Updates every category that has sources. One failure doesn't stop the rest.
async function updateAll(ids) {
  if (status.running) return status.last ? status.last.results : {};
  status.running = true;
  const results = {};
  try {
    const cats = config.get().categories;
    for (const id of ids || Object.keys(cats)) {
      if (!cats[id] || !cats[id].sources.length) continue;
      try {
        results[id] = { ok: true, count: await updateCategory(id) };
      } catch (err) {
        results[id] = { ok: false, error: err.message };
      }
    }
  } finally {
    status.running = false;
    status.last = { time: Date.now(), results };
  }
  return results;
}

module.exports = { LISTS_DIR, listPath, validId, loadFileSet, needsDownload, updateCategory, updateAll, status };

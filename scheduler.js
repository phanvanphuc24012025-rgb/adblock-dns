// Re-downloads all category lists on a timer, inside the DNS server process.
// A failed download is logged and retried next cycle; old lists stay in use.

const lists = require('./lists');

async function runUpdateCycle(onComplete) {
  console.log('[scheduler] Running scheduled blocklist update...');
  const results = await lists.updateAll();
  for (const [id, r] of Object.entries(results)) {
    if (!r.ok) console.error(`[scheduler] ${id} update failed: ${r.error}`);
  }
  console.log('[scheduler] Update cycle finished.');
  if (typeof onComplete === 'function') onComplete();
}

function startScheduler(intervalHours, onComplete) {
  if (!(intervalHours > 0)) return console.log('[scheduler] Auto-update disabled.');
  console.log(`[scheduler] Auto-update enabled: every ${intervalHours}h.`);
  setInterval(() => runUpdateCycle(onComplete), intervalHours * 60 * 60 * 1000).unref();
}

module.exports = { startScheduler, runUpdateCycle };

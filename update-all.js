// `npm run update-all` — refresh every category list that has sources.
const config = require('./config');
const lists = require('./lists');

config.load();
lists.updateAll().then((results) => {
  let failed = false;
  for (const [id, r] of Object.entries(results)) {
    if (r.ok) console.log(`OK    ${id}: ${r.count} domains`);
    else { failed = true; console.error(`FAIL  ${id}: ${r.error}`); }
  }
  process.exit(failed ? 1 : 0);
});

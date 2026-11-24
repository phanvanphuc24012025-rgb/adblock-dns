// Kept for compatibility: refreshes the "ads" category.
const config = require('./config');
const lists = require('./lists');

async function updateBlocklist() {
  config.load();
  return lists.updateCategory('ads');
}

module.exports = { updateBlocklist };

if (require.main === module) {
  updateBlocklist().catch((err) => {
    console.error('Failed:', err.message);
    process.exit(1);
  });
}

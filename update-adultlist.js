// Kept for compatibility: refreshes the "gambling" and "porn" categories.
const config = require('./config');
const lists = require('./lists');

async function updateAdultList() {
  config.load();
  return (await lists.updateCategory('gambling')) + (await lists.updateCategory('porn'));
}

module.exports = { updateAdultList };

if (require.main === module) {
  updateAdultList().catch((err) => {
    console.error('Failed:', err.message);
    process.exit(1);
  });
}

// Removes the "AdblockDNS" Windows Service installed by install-service.js.
// Run from an Administrator PowerShell: npm run uninstall-service

const path = require('path');
const { Service } = require('node-windows');

const svc = new Service({
  name: 'AdblockDNS',
  script: path.join(__dirname, 'index.js')
});

svc.on('uninstall', () => {
  console.log('Service uninstalled.');
});

svc.on('error', (err) => {
  console.error('Service error:', err);
});

console.log('Uninstalling "AdblockDNS" Windows Service...');
svc.uninstall();

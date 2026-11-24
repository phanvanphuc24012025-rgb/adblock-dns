// Installs this DNS ad-blocker as a real Windows Service using node-windows.
// A proper service is more reliable than a Task Scheduler entry: Windows
// restarts it automatically if it crashes, and it runs at boot before any
// user logs in.
//
// Run this once from an Administrator PowerShell:
//   npm run install-service
//
// To remove it later:
//   npm run uninstall-service

const path = require('path');
const { Service } = require('node-windows');

const svc = new Service({
  name: 'AdblockDNS',
  description: 'DNS-level ad and malware blocker for the home network.',
  script: path.join(__dirname, 'index.js')
});

svc.on('install', () => {
  console.log('Service installed. Starting it now...');
  svc.start();
});

svc.on('alreadyinstalled', () => {
  console.log('Service is already installed.');
});

svc.on('start', () => {
  console.log('Service started. It will now also start automatically on every boot.');
});

svc.on('error', (err) => {
  console.error('Service error:', err);
});

console.log('Installing "AdblockDNS" as a Windows Service (needs Administrator)...');
svc.install();

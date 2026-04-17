#!/usr/bin/env node

/**
 * Recon Web UI CLI
 *
 * Starts the web UI for recon-fuzzer.
 * Connects to the fuzzer's WebSocket server for real-time updates.
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

// Parse arguments
const args = process.argv.slice(2);
let wsPort = process.env.RECON_WS_PORT || '4444';
// UI port defaults to WS port + 1 (e.g., 4445 if WS is 4444)
let port = process.env.RECON_UI_PORT || process.env.PORT || String(parseInt(wsPort) + 1);

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--port' || arg === '-p') {
    port = args[++i];
  } else if (arg === '--ws-port') {
    wsPort = args[++i];
  } else if (arg === '--help' || arg === '-h') {
    console.log(`
Recon Web UI - Interactive fuzzer dashboard

Usage:
  npx recon-web-ui [options]

Options:
  --port, -p <port>    Port for the web UI (default: ws-port + 1, e.g., 4445)
  --ws-port <port>     WebSocket server port to connect to (default: 4444)
  --help, -h           Show this help message

Environment Variables:
  RECON_UI_PORT        Port for the web UI
  RECON_WS_PORT        WebSocket server port (set by recon fuzz --web)
  PORT                 Alternative port variable

Example:
  npx recon-web-ui
  npx recon-web-ui --ws-port 4444              # UI on 4445, WS on 4444
  npx recon-web-ui --port 3000 --ws-port 4444  # UI on 3000, WS on 4444
`);
    process.exit(0);
  }
}

// Set environment for Next.js
process.env.NEXT_PUBLIC_WS_PORT = wsPort;
process.env.PORT = port;

const packageDir = path.resolve(__dirname, '..');
const nextDir = path.join(packageDir, '.next');

console.log(`
╔═══════════════════════════════════════════════════════╗
║           Recon Web UI - Fuzzer Dashboard             ║
╚═══════════════════════════════════════════════════════╝

  UI:        http://localhost:${port}
  WebSocket: ws://localhost:${wsPort}/ws
`);

// Check if built
if (!fs.existsSync(nextDir)) {
  console.log('Building web UI for first run...');
  const buildResult = require('child_process').spawnSync('npm', ['run', 'build'], {
    cwd: packageDir,
    stdio: 'inherit',
    shell: true
  });
  if (buildResult.status !== 0) {
    console.error('Build failed. Try running: npm run build');
    process.exit(1);
  }
}

// Start the Next.js server
const nextBin = path.join(packageDir, 'node_modules', '.bin', 'next');
const child = spawn(nextBin, ['start', '-p', port], {
  cwd: packageDir,
  stdio: 'inherit',
  env: {
    ...process.env,
    PORT: port,
    NEXT_PUBLIC_WS_PORT: wsPort
  }
});

child.on('error', (err) => {
  console.error('Failed to start:', err.message);
  process.exit(1);
});

child.on('exit', (code) => {
  process.exit(code || 0);
});

// Handle Ctrl+C gracefully
process.on('SIGINT', () => {
  child.kill('SIGINT');
});

process.on('SIGTERM', () => {
  child.kill('SIGTERM');
});

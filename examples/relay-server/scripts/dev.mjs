#!/usr/bin/env node
import { spawn } from 'node:child_process';

function run(cmd, args, opts = {}) {
  const p = spawn(cmd, args, { stdio: 'inherit', ...opts });
  p.on('exit', (code) => {
    if (code !== 0) process.exit(code ?? 1);
  });
  return p;
}

// Default behavior: keep startup deterministic by avoiding concurrent SDK rebuilds while
// relay `node --watch` is running. This prevents transient ESM export mismatches mid-restart.
const watchSdk =
  String(process.env.RELAY_WATCH_SDK || '').trim() === '1' ||
  String(process.env.RELAY_WATCH_SDK || '').trim().toLowerCase() === 'true';
const sdk = watchSdk ? run('pnpm', ['-C', '../../sdk', 'dev']) : null;
if (!watchSdk) {
  console.log('[relay dev] SDK watch disabled (set RELAY_WATCH_SDK=1 to enable)');
}

// Start TypeScript compiler in watch mode
const tsc = run('pnpm', ['run', 'build:watch']);

// Once dist exists, start node with --watch; immediately starting is fine as --watch waits for changes
const node = run('node', ['--watch', 'dist/index.js']);

function shutdown() {
  try {
    sdk?.kill();
  } catch {}
  try {
    tsc.kill();
  } catch {}
  try {
    node.kill();
  } catch {}
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

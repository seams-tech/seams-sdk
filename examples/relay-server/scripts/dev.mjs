#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process';

function run(cmd, args, opts = {}) {
  const p = spawn(cmd, args, { stdio: 'inherit', ...opts });
  p.on('exit', (code) => {
    if (code !== 0) process.exit(code ?? 1);
  });
  return p;
}

function runSync(cmd, args, opts = {}) {
  const result = spawnSync(cmd, args, { stdio: 'inherit', ...opts });
  if ((result.status ?? 0) !== 0) process.exit(result.status ?? 1);
}

function ensureFreshSdkBuild() {
  const freshness = spawnSync('pnpm', ['-C', '../../sdk', 'run', 'build:check:server-runtime'], {
    stdio: 'inherit',
  });
  if (freshness.status === 0) return;
  runSync('pnpm', ['-C', '../../sdk', 'build:rolldown']);
}

ensureFreshSdkBuild();

// Keep the relay server runtime aligned with SDK router changes during local dev.
const sdk = run('pnpm', ['-C', '../../sdk', 'dev']);

// Start TypeScript compiler in watch mode
const tsc = run('pnpm', ['run', 'build:watch']);

// Once dist exists, start node with --watch; immediately starting is fine as --watch waits for changes
const node = run('node', ['--watch', 'dist/index.js']);

function shutdown() {
  try {
    sdk.kill();
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

#!/usr/bin/env node
import { spawn } from 'node:child_process';

function run(cmd, args, opts = {}) {
  const p = spawn(cmd, args, { stdio: 'inherit', ...opts });
  p.on('exit', (code) => {
    if (code !== 0) process.exit(code ?? 1);
  });
  return p;
}

function runOnce(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: 'inherit', ...opts });
    p.on('error', reject);
    p.on('exit', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${cmd} ${args.join(' ')} exited with code ${code ?? 'unknown'}`));
    });
  });
}

console.log('[relay dev] running initial TypeScript build');
await runOnce('pnpm', ['run', 'build']);

// Start TypeScript compiler in watch mode
const tsc = run('pnpm', ['run', 'build:watch']);

// Once dist exists, start node with --watch; immediately starting is fine as --watch waits for changes
const node = run('node', ['--watch', 'dist/index.js']);

function shutdown() {
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

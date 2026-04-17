#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { existsSync, utimesSync, watch } from 'node:fs';
import path from 'node:path';

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

const relayDistEntrypoint = path.resolve(process.cwd(), 'dist/index.js');
const sdkServerDistDir = path.resolve(process.cwd(), '../../sdk/dist/esm/server');
let relayRestartTouchTimer = null;
let sdkDistWatcher = null;

function touchRelayEntrypoint(reason) {
  if (relayRestartTouchTimer) clearTimeout(relayRestartTouchTimer);
  relayRestartTouchTimer = setTimeout(() => {
    relayRestartTouchTimer = null;
    if (!existsSync(relayDistEntrypoint)) return;
    const now = new Date();
    utimesSync(relayDistEntrypoint, now, now);
    console.log(`[relay dev] restarted relay after ${reason}`);
  }, 150);
}

if (existsSync(sdkServerDistDir)) {
  try {
    sdkDistWatcher = watch(sdkServerDistDir, { recursive: true }, (_eventType, filename) => {
      if (filename && !String(filename).endsWith('.js')) return;
      touchRelayEntrypoint('SDK server dist change');
    });
    console.log(`[relay dev] watching SDK server dist: ${sdkServerDistDir}`);
  } catch (error) {
    console.warn('[relay dev] unable to watch SDK server dist for relay restarts:', error);
  }
} else {
  console.log(`[relay dev] SDK server dist not found, skipping relay restart watcher: ${sdkServerDistDir}`);
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
  try {
    sdkDistWatcher?.close();
  } catch {}
  if (relayRestartTouchTimer) clearTimeout(relayRestartTouchTimer);
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

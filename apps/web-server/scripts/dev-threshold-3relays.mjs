#!/usr/bin/env node
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import dotenv from 'dotenv';

function run(cmd, args, opts = {}) {
  const p = spawn(cmd, args, { stdio: 'inherit', ...opts });
  p.on('exit', (code) => {
    if (code !== 0) process.exit(code ?? 1);
  });
  return p;
}

dotenv.config();

const coordinatorSharedSecretB64u =
  String(process.env.THRESHOLD_COORDINATOR_SHARED_SECRET_B64U || '').trim() ||
  crypto.randomBytes(32).toString('base64url');

// Default behavior: keep startup deterministic by avoiding concurrent SDK rebuilds while
// relay `node --watch` is running. This prevents transient ESM export mismatches mid-restart.
const watchSdk =
  String(process.env.RELAY_WATCH_SDK || '').trim() === '1' ||
  String(process.env.RELAY_WATCH_SDK || '')
    .trim()
    .toLowerCase() === 'true';
const sdk = watchSdk ? run('pnpm', ['-C', '../../packages/sdk-web', 'dev']) : null;
if (!watchSdk) {
  console.log('[relay dev] SDK watch disabled (set RELAY_WATCH_SDK=1 to enable)');
}

// Run TypeScript compiler in watch mode once.
const tsc = run('pnpm', ['run', 'build:watch']);

// Coordinator talks to cosigners over direct localhost HTTP to avoid TLS trust issues
// (Caddy still provides the browser-facing HTTPS origins).
const relayerCosignersJson = JSON.stringify([
  { cosignerId: 1, relayerUrl: 'http://127.0.0.1:3000' },
  { cosignerId: 2, relayerUrl: 'http://127.0.0.1:3001' },
  { cosignerId: 3, relayerUrl: 'http://127.0.0.1:3002' },
]);
const coordinatorPeersJson = JSON.stringify([
  { instanceId: 'coordinator-a', relayerUrl: 'https://localhost:9444' },
]);

const commonEnv = {
  ...process.env,
  THRESHOLD_COORDINATOR_SHARED_SECRET_B64U: coordinatorSharedSecretB64u,
  THRESHOLD_ED25519_RELAYER_COSIGNERS: relayerCosignersJson,
  THRESHOLD_ED25519_RELAYER_COSIGNER_T: '2',
};

const coordinator = run('node', ['--watch', 'dist/index.js'], {
  env: {
    ...commonEnv,
    PORT: '3000',
    THRESHOLD_NODE_ROLE: 'coordinator',
    THRESHOLD_COORDINATOR_INSTANCE_ID: 'coordinator-a',
    THRESHOLD_COORDINATOR_PEERS: coordinatorPeersJson,
    THRESHOLD_ED25519_SHARE_MODE: 'derived',
    THRESHOLD_ED25519_RELAYER_COSIGNER_ID: '1',
  },
});

const cosigner2 = run('node', ['--watch', 'dist/index.js'], {
  env: {
    ...commonEnv,
    PORT: '3001',
    THRESHOLD_NODE_ROLE: 'cosigner',
    THRESHOLD_COORDINATOR_INSTANCE_ID: '',
    THRESHOLD_COORDINATOR_PEERS: '',
    THRESHOLD_ED25519_RELAYER_COSIGNER_ID: '2',
    THRESHOLD_ED25519_SHARE_MODE: '',
  },
});

const cosigner3 = run('node', ['--watch', 'dist/index.js'], {
  env: {
    ...commonEnv,
    PORT: '3002',
    THRESHOLD_NODE_ROLE: 'cosigner',
    THRESHOLD_COORDINATOR_INSTANCE_ID: '',
    THRESHOLD_COORDINATOR_PEERS: '',
    THRESHOLD_ED25519_RELAYER_COSIGNER_ID: '3',
    THRESHOLD_ED25519_SHARE_MODE: '',
  },
});

function shutdown(signal) {
  console.log(`[shutdown] received ${signal}, closing relay fleet...`);
  try {
    sdk?.kill();
  } catch {}
  try {
    tsc.kill();
  } catch {}
  try {
    coordinator.kill();
  } catch {}
  try {
    cosigner2.kill();
  } catch {}
  try {
    cosigner3.kill();
  } catch {}
  process.exit(0);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

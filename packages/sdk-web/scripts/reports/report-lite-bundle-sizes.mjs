#!/usr/bin/env node
/**
 * Report bundle sizes (raw/gzip/brotli) for the root SDK entry and wallet-origin assets.
 *
 * Usage:
 *   pnpm build:sdk-prod
 *   pnpm -C packages/sdk-web size:lite
 *   pnpm -C packages/sdk-web size:lite:check
 */
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sdkRoot = path.resolve(path.join(__dirname, '../..'));

const argv = process.argv.slice(2);

const HELP = argv.includes('--help') || argv.includes('-h');
const CHECK = argv.includes('--check');
const JSON_OUTPUT = argv.includes('--json');

if (HELP) {
  console.log(
    `
[report-lite-bundle-sizes] Report lite bundle sizes (raw/gzip/brotli).

Reads from:
  - dist/esm/index.js
  - dist/workers/*

Options:
  --check   Enforce budgets (exit non-zero on regressions)
  --json    Print machine-readable JSON
  -h,--help Show help
`.trim(),
  );
  process.exit(0);
}

function fail(msg) {
  console.error(`\n[report-lite-bundle-sizes] ${msg}`);
  process.exit(1);
}

function formatBytes(bytes) {
  const kib = bytes / 1024;
  if (kib < 1024) return `${kib.toFixed(1)} KiB`;
  return `${(kib / 1024).toFixed(2)} MiB`;
}

function compressGzip(buf) {
  return zlib.gzipSync(buf, { level: 9 });
}

function compressBrotli(buf) {
  return zlib.brotliCompressSync(buf, {
    params: {
      [zlib.constants.BROTLI_PARAM_QUALITY]: 11,
    },
  });
}

const TARGETS = [
  {
    id: 'sdk-index',
    label: 'sdk entry',
    relPath: 'dist/esm/index.js',
    budget: { raw: 8_000, gzip: 3_000, brotli: 3_000 },
  },
  {
    id: 'secure-confirm-worker',
    label: 'secure-confirm worker',
    relPath: 'dist/workers/passkey-confirm.worker.js',
    budget: { raw: 220_000, gzip: 38_000, brotli: 32_000 },
  },
  {
    id: 'signer-worker',
    label: 'signer worker',
    relPath: 'dist/workers/near-signer.worker.js',
    budget: { raw: 90_000, gzip: 20_000, brotli: 20_000 },
  },
  {
    id: 'ecdsa-derivation-client-worker',
    label: 'ECDSA derivation client worker',
    relPath: 'dist/workers/ecdsa-derivation-client.worker.js',
    budget: { raw: 55_000, gzip: 14_000, brotli: 14_000 },
  },
  {
    id: 'ecdsa-presign-client-worker',
    label: 'ECDSA presign client worker',
    relPath: 'dist/workers/ecdsa-presign-client.worker.js',
    budget: { raw: 55_000, gzip: 14_000, brotli: 14_000 },
  },
  {
    id: 'ecdsa-online-client-worker',
    label: 'ECDSA online client worker',
    relPath: 'dist/workers/ecdsa-online-client.worker.js',
    budget: { raw: 45_000, gzip: 12_000, brotli: 12_000 },
  },
  {
    id: 'ecdsa-derivation-client-wasm',
    label: 'ECDSA derivation client WASM',
    relPath: 'dist/workers/router_ab_ecdsa_derivation_client_bg.wasm',
    budget: { raw: 630_000, gzip: 250_000, brotli: 200_000 },
  },
  {
    id: 'ecdsa-presign-client-wasm',
    label: 'ECDSA presign client WASM',
    relPath: 'dist/workers/router_ab_ecdsa_presign_client_bg.wasm',
  },
  {
    id: 'ecdsa-online-client-wasm',
    label: 'ECDSA online client WASM',
    relPath: 'dist/workers/router_ab_ecdsa_online_client_bg.wasm',
  },
  {
    id: 'ed25519-yao-client-wasm',
    label: 'Ed25519 Yao client WASM',
    relPath: 'dist/workers/router_ab_ed25519_yao_client_bg.wasm',
    budget: { raw: 556_435, gzip: 223_677, brotli: 223_677 },
  },
  {
    id: 'wasm-signer',
    label: 'wasm signer',
    relPath: 'dist/workers/wasm_signer_worker_bg.wasm',
    budget: { raw: 900_000, gzip: 360_000, brotli: 340_000 },
  },
];

const rows = [];
const missing = [];

for (const t of TARGETS) {
  const abs = path.join(sdkRoot, t.relPath);
  if (!fs.existsSync(abs)) {
    missing.push(t.relPath);
    continue;
  }

  const buf = fs.readFileSync(abs);
  const gzip = compressGzip(buf);
  const brotli = compressBrotli(buf);

  rows.push({
    id: t.id,
    label: t.label,
    path: t.relPath,
    raw: buf.length,
    gzip: gzip.length,
    brotli: brotli.length,
    budget: t.budget,
  });
}

if (missing.length) {
  const hint = `Missing build outputs:\n${missing.map((p) => `  - ${p}`).join('\n')}\n\nDid you run 'pnpm build:sdk-prod' (or 'pnpm build:sdk')?`;
  if (CHECK) fail(hint);
  console.warn(`\n[report-lite-bundle-sizes] ${hint}`);
}

const totals = rows.reduce(
  (acc, r) => {
    acc.raw += r.raw;
    acc.gzip += r.gzip;
    acc.brotli += r.brotli;
    return acc;
  },
  { raw: 0, gzip: 0, brotli: 0 },
);

if (JSON_OUTPUT) {
  console.log(
    JSON.stringify(
      {
        sdkRoot,
        targets: rows,
        totals,
        missing,
      },
      null,
      2,
    ),
  );
} else {
  console.log('\n[report-lite-bundle-sizes] Sizes (raw / gzip / brotli):');
  for (const r of rows) {
    console.log(
      `- ${r.label} (${r.path}): ${formatBytes(r.raw)} / ${formatBytes(r.gzip)} / ${formatBytes(r.brotli)}`,
    );
  }
  console.log(
    `\n[report-lite-bundle-sizes] Totals: ${formatBytes(totals.raw)} / ${formatBytes(totals.gzip)} / ${formatBytes(
      totals.brotli,
    )}`,
  );
}

if (CHECK) {
  const failures = [];
  for (const r of rows) {
    const b = r.budget;
    if (!b) continue;
    if (typeof b.raw === 'number' && r.raw > b.raw)
      failures.push(`${r.path}: raw ${r.raw} > ${b.raw}`);
    if (typeof b.gzip === 'number' && r.gzip > b.gzip)
      failures.push(`${r.path}: gzip ${r.gzip} > ${b.gzip}`);
    if (typeof b.brotli === 'number' && r.brotli > b.brotli)
      failures.push(`${r.path}: brotli ${r.brotli} > ${b.brotli}`);
  }

  if (failures.length) {
    fail(`Bundle size budgets exceeded:\n${failures.map((l) => `  - ${l}`).join('\n')}`);
  }

  console.log('[report-lite-bundle-sizes] OK: budgets satisfied');
}

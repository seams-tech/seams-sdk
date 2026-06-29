#!/usr/bin/env node
/**
 * Report wallet iframe boot-path, worker, and WASM sizes.
 *
 * Usage:
 *   pnpm build:sdk-prod
 *   pnpm -C packages/sdk-web check:bundle-size
 *   pnpm -C packages/sdk-web check:bundle-size -- --budget walletHostGzip=100000 --budget ecdsaWasmGzip=1500000
 */
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sdkRoot = path.resolve(path.join(__dirname, '../..'));
const distRoot = path.join(sdkRoot, 'dist');

const argv = process.argv.slice(2);
const help = argv.includes('--help') || argv.includes('-h');
const jsonOutput = argv.includes('--json');

if (help) {
  console.log(
    `
[report-wallet-iframe-bundle-size] Report wallet iframe bundle sizes.

Reads from:
  - dist/esm/sdk/wallet-iframe-host-runtime.js
  - static JS/CSS files imported by that host entry
  - dist/workers/*

Options:
  --budget key=value  Enforce an explicit byte budget, repeatable
  --json              Print machine-readable JSON
  -h,--help           Show help

Budget keys:
  walletHostGzip, walletHostBootPathGzip, walletHostStaticImportsGzip
  workerAndWasmGzip, ecdsaWasmGzip, nearWasmGzip, tempoWasmGzip, hssWasmGzip
`.trim(),
  );
  process.exit(0);
}

function formatBytes(bytes) {
  const kib = bytes / 1024;
  if (kib < 1024) return `${kib.toFixed(1)} KiB`;
  return `${(kib / 1024).toFixed(2)} MiB`;
}

function gzipSize(buf) {
  return zlib.gzipSync(buf, { level: 9 }).length;
}

function relFromSdk(absPath) {
  return path.relative(sdkRoot, absPath).split(path.sep).join('/');
}

function readSize(absPath) {
  const buf = fs.readFileSync(absPath);
  return {
    raw: buf.length,
    gzip: gzipSize(buf),
  };
}

function parseBudgetArgs(args) {
  const budgets = new Map();
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg !== '--budget') continue;
    const spec = args[i + 1];
    i += 1;
    if (!spec || !spec.includes('=')) {
      throw new Error('--budget requires key=value');
    }
    const [key, valueText] = spec.split('=', 2);
    const value = Number(valueText);
    if (!key || !Number.isFinite(value) || value < 0) {
      throw new Error(`Invalid budget: ${spec}`);
    }
    budgets.set(key, Math.floor(value));
  }
  return budgets;
}

function parseStaticImportSpecifiers(source) {
  const specs = [];
  const patterns = [
    /\bimport\s+(?:[^'"]+?\s+from\s*)?['"]([^'"]+)['"]/g,
    /\bexport\s+[^'"]+?\s+from\s+['"]([^'"]+)['"]/g,
  ];
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(source))) {
      specs.push(match[1]);
    }
  }
  return specs;
}

function resolveImport(fromAbs, specifier) {
  if (!specifier.startsWith('.')) return null;
  const base = path.resolve(path.dirname(fromAbs), specifier);
  const candidates = [
    base,
    `${base}.js`,
    `${base}.mjs`,
    `${base}.css`,
    path.join(base, 'index.js'),
  ];
  return candidates.find((candidate) => fs.existsSync(candidate) && fs.statSync(candidate).isFile()) ?? null;
}

function collectStaticImports(entryAbs) {
  const seen = new Set();
  const ordered = [];
  const visit = (fileAbs) => {
    const source = fs.readFileSync(fileAbs, 'utf8');
    for (const specifier of parseStaticImportSpecifiers(source)) {
      const resolved = resolveImport(fileAbs, specifier);
      if (!resolved) continue;
      const relativeToDist = path.relative(distRoot, resolved);
      if (relativeToDist.startsWith('..') || path.isAbsolute(relativeToDist)) continue;
      if (seen.has(resolved) || resolved === entryAbs) continue;
      seen.add(resolved);
      ordered.push(resolved);
      if (/\.(mjs|js)$/.test(resolved)) visit(resolved);
    }
  };
  if (fs.existsSync(entryAbs)) visit(entryAbs);
  return ordered.sort((a, b) => relFromSdk(a).localeCompare(relFromSdk(b)));
}

function makeRow(label, absPath, group) {
  const size = readSize(absPath);
  return {
    label,
    path: relFromSdk(absPath),
    group,
    raw: size.raw,
    gzip: size.gzip,
  };
}

function sumRows(rows) {
  return rows.reduce(
    (acc, row) => {
      acc.raw += row.raw;
      acc.gzip += row.gzip;
      return acc;
    },
    { raw: 0, gzip: 0 },
  );
}

function printRows(title, rows) {
  console.log(`\n${title}`);
  if (rows.length === 0) {
    console.log('  - none');
    return;
  }
  for (const row of rows) {
    console.log(`  - ${row.label} (${row.path}): ${formatBytes(row.raw)} raw / ${formatBytes(row.gzip)} gzip`);
  }
}

let budgets;
try {
  budgets = parseBudgetArgs(argv);
} catch (err) {
  console.error(`\n[report-wallet-iframe-bundle-size] ${err.message}`);
  process.exit(1);
}

const hostAbs = path.join(distRoot, 'esm/sdk/wallet-iframe-host-runtime.js');
const workerTargets = [
  ['passkeyConfirmWorker', 'passkey confirm worker', 'dist/workers/passkey-confirm.worker.js'],
  ['emailOtpWorker', 'Email OTP worker', 'dist/workers/email-otp.worker.js'],
  ['nearSignerWorker', 'NEAR signer worker', 'dist/workers/near-signer.worker.js'],
  ['nearWasm', 'NEAR signer WASM', 'dist/workers/wasm_signer_worker_bg.wasm'],
  ['nearWorkerWasm', 'NEAR worker WASM alias', 'dist/workers/near_signer.wasm'],
  ['ethSignerWorker', 'ECDSA signer worker', 'dist/workers/eth-signer.worker.js'],
  ['ecdsaWasm', 'ECDSA signer WASM', 'dist/workers/eth_signer.wasm'],
  ['tempoSignerWorker', 'Tempo signer worker', 'dist/workers/tempo-signer.worker.js'],
  ['tempoWasm', 'Tempo signer WASM', 'dist/workers/tempo_signer.wasm'],
  ['hssClientWorker', 'HSS client worker', 'dist/workers/hss-client.worker.js'],
  ['hssWasm', 'HSS client WASM', 'dist/workers/hss_client_signer_bg.wasm'],
  ['shamir3PassWorker', 'Shamir3Pass worker', 'dist/workers/shamir3pass.worker.js'],
  ['shamir3PassWasm', 'Shamir3Pass WASM', 'dist/workers/shamir3pass_runtime_bg.wasm'],
  ['emailOtpRuntimeWasm', 'Email OTP runtime WASM', 'dist/workers/email_otp_runtime_bg.wasm'],
  ['thresholdPrfWasm', 'threshold PRF WASM', 'dist/workers/threshold_prf.wasm'],
];

const missing = [];
const hostRows = [];
const staticImportRows = [];
const workerRows = [];

if (fs.existsSync(hostAbs)) {
  hostRows.push(makeRow('wallet host runtime', hostAbs, 'walletHost'));
  for (const staticImportAbs of collectStaticImports(hostAbs)) {
    staticImportRows.push(makeRow(path.basename(staticImportAbs), staticImportAbs, 'walletHostStaticImport'));
  }
} else {
  missing.push(relFromSdk(hostAbs));
}

for (const [id, label, relPath] of workerTargets) {
  const absPath = path.join(sdkRoot, relPath);
  if (!fs.existsSync(absPath)) {
    missing.push(relPath);
    continue;
  }
  workerRows.push({ id, ...makeRow(label, absPath, 'workerAndWasm') });
}

const hostTotal = sumRows(hostRows);
const staticImportTotal = sumRows(staticImportRows);
const bootPathTotal = sumRows([...hostRows, ...staticImportRows]);
const workerTotal = sumRows(workerRows);

const metrics = {
  walletHostGzip: hostTotal.gzip,
  walletHostBootPathGzip: bootPathTotal.gzip,
  walletHostStaticImportsGzip: staticImportTotal.gzip,
  workerAndWasmGzip: workerTotal.gzip,
};
for (const row of workerRows) {
  if (row.id === 'ecdsaWasm') metrics.ecdsaWasmGzip = row.gzip;
  if (row.id === 'nearWasm') metrics.nearWasmGzip = row.gzip;
  if (row.id === 'tempoWasm') metrics.tempoWasmGzip = row.gzip;
  if (row.id === 'hssWasm') metrics.hssWasmGzip = row.gzip;
}

if (jsonOutput) {
  console.log(
    JSON.stringify(
      {
        sdkRoot,
        host: hostRows,
        staticImports: staticImportRows,
        workersAndWasm: workerRows,
        totals: {
          walletHost: hostTotal,
          walletHostStaticImports: staticImportTotal,
          walletHostBootPath: bootPathTotal,
          workerAndWasm: workerTotal,
        },
        metrics,
        missing,
      },
      null,
      2,
    ),
  );
} else {
  console.log('\n[report-wallet-iframe-bundle-size] Wallet iframe bundle sizes');
  printRows('Wallet host boot entry', hostRows);
  printRows('Wallet host static imports', staticImportRows);
  console.log(
    `\nWallet host boot-path total: ${formatBytes(bootPathTotal.raw)} raw / ${formatBytes(bootPathTotal.gzip)} gzip`,
  );
  printRows('Wallet workers and WASM', workerRows);
  console.log(`\nWorker/WASM total: ${formatBytes(workerTotal.raw)} raw / ${formatBytes(workerTotal.gzip)} gzip`);
  if (missing.length) {
    console.warn(
      `\n[report-wallet-iframe-bundle-size] Missing build outputs:\n${missing
        .map((p) => `  - ${p}`)
        .join('\n')}\n\nRun 'pnpm build:sdk-prod' before using this report in CI.`,
    );
  }
}

const failures = [];
for (const [key, budget] of budgets) {
  const measured = metrics[key];
  if (typeof measured !== 'number') {
    failures.push(`${key}: no measured value`);
    continue;
  }
  if (measured > budget) failures.push(`${key}: ${measured} > ${budget}`);
}

if (failures.length) {
  console.error(
    `\n[report-wallet-iframe-bundle-size] Bundle size budgets exceeded:\n${failures
      .map((failure) => `  - ${failure}`)
      .join('\n')}`,
  );
  process.exit(1);
}

if (budgets.size > 0 && !jsonOutput) {
  console.log('[report-wallet-iframe-bundle-size] OK: explicit budgets satisfied');
}

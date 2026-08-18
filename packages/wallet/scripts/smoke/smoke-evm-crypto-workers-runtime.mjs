#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sdkRoot = path.resolve(path.join(__dirname, '../..'));
const repoRoot = path.resolve(sdkRoot, '../..');

const wasmPkgJsAbs = path.join(repoRoot, 'wasm', 'evm_crypto', 'pkg', 'evm_crypto.js');
const workerWasmAbs = path.join(sdkRoot, 'dist', 'workers', 'evm_crypto.wasm');

function fail(msg) {
  console.error(`\n[smoke-evm-crypto-workers-runtime] ${msg}`);
  process.exit(1);
}

async function fileExists(absPath) {
  try {
    await fs.access(absPath);
    return true;
  } catch {
    return false;
  }
}

if (!(await fileExists(wasmPkgJsAbs))) {
  fail(`Missing wasm-bindgen JS at ${wasmPkgJsAbs}. Run 'pnpm build:sdk-prod' first.`);
}
if (!(await fileExists(workerWasmAbs))) {
  fail(`Missing worker WASM at ${workerWasmAbs}.`);
}

const mod = await import(pathToFileURL(wasmPkgJsAbs).href);
const initWasm = mod.default || mod.__wbg_init;
if (typeof initWasm !== 'function')
  fail('evm_crypto init export is missing (expected default or __wbg_init)');
if (typeof mod.init_evm_crypto !== 'function') fail('evm_crypto init_evm_crypto export is missing');
if ('threshold_ecdsa_finalize_signature' in mod || 'ThresholdEcdsaPresignSession' in mod) {
  fail('evm_crypto exposes a forbidden threshold ECDSA operation');
}

const originalFetch = globalThis.fetch;
if (typeof originalFetch !== 'function')
  fail('global fetch is required for workers-runtime smoke check');

function requestUrl(input) {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  if (typeof Request === 'function' && input instanceof Request) return input.url;
  return String(input);
}

async function fetchWorkerWasm(input, init) {
  const urlString = requestUrl(input);

  if (urlString.startsWith('file://')) {
    const filePath = fileURLToPath(urlString);
    const bytes = await fs.readFile(filePath);
    return new Response(bytes, {
      status: 200,
      headers: {
        'Content-Type': 'application/wasm',
      },
    });
  }

  return await originalFetch(input, init);
}

globalThis.fetch = fetchWorkerWasm;

try {
  await initWasm({ module_or_path: pathToFileURL(workerWasmAbs) });
  mod.init_evm_crypto();
} finally {
  globalThis.fetch = originalFetch;
}

console.log('[smoke-evm-crypto-workers-runtime] OK');

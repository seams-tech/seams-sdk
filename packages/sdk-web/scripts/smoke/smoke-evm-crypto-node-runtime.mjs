#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sdkRoot = path.resolve(path.join(__dirname, '../..'));
const repoRoot = path.resolve(sdkRoot, '../..');

const wasmPkgJsAbs = path.join(repoRoot, 'wasm', 'evm_crypto', 'pkg', 'evm_crypto.js');
const sourceWasmAbs = path.join(repoRoot, 'wasm', 'evm_crypto', 'pkg', 'evm_crypto_bg.wasm');

function fail(msg) {
  console.error(`\n[smoke-evm-crypto-node-runtime] ${msg}`);
  process.exit(1);
}

if (!fs.existsSync(wasmPkgJsAbs)) {
  fail(`Missing wasm-bindgen JS at ${wasmPkgJsAbs}. Run 'pnpm build:sdk-prod' first.`);
}
if (!fs.existsSync(sourceWasmAbs)) {
  fail(`Missing source WASM at ${sourceWasmAbs}.`);
}

const mod = await import(pathToFileURL(wasmPkgJsAbs).href);
const initWasm = mod.default || mod.__wbg_init;
if (typeof initWasm !== 'function')
  fail('evm_crypto init export is missing (expected default or __wbg_init)');
if (typeof mod.init_evm_crypto !== 'function') fail('evm_crypto init_evm_crypto export is missing');
if ('threshold_ecdsa_finalize_signature' in mod || 'ThresholdEcdsaPresignSession' in mod) {
  fail('evm_crypto exposes a forbidden threshold ECDSA operation');
}

const sourceWasmBytes = fs.readFileSync(sourceWasmAbs);
const sourceWasmBuffer = new ArrayBuffer(sourceWasmBytes.byteLength);
new Uint8Array(sourceWasmBuffer).set(sourceWasmBytes);
const compiledModule = await WebAssembly.compile(sourceWasmBuffer);

await initWasm({ module_or_path: compiledModule });
mod.init_evm_crypto();

console.log('[smoke-evm-crypto-node-runtime] OK');

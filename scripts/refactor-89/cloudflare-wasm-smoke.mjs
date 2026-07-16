#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import process from 'node:process';

import { Miniflare } from 'miniflare';

function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (typeof flag !== 'string' || !flag.startsWith('--') || typeof value !== 'string') {
      throw new Error('usage: cloudflare-wasm-smoke.mjs --binding PATH --wasm PATH --sha256 HEX');
    }
    values.set(flag, value);
  }

  const bindingPath = values.get('--binding');
  const wasmPath = values.get('--wasm');
  const expectedSha256 = values.get('--sha256');
  if (bindingPath === undefined || wasmPath === undefined || expectedSha256 === undefined) {
    throw new Error('usage: cloudflare-wasm-smoke.mjs --binding PATH --wasm PATH --sha256 HEX');
  }
  return { bindingPath, wasmPath, expectedSha256 };
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function workerSource(bindingName, wasmName) {
  return `
import init, { initSync } from "./${bindingName}";
import wasmModule from "./${wasmName}";

const wasmExports = initSync({ module: wasmModule });

async function fetch() {
  return Response.json({
    ok: true,
    asyncInitializerType: typeof init,
    memoryBytes: wasmExports.memory.buffer.byteLength,
    moduleExportCount: WebAssembly.Module.exports(wasmModule).length,
  });
}

export default { fetch };
`;
}

async function dispatchAndParse(miniflare) {
  const response = await miniflare.dispatchFetch('https://phase1.invalid/smoke');
  assert.equal(response.status, 200);
  return response.json();
}

async function main() {
  const { bindingPath, wasmPath, expectedSha256 } = parseArguments(process.argv.slice(2));
  const [bindingBytes, wasmBytes] = await Promise.all([readFile(bindingPath), readFile(wasmPath)]);
  assert.equal(sha256(wasmBytes), expectedSha256, 'Wasm digest differs from frozen evidence');

  const entryPath = 'phase1-cloudflare-smoke/worker.mjs';
  const bindingName = 'binding.js';
  const wasmName = 'artifact.wasm';
  const miniflare = new Miniflare({
    compatibilityDate: '2026-07-16',
    modules: [
      { type: 'ESModule', path: entryPath, contents: workerSource(bindingName, wasmName) },
      {
        type: 'ESModule',
        path: 'phase1-cloudflare-smoke/binding.js',
        contents: bindingBytes.toString('utf8'),
      },
      {
        type: 'CompiledWasm',
        path: 'phase1-cloudflare-smoke/artifact.wasm',
        contents: wasmBytes,
      },
    ],
  });

  try {
    const cold = await dispatchAndParse(miniflare);
    const warm = await dispatchAndParse(miniflare);
    assert.equal(cold.ok, true);
    assert.equal(cold.asyncInitializerType, 'function');
    assert.ok(cold.memoryBytes > 0);
    assert.ok(cold.moduleExportCount > 0);
    assert.deepEqual(warm, cold);
    process.stdout.write(`${JSON.stringify({ runtime: 'workerd', cold, warm })}\n`);
  } finally {
    await miniflare.dispose();
  }
}

await main();

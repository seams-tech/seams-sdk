#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

function fail(message) {
  throw new Error(message);
}

function round(value) {
  return Number(value.toFixed(3));
}

function summarize(samples) {
  const sorted = [...samples].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  const median =
    sorted.length % 2 === 0 ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle];
  return {
    samples: samples.map(round),
    median: round(median),
    min: round(sorted[0]),
    max: round(sorted.at(-1)),
  };
}

function measureRead(path, iterations) {
  const samples = [];
  for (let index = 0; index < iterations; index += 1) {
    const started = performance.now();
    readFileSync(path);
    samples.push(performance.now() - started);
  }
  return summarize(samples);
}

async function measureCompile(bytes, iterations) {
  const samples = [];
  let firstModule;
  for (let index = 0; index < iterations; index += 1) {
    const started = performance.now();
    const module = await WebAssembly.compile(bytes);
    samples.push(performance.now() - started);
    firstModule ??= module;
  }
  return { measurement: summarize(samples), module: firstModule };
}

async function importFresh(jsPath, index) {
  const url = pathToFileURL(jsPath);
  url.searchParams.set('refactor89Sample', String(index));
  return import(url.href);
}

async function measureInstantiation(jsPath, module, iterations) {
  const samples = [];
  let linearMemoryBytes = null;
  for (let index = 0; index < iterations; index += 1) {
    const bindings = await importFresh(jsPath, index);
    const started = performance.now();
    const exports = bindings.initSync({ module });
    samples.push(performance.now() - started);
    if (exports.memory instanceof WebAssembly.Memory) {
      linearMemoryBytes = exports.memory.buffer.byteLength;
    }
  }
  return { measurement: summarize(samples), linearMemoryBytes };
}

async function measureFirstCall(jsPath, module, exportName, index) {
  if (exportName === undefined) {
    return null;
  }
  const bindings = await importFresh(jsPath, index);
  bindings.initSync({ module });
  const operation = bindings[exportName];
  if (typeof operation !== 'function') {
    fail(`missing zero-argument first-call export ${exportName}`);
  }
  const started = performance.now();
  operation();
  return round(performance.now() - started);
}

async function main(arguments_) {
  const [jsPath, wasmPath, firstCallExport] = arguments_;
  if (jsPath === undefined || wasmPath === undefined) {
    fail('usage: wasm-load-benchmark.mjs <bindings-js> <wasm> [zero-argument-export]');
  }
  const rssBeforeBytes = process.memoryUsage().rss;
  const readStarted = performance.now();
  const bytes = readFileSync(wasmPath);
  const firstReadMs = performance.now() - readStarted;
  const compile = await measureCompile(bytes, 11);
  const instantiation = await measureInstantiation(jsPath, compile.module, 11);
  const firstCallMs = await measureFirstCall(jsPath, compile.module, firstCallExport, 1000);
  const rssAfterBytes = process.memoryUsage().rss;
  process.stdout.write(
    `${JSON.stringify(
      {
        schema: 'seams.refactor89.wasm-load-benchmark.v1',
        runtime: process.version,
        artifactBytes: bytes.length,
        firstFilesystemReadMs: round(firstReadMs),
        repeatedFilesystemReadMs: measureRead(wasmPath, 11),
        compileMs: compile.measurement,
        instantiateMs: instantiation.measurement,
        firstCall:
          firstCallExport === undefined ? null : { export: firstCallExport, ms: firstCallMs },
        initializedLinearMemoryBytes: instantiation.linearMemoryBytes,
        processRssBeforeBytes: rssBeforeBytes,
        processRssAfterBytes: rssAfterBytes,
        processRssDeltaBytes: rssAfterBytes - rssBeforeBytes,
        limitation:
          'Filesystem read is a local fetch proxy; network and Cloudflare Worker fetch remain unmeasured.',
      },
      null,
      2,
    )}\n`,
  );
}

await main(process.argv.slice(2));

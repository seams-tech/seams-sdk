#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoSource(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function sourceRangeBetween(source, startNeedle, endNeedle) {
  const start = source.indexOf(startNeedle);
  assert.ok(start >= 0, `missing source range start: ${startNeedle}`);
  const end = source.indexOf(endNeedle, start + startNeedle.length);
  assert.ok(end > start, `missing source range end: ${endNeedle}`);
  return source.slice(start, end);
}

function checkReservedPresignFailureBurnsWasmHandleFirst() {
  const source = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts',
  );
  const functionRange = sourceRangeBetween(
    source,
    'async function signReservedRouterAbEd25519Presign(args: {',
    'async function trySignRouterAbEd25519WithPresignPool(',
  );
  const catchRange = sourceRangeBetween(functionRange, '} catch (error) {', '    throw error;');
  const wasmBurnIndex = catchRange.indexOf('await burnThresholdEd25519ClientPresignWasm({');
  const jsBurnIndex = catchRange.indexOf('burnThresholdEd25519ReservedPresign({');

  assert.ok(wasmBurnIndex >= 0, 'reserved presign catch block must burn WASM nonce handle');
  assert.ok(
    jsBurnIndex > wasmBurnIndex,
    'reserved presign catch block must burn WASM nonce handle before JS reservation state',
  );
  assert.ok(
    catchRange.includes('clientNonceHandleB64u: reservation.reservation.entry.nonceHandle'),
    'reserved presign catch block must pass the reserved client nonce handle',
  );
  assert.ok(
    catchRange.includes('workerCtx: input.ctx'),
    'reserved presign catch block must use the signing worker context',
  );
  assert.ok(
    catchRange.includes('}).catch(ignoreClientPresignBurnFailure);'),
    'reserved presign catch block must ignore best-effort WASM nonce burn failures',
  );
}

function checkClientPresignHandlesUseCsprngOutput() {
  const source = readRepoSource('wasm/near_signer/src/threshold/worker_material.rs');
  const handleRange = sourceRangeBetween(
    source,
    'fn next_client_presign_handle() -> Result<String, JsValue> {',
    'fn random_worker_material_handle()',
  );

  assert.equal(
    source.includes('CLIENT_PRESIGN_HANDLE_COUNTER'),
    false,
    'client presign handles must not use a process-local counter',
  );
  assert.ok(
    handleRange.includes('random_fixed_bytes::<16>("client presign handle")?'),
    'client presign handles must come from CSPRNG bytes',
  );
  assert.ok(
    handleRange.includes('base64_url_encode(&bytes)'),
    'client presign handles must be URL-safe encoded random bytes',
  );
  assert.equal(
    handleRange.includes('format!("ed25519-client-presign:{id}")'),
    false,
    'client presign handles must not use deterministic formatted IDs',
  );
}

checkReservedPresignFailureBurnsWasmHandleFirst();
checkClientPresignHandlesUseCsprngOutput();

console.log('[check-threshold-ed25519-presign-nonce-lifecycle] passed');

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function sourceRangeBetween(source: string, startNeedle: string, endNeedle: string): string {
  const start = source.indexOf(startNeedle);
  expect(start, `missing source range start: ${startNeedle}`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf(endNeedle, start + startNeedle.length);
  expect(end, `missing source range end: ${endNeedle}`).toBeGreaterThan(start);
  return source.slice(start, end);
}

test.describe('Threshold Ed25519 presign nonce lifecycle guards', () => {
  test('reserved presign failure burns the WASM nonce handle before burning JS state', () => {
    const source = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts',
    );
    const functionRange = sourceRangeBetween(
      source,
      'async function signReservedRouterAbEd25519Presign(args: {',
      'async function trySignRouterAbEd25519WithPresignPool(',
    );
    const catchRange = sourceRangeBetween(
      functionRange,
      '} catch (error) {',
      '    throw error;',
    );
    const wasmBurnIndex = catchRange.indexOf('await burnThresholdEd25519ClientPresignWasm({');
    const jsBurnIndex = catchRange.indexOf('burnThresholdEd25519ReservedPresign({');

    expect(wasmBurnIndex).toBeGreaterThanOrEqual(0);
    expect(jsBurnIndex).toBeGreaterThan(wasmBurnIndex);
    expect(catchRange).toContain(
      'clientNonceHandleB64u: reservation.reservation.entry.nonceHandle',
    );
    expect(catchRange).toContain('workerCtx: input.ctx');
    expect(catchRange).toContain('}).catch(ignoreClientPresignBurnFailure);');
  });

  test('client presign handles are generated from CSPRNG output', () => {
    const source = readRepoSource('wasm/near_signer/src/threshold/worker_material.rs');
    const handleRange = sourceRangeBetween(
      source,
      'fn next_client_presign_handle() -> Result<String, JsValue> {',
      'fn random_worker_material_handle()',
    );

    expect(source).not.toContain('CLIENT_PRESIGN_HANDLE_COUNTER');
    expect(handleRange).toContain('random_fixed_bytes::<16>("client presign handle")?');
    expect(handleRange).toContain('base64_url_encode(&bytes)');
    expect(handleRange).not.toContain('format!("ed25519-client-presign:{id}")');
  });
});

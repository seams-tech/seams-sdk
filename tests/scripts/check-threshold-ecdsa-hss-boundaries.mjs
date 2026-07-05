#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function listFiles(root, extensions) {
  const entries = fs.readdirSync(root, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'target' || entry.name === 'dist') return [];
      return listFiles(fullPath, extensions);
    }
    return extensions.some((extension) => entry.name.endsWith(extension)) ? [fullPath] : [];
  });
}

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function assertNoOffenders(label, offenders) {
  assert.deepEqual(offenders, [], `${label}\n${offenders.join('\n')}`);
}

function checkPresignRefillScheduler() {
  const source = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signers/secp256k1.ts',
  );
  const schedulerCallCount =
    source.match(/scheduleRouterAbEcdsaHssSigningRefill\(\{/g)?.length || 0;

  assert.ok(schedulerCallCount >= 2, 'secp256k1 signing path must schedule ECDSA HSS refills');
  assert.ok(
    source.includes('scheduleRouterAbEcdsaHssClientPresignaturePoolRefill({'),
    'secp256k1 signing path must refill the client presignature pool',
  );
  assert.ok(source.includes("trigger: 'commit_start'"), 'missing commit_start refill trigger');
  assert.ok(source.includes("trigger: 'post_sign_success'"), 'missing post_sign_success refill trigger');
}

function checkRoleLocalSigningAuthorization() {
  const source = readRepoFile(
    'packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts',
  );
  for (const token of [
    'deriveEcdsaKeyMaterialFromPersistedBackend',
    'bootstrapEcdsaFromRegistrationMaterial',
    'getEcdsaIntegratedKeyRecordByKeyHandle',
  ]) {
    assert.equal(source.includes(token), false, `Threshold signing service retained ${token}`);
  }
}

function checkNoRuntimeV1DerivationSurfaces() {
  const roots = [
    'packages/sdk-web/src',
    'packages/sdk-server-ts/src',
    'packages/shared-ts/src',
    'wasm/eth_signer/src',
    'wasm/hss_client_signer/src',
    'wasm/threshold_prf/src',
  ];
  const forbiddenTokens = [
    'EcdsaHssStableKeyContextV1',
    'encode_context_v1',
    'derive_client_share_v1',
    'derive_relayer_share_v1',
    'derive_relayer_share_for_client_public_v1',
    'public_transcript_digest_v1',
    'export_authorization_digest_v1',
    'reconstruct_export_key_v1',
  ];
  const offenders = [];

  for (const relativeRoot of roots) {
    for (const filePath of listFiles(path.join(repoRoot, relativeRoot), ['.ts', '.tsx', '.rs'])) {
      const source = fs.readFileSync(filePath, 'utf8');
      for (const token of forbiddenTokens) {
        if (token === 'EcdsaHssStableKeyContextV1') {
          if (/(?<!RouterAb)EcdsaHssStableKeyContextV1/.test(source)) {
            offenders.push(`${path.relative(repoRoot, filePath)} contains ${token}`);
          }
          continue;
        }
        if (source.includes(token)) {
          offenders.push(`${path.relative(repoRoot, filePath)} contains ${token}`);
        }
      }
    }
  }

  assertNoOffenders('runtime ECDSA HSS code must not call v1 derivation surfaces', offenders);
}

function checkProductionBridgeDoesNotExposeRootMaterial() {
  const relativePaths = [
    'packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPoolFillHandlers.ts',
    'packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPresignBridge.ts',
    'packages/shared-ts/src/utils/routerAbEcdsaHss.ts',
  ];
  const forbiddenTokens = [
    'privateKeyHex',
    'private_key_hex',
    'clientRootShare32B64u',
    'serverExportShare32B64u',
    'reconstruct_export_key',
    'reconstructExportKey',
    'x_export',
    'canonical_x',
    'canonicalX',
    'rawRoot',
    'raw_root',
    'rootMaterial',
    'root_material',
  ];
  const offenders = [];

  for (const relativePath of relativePaths) {
    const source = readRepoFile(relativePath);
    for (const token of forbiddenTokens) {
      if (source.includes(token)) offenders.push(`${relativePath} contains ${token}`);
    }
  }

  assertNoOffenders('Router A/B ECDSA HSS bridge must not expose export or root material', offenders);
}

function checkEcdsaHssCrateHasNoOldContextVersionApi() {
  const forbiddenTokens = [
    'reference_v1',
    'ClientOutputV1',
    'EcdsaHssStableKeyContextV1',
    'PrepareEnvelopeV1',
    'derive_client_share_v1',
    'wallet_session_user_id',
    'subject_id',
    'ecdsa-hss-v1',
  ];
  const offenders = [];

  for (const filePath of listFiles(path.join(repoRoot, 'crates/ecdsa-hss/src'), ['.rs'])) {
    const source = fs.readFileSync(filePath, 'utf8');
    for (const token of forbiddenTokens) {
      if (source.includes(token)) offenders.push(`${path.relative(repoRoot, filePath)} contains ${token}`);
    }
  }

  assertNoOffenders('ECDSA HSS crate source must not retain old context-version API', offenders);
}

checkPresignRefillScheduler();
checkRoleLocalSigningAuthorization();
checkNoRuntimeV1DerivationSurfaces();
checkProductionBridgeDoesNotExposeRootMaterial();
checkEcdsaHssCrateHasNoOldContextVersionApi();

console.log('[check-threshold-ecdsa-hss-boundaries] passed');

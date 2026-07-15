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
  assert.ok(
    source.includes("trigger: 'post_sign_success'"),
    'missing post_sign_success refill trigger',
  );
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
    'wasm/ecdsa_client_signer/src',
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

  assertNoOffenders(
    'Router A/B ECDSA HSS bridge must not expose export or root material',
    offenders,
  );
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
      if (source.includes(token))
        offenders.push(`${path.relative(repoRoot, filePath)} contains ${token}`);
    }
  }

  assertNoOffenders('ECDSA HSS crate source must not retain old context-version API', offenders);
}

function checkEcdsaClientSignerHasOneExplicitOwner() {
  assert.equal(
    fs.existsSync(path.join(repoRoot, 'wasm/hss_client_signer')),
    false,
    'the mixed hss_client_signer crate must stay deleted',
  );

  const roots = [
    'packages/sdk-web/src',
    'packages/sdk-web/scripts',
    'benchmarks/ecdsa-hss-wasm',
    'wasm/ecdsa_client_signer',
  ];
  const forbiddenTokens = [
    'wasm/hss_client_signer',
    'hssClientSignerWasm',
    '/sdk/workers/hss-client.worker.js',
    'SOURCE_SIGNING_WORKERS/hss-client.worker.ts',
    'hss_client_signer.js',
    'threshold_ed25519_seed_export_artifact_from_seed',
    'mod threshold_hss',
    '__W3A_HSS_CLIENT_WORKER_URL__',
    "'hssClient'",
    'HSS_CLIENT_SIGNER',
    'SOURCE_WASM_HSS_CLIENT_SIGNER',
    'WORKER_HSS_CLIENT',
    'RUNTIME_HSS_CLIENT_WORKER',
    'SIGNER_WORKER_MANAGER_CONFIG.HSS_CLIENT_WORKER',
    'BUILD_PATHS.RUNTIME.HSS_CLIENT_WORKER',
  ];
  const offenders = [];

  for (const relativeRoot of roots) {
    for (const filePath of listFiles(path.join(repoRoot, relativeRoot), [
      '.ts',
      '.tsx',
      '.mjs',
      '.sh',
      '.rs',
      '.toml',
    ])) {
      const source = fs.readFileSync(filePath, 'utf8');
      for (const token of forbiddenTokens) {
        if (source.includes(token))
          offenders.push(`${path.relative(repoRoot, filePath)} contains ${token}`);
      }
    }
  }

  const rootPackage = readRepoFile('package.json');
  for (const token of forbiddenTokens) {
    if (rootPackage.includes(token)) offenders.push(`package.json contains ${token}`);
  }

  assertNoOffenders('ECDSA client signer must have one explicit ECDSA owner', offenders);
}

function checkNormalSigningHasOneRuntimeOwner() {
  const sourceRoots = [
    path.join(repoRoot, 'packages/sdk-server-ts/src'),
    path.join(repoRoot, 'packages/console-server-ts/src'),
    path.join(repoRoot, 'apps/web-server/src'),
  ];
  const forbiddenTokens = [
    'getRouterAbNormalSigningWorkerId',
    'getRouterAbSigningWorkerPrivateHttpConfig',
    'reserveRouterAbNormalSigningPrepareReplay',
    'reserveRouterAbNormalSigningBudget',
    'commitRouterAbNormalSigningBudget',
    'validateRouterAbNormalSigningBudget',
    'releaseRouterAbNormalSigningBudget',
    'releaseRouterAbNormalSigningBudgetForIdentity',
    'ROUTER_AB_ECDSA_HSS_POOL_FILL_SIGNING_WORKER_URL',
    'ROUTER_AB_INTERNAL_SERVICE_AUTH_TOKEN',
    'internal_service_auth_token',
    'InternalServiceAuthToken',
    'service-auth token',
  ];
  const offenders = [];

  for (const sourceRoot of sourceRoots) {
    for (const filePath of listFiles(sourceRoot, ['.ts', '.tsx'])) {
      const source = fs.readFileSync(filePath, 'utf8');
      for (const token of forbiddenTokens) {
        if (source.includes(token)) {
          offenders.push(`${path.relative(repoRoot, filePath)} contains ${token}`);
        }
      }
    }
  }

  const thresholdService = readRepoFile(
    'packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts',
  );
  assert.equal(
    thresholdService.includes('export type RouterAbNormalSigningBudget'),
    false,
    'ThresholdSigningService must not own normal-signing budget types',
  );
  for (const token of [
    'provisionRouterAbEd25519YaoNormalSigningSession',
    'refreshRouterAbEd25519YaoNormalSigningBudget',
    'seedLocalRouterAbEd25519NormalSigningSession',
    'seedLocalRouterAbEcdsaHssNormalSigningSession',
    'LocalRouterAbEd25519NormalSigningSeedInput',
    'LocalRouterAbEcdsaHssNormalSigningSeedInput',
    'deleteEcdsaHssRoleLocalKeyByBootstrapIdentity',
    'verifyEcdsaHssRoleLocalBootstrapPersisted',
  ]) {
    assert.equal(
      thresholdService.includes(token),
      false,
      `ThresholdSigningService must not retain ${token}`,
    );
  }
  for (const method of [
    'getEcdsaKeyIdentityMetadata',
    'verifyEcdsaSigningRootWalletAddress',
    'ecdsaHssRoleLocalBootstrap',
    'verifyEcdsaHssRoleLocalClientRootProofForExistingKey',
    'ecdsaHssRoleLocalExportShare',
  ]) {
    assert.equal(
      new RegExp(`\\b${method}\\s*\\(`).test(thresholdService),
      false,
      `ThresholdSigningService must not retain ${method}`,
    );
  }

  const privateRoutes = readRepoFile(
    'packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts',
  );
  assert.equal(
    privateRoutes.includes('getThresholdSigningService'),
    false,
    'normal-signing routes must use RouterAbNormalSigningRuntime directly',
  );
  assert.equal(
    privateRoutes.includes('ThresholdSigningService'),
    false,
    'normal-signing routes must not depend on ThresholdSigningService',
  );

  assertNoOffenders('normal signing must have one RouterAbNormalSigningRuntime owner', offenders);
}

checkPresignRefillScheduler();
checkRoleLocalSigningAuthorization();
checkNoRuntimeV1DerivationSurfaces();
checkProductionBridgeDoesNotExposeRootMaterial();
checkEcdsaHssCrateHasNoOldContextVersionApi();
checkEcdsaClientSignerHasOneExplicitOwner();
checkNormalSigningHasOneRuntimeOwner();

console.log('[check-threshold-ecdsa-hss-boundaries] passed');

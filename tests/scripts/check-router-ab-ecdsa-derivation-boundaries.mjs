#!/usr/bin/env node

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { brotliCompressSync, constants as zlibConstants, gzipSync } from 'node:zlib';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ecdsaRegistrationClientManifest = 'wasm/ecdsa_registration_client/Cargo.toml';
const ecdsaRegistrationClientWasm =
  'wasm/ecdsa_registration_client/pkg/ecdsa_registration_client_bg.wasm';
const ecdsaRegistrationClientGeneratedJs =
  'wasm/ecdsa_registration_client/pkg/ecdsa_registration_client.js';
const ecdsaRegistrationClientGeneratedTypes =
  'wasm/ecdsa_registration_client/pkg/ecdsa_registration_client.d.ts';
const ecdsaDerivationClientManifest = 'wasm/router_ab_ecdsa_derivation_client/Cargo.toml';
const ecdsaDerivationClientWasm =
  'wasm/router_ab_ecdsa_derivation_client/pkg/router_ab_ecdsa_derivation_client_bg.wasm';
const ecdsaDerivationClientGeneratedJs =
  'wasm/router_ab_ecdsa_derivation_client/pkg/router_ab_ecdsa_derivation_client.js';
const ecdsaDerivationClientGeneratedTypes =
  'wasm/router_ab_ecdsa_derivation_client/pkg/router_ab_ecdsa_derivation_client.d.ts';

const forbiddenEcdsaDerivationClientPackages = new Map([
  ['threshold-signatures', 'threshold signing, triples, and presign protocol driver'],
  ['evm_crypto', 'unrelated EVM codec and local signing artifact'],
  ['router-ab-core', 'Router and server protocol API'],
  ['router-ab-cloudflare', 'Cloudflare Router and Deriver API'],
  ['router-ab-dev', 'local Router and Deriver runtime'],
  ['threshold-prf', 'Deriver threshold-PRF backend'],
  ['ed25519-yao', 'Ed25519 Yao role engine'],
  ['router-ab-ed25519-yao', 'Ed25519 Yao server adapter'],
  ['router-ab-ed25519-yao-client', 'unrelated Ed25519 client'],
  ['router-ab-ed25519-yao-protocol', 'unrelated Ed25519 protocol'],
  ['ecdsa-hss', 'retired ECDSA HSS owner'],
  ['ecdsa_client_signer', 'retired ECDSA client artifact'],
  ['hss_client_signer', 'retired mixed HSS client artifact'],
]);

const allowedEcdsaRegistrationClientExports = new Set([
  'finalize_ecdsa_client_bootstrap_v1',
  'open_ecdsa_role_local_signing_share_v1',
  'prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1',
  'prepare_ecdsa_client_bootstrap_v1',
]);

const allowedEcdsaDerivationClientExports = new Set(['build_ecdsa_role_local_export_artifact_v1']);

const allowedEcdsaClientCeremonyWasmExports = new Set([
  '__wbg_routerabecdsaclientceremonyv1_free',
  'routerabecdsaclientceremonyv1_build_activation_refresh_request',
  'routerabecdsaclientceremonyv1_build_explicit_export_request',
  'routerabecdsaclientceremonyv1_build_registration_request',
  'routerabecdsaclientceremonyv1_close',
  'routerabecdsaclientceremonyv1_finalize_encrypted_proof_bundles',
  'routerabecdsaclientceremonyv1_new',
  'routerabecdsaclientceremonyv1_public_key',
  'routerabecdsaclientceremonyv1_registration_binding',
]);

const requiredEcdsaClientCeremonyTypeMethods = [
  'free',
  'public_key',
  'build_registration_request',
  'registration_binding',
  'build_explicit_export_request',
  'build_activation_refresh_request',
  'finalize_encrypted_proof_bundles',
  'close',
];

const forbiddenRawEcdsaClientSecretBoundaryTokens = [
  'client_ephemeral_private_key32_b64u',
  'clientEphemeralPrivateKey32B64u',
  'open_and_finalize_router_ab_ecdsa_client_proof_bundles_v1',
  'finalize_router_ab_ecdsa_prf_output_v1',
];

const forbiddenEcdsaDerivationArtifactTokens = [
  'ecdsa_hss',
  'ecdsa-hss',
  'hss_client',
  'threshold_signatures',
  'threshold_ecdsa_presign',
  'presignature',
  'presign_',
  'triple',
  'cait_sith',
  'deriver_',
  'relayer_bootstrap',
  'server_bootstrap',
  'router_service',
];

function listFiles(root, extensions) {
  const entries = fs.readdirSync(root, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (
        entry.name === 'target' ||
        entry.name === 'dist' ||
        entry.name === 'node_modules' ||
        entry.name === '.pnpm-store' ||
        entry.name === '.lake' ||
        entry.name === '.wrangler' ||
        entry.name === 'out' ||
        entry.name === 'test-results' ||
        entry.name === 'playwright-report' ||
        entry.name === 'blob-report' ||
        entry.name === 'coverage' ||
        entry.name === '.cache' ||
        entry.name === '.vite' ||
        entry.name === 'docs'
      ) {
        return [];
      }
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
    source.match(/scheduleRouterAbEcdsaDerivationSigningRefill\(\{/g)?.length || 0;

  assert.ok(
    schedulerCallCount >= 2,
    'secp256k1 signing path must schedule Router A/B ECDSA derivation refills',
  );
  assert.ok(
    source.includes('scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill({'),
    'secp256k1 signing path must refill the client presignature pool',
  );
  assert.ok(source.includes("trigger: 'commit_start'"), 'missing commit_start refill trigger');
  assert.ok(
    source.includes("trigger: 'post_sign_success'"),
    'missing post_sign_success refill trigger',
  );
}

function checkNoRuntimeV1DerivationSurfaces() {
  const roots = [
    'packages/sdk-web/src',
    'packages/sdk-server-ts/src',
    'packages/shared-ts/src',
    'wasm/evm_crypto/src',
    'wasm/ecdsa_registration_client/src',
    'wasm/router_ab_ecdsa_derivation_client/src',
    'wasm/router_ab_ecdsa_online_client/src',
    'wasm/router_ab_ecdsa_presign_client/src',
    'wasm/router_ab_ecdsa_signing_worker/src',
    'wasm/threshold_prf/src',
  ];
  const forbiddenTokens = [
    'EcdsaDerivationStableKeyContextV1',
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
        if (token === 'EcdsaDerivationStableKeyContextV1') {
          if (/(?<!RouterAb)EcdsaDerivationStableKeyContextV1/.test(source)) {
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

  assertNoOffenders(
    'runtime Router A/B ECDSA derivation code must not call v1 derivation surfaces',
    offenders,
  );
}

function checkProductionBridgeDoesNotExposeRootMaterial() {
  const relativePaths = [
    'packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaDerivationPoolFillHandlers.ts',
    'packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaDerivationPresignBridge.ts',
    'packages/shared-ts/src/utils/routerAbEcdsaDerivation.ts',
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
    'Router A/B ECDSA derivation bridge must not expose export or root material',
    offenders,
  );
}

function checkEcdsaDerivationCrateHasNoOldContextVersionApi() {
  const forbiddenTokens = [
    'reference_v1',
    'ClientOutputV1',
    'EcdsaDerivationStableKeyContextV1',
    'PrepareEnvelopeV1',
    'derive_client_share_v1',
    'wallet_session_user_id',
    'subject_id',
    'ecdsa-hss-v1',
  ];
  const offenders = [];

  for (const filePath of listFiles(path.join(repoRoot, 'crates/router-ab-ecdsa-derivation/src'), [
    '.rs',
  ])) {
    const source = fs.readFileSync(filePath, 'utf8');
    for (const token of forbiddenTokens) {
      if (source.includes(token))
        offenders.push(`${path.relative(repoRoot, filePath)} contains ${token}`);
    }
  }

  assertNoOffenders(
    'Router A/B ECDSA derivation crate source must not retain old context-version API',
    offenders,
  );
}

function checkEcdsaDerivationClientHasOneExplicitOwner() {
  for (const relativePath of [
    'wasm/ecdsa_client_signer',
    'wasm/eth_signer',
    'wasm/hss_client_signer',
    'packages/sdk-web/src/core/signingEngine/threshold/crypto/ecdsaClientSignerWasm.ts',
  ]) {
    assert.equal(
      fs.existsSync(path.join(repoRoot, relativePath)),
      false,
      `retired ECDSA client artifact was restored: ${relativePath}`,
    );
  }

  const roots = [
    'packages/sdk-web/src',
    'packages/sdk-web/scripts',
    'wasm/evm_crypto',
    'wasm/router_ab_ecdsa_derivation_client',
    'wasm/router_ab_ecdsa_online_client',
    'wasm/router_ab_ecdsa_presign_client',
    'wasm/router_ab_ecdsa_signing_worker',
  ];
  const forbiddenTokens = [
    'ecdsaClientSignerWasm',
    'EcdsaClientSignerWasm',
    'initEcdsaClientSigner',
    'ecdsa_client_signer',
    'ecdsa-client-signer',
    'ecdsa-hss-client',
    'ethSigner',
    'EthSigner',
    'ETH_SIGNER',
    'eth_signer',
    'eth-signer',
    'clientSigningMaterialBoundary',
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

  assertNoOffenders('ECDSA derivation client must have one explicit ECDSA owner', offenders);
}

function checkRegistrationProofVerificationInitializesBothWasmOwners() {
  const source = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-derivation-client.worker.ts',
  );
  const verifyCase = source.indexOf(
    'case EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRegistrationClientProofs:',
  );
  const nextReturn = source.indexOf('      return;', verifyCase);
  assert.ok(verifyCase >= 0, 'registration proof verification operation is missing');
  assert.ok(nextReturn > verifyCase, 'registration proof verification initialization is incomplete');
  const initializationBlock = source.slice(verifyCase, nextReturn);
  assert.ok(
    initializationBlock.includes('initializeEcdsaDerivationClientWasm()'),
    'registration proof verification must initialize the derivation ceremony WASM',
  );
  assert.ok(
    initializationBlock.includes('initializeEcdsaRegistrationClientWasm()'),
    'registration proof verification must initialize the registration bootstrap WASM',
  );
}

function checkActiveSourceUsesCurrentVocabulary() {
  const roots = [
    'apps/seams-site/src',
    'crates/router-ab-cloudflare/src',
    'crates/router-ab-core/src',
    'crates/router-ab-dev/src',
    'crates/router-ab-ecdsa-derivation/src',
    'crates/signer-core/src',
    'packages/console-server-ts/src',
    'packages/sdk-server-ts/src',
    'packages/sdk-web/src',
    'packages/shared-ts/src',
    'wasm/evm_crypto/src',
    'wasm/ecdsa_registration_client/src',
    'wasm/router_ab_ecdsa_derivation_client/src',
    'wasm/router_ab_ecdsa_online_client/src',
    'wasm/router_ab_ecdsa_presign_client/src',
    'wasm/router_ab_ecdsa_signing_worker/src',
    'wasm/threshold_prf/src',
  ];
  const forbiddenTokens = [
    'ecdsaClientSignerWasm',
    'EcdsaClientSignerWasm',
    'initEcdsaClientSigner',
    'ecdsa_client_signer',
    'ecdsa-client-signer',
    'ecdsa-hss-client',
    'ethSigner',
    'EthSigner',
    'ETH_SIGNER',
    'eth_signer',
    'eth-signer',
    'clientSigningMaterialBoundary',
    'EcdsaHss',
    'ecdsaHss',
    'ecdsa_hss',
    'ecdsa-hss',
    'ECDSA_HSS',
    'ECDSA-HSS',
    'ECDSA HSS',
    'hssClientSharePublicKey',
    'HssClient',
    'hssClient',
    'hss_client_signer',
    '/hss/respond',
  ];
  const offenders = [];

  for (const relativeRoot of roots) {
    for (const filePath of listFiles(path.join(repoRoot, relativeRoot), [
      '.ts',
      '.tsx',
      '.mjs',
      '.rs',
      '.toml',
    ])) {
      const source = fs.readFileSync(filePath, 'utf8');
      for (const token of forbiddenTokens) {
        if (source.includes(token)) {
          offenders.push(`${path.relative(repoRoot, filePath)} contains ${token}`);
        }
      }
    }
  }

  assertNoOffenders('active source must use Router A/B ECDSA derivation vocabulary', offenders);
}

const retiredVocabularyGuardPaths = new Set([
  'crates/router-ab-cloudflare/tests/normal_signing_worker_boundaries.rs',
  'crates/router-ab-cloudflare/tests/secret_material_boundaries.rs',
  'crates/router-ab-core/tests/source_guards.rs',
  'crates/router-ab-dev/tests/ed25519_yao_local_profiles.rs',
  'crates/router-ab-ecdsa-derivation/tests/source_boundaries.rs',
  'crates/router-ab-ed25519-yao/tests/source_boundaries.rs',
  'packages/sdk-web/scripts/checks/check-signing-root-refactor-boundaries.mjs',
  'tests/scripts/check-auth-secret-terminology.mjs',
  'tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs',
  'tests/scripts/check-cross-platform-boundaries.mjs',
  'tests/scripts/check-ecdsa-client-worker-split.mjs',
  'tests/scripts/check-ed25519-yao-near-signing-boundaries.mjs',
  'tests/scripts/check-key-export-boundaries.mjs',
  'tests/scripts/check-route-lifecycle-domain-boundaries.mjs',
  'tests/scripts/check-router-ab-ecdsa-derivation-boundaries.mjs',
  'tests/scripts/check-router-ab-server-wallet-session-claim-boundaries.mjs',
  'tools/ed25519-yao-generator/tests/lifecycle_vectors.rs',
]);

const currentDocumentationPaths = [
  'benchmarks/router-ab-ecdsa-derivation-wasm/README.md',
  'crates/router-ab-ed25519-yao/README.md',
  'crates/seams-embedded/docs/robotics-key-choice.md',
  'docs/intended-behaviours.md',
  'docs/otp/email-otp.md',
  'docs/threshold-ecdsa/cait-sith-math.md',
  'docs/threshold-ecdsa/ecdsa-threshold-signing.md',
  'docs/threshold-ecdsa/evm-family-address-invariant.md',
];

const repositorySurfaceRoots = [
  '.github',
  'apps',
  'benchmarks',
  'crates',
  'packages',
  'tests',
  'tools',
  'wasm',
];

const repositorySurfaceExtensions = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.mjs',
  '.cjs',
  '.rs',
  '.toml',
  '.json',
  '.yaml',
  '.yml',
  '.sh',
]);

const runtimeArtifactDirectoryNames = new Set([
  'target',
  'dist',
  'node_modules',
  '.pnpm-store',
  '.lake',
  '.wrangler',
  'out',
  'test-results',
  'playwright-report',
  'blob-report',
  'coverage',
  '.cache',
  '.vite',
]);

function isRepositorySurfacePath(relativePath) {
  for (const root of repositorySurfaceRoots) {
    if (relativePath === root || relativePath.startsWith(`${root}/`)) return true;
  }
  return false;
}

function isNonProductionBenchmarkPath(relativePath) {
  const pathSegments = relativePath.split('/');
  return (
    pathSegments.length >= 2 &&
    pathSegments[0] === 'crates' &&
    pathSegments[1].endsWith('-cloudflare-bench')
  );
}

function isRuntimeArtifactPath(relativePath) {
  const pathSegments = relativePath.split('/');
  for (const segment of pathSegments) {
    if (runtimeArtifactDirectoryNames.has(segment)) return true;
  }
  return false;
}

function listRepositorySurfaceFiles() {
  const result = spawnSync(
    'git',
    ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
    {
      cwd: repoRoot,
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
    },
  );
  assert.equal(
    result.status,
    0,
    `failed to enumerate repository source surfaces\n${result.stderr || result.stdout}`,
  );

  const files = [];
  for (const relativePath of result.stdout.split('\0')) {
    if (!relativePath || !isRepositorySurfacePath(relativePath)) continue;
    if (isNonProductionBenchmarkPath(relativePath)) continue;
    if (isRuntimeArtifactPath(relativePath)) continue;
    if (relativePath.split('/').includes('docs')) continue;
    if (!repositorySurfaceExtensions.has(path.extname(relativePath))) continue;
    const absolutePath = path.join(repoRoot, relativePath);
    if (!fs.existsSync(absolutePath) || !fs.statSync(absolutePath).isFile()) continue;
    files.push(absolutePath);
  }
  return files;
}

function checkRuntimeArtifactsAreNotSourceSurfaces() {
  for (const relativePath of [
    'tests/test-results/trace.json',
    'tests/playwright-report/index.html',
    'tests/blob-report/report.json',
    'packages/sdk-server-ts/.wrangler/tmp/worker.js',
    'wasm/router_ab_ecdsa_derivation_client/target/debug/deps/output.json',
  ]) {
    assert.equal(
      isRuntimeArtifactPath(relativePath),
      true,
      `${relativePath} must be classified as a runtime artifact`,
    );
  }
  assert.equal(
    isRuntimeArtifactPath('packages/sdk-web/src/core/signingEngine/session/public.ts'),
    false,
    'tracked implementation source must remain in the terminology scan',
  );
}

function checkRepositorySurfacesUseCurrentVocabulary() {
  const retiredMarkers = [
    /HSS/,
    /Hss/,
    /hss/,
    /threshold_ed25519_session_v1/,
    /threshold_ecdsa_session_v2/,
    /LegacyThresholdSessionJwtKind/,
    /THRESHOLD_ED25519_SESSION_AUTH_TOKEN_KIND/,
    /THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND/,
    /thresholdServicePresent/,
    /threshold_service_missing/,
    /ecdsaClientSignerWasm/,
    /EcdsaClientSignerWasm/,
    /initEcdsaClientSigner/,
    /ecdsa_client_signer/,
    /ecdsa-client-signer/,
    /ecdsa-hss-client/,
    /ethSigner/,
    /EthSigner/,
    /ETH_SIGNER/,
    /eth_signer/,
    /eth-signer/,
    /clientSigningMaterialBoundary/,
  ];
  const offenders = [];

  for (const filePath of listRepositorySurfaceFiles()) {
    const relativePath = path.relative(repoRoot, filePath);
    if (retiredVocabularyGuardPaths.has(relativePath)) continue;
    const source = fs.readFileSync(filePath, 'utf8');
    for (const marker of retiredMarkers) {
      if (marker.test(source)) offenders.push(`${relativePath} contains ${marker}`);
    }
  }

  for (const relativePath of ['.gitignore', 'package.json', 'justfile']) {
    const source = readRepoFile(relativePath);
    for (const marker of retiredMarkers) {
      if (marker.test(source)) offenders.push(`${relativePath} contains ${marker}`);
    }
  }

  for (const relativePath of currentDocumentationPaths) {
    const source = readRepoFile(relativePath);
    for (const marker of [
      /HSS/,
      /Hss/,
      /hss/,
      /ecdsaClientSignerWasm/,
      /EcdsaClientSignerWasm/,
      /ecdsa_client_signer/,
      /ecdsa-client-signer/,
      /ethSigner/,
      /EthSigner/,
      /ETH_SIGNER/,
      /eth_signer/,
      /eth-signer/,
    ]) {
      if (marker.test(source)) offenders.push(`${relativePath} contains ${marker}`);
    }
  }

  assertNoOffenders(
    'active package, fixture, generated-binding, build, test, and current documentation surfaces must use current vocabulary',
    offenders,
  );
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

  const deletedGenericServicePaths = [
    'packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts',
    'packages/sdk-server-ts/src/core/ThresholdService/createThresholdSigningService.ts',
    'packages/sdk-server-ts/src/core/ThresholdService/createCloudflareDurableObjectThresholdSigningService.ts',
    'tests/helpers/thresholdServiceTestUtils.ts',
  ];
  for (const relativePath of deletedGenericServicePaths) {
    assert.equal(
      fs.existsSync(path.join(repoRoot, relativePath)),
      false,
      `deleted generic threshold service path was restored: ${relativePath}`,
    );
  }

  const forbiddenGenericServiceTokens = [
    'ThresholdSigningService',
    'createThresholdSigningService',
    'getThresholdSigningService',
    'ThresholdSigningAdapter',
    'thresholdServiceTestUtils',
  ];
  for (const sourceRoot of sourceRoots) {
    for (const filePath of listFiles(sourceRoot, ['.ts', '.tsx'])) {
      const source = fs.readFileSync(filePath, 'utf8');
      for (const token of forbiddenGenericServiceTokens) {
        if (source.includes(token)) {
          offenders.push(`${path.relative(repoRoot, filePath)} contains ${token}`);
        }
      }
    }
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

function parseCargoTreePackageNames(tree) {
  const packageNames = new Set();
  for (const line of tree.split('\n')) {
    const match = /^([A-Za-z0-9_-]+)\s+v\d/.exec(line.trim());
    if (match) packageNames.add(match[1]);
  }
  return packageNames;
}

function checkLockedEcdsaClientDependencyTree(input) {
  const result = spawnSync(
    'cargo',
    [
      'tree',
      '--locked',
      '--manifest-path',
      input.manifest,
      '--target',
      'wasm32-unknown-unknown',
      '--edges',
      'normal',
      '--prefix',
      'none',
      '--format',
      '{p}',
    ],
    {
      cwd: repoRoot,
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  assert.equal(
    result.status,
    0,
    `locked ${input.label} cargo tree failed\n${result.stderr || result.stdout}`,
  );

  const packageNames = parseCargoTreePackageNames(result.stdout);
  assert.ok(
    packageNames.has(input.rootPackage),
    `locked dependency tree is missing the ${input.label} root package`,
  );
  assert.ok(
    packageNames.has('router-ab-ecdsa-derivation'),
    'locked dependency tree is missing the role-local derivation owner',
  );
  assert.ok(
    packageNames.has('signer-core'),
    'locked dependency tree is missing the narrow signer-core client boundary',
  );

  const offenders = [];
  for (const [packageName, responsibility] of forbiddenEcdsaDerivationClientPackages) {
    if (packageNames.has(packageName)) {
      offenders.push(`${packageName}: ${responsibility}`);
    }
  }
  assertNoOffenders(
    `locked ${input.label} dependency tree contains forbidden ownership`,
    offenders,
  );
}

function checkLockedEcdsaClientDependencyTrees() {
  checkLockedEcdsaClientDependencyTree({
    manifest: ecdsaRegistrationClientManifest,
    rootPackage: 'ecdsa_registration_client',
    label: 'ECDSA registration client',
  });
  checkLockedEcdsaClientDependencyTree({
    manifest: ecdsaDerivationClientManifest,
    rootPackage: 'router_ab_ecdsa_derivation_client',
    label: 'ECDSA export client',
  });
}

function isAllowedWasmBindgenRuntimeExport(name) {
  return name === 'memory' || name.startsWith('__wbindgen_') || name.startsWith('__externref_');
}

function checkForbiddenArtifactTokens(label, values) {
  const offenders = [];
  for (const value of values) {
    const normalized = value.toLowerCase();
    for (const token of forbiddenEcdsaDerivationArtifactTokens) {
      if (normalized.includes(token)) offenders.push(`${value} contains ${token}`);
    }
  }
  assertNoOffenders(label, offenders);
}

function checkForbiddenArtifactSource(label, source) {
  const offenders = [];
  const normalized = source.toLowerCase();
  for (const token of forbiddenEcdsaDerivationArtifactTokens) {
    if (normalized.includes(token)) offenders.push(token);
  }
  assertNoOffenders(label, offenders);
}

function generatedTypeScriptFunctionExports(source) {
  const exports = [];
  const pattern = /^export function ([A-Za-z0-9_]+)/gm;
  for (let match = pattern.exec(source); match; match = pattern.exec(source)) {
    exports.push(match[1]);
  }
  return exports;
}

function checkOpaqueEcdsaClientCeremonySourceBoundary() {
  const roots = [
    'packages/sdk-web/src',
    'packages/shared-ts/src',
    'wasm/ecdsa_registration_client/src',
    'wasm/router_ab_ecdsa_derivation_client/src',
  ];
  const offenders = [];
  for (const relativeRoot of roots) {
    for (const filePath of listFiles(path.join(repoRoot, relativeRoot), ['.ts', '.tsx', '.rs'])) {
      const source = fs.readFileSync(filePath, 'utf8');
      for (const token of forbiddenRawEcdsaClientSecretBoundaryTokens) {
        if (source.includes(token)) {
          offenders.push(`${path.relative(repoRoot, filePath)} contains ${token}`);
        }
      }
    }
  }
  assertNoOffenders(
    'Router A/B ECDSA client private material must remain inside the opaque Rust ceremony',
    offenders,
  );
}

function checkGeneratedEcdsaRegistrationClientArtifactSurface() {
  const wasmPath = path.join(repoRoot, ecdsaRegistrationClientWasm);
  const generatedJsPath = path.join(repoRoot, ecdsaRegistrationClientGeneratedJs);
  const generatedTypesPath = path.join(repoRoot, ecdsaRegistrationClientGeneratedTypes);
  for (const requiredPath of [wasmPath, generatedJsPath, generatedTypesPath]) {
    assert.ok(
      fs.existsSync(requiredPath),
      `missing generated ECDSA registration client artifact: ${path.relative(repoRoot, requiredPath)}; run pnpm -C packages/sdk-web build:wasm`,
    );
  }

  const wasmBytes = fs.readFileSync(wasmPath);
  const module = new WebAssembly.Module(wasmBytes);
  const wasmImports = WebAssembly.Module.imports(module);
  const wasmExports = WebAssembly.Module.exports(module);
  const unexpectedImports = [];
  for (const entry of wasmImports) {
    const allowedName = entry.name.startsWith('__wbindgen_') || entry.name.startsWith('__wbg_');
    if (entry.module !== 'wbg' || entry.kind !== 'function' || !allowedName) {
      unexpectedImports.push(`${entry.module}.${entry.name}:${entry.kind}`);
    }
  }
  assertNoOffenders(
    'generated ECDSA registration client WASM has unexpected host imports',
    unexpectedImports,
  );

  const namedWasmExports = wasmExports.map((entry) => entry.name);
  const unexpectedExports = wasmExports
    .filter((entry) => {
      return (
        !allowedEcdsaRegistrationClientExports.has(entry.name) &&
        !isAllowedWasmBindgenRuntimeExport(entry.name)
      );
    })
    .map((entry) => `${entry.name}:${entry.kind}`);
  assertNoOffenders(
    'generated ECDSA registration client WASM exposes a post-registration API',
    unexpectedExports,
  );
  for (const requiredExport of allowedEcdsaRegistrationClientExports) {
    assert.ok(
      namedWasmExports.includes(requiredExport),
      `generated ECDSA registration client WASM is missing ${requiredExport}`,
    );
  }

  const generatedJs = fs.readFileSync(generatedJsPath, 'utf8');
  const generatedTypes = fs.readFileSync(generatedTypesPath, 'utf8');
  const typeFunctionExports = generatedTypeScriptFunctionExports(generatedTypes);
  const unexpectedTypeExports = typeFunctionExports.filter((exportName) => {
    return exportName !== 'initSync' && !allowedEcdsaRegistrationClientExports.has(exportName);
  });
  assertNoOffenders(
    'generated ECDSA registration client TypeScript exposes a post-registration API',
    unexpectedTypeExports,
  );
  for (const requiredExport of allowedEcdsaRegistrationClientExports) {
    assert.ok(
      typeFunctionExports.includes(requiredExport),
      `generated ECDSA registration client TypeScript is missing ${requiredExport}`,
    );
  }
  for (const forbiddenToken of [
    'build_ecdsa_role_local_export_artifact_v1',
    'RouterAbEcdsaClientCeremonyV1',
    'build_explicit_export_request',
    'build_recovery_request',
    'build_activation_refresh_request',
  ]) {
    assert.equal(
      generatedJs.includes(forbiddenToken) || generatedTypes.includes(forbiddenToken),
      false,
      `generated ECDSA registration client artifact contains ${forbiddenToken}`,
    );
  }

  const gzipBytes = gzipSync(wasmBytes, { level: 9 }).length;
  const brotliBytes = brotliCompressSync(wasmBytes, {
    params: {
      [zlibConstants.BROTLI_PARAM_QUALITY]: 11,
    },
  }).length;
  assert.ok(
    gzipBytes <= 100 * 1024,
    `ECDSA registration client WASM exceeds the 100 KiB gzip budget: ${gzipBytes} bytes`,
  );
  assert.ok(
    brotliBytes <= 85 * 1024,
    `ECDSA registration client WASM exceeds the 85 KiB Brotli budget: ${brotliBytes} bytes`,
  );

  const importAndExportNames = [...namedWasmExports, ...typeFunctionExports];
  for (const entry of wasmImports) {
    importAndExportNames.push(entry.module, entry.name);
  }
  checkForbiddenArtifactTokens(
    'generated ECDSA registration client import/export names retain forbidden ownership',
    importAndExportNames,
  );
  checkForbiddenArtifactSource(
    `${ecdsaRegistrationClientGeneratedJs} retains forbidden ownership`,
    generatedJs,
  );
  checkForbiddenArtifactSource(
    `${ecdsaRegistrationClientGeneratedTypes} retains forbidden ownership`,
    generatedTypes,
  );
}

function checkGeneratedEcdsaDerivationClientArtifactSurface() {
  const wasmPath = path.join(repoRoot, ecdsaDerivationClientWasm);
  const generatedJsPath = path.join(repoRoot, ecdsaDerivationClientGeneratedJs);
  const generatedTypesPath = path.join(repoRoot, ecdsaDerivationClientGeneratedTypes);
  for (const requiredPath of [wasmPath, generatedJsPath, generatedTypesPath]) {
    assert.ok(
      fs.existsSync(requiredPath),
      `missing generated ECDSA derivation client artifact: ${path.relative(repoRoot, requiredPath)}; run pnpm -C packages/sdk-web build:wasm`,
    );
  }

  const module = new WebAssembly.Module(fs.readFileSync(wasmPath));
  const wasmImports = WebAssembly.Module.imports(module);
  const wasmExports = WebAssembly.Module.exports(module);
  const unexpectedImports = [];
  for (const entry of wasmImports) {
    const allowedName = entry.name.startsWith('__wbindgen_') || entry.name.startsWith('__wbg_');
    if (entry.module !== 'wbg' || entry.kind !== 'function' || !allowedName) {
      unexpectedImports.push(`${entry.module}.${entry.name}:${entry.kind}`);
    }
  }
  assertNoOffenders(
    'generated ECDSA derivation client WASM has unexpected host imports',
    unexpectedImports,
  );

  const unexpectedExports = [];
  const namedWasmExports = [];
  for (const entry of wasmExports) {
    namedWasmExports.push(entry.name);
    if (
      !allowedEcdsaDerivationClientExports.has(entry.name) &&
      !allowedEcdsaClientCeremonyWasmExports.has(entry.name) &&
      !isAllowedWasmBindgenRuntimeExport(entry.name)
    ) {
      unexpectedExports.push(`${entry.name}:${entry.kind}`);
    }
  }
  assertNoOffenders(
    'generated ECDSA derivation client WASM exposes a non-client API',
    unexpectedExports,
  );
  for (const requiredExport of allowedEcdsaDerivationClientExports) {
    assert.ok(
      namedWasmExports.includes(requiredExport),
      `generated ECDSA derivation client WASM is missing ${requiredExport}`,
    );
  }
  for (const requiredExport of allowedEcdsaClientCeremonyWasmExports) {
    assert.ok(
      namedWasmExports.includes(requiredExport),
      `generated ECDSA derivation client WASM is missing ${requiredExport}`,
    );
  }

  const generatedJs = fs.readFileSync(generatedJsPath, 'utf8');
  const generatedTypes = fs.readFileSync(generatedTypesPath, 'utf8');
  const typeFunctionExports = generatedTypeScriptFunctionExports(generatedTypes);
  const unexpectedTypeExports = [];
  for (const exportName of typeFunctionExports) {
    if (exportName !== 'initSync' && !allowedEcdsaDerivationClientExports.has(exportName)) {
      unexpectedTypeExports.push(exportName);
    }
  }
  assertNoOffenders(
    'generated ECDSA derivation client TypeScript exposes a non-client API',
    unexpectedTypeExports,
  );
  for (const requiredExport of allowedEcdsaDerivationClientExports) {
    assert.ok(
      typeFunctionExports.includes(requiredExport),
      `generated ECDSA derivation client TypeScript is missing ${requiredExport}`,
    );
  }
  assert.ok(
    generatedTypes.includes('export class RouterAbEcdsaClientCeremonyV1 {'),
    'generated ECDSA derivation client TypeScript is missing the opaque ceremony class',
  );
  for (const methodName of requiredEcdsaClientCeremonyTypeMethods) {
    assert.ok(
      generatedTypes.includes(`  ${methodName}(`),
      `generated ECDSA derivation client TypeScript is missing ceremony method ${methodName}`,
    );
  }
  for (const token of forbiddenRawEcdsaClientSecretBoundaryTokens) {
    assert.equal(
      generatedJs.includes(token) || generatedTypes.includes(token),
      false,
      `generated ECDSA derivation client artifact exposes raw secret boundary token ${token}`,
    );
  }

  const importAndExportNames = [...namedWasmExports, ...typeFunctionExports];
  for (const entry of wasmImports) {
    importAndExportNames.push(entry.module, entry.name);
  }
  checkForbiddenArtifactTokens(
    'generated ECDSA derivation client import/export names retain forbidden ownership',
    importAndExportNames,
  );
  checkForbiddenArtifactSource(
    `${ecdsaDerivationClientGeneratedJs} retains forbidden ownership`,
    generatedJs,
  );
  checkForbiddenArtifactSource(
    `${ecdsaDerivationClientGeneratedTypes} retains forbidden ownership`,
    generatedTypes,
  );
}

checkPresignRefillScheduler();
checkNoRuntimeV1DerivationSurfaces();
checkProductionBridgeDoesNotExposeRootMaterial();
checkEcdsaDerivationCrateHasNoOldContextVersionApi();
checkEcdsaDerivationClientHasOneExplicitOwner();
checkRegistrationProofVerificationInitializesBothWasmOwners();
checkActiveSourceUsesCurrentVocabulary();
checkRuntimeArtifactsAreNotSourceSurfaces();
checkRepositorySurfacesUseCurrentVocabulary();
checkNormalSigningHasOneRuntimeOwner();
checkLockedEcdsaClientDependencyTrees();
checkOpaqueEcdsaClientCeremonySourceBoundary();
checkGeneratedEcdsaRegistrationClientArtifactSurface();
checkGeneratedEcdsaDerivationClientArtifactSurface();

console.log('[check-router-ab-ecdsa-derivation-boundaries] passed');

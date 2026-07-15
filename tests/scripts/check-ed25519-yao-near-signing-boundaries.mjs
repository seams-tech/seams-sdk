#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoSource(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function requireSourceSlice(source, startMarker, endMarker, relativePath) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.ok(start >= 0, `${relativePath} is missing ${startMarker}`);
  assert.ok(end > start, `${relativePath} is missing ${endMarker} after ${startMarker}`);
  return source.slice(start, end);
}

function requireDeleted(relativePath) {
  assert.equal(
    fs.existsSync(path.join(repoRoot, relativePath)),
    false,
    `${relativePath} must stay deleted`,
  );
}

function listSourceFiles(relativeDirectory, filePattern = /\.(?:ts|tsx|js|mjs)$/) {
  const absoluteDirectory = path.join(repoRoot, relativeDirectory);
  const files = [];
  for (const entry of fs.readdirSync(absoluteDirectory, { withFileTypes: true })) {
    const relativePath = path.join(relativeDirectory, entry.name);
    if (entry.isDirectory()) {
      files.push(...listSourceFiles(relativePath, filePattern));
      continue;
    }
    if (filePattern.test(entry.name)) {
      files.push(relativePath);
    }
  }
  return files;
}

const signingFlows = [
  'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts',
];
const executorPath =
  'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519YaoNormalSigning.ts';
const executor = readRepoSource(executorPath);
const registrationOperationPath =
  'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts';
const registrationOperation = readRepoSource(registrationOperationPath);
const ed25519AddSignerPath =
  'packages/sdk-web/src/core/signingEngine/flows/registration/services/passkeyEd25519YaoAddSigner.ts';
const ed25519AddSigner = readRepoSource(ed25519AddSignerPath);

for (const marker of [
  'ed25519_yao_add_signer_unavailable',
  'Ed25519 Yao add-signer is unavailable',
]) {
  assert.ok(
    !registrationOperation.includes(marker),
    `${registrationOperationPath} contains obsolete add-signer placeholder ${marker}`,
  );
}
assert.match(registrationOperation, /await registerVerifiedPasskeyEd25519YaoAddSignerV1\(/);

const ed25519AddSignerOperation = requireSourceSlice(
  registrationOperation,
  'async function addPasskeyEd25519YaoWalletSigner(',
  'async function addPasskeyEcdsaWalletSigner(',
  registrationOperationPath,
);
const ecdsaAddSignerOperation = requireSourceSlice(
  registrationOperation,
  'async function addPasskeyEcdsaWalletSigner(',
  'async function dispatchPasskeyWalletAddSigner(',
  registrationOperationPath,
);

for (const marker of [
  "kind: 'near_ed25519'",
  'activationReference: pending.activationReference()',
  "'wallet-ed25519-add-signer-finalize'",
]) {
  assert.ok(
    ed25519AddSignerOperation.includes(marker),
    `${registrationOperationPath} Ed25519 add-signer is missing ${marker}`,
  );
}

for (const marker of [
  'preparePasskeyEcdsaBootstrap',
  'respondWalletAddSignerEcdsa',
  'parseWalletRegistrationEcdsaHssRespond',
  'ThresholdSigningService',
]) {
  assert.ok(
    !ed25519AddSigner.includes(marker),
    `${ed25519AddSignerPath} crosses into the ECDSA add-signer branch via ${marker}`,
  );
  assert.ok(
    !ed25519AddSignerOperation.includes(marker),
    `${registrationOperationPath} Ed25519 add-signer crosses into ECDSA via ${marker}`,
  );
}

for (const marker of [
  'registerVerifiedPasskeyEd25519YaoAddSignerV1',
  'PendingProductEd25519YaoRegistrationV1',
  'router_ab_ed25519_yao_activation_reference_v1',
]) {
  assert.ok(
    !ecdsaAddSignerOperation.includes(marker),
    `${registrationOperationPath} ECDSA add-signer crosses into Yao via ${marker}`,
  );
}

for (const relativePath of signingFlows) {
  const source = readRepoSource(relativePath);
  assert.match(source, /tryFinalizeRouterAbEd25519(?:NearTransaction|SignatureOnly)NormalSigning/);
  assert.doesNotMatch(source, /Hss|HSS|hssLifecycle|workerMaterialHandle|presignPool/);
  assert.doesNotMatch(source, /deriver|Deriver/);
}

for (const marker of [
  'prepareRouterAbNormalSigningV2',
  'activeClient.createSigningShare',
  'finalizeRouterAbNormalSigningV2',
  'requireActiveClientMatchesNormalSigningOperation',
]) {
  assert.ok(executor.includes(marker), `${executorPath} must contain ${marker}`);
}
assert.doesNotMatch(executor, /Hss|HSS|hssLifecycle|workerMaterialHandle|presignPool/);
assert.doesNotMatch(executor, /\/threshold-ed25519\//);

for (const relativePath of [
  'crates/ed25519-hss',
  'benchmarks/ed25519-hss-advance-sources',
  'benchmarks/ed25519-hss-tail',
  'benchmarks/ed25519-hss-wasm',
  'packages/shared-ts/src/threshold/ed25519HssBinding.ts',
  'packages/sdk-web/src/core/signingEngine/session/ed25519MaterialAdvance.ts',
  'packages/sdk-web/src/core/signingEngine/session/ed25519MaterialAuthority.ts',
  'packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssClientBase.ts',
  'packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts',
  'packages/sdk-web/src/core/signingEngine/threshold/ed25519/workerMaterialHandle.ts',
  'packages/sdk-web/src/core/signingEngine/threshold/ed25519/presignPool.ts',
  'packages/sdk-web/src/core/signingEngine/flows/recovery/nearEd25519ExportFlow.ts',
  'packages/sdk-web/src/core/signingEngine/flows/recovery/nearEd25519HssExport.ts',
  'packages/sdk-web/src/core/signingEngine/flows/recovery/nearEd25519SeedReportExport.ts',
  'wasm/near_signer/src/handlers/handle_threshold_ed25519_derive_hss_client_inputs.rs',
  'docs/hss-threshold-ed25519.md',
  'docs/hss-separate-wasm.md',
  'docs/hss-export-key.md',
  'docs/threshold-ed25519/stateless-shared-root.md',
  'crates/seams-embedded/docs/robotics-hss-key-choice.md',
]) {
  requireDeleted(relativePath);
}

const ed25519ExportOperationPath =
  'packages/sdk-web/src/core/signingEngine/flows/recovery/ed25519YaoExportFlow.ts';
const ed25519ExportOperation = readRepoSource(ed25519ExportOperationPath);
for (const marker of [
  'exportEd25519YaoKeyWithFreshPasskey',
  'resolveActiveCapability',
  'artifactKind: ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1',
  'resolveExportContext',
  'exportSeedWithFreshAuthorization',
]) {
  assert.ok(
    ed25519ExportOperation.includes(marker),
    `${ed25519ExportOperationPath} is missing strict Yao export marker ${marker}`,
  );
}
for (const forbidden of [
  /Hss|HSS|hssLifecycle/,
  /seedB64u/,
  /deriver_[ab]_client_package/,
  /localStorage|indexedDB|setAppState|console\.(?:log|warn|error)/,
]) {
  assert.doesNotMatch(
    ed25519ExportOperation,
    forbidden,
    `${ed25519ExportOperationPath} leaks secret export handling outside the secure worker/WASM boundary`,
  );
}

const ed25519ExportWorkerPath =
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts';
const ed25519ExportWorker = readRepoSource(ed25519ExportWorkerPath);
for (const marker of [
  'runEd25519YaoExportWithUi',
  "requirePrfB64uFromCredential(credential, 'first')",
  'deriveRouterAbEd25519YaoExportConfirmationDigestV1',
  'RouterAbEd25519YaoClientV1.initializeBundled()',
]) {
  assert.ok(
    ed25519ExportWorker.includes(marker),
    `${ed25519ExportWorkerPath} is missing secure export marker ${marker}`,
  );
}

for (const relativePath of listSourceFiles('packages/sdk-web/src')) {
  if (
    relativePath === ed25519ExportWorkerPath ||
    relativePath === 'packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoClient.ts'
  ) {
    continue;
  }
  const source = readRepoSource(relativePath);
  assert.doesNotMatch(
    source,
    /Wasm(?:PasskeyClient|EmailOtpClient)ExportSessionV1|take_export_artifact_json|deriver_[ab]_client_package/,
    `${relativePath} bypasses the secure Ed25519 export worker/WASM boundary`,
  );
}

const forbiddenEd25519HssPatterns = [
  /Ed25519Hss/,
  /ed25519Hss/,
  /ed25519_hss/,
  /threshold-ed25519-hss/,
  /Ed25519WorkerMaterial/,
  /ed25519WorkerMaterial/,
  /sealedWorkerMaterial/,
  /threshold_ed25519_derive_hss/,
];
const forbiddenPromotedLocalYaoPatterns = [/LocalRouterAbEd25519Yao/];
const forbiddenEd25519YaoPlaceholderPatterns = [
  /ed25519_yao_(?:registration|recovery|add_signer|iframe|email_otp)_(?:unavailable|unsupported)/i,
  /ed25519_yao_[a-z0-9_]*(?:not_implemented|placeholder)/i,
  /Ed25519 Yao (?:registration|recovery|add-signer|iframe|Email OTP) (?:is )?(?:unavailable|unsupported|not implemented)/i,
];
const retiredSplitDerivationPatterns = [
  /\/router-ab\/split-derivation/,
  /\/router-ab\/signer-[ab]\/ed25519-yao/,
  /CLOUDFLARE_ROUTER_SPLIT_DERIVATION_PUBLIC_REQUEST_PATH/,
  /handle_cloudflare_router_recipient_proof_bundle_authenticated_public_request_v1/,
  /CloudflareRouterRecipientProofBundleAdmissionResponseV1/,
];

for (const relativePath of [
  'wasm/ecdsa_client_signer/pkg/ecdsa_client_signer.d.ts',
  'wasm/ecdsa_client_signer/pkg/ecdsa_client_signer.js',
  'wasm/near_signer/pkg/wasm_signer_worker.d.ts',
  'wasm/near_signer/pkg/wasm_signer_worker.js',
]) {
  const generatedSource = readRepoSource(relativePath);
  for (const pattern of forbiddenEd25519HssPatterns) {
    assert.doesNotMatch(
      generatedSource,
      pattern,
      `${relativePath} contains a generated export for deleted Ed25519 HSS code`,
    );
  }
}

for (const relativeDirectory of [
  'packages/shared-ts/src',
  'packages/sdk-server-ts/src',
  'packages/sdk-web/src',
  'tests/unit',
]) {
  for (const relativePath of listSourceFiles(relativeDirectory)) {
    const source = readRepoSource(relativePath);
    for (const pattern of forbiddenEd25519HssPatterns) {
      assert.doesNotMatch(source, pattern, `${relativePath} contains deleted Ed25519 HSS code`);
    }
    for (const pattern of forbiddenEd25519YaoPlaceholderPatterns) {
      assert.doesNotMatch(
        source,
        pattern,
        `${relativePath} contains an obsolete Ed25519 Yao placeholder`,
      );
    }
    if (relativePath.startsWith('packages/')) {
      for (const pattern of forbiddenPromotedLocalYaoPatterns) {
        assert.doesNotMatch(
          source,
          pattern,
          `${relativePath} contains obsolete local-only Yao type naming`,
        );
      }
    }
  }
}

const retiredSplitDerivationActiveFiles = [
  ...listSourceFiles('crates/router-ab-cloudflare/src', /\.rs$/),
  ...listSourceFiles('crates/router-ab-dev/src', /\.rs$/),
  ...listSourceFiles('packages/shared-ts/src'),
  ...listSourceFiles('packages/sdk-server-ts/src'),
  ...listSourceFiles('packages/sdk-web/src'),
  ...listSourceFiles('apps/docs/src', /\.(?:ts|tsx|js|mjs|md|mdx)$/),
  'crates/router-ab-cloudflare/scripts/assert-release-ready.mjs',
  'crates/router-ab-cloudflare/Cargo.toml',
  'crates/router-ab-cloudflare/package.json',
  'crates/router-ab-cloudflare/wrangler.router.toml',
  'crates/router-ab-cloudflare/wrangler.deriver-a.toml',
  'crates/router-ab-cloudflare/wrangler.deriver-b.toml',
  'docs/router-a-b-local-dev.md',
  'docs/router-a-b-SPEC.md',
];
for (const relativePath of retiredSplitDerivationActiveFiles) {
  const source = readRepoSource(relativePath);
  for (const pattern of retiredSplitDerivationPatterns) {
    assert.doesNotMatch(
      source,
      pattern,
      `${relativePath} revives the retired generic split-derivation route`,
    );
  }
}

console.log('[check-ed25519-yao-near-signing-boundaries] passed');

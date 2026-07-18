#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SDK_WEB_SRC = 'packages/sdk-web/src';
const ECDSA_HANDLE_MODULE =
  'packages/sdk-web/src/core/signingEngine/session/identity/ecdsaDerivationSigningMaterialHandle.ts';

function absolutePath(relativePath) {
  return path.join(repoRoot, relativePath);
}

function readRepoSource(relativePath) {
  return fs.readFileSync(absolutePath(relativePath), 'utf8');
}

function assertContains(source, marker, label) {
  assert.ok(source.includes(marker), `${label}: missing ${marker}`);
}

function assertNotContains(source, marker, label) {
  assert.ok(!source.includes(marker), `${label}: unexpectedly contained ${marker}`);
}

function extractSourceBlock(source, startMarker, endMarker, label) {
  const start = source.indexOf(startMarker);
  assert.ok(start >= 0, `${label}: missing start marker ${startMarker}`);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.ok(end > start, `${label}: missing end marker ${endMarker}`);
  return source.slice(start, end + endMarker.length);
}

function countOccurrences(source, needle) {
  return source.split(needle).length - 1;
}

function assertSourceOrder(source, earlier, later, label) {
  const earlierIndex = source.indexOf(earlier);
  const laterIndex = source.indexOf(later);
  assert.ok(earlierIndex >= 0, `${label}: missing earlier marker ${earlier}`);
  assert.ok(laterIndex >= 0, `${label}: missing later marker ${later}`);
  assert.ok(earlierIndex < laterIndex, `${label}: expected ${earlier} before ${later}`);
}

function listTypeScriptFiles(relativePath) {
  const absoluteRoot = absolutePath(relativePath);
  const stat = fs.statSync(absoluteRoot);
  if (stat.isFile()) return /\.(ts|tsx)$/.test(relativePath) ? [relativePath] : [];

  const files = [];
  for (const entry of fs.readdirSync(absoluteRoot, { withFileTypes: true })) {
    if (entry.name === 'dist' || entry.name === 'node_modules') continue;
    const childPath = path.join(relativePath, entry.name).split(path.sep).join('/');
    if (entry.isDirectory()) files.push(...listTypeScriptFiles(childPath));
    if (entry.isFile() && /\.(ts|tsx)$/.test(entry.name)) files.push(childPath);
  }
  return files;
}

function assertSourceHasAll(source, markers, label) {
  const missingMarkers = [];
  for (const marker of markers) {
    if (!source.includes(marker)) missingMarkers.push(marker);
  }
  assert.deepEqual(missingMarkers, [], `${label}: missing markers\n${missingMarkers.join('\n')}`);
}

function checkRoleLocalEcdsaMaterialHandlesAreIdentityLocal() {
  const offenders = [];
  for (const relativePath of listTypeScriptFiles(SDK_WEB_SRC)) {
    if (relativePath === ECDSA_HANDLE_MODULE) continue;
    if (readRepoSource(relativePath).includes('router-ab-ecdsa-role-local:')) {
      offenders.push(relativePath);
    }
  }

  assert.deepEqual(offenders, [], `role-local ECDSA handle offenders\n${offenders.join('\n')}`);
  assertContains(
    readRepoSource(ECDSA_HANDLE_MODULE),
    'EcdsaRoleLocalMaterialBinding',
    ECDSA_HANDLE_MODULE,
  );
}

function checkWalletScopedUnlockAvoidsCollapsedNearBindingError() {
  const walletAuth = readRepoSource('packages/sdk-web/src/SeamsWeb/operations/auth/walletAuth.ts');
  assertNotContains(
    walletAuth,
    'wallet-scoped auth requires a resolved NEAR account binding',
    'walletAuth',
  );
  assertContains(walletAuth, 'WalletUnlockSubject', 'walletAuth');
}

function checkVisibleIframePasskeyRegistrationUsesProvidedWalletId() {
  const publicTypes = readRepoSource('packages/sdk-web/src/SeamsWeb/publicApi/types.ts');
  const messages = readRepoSource('packages/sdk-web/src/SeamsWeb/walletIframe/shared/messages.ts');
  const controller = readRepoSource(
    'packages/sdk-web/src/react/components/SeamsAuthMenu/controller/useSeamsAuthMenuController.ts',
  );
  const client = readRepoSource(
    'packages/sdk-web/src/react/components/SeamsAuthMenu/client.tsx',
  );

  assertContains(controller, 'type PasskeyRegistrationDraft', 'SeamsAuthMenu controller');
  assertContains(controller, 'createReadableWalletId()', 'SeamsAuthMenu controller');
  assertContains(
    controller,
    'props.onRegister?.(registrationRequest)',
    'SeamsAuthMenu controller',
  );
  assertContains(client, 'onClick={controller.onProceed}', 'SeamsAuthMenu client');
  assertNotContains(
    publicTypes,
    'CreatePasskeyRegistrationActivationSurfaceArgs',
    'registration public types',
  );
  assertNotContains(
    messages,
    'PM_REGISTRATION_ACTIVATION_PREPARE',
    'wallet iframe messages',
  );
}


function checkPostStartRegistrationRoutesUseStoredPreparedState() {
  const service = readRepoSource(
    'packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts',
  );
  const startBlock = extractSourceBlock(
    service,
    '  async startWalletRegistration(',
    '  async respondWalletRegistrationEcdsaDerivation(',
    'startWalletRegistration',
  );
  const respondBlock = extractSourceBlock(
    service,
    '  async respondWalletRegistrationEcdsaDerivation(',
    '  async finalizeWalletRegistration(',
    'respondWalletRegistrationEcdsaDerivation',
  );
  const finalizeStart = service.indexOf('  async finalizeWalletRegistration(');
  assert.ok(finalizeStart >= 0, 'missing finalizeWalletRegistration');
  const finalizeBlock = service.slice(finalizeStart);

  assertContains(startBlock, 'parseD1RegistrationIntent(request.intent)', 'start block');
  assertNotContains(respondBlock, 'parseD1RegistrationIntent', 'respond block');
  assertNotContains(finalizeBlock, 'parseD1RegistrationIntent', 'finalize block');
  assertContains(
    respondBlock,
    'registrationSignerBranchesFromPlan(ceremony.signerPlan)',
    'respond block',
  );
  assertContains(
    finalizeBlock,
    'registrationSignerBranchesFromPlan(ceremony.signerPlan)',
    'finalize block',
  );
  assertContains(
    startBlock,
    'resolveRegistrationPreparedContextFromPlan({',
    'start block',
  );
  assertContains(startBlock, 'signerPlan: branches.value.plan', 'start block');
  assertContains(startBlock, 'preparedContext: preparedContext.preparedContext', 'start block');
}

function checkRegistrationIntentDigestVerificationStaysAtResponseBoundary() {
  const registration = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  );
  const digestBoundary = extractSourceBlock(
    registration,
    'async function verifyWalletRegistrationIntentResponse(input: {',
    '\n}\n\ntype WalletRegistrationPrecomputeReady',
    'registration intent response verifier',
  );

  assertContains(
    digestBoundary,
    'computeRegistrationIntentDigest(input.intentResponse.intent)',
    'registration intent response verifier',
  );
  assertContains(
    digestBoundary,
    'Registration intent digest mismatch',
    'registration intent response verifier',
  );
  assert.equal(countOccurrences(registration, 'computeRegistrationIntentDigest('), 1);
  assertContains(registration, 'verifyWalletRegistrationIntentResponse({', 'registration');
}

function checkRegistrationTimingKeepsTailBucketsObservational() {
  const registration = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  );
  const zeroBuckets = extractSourceBlock(
    registration,
    'function createZeroRegistrationTimingBucketValues(): RegistrationTimingBucketValues {',
    '\n}\n\nfunction copyRegistrationTimingBucketValues',
    'zero registration timing buckets',
  );
  const criticalPathBuckets = extractSourceBlock(
    registration,
    'const REGISTRATION_CRITICAL_PATH_BUCKETS: readonly RegistrationTimingBucketName[] = [',
    '\n];',
    'registration critical path bucket list',
  );
  const zeroInitializedBuckets = [
    'ecdsaRegistrationPersistenceMs',
    'ecdsaRegistrationSessionFinalizeMs',
    'ecdsaRegistrationLocalRecordPersistenceMs',
    'ecdsaRegistrationTargetCount',
    'ecdsaRegistrationClientFinalizeMs',
    'ecdsaRegistrationClientMaterialStoreMs',
    'ecdsaRegistrationServerBootstrapMs',
    'ecdsaRegistrationPasskeyBootstrapStoreMs',
    'ecdsaRegistrationRoleLocalRecordPersistenceMs',
    'ecdsaRegistrationWarmSessionHydrationMs',
    'ecdsaRegistrationWarmSessionWorkerReadyMs',
    'ecdsaRegistrationWarmSessionWorkerPutMs',
    'ecdsaRegistrationWarmSessionSealedRecordPersistMs',
    'ecdsaRegistrationWarmSessionSealResolveTransportMs',
    'ecdsaRegistrationWarmSessionSealExistingRecordReadMs',
    'ecdsaRegistrationWarmSessionSealPolicyReadMs',
    'ecdsaRegistrationWarmSessionSealApplyServerSealMs',
    'ecdsaRegistrationWarmSessionSealApplyRuntimeSetupMs',
    'ecdsaRegistrationWarmSessionSealApplyClientSealMs',
    'ecdsaRegistrationWarmSessionSealApplyServerRouteMs',
    'ecdsaRegistrationWarmSessionSealApplyClientUnsealMs',
    'ecdsaRegistrationWarmSessionSealApplyPolicyUpdateMs',
    'ecdsaRegistrationWarmSessionSealRegisterMs',
    'ecdsaRegistrationWarmSessionSealVerifyReadMs',
    'ecdsaRegistrationEmailOtpSessionCommitMs',
  ];
  const observationalBuckets = [
    'ecdsaRegistrationSessionFinalizeMs',
    'ecdsaRegistrationLocalRecordPersistenceMs',
    'ecdsaRegistrationTargetCount',
    'ecdsaRegistrationClientFinalizeMs',
    'ecdsaRegistrationClientMaterialStoreMs',
    'ecdsaRegistrationServerBootstrapMs',
    'ecdsaRegistrationPasskeyBootstrapStoreMs',
    'ecdsaRegistrationRoleLocalRecordPersistenceMs',
    'ecdsaRegistrationWarmSessionHydrationMs',
    'ecdsaRegistrationWarmSessionWorkerReadyMs',
    'ecdsaRegistrationWarmSessionWorkerPutMs',
    'ecdsaRegistrationWarmSessionSealedRecordPersistMs',
    'ecdsaRegistrationWarmSessionSealResolveTransportMs',
    'ecdsaRegistrationWarmSessionSealExistingRecordReadMs',
    'ecdsaRegistrationWarmSessionSealPolicyReadMs',
    'ecdsaRegistrationWarmSessionSealApplyServerSealMs',
    'ecdsaRegistrationWarmSessionSealApplyRuntimeSetupMs',
    'ecdsaRegistrationWarmSessionSealApplyClientSealMs',
    'ecdsaRegistrationWarmSessionSealApplyServerRouteMs',
    'ecdsaRegistrationWarmSessionSealApplyClientUnsealMs',
    'ecdsaRegistrationWarmSessionSealApplyPolicyUpdateMs',
    'ecdsaRegistrationWarmSessionSealRegisterMs',
    'ecdsaRegistrationWarmSessionSealVerifyReadMs',
    'ecdsaRegistrationEmailOtpSessionCommitMs',
  ];

  for (const bucket of zeroInitializedBuckets) {
    assertContains(zeroBuckets, `${bucket}: 0`, 'zero registration timing buckets');
  }
  for (const bucket of zeroInitializedBuckets) {
    if (observationalBuckets.includes(bucket)) continue;
    assertContains(criticalPathBuckets, `'${bucket}'`, 'registration critical path bucket list');
  }
  for (const bucket of observationalBuckets) {
    assertNotContains(criticalPathBuckets, `'${bucket}'`, 'registration critical path bucket list');
  }
  assertContains(registration, 'registration_critical_path_summary_v1', 'registration');
  assertContains(registration, 'JSON.stringify(summary)', 'registration');
}

function checkEmailOtpUnlockCurrentSessionsUseCommitCommands() {
  const warmPersistence = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.ts',
  );
  const ecdsaRecords = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/persistence/records.ts',
  );
  const ecdsaPublication = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaPublication.ts',
  );
  const ed25519CurrentCommit = extractSourceBlock(
    warmPersistence,
    'export function persistWarmSessionEd25519Capability',
    'publishResolvedIdentity({',
    'Ed25519 current warm-session commit',
  );
  const ecdsaCurrentCommit = extractSourceBlock(
    ecdsaRecords,
    'export function upsertThresholdEcdsaSessionFromBootstrap',
    'export function upsertThresholdEcdsaSessionFact',
    'ECDSA current session commit',
  );
  assertContains(
    ed25519CurrentCommit,
    'upsertThresholdEd25519SessionFact({',
    'Ed25519 current warm-session commit',
  );
  assertNotContains(
    ed25519CurrentCommit,
    'WorkerMaterial',
    'Ed25519 current warm-session commit',
  );
  assertContains(
    warmPersistence,
    "curve: 'ed25519'",
    'Ed25519 current warm-session commit',
  );
  assertContains(
    ecdsaCurrentCommit,
    'buildOperationUsableThresholdEcdsaSessionRecord',
    'ECDSA current session commit',
  );
  assertContains(
    ecdsaCurrentCommit,
    'commitCurrentThresholdEcdsaSession({',
    'ECDSA current session commit',
  );
  assertContains(
    ecdsaCurrentCommit,
    "transition: args.source === 'registration' ? 'registration' : 'wallet_unlock'",
    'ECDSA current session commit',
  );
  assertContains(ecdsaPublication, 'commitEvmFamilyThresholdEcdsaSessions({', 'ECDSA publication');
  assertContains(
    ecdsaPublication,
    'persistEmailOtpEcdsaSigningSessionSealForUnlock(',
    'ECDSA publication',
  );
  assertNotContains(ecdsaPublication, 'upsertThresholdEcdsaSessionFact', 'ECDSA publication');
}

function main() {
  checkRoleLocalEcdsaMaterialHandlesAreIdentityLocal();
  checkWalletScopedUnlockAvoidsCollapsedNearBindingError();
  checkVisibleIframePasskeyRegistrationUsesProvidedWalletId();
  checkPostStartRegistrationRoutesUseStoredPreparedState();
  checkRegistrationIntentDigestVerificationStaysAtResponseBoundary();
  checkRegistrationTimingKeepsTailBucketsObservational();
  checkEmailOtpUnlockCurrentSessionsUseCommitCommands();
  console.log('[registration-capability-subjects] ok');
}

main();

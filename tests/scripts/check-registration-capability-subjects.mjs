#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SDK_WEB_SRC = 'packages/sdk-web/src';
const ECDSA_HANDLE_MODULE =
  'packages/sdk-web/src/core/signingEngine/session/identity/ecdsaHssSigningMaterialHandle.ts';

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
  const seamsAuthMenuTypes = readRepoSource(
    'packages/sdk-web/src/react/components/SeamsAuthMenu/types.ts',
  );
  const hostNear = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/walletIframe/host/handlers/near.ts',
  );
  const touchIdPrompt = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt.ts',
  );
  const registrationFlow = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/registration.ts',
  );
  const activationSurfaceArgs = extractSourceBlock(
    publicTypes,
    'export type CreatePasskeyRegistrationActivationSurfaceArgs = {',
    '};',
    'passkey registration activation surface args',
  );
  const activationPreparePayload = extractSourceBlock(
    messages,
    'export interface PMRegistrationActivationPreparePayload {',
    '\n}',
    'registration activation prepare payload',
  );

  assertContains(
    activationSurfaceArgs,
    "wallet: Extract<RegisterWalletInput, { kind: 'provided' }>",
    'activation surface args',
  );
  assertContains(
    activationPreparePayload,
    "wallet: Extract<RegisterWalletInput, { kind: 'provided' }>",
    'activation prepare payload',
  );
  assertNotContains(
    activationSurfaceArgs,
    "wallet?: Extract<RegisterWalletInput, { kind: 'provided' }>",
    'activation surface args',
  );
  assertNotContains(
    activationPreparePayload,
    "wallet?: Extract<RegisterWalletInput, { kind: 'provided' }>",
    'activation prepare payload',
  );
  assertContains(controller, 'type PasskeyRegistrationDraft', 'SeamsAuthMenu controller');
  assertContains(controller, 'createReadableWalletId()', 'SeamsAuthMenu controller');
  assertContains(
    controller,
    'createSeamsAuthMenuRegistrationRequest',
    'SeamsAuthMenu controller',
  );
  assertContains(
    controller,
    'props.onRegister?.(registrationRequest)',
    'SeamsAuthMenu controller',
  );
  assertContains(
    seamsAuthMenuTypes,
    'export type SeamsAuthMenuRegistrationRequest =',
    'SeamsAuthMenu types',
  );
  assertContains(seamsAuthMenuTypes, "kind: 'implicit_wallet'", 'SeamsAuthMenu types');
  assertContains(
    seamsAuthMenuTypes,
    "kind: 'sponsored_named_near_account'",
    'SeamsAuthMenu types',
  );
  assertNotContains(seamsAuthMenuTypes, 'onRegister?: (options?:', 'SeamsAuthMenu types');
  assertNotContains(
    controller,
    'props.onRegister?.(registrationOptions)',
    'SeamsAuthMenu controller',
  );
  assertNotContains(controller, 'createServerAllocatedWalletId', 'SeamsAuthMenu controller');
  assertNotContains(controller, 'createReadableRegistrationWalletId', 'SeamsAuthMenu controller');
  assertContains(hostNear, 'parseRegistrationActivationProvidedWallet', 'wallet iframe NEAR host');
  assertNotContains(hostNear, '...(payload.wallet', 'wallet iframe NEAR host');
  assertContains(touchIdPrompt, 'requireExpectedPasskeyRegistrationUser', 'Touch ID prompt');
  assertNotContains(touchIdPrompt, 'generateSignerSlotDisplayName', 'Touch ID prompt');
  assertNotContains(
    registrationFlow,
    'derivePasskeyRegistrationIntendedUserName',
    'registration UI flow',
  );
}

function checkRegistrationSuccessBuildsActiveStateWithoutPersistedLaneInventory() {
  const registration = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  );
  assertSourceHasAll(
    registration,
    [
      'buildRegistrationActiveRuntimeState',
      "'registration_active_runtime_state_v1'",
      'identity: ExactEd25519SigningLaneIdentity;',
      'identities: readonly [ExactEcdsaSigningLaneIdentity, ...ExactEcdsaSigningLaneIdentity[]];',
      'exactEd25519SigningLaneIdentity({',
      'exactEcdsaSigningLaneIdentity({',
      'registration_active_runtime_state_constructed',
    ],
    'registration active state',
  );
  assertNotContains(registration, 'assertImmediateRegistrationSigningLanes', 'registration');
  assertNotContains(registration, 'readPersistedAvailableSigningLanes', 'registration');
}

function checkRegistrationPersistencePlanCarriesExplicitWriteSubjects() {
  const registration = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  );
  assertSourceHasAll(
    registration,
    [
      'type RegistrationPersistenceWriteSubjects =',
      "'registration_persistence_write_subjects_v1'",
      'walletProfile: RegistrationPersistenceWalletProfileSubject;',
      'authMethod: RegistrationPersistenceAuthMethodSubject;',
      'RegistrationPersistenceSignerActivationSubject,',
      'RegistrationPersistenceKeyMaterialSubject,',
      'RegistrationPersistenceRuntimeSessionSubject,',
      'selectedWalletState: RegistrationPersistenceSelectedWalletStateSubject;',
      'function buildRegistrationPersistencePlan(args: {',
      'writeSubjects: buildRegistrationPersistenceWriteSubjects(args)',
      'const persistencePlan = buildRegistrationPersistencePlan({',
    ],
    'registration persistence plan',
  );
  assertNotContains(
    registration,
    'const persistencePlan: RegistrationPersistencePlan = {',
    'registration persistence plan',
  );
}

function checkPostPrepareRegistrationRoutesUseStoredPreparedState() {
  const service = readRepoSource(
    'packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts',
  );
  const prepareBlock = extractSourceBlock(
    service,
    '  async prepareWalletRegistration(',
    '  async startWalletRegistration(',
    'prepareWalletRegistration',
  );
  const startBlock = extractSourceBlock(
    service,
    '  async startWalletRegistration(',
    '  async respondWalletRegistrationHss(',
    'startWalletRegistration',
  );
  const respondBlock = extractSourceBlock(
    service,
    '  async respondWalletRegistrationHss(',
    '  async finalizeWalletRegistration(',
    'respondWalletRegistrationHss',
  );
  const finalizeStart = service.indexOf('  async finalizeWalletRegistration(');
  assert.ok(finalizeStart >= 0, 'missing finalizeWalletRegistration');
  const finalizeBlock = service.slice(finalizeStart);

  assertContains(prepareBlock, 'parseD1RegistrationIntent(request.intent)', 'prepare block');
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
  assertContains(startBlock, 'preparedRegistrationState.preparation.signerPlan', 'start block');
  assertContains(
    startBlock,
    'preparedRegistrationState.preparation.preparedContext',
    'start block',
  );
}

function checkRegistrationPrecomputeOwnershipIsScopeChecked() {
  const registration = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  );
  const googleEmailOtpFlow = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts',
  );

  assertSourceHasAll(
    registration,
    [
      'type RegisterWalletPrecomputeMode =',
      "kind: 'start_inside_register_wallet'",
      "kind: 'use_started_precompute'",
      'assertWalletRegistrationPrecomputeScopeMatches({',
      'Started wallet registration precompute scope mismatch',
      'export async function registerWallet(',
      "precomputeMode: { kind: 'start_inside_register_wallet' }",
      'export async function registerWalletWithStartedPrecompute(',
      "kind: 'use_started_precompute'",
    ],
    'registration precompute ownership',
  );
  assertSourceHasAll(
    googleEmailOtpFlow,
    [
      'const precompute = deps.startWalletRegistrationPrecompute(registrationArgs);',
      'deps.registerWalletWithStartedPrecompute({',
      "precompute.kind === 'started'",
      'disposeWalletRegistrationPrecompute(precompute.handle)',
    ],
    'Google Email OTP registration precompute',
  );
}

function checkRegistrationIntentDigestVerificationStaysAtResponseBoundary() {
  const registration = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  );
  const digestBoundary = extractSourceBlock(
    registration,
    'async function verifyWalletRegistrationIntentResponse(input: {',
    '\n}\n\nfunction walletScopeKey',
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
    'thresholdEd25519SessionPersistenceMs',
    'thresholdEd25519KeyMaterialPersistenceMs',
    'thresholdEd25519SessionNormalizeMs',
    'thresholdEd25519WarmMaterialValidationMs',
    'thresholdEd25519WarmCapabilityPersistenceMs',
    'thresholdEd25519WorkerMaterialPersistenceMs',
    'thresholdEd25519SigningSessionHydrationMs',
    'thresholdEd25519SealedSessionPersistenceMs',
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
    'walletStateActivationMs',
    'immediateSigningLaneAssertionMs',
  ];
  const observationalBuckets = [
    'thresholdEd25519SessionPersistenceMs',
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
  assertNotContains(
    registration,
    'threshold_ed25519_warm_material_reconstruction_started',
    'registration',
  );
}

function checkRegistrationWorkerMaterialIsStoredFromFinalizedHssReport() {
  const bootstrap = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts',
  );
  const passkeyRegistrationStore = extractSourceBlock(
    bootstrap,
    'async function persistPasskeyRegisteredThresholdEd25519WorkerMaterial(args: {',
    '\n}\n\nasync function refreshDurableThresholdEd25519SealedSessionWithWorkerMaterial',
    'passkey registration worker material persistence',
  );
  const emailOtpRegistrationStore = extractSourceBlock(
    bootstrap,
    'async function persistEmailOtpRegisteredThresholdEd25519WorkerMaterial(args: {',
    '\n}\n\nexport async function reconstructThresholdEd25519SigningMaterialFromWarmSession',
    'Email OTP registration worker material persistence',
  );

  for (const block of [passkeyRegistrationStore, emailOtpRegistrationStore]) {
    assertContains(
      block,
      'storeThresholdEd25519WorkerMaterialFromFinalizedHssReport',
      'registration worker material persistence',
    );
    assertNotContains(
      block,
      'runThresholdEd25519HssCeremonyWithMaterialHandle',
      'registration worker material persistence',
    );
    assertContains(
      block,
      'finalizedRegistrationHssMaterial',
      'registration worker material persistence',
    );
  }
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
  const sealedRestore = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts',
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
  const exactSealedRestore = extractSourceBlock(
    sealedRestore,
    'function upsertEd25519SessionRecordFromExactSealedWorkerMaterial',
    'export async function hydrateAccountScopedDiscoveryEd25519SessionFromDurableSealedWorkerMaterial',
    'exact sealed restore',
  );
  const reusableSealedRestore = extractSourceBlock(
    sealedRestore,
    'function upsertEd25519SessionRecordFromReusableSealedWorkerMaterial',
    'export async function resolveReusableEd25519WorkerMaterialForLoginSession',
    'reusable sealed restore',
  );
  const reusableLoginMaterialPersistence = extractSourceBlock(
    sealedRestore,
    'export function persistEd25519LoginSessionFromReusableWorkerMaterial',
    'type Ed25519DurableRestoreLookupResult',
    'reusable login material persistence',
  );

  assertContains(
    ed25519CurrentCommit,
    'buildOperationUsableThresholdEd25519SessionRecord',
    'Ed25519 current warm-session commit',
  );
  assertContains(
    ed25519CurrentCommit,
    'commitCurrentThresholdEd25519Session({',
    'Ed25519 current warm-session commit',
  );
  assertContains(
    ed25519CurrentCommit,
    "source === 'email_otp' ? 'step_up' : 'wallet_unlock'",
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
  assertContains(exactSealedRestore, 'upsertThresholdEd25519SessionFact({', 'exact sealed restore');
  assertNotContains(
    exactSealedRestore,
    'commitCurrentThresholdEd25519Session',
    'exact sealed restore',
  );
  assertContains(
    reusableSealedRestore,
    'upsertThresholdEd25519SessionFact({',
    'reusable sealed restore',
  );
  assertNotContains(
    reusableSealedRestore,
    'commitCurrentThresholdEd25519Session',
    'reusable sealed restore',
  );
  assertContains(
    reusableLoginMaterialPersistence,
    'upsertThresholdEd25519SessionFact({',
    'reusable login material persistence',
  );
  assertNotContains(
    reusableLoginMaterialPersistence,
    'commitCurrentThresholdEd25519Session',
    'reusable login material persistence',
  );
}

function checkEmailOtpUnlockSuccessBuildsTypedActivationPlan() {
  const seamsWeb = readRepoSource('packages/sdk-web/src/SeamsWeb/SeamsWeb.ts');
  const provisioning = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/provisioning.ts',
  );
  const ecdsaLogin = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts',
  );
  const ed25519Warmup = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Warmup.ts',
  );
  const ecdsaPublication = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaPublication.ts',
  );
  const ed25519UnlockDomain = extractSourceBlock(
    seamsWeb,
    '  private async loginWithEmailOtpEd25519CapabilityDomain',
    '  private async loginWithEmailOtpEcdsaCapabilityDomain',
    'Email OTP Ed25519 unlock domain',
  );
  const ecdsaUnlockDomain = extractSourceBlock(
    seamsWeb,
    '  private async loginWithEmailOtpEcdsaCapabilityDomain',
    '  private async refreshEmailOtpSigningSessionDomain',
    'Email OTP ECDSA unlock domain',
  );
  const ecdsaIframeUnlockDomain = extractSourceBlock(
    ecdsaUnlockDomain,
    '      if (this.walletIframe.shouldUseWalletIframe()) {',
    '      const workerProgressPhases = new Set<UnlockEventPhase>();',
    'Email OTP ECDSA iframe unlock domain',
  );
  const ecdsaLocalUnlockDomain = extractSourceBlock(
    ecdsaUnlockDomain,
    '      const workerProgressPhases = new Set<UnlockEventPhase>();',
    '      return result;',
    'Email OTP ECDSA local unlock domain',
  );
  const ed25519LoginInternal = extractSourceBlock(
    ed25519Warmup,
    '  async loginWithEd25519CapabilityInternal',
    '  async loginForSigning',
    'Email OTP Ed25519 internal login',
  );

  assertSourceHasAll(
    seamsWeb,
    [
      'type EmailOtpUnlockActivationPlan =',
      "'email_otp_unlock_activation_plan_v1'",
      'activeSession: ActiveWalletSession;',
      'type EmailOtpUnlockPrewarmSnapshot =',
      'prewarm: EmailOtpUnlockPrewarmSnapshot;',
      'emailOtpUnlockPrewarmSnapshot({',
      "kind: 'prewarm_attempted'",
      "kind: 'not_prewarmed'",
      'buildEmailOtpUnlockActiveSession({',
      'walletAuthAuthoritiesMatch(authority, ecdsaAuthority)',
      "requireEmailOtpUnlockBearerJwt(record.walletSessionJwt, 'ECDSA');",
      'buildEmailOtpEd25519UnlockActivationPlan({',
      'buildEmailOtpEcdsaUnlockActivationPlan({',
      'requireEmailOtpUnlockEcdsaCurrentRecords',
      'warmCapabilities',
      "'walletIframeRoundTripMs'",
      "'emailOtpProofVerificationMs'",
      "'appSessionExchangeMs'",
      "'ed25519MaterialRestoreMs'",
      "'ecdsaMaterialRestoreMs'",
      "'signingSessionSealApplyMs'",
      "'warmCapabilityPersistenceMs'",
      "'activeRuntimeConstructionMs'",
      'recordEmailOtpUnlockElapsedTiming(',
      'result.timings.signingSessionSealApplyMs',
      'result.timings.warmCapabilityPersistenceMs',
      'result.timings.ed25519MaterialRestoreMs',
      'logEmailOtpUnlockActivationPlan(',
      'JSON.stringify(summary)',
      'OperationUsableThresholdEd25519SessionRecord',
      'OperationUsableThresholdEcdsaSessionRecord',
    ],
    'SeamsWeb Email OTP unlock activation plan',
  );
  assertNotContains(
    seamsWeb,
    'Email OTP unlock ECDSA current record bearer JWT mismatch',
    'SeamsWeb Email OTP unlock activation plan',
  );
  assertSourceOrder(
    ed25519UnlockDomain,
    'logEmailOtpUnlockActivationPlan(',
    'phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED',
    'Email OTP Ed25519 unlock domain',
  );
  assertSourceOrder(
    ed25519UnlockDomain,
    'logEmailOtpUnlockActivationPlan(',
    'phase: UnlockEventPhase.STEP_07_COMPLETED',
    'Email OTP Ed25519 unlock domain',
  );
  assertSourceOrder(
    ecdsaLocalUnlockDomain,
    'logEmailOtpUnlockActivationPlan(',
    'phase: UnlockEventPhase.STEP_07_COMPLETED',
    'Email OTP ECDSA local unlock domain',
  );
  assertSourceOrder(
    ecdsaIframeUnlockDomain,
    'const result = await router.loginWithEmailOtpEcdsaCapability(iframeArgs);',
    'phase: UnlockEventPhase.STEP_07_COMPLETED',
    'Email OTP ECDSA iframe unlock domain',
  );
  assertSourceHasAll(
    ecdsaLogin,
    [
      'timings: EmailOtpThresholdEcdsaLoginTimings;',
      'createEmailOtpThresholdEcdsaLoginTimings()',
      'mergeEmailOtpEcdsaPublicationTimingsIntoLoginTimings',
      'tryActivateEmailOtpEd25519UnlockFromSealedMaterial({',
    ],
    'Email OTP ECDSA login',
  );
  assertSourceOrder(
    ecdsaLogin,
    'tryActivateEmailOtpEd25519UnlockFromSealedMaterial({',
    ': await ports.reconstructEd25519Session(ed25519ReconstructionArgs);',
    'Email OTP ECDSA login',
  );
  assertSourceHasAll(
    ed25519Warmup,
    [
      'timings: EmailOtpThresholdEd25519LoginTimings;',
      'createEmailOtpThresholdEd25519LoginTimings()',
      'tryActivateEmailOtpEd25519UnlockFromSealedMaterial',
      'canonicalizeLaneFacts(facts, emailOtpEd25519UnlockLaneInventoryAdapter)',
      "operation: 'wallet_unlock'",
      'mergeEmailOtpThresholdEd25519ProvisioningTimingsIntoLoginTimings',
    ],
    'Email OTP Ed25519 warmup',
  );
  assertSourceOrder(
    ed25519LoginInternal,
    'tryActivateEmailOtpEd25519UnlockFromSealedMaterial({',
    'const provisioned = await this.reconstructSession({',
    'Email OTP Ed25519 internal login',
  );
  assertSourceHasAll(
    provisioning,
    [
      'record: OperationUsableThresholdEd25519SessionRecord;',
      'buildOperationUsableThresholdEd25519SessionRecord(',
      'reconstructionTimings: EmailOtpThresholdEd25519ProvisioningTimings;',
    ],
    'Email OTP Ed25519 provisioning',
  );
  assertSourceHasAll(
    ecdsaPublication,
    [
      'type EmailOtpEcdsaPublicationTimings =',
      'signingSessionSealApplyMs',
      'warmCapabilityPersistenceMs',
    ],
    'Email OTP ECDSA publication',
  );
}

function main() {
  checkRoleLocalEcdsaMaterialHandlesAreIdentityLocal();
  checkWalletScopedUnlockAvoidsCollapsedNearBindingError();
  checkVisibleIframePasskeyRegistrationUsesProvidedWalletId();
  checkRegistrationSuccessBuildsActiveStateWithoutPersistedLaneInventory();
  checkRegistrationPersistencePlanCarriesExplicitWriteSubjects();
  checkPostPrepareRegistrationRoutesUseStoredPreparedState();
  checkRegistrationPrecomputeOwnershipIsScopeChecked();
  checkRegistrationIntentDigestVerificationStaysAtResponseBoundary();
  checkRegistrationTimingKeepsTailBucketsObservational();
  checkRegistrationWorkerMaterialIsStoredFromFinalizedHssReport();
  checkEmailOtpUnlockCurrentSessionsUseCommitCommands();
  checkEmailOtpUnlockSuccessBuildsTypedActivationPlan();
  console.log('[registration-capability-subjects] ok');
}

main();

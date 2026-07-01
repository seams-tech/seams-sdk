import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listTypeScriptFiles(relativePath: string): string[] {
  const absolutePath = path.join(repoRoot, relativePath);
  const stat = fs.statSync(absolutePath);
  if (stat.isFile()) return /\.tsx?$/.test(relativePath) ? [relativePath] : [];

  const files: string[] = [];
  for (const entry of fs.readdirSync(absolutePath, { withFileTypes: true })) {
    if (entry.name === 'dist' || entry.name === 'node_modules') continue;
    const childPath = path.join(relativePath, entry.name);
    if (entry.isDirectory()) files.push(...listTypeScriptFiles(childPath));
    if (entry.isFile() && /\.tsx?$/.test(entry.name)) files.push(childPath);
  }
  return files;
}

function sourceRangeBetween(source: string, startNeedle: string, endNeedle: string): string {
  const start = source.indexOf(startNeedle);
  expect(start, `missing source range start: ${startNeedle}`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf(endNeedle, start + startNeedle.length);
  expect(end, `missing source range end: ${endNeedle}`).toBeGreaterThan(start);
  return source.slice(start, end);
}

function allSdkSourceFiles(): string[] {
  return listTypeScriptFiles('packages/sdk-web/src').filter(
    (relativePath) => !relativePath.endsWith('.typecheck.ts'),
  );
}

function collectMarkerOffenders(markers: readonly string[]): string[] {
  const offenders: string[] = [];
  for (const relativePath of allSdkSourceFiles()) {
    const source = readRepoSource(relativePath);
    for (const marker of markers) {
      if (source.includes(marker)) offenders.push(`${relativePath} contains ${marker}`);
    }
  }
  return offenders;
}

test('Refactor 74 Phase 9 removes legacy fallback helper names from active SDK code', () => {
  const forbiddenMarkers = [
    'restorePasskeyEd25519SessionBeforePlanningBestEffort',
    'readRefreshedEd25519CapabilityOrCurrent',
    'hydrateLatestEd25519SessionFromDurableSealedWorkerMaterial',
    'knownMissingCacheKey',
    'rememberKnownMissing',
    'hasKnownMissing',
    'cacheSigningSessionPrfFirstBestEffort',
    'attachEd25519SessionToEmailOtpSigningSessionSealBestEffort',
    'selectReconnectWalletSessionJwt',
    'selectSigningSessionStatusForUi',
    'snapshotLaneToSigningSessionStatus',
  ] as const;

  const offenders = collectMarkerOffenders(forbiddenMarkers);
  expect(offenders, offenders.join('\n')).toEqual([]);
});

test('Refactor 74 Phase 9 rejects committed commented-out legacy fallback blocks', () => {
  const forbiddenCommentPatterns = [
    /\/\/.*restorePasskeyEd25519SessionBeforePlanningBestEffort/,
    /\/\/.*readRefreshedEd25519CapabilityOrCurrent/,
    /\/\/.*hydrateLatestEd25519SessionFromDurableSealedWorkerMaterial/,
    /\/\/.*knownMissingCacheKey/,
    /\/\/.*candidates\[0\] \|\| null/,
    /\/\/.*claimWarmSessionPrfFirst/,
    /\/\/.*WARM_SESSION_MATERIAL_CLAIM/,
    /\/\/.*TODO remove legacy/,
    /\/\/.*LEGACY/,
  ] as const;
  const offenders: string[] = [];
  for (const relativePath of allSdkSourceFiles()) {
    const source = readRepoSource(relativePath);
    for (const pattern of forbiddenCommentPatterns) {
      if (pattern.test(source)) offenders.push(`${relativePath} matches ${pattern}`);
    }
  }
  expect(offenders, offenders.join('\n')).toEqual([]);
});

test('Refactor 74 Phase 9 keeps policy-hint fallback display-only', () => {
  const loginSource = readRepoSource('packages/sdk-web/src/SeamsWeb/operations/auth/login.ts');
  const displaySnapshotHelper = sourceRangeBetween(
    loginSource,
    'function snapshotLaneToDisplaySigningSessionStatus(',
    'function snapshotToSigningSessionStatusForUi(',
  );
  const displaySelectionHelper = sourceRangeBetween(
    loginSource,
    'function selectSigningSessionStatusForDisplay(',
    'function snapshotLaneToDisplaySigningSessionStatus(',
  );

  expect(displaySnapshotHelper).toContain('lane.policyHint?.remainingUses');
  expect(displaySnapshotHelper).toContain('lane.policyHint?.expiresAtMs');
  expect(displaySelectionHelper).not.toContain('candidates[0] || null');
  expect(loginSource).not.toContain('function snapshotLaneToSigningSessionStatus(');
  expect(loginSource).not.toContain('function selectSigningSessionStatusForUi(');
});

test('Refactor 74 Phase 9 models authority-bearing reconnect selection as exact or fail-closed', () => {
  const ecdsaProvisionPlan = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts',
  );
  const selector = sourceRangeBetween(
    ecdsaProvisionPlan,
    'type ReconnectWalletSessionJwtSelection =',
    'function passkeyCredentialIdB64uFromReconnectRecord(',
  );

  expect(selector).toContain("kind: 'exact_match'");
  expect(selector).toContain("kind: 'duplicate_records'");
  expect(selector).toContain("kind: 'not_found'");
  expect(selector).toContain("case 'duplicate_records':");
  expect(selector).toContain('duplicate exact matches');
  expect(selector).not.toContain('candidates[0] || null');
});

test('Refactor 74 Phase 9 removes first-candidate fallback markers from lane selection', () => {
  const transactionLaneSelector = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/identity/selectLane.ts',
  );
  const exportLaneSelector = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts',
  );
  const transactionSelection = sourceRangeBetween(
    transactionLaneSelector,
    'function selectOnlyConcreteTransactionCandidate',
    'export function selectTransactionLane',
  );
  const exportSelection = sourceRangeBetween(
    exportLaneSelector,
    'function selectExactExportAvailableLane',
    'function exactEd25519IdentityForExportLane',
  );

  expect(transactionSelection).toContain('switch (candidates.length)');
  expect(transactionSelection).toContain('case 0:');
  expect(transactionSelection).toContain('case 1:');
  expect(transactionSelection).toContain('default:');
  expect(transactionSelection).not.toContain('selectNewestCandidateWhenUnambiguous');
  expect(transactionSelection).not.toContain('candidateStatePriority');
  expect(transactionSelection).not.toContain('candidateSourcePriority');
  expect(transactionSelection).not.toContain('bestStateCandidates[0] || null');
  expect(transactionSelection).not.toContain('bestSourceCandidates[0] || null');
  expect(transactionSelection).not.toContain('candidates[0] || null');

  expect(exportSelection).toContain('duplicate_records');
  expect(exportSelection).toContain('no_candidate');
  expect(exportSelection).toContain('args.candidates.length !== 1');
  expect(exportSelection).not.toContain('selectNewestExportLaneWhenUnambiguous');
  expect(exportSelection).not.toContain('candidateStatePriority');
  expect(exportSelection).not.toContain('candidateSourcePriority');
  expect(exportSelection).not.toContain('stateCandidates[0] || null');
  expect(exportSelection).not.toContain('sourceCandidates[0] || null');
  expect(exportSelection).not.toContain('candidates[0] || null');
});

test('Refactor 74 Phase 9 keeps ECDSA threshold-session lookup exact or fail-closed', () => {
  const recordsSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/persistence/records.ts',
  );
  const inMemoryLookup = sourceRangeBetween(
    recordsSource,
    'function getInMemoryThresholdEcdsaSessionRecordByThresholdSessionId',
    'function normalizeThresholdEcdsaSessionStoreSource',
  );
  const uniqueSelector = sourceRangeBetween(
    recordsSource,
    'function selectUniqueThresholdEcdsaRecordByThresholdSessionId',
    'export function deriveThresholdEcdsaRuntimeLaneKey',
  );
  const exportedLookup = sourceRangeBetween(
    recordsSource,
    'export function getThresholdEcdsaSessionRecordByThresholdSessionId',
    'export function upsertStoredThresholdEd25519SessionRecord',
  );

  expect(inMemoryLookup).toContain('selectUniqueThresholdEcdsaRecordByThresholdSessionId({');
  expect(uniqueSelector).toContain('switch (unique.size)');
  expect(uniqueSelector).toContain('case 0:');
  expect(uniqueSelector).toContain('case 1:');
  expect(uniqueSelector).toContain('default:');
  expect(exportedLookup).toContain('selectUniqueThresholdEcdsaRecordByThresholdSessionId({');
  expect(inMemoryLookup).not.toContain('[0] || null');
  expect(exportedLookup).not.toContain('[0] || null');
});

test('Refactor 74 Phase 9 keeps budget compatibility fallback at the boundary parser only', () => {
  const budgetReader = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts',
  );
  const parser = sourceRangeBetween(
    budgetReader,
    'function parseTrustedBudgetStatusPayload',
    'async function fetchTrustedWalletSigningBudgetStatus',
  );
  expect(parser).toContain('record.committedRemainingUses ?? record.remainingUses');
  expect(parser).toContain('record.availableUses ?? record.remainingUses');

  const nearPlanner = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts',
  );
  expect(nearPlanner).toContain(
    'type TrustedActiveEd25519SigningBudgetStatus = SigningSessionStatus &',
  );
  expect(nearPlanner).toContain('committedRemainingUses: number;');
  expect(nearPlanner).toContain('inFlightReservedUses: number;');
  expect(nearPlanner).toContain('committedUsesForBudgetAdmission(args.trustedStatus)');
  expect(nearPlanner).not.toContain('record.availableUses ?? record.remainingUses');
  expect(nearPlanner).not.toContain('policyHint');
});

test('Refactor 74 Phase 9 uses typed restore and companion attachment outcomes', () => {
  const nearPlanner = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts',
  );
  expect(nearPlanner).toContain('type PrePlanningEd25519MaterialRestoreResult =');
  expect(nearPlanner).toContain("kind: 'missing_unseal_authorization'");
  expect(nearPlanner).toContain("code: 'capability_refresh_failed'");
  expect(nearPlanner).not.toContain('catch (error) {\n    logPasskeyEd25519PlanningRestoreFailure');

  const ecdsaRecovery = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.ts',
  );
  const ecdsaRecoveryTypecheck = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.typecheck.ts',
  );
  expect(ecdsaRecovery).toContain('export type EmailOtpEcdsaRestoreSource =');
  expect(ecdsaRecovery).toContain("kind: 'sealed_record_restore';");
  expect(ecdsaRecovery).toContain('ecdsaRecord?: never;');
  expect(ecdsaRecovery).toContain("kind: 'current_record_restore';");
  expect(ecdsaRecovery).not.toContain('args.configs.signing.sessionSeal');
  expect(ecdsaRecovery).not.toContain('ecdsaRecord?.thresholdSessionId || sealedRecord.');
  expect(ecdsaRecovery).not.toContain('ecdsaRecord?.signingGrantId || sealedRecord.');
  expect(ecdsaRecovery).not.toContain('ecdsaRecord?.relayerUrl || sealedRecord.');
  expect(ecdsaRecovery).not.toContain('ecdsaRecord?.chainTarget || sealedRecord.');
  expect(ecdsaRecovery).not.toContain('ecdsaRecord?.keyHandle || sealedRecord.');
  expect(ecdsaRecovery).not.toContain('ecdsaRecord?.relayerKeyId || sealedRecord.');
  expect(ecdsaRecoveryTypecheck).toContain(
    'sealed-source restore cannot carry current-record fallback bags',
  );
  expect(ecdsaRecoveryTypecheck).toContain('current-source restore requires the current ECDSA record');
  expect(ecdsaRecoveryTypecheck).toContain('restore source branches require Wallet Session JWT');

  const companionSessions = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/companionSessions.ts',
  );
  const emailOtpProvisioning = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/provisioning.ts',
  );
  const companionTypecheck = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/companionSessions.typecheck.ts',
  );
  expect(companionSessions).toContain('export type EmailOtpCompanionSessionAttachResult =');
  expect(companionSessions).toContain("kind: 'missing_required_material'");
  expect(companionSessions).toContain("kind: 'not_required'");
  expect(companionSessions).toContain("kind: 'signing_grant_exact'");
  expect(companionSessions).toContain("kind: 'latest_wallet_record'");
  expect(companionSessions).toContain("kind: 'exact_match'");
  expect(companionSessions).toContain("kind: 'duplicate_records'");
  expect(companionSessions).toContain("kind: 'display_only_fallback'");
  expect(companionSessions).not.toContain('walletScopedRecords.length ? walletScopedRecords : records');
  expect(companionSessions).not.toContain(
    'records.filter((record) => record.signingGrantId === signingGrantId)[0] || null',
  );
  expect(emailOtpProvisioning).toContain('switch (result.kind)');
  expect(emailOtpProvisioning).toContain("case 'attached':");
  expect(emailOtpProvisioning).toContain("case 'already_attached':");
  expect(emailOtpProvisioning).toContain("case 'not_required':");
  expect(emailOtpProvisioning).toContain("case 'missing_required_material':");
  expect(emailOtpProvisioning).toContain("case 'failed':");
  expect(companionTypecheck).toContain('Exact companion selection requires signingGrantId');
});

test('Refactor 74 Phase 9 keeps exact signing out of account-scoped restore discovery', () => {
  const exactSigningFiles = [
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519MaterialRestoreAuthorization.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts',
  ] as const;
  const forbiddenExactSigningMarkers = [
    'hydrateAccountScopedDiscoveryEd25519SessionFromDurableSealedWorkerMaterial',
    'hydrateLatestEd25519SessionFromDurableSealedWorkerMaterial',
    'listPasskeyEd25519RestoreSealedSessionsForWallet',
  ] as const;
  const offenders: string[] = [];
  for (const relativePath of exactSigningFiles) {
    const source = readRepoSource(relativePath);
    for (const marker of forbiddenExactSigningMarkers) {
      if (source.includes(marker)) offenders.push(`${relativePath} contains ${marker}`);
    }
  }
  expect(offenders, offenders.join('\n')).toEqual([]);

  const loginSource = readRepoSource('packages/sdk-web/src/SeamsWeb/operations/auth/login.ts');
  const thresholdWarmSessionBootstrap = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts',
  );
  const exactHydrateSignature = sourceRangeBetween(
    thresholdWarmSessionBootstrap,
    'export async function hydrateExactEd25519SessionFromDurableSealedWorkerMaterial(args: {',
    '}): Promise<',
  );
  const exactRestoreSelection = sourceRangeBetween(
    thresholdWarmSessionBootstrap,
    'type ExactEd25519WorkerMaterialRestoreRecordSelection =',
    'function ed25519ThresholdSessionIdFromSealedRecord(',
  );
  const exactHydrateImplementation = sourceRangeBetween(
    thresholdWarmSessionBootstrap,
    'export async function hydrateExactEd25519SessionFromDurableSealedWorkerMaterial(args: {',
    'export async function hydrateAccountScopedDiscoveryEd25519SessionFromDurableSealedWorkerMaterial(args: {',
  );
  const exactHydrateMatcher = sourceRangeBetween(
    thresholdWarmSessionBootstrap,
    'function sealedEd25519RestoreRecordMatchesExactSession(args: {',
    'function sealedEd25519RestoreRuntimePolicyScope(',
  );
  const currentHydrateMatcher = sourceRangeBetween(
    thresholdWarmSessionBootstrap,
    'function ed25519RestoreIdentityMismatchReasons(args: {',
    'type ExactEd25519WorkerMaterialRestoreRecordSelection =',
  );
  const currentHydrateImplementation = sourceRangeBetween(
    thresholdWarmSessionBootstrap,
    'function summarizeEd25519DurableRestoreLookupFailure(args: {',
    'function ed25519DurableRestoreCandidateSummary(args: {',
  );
  const loginUnsealInstaller = sourceRangeBetween(
    loginSource,
    'async function installThresholdLoginEd25519WarmSessionUnsealAuthorization(args: {',
    'function ignoreThresholdLoginEd25519HydrationError(): null',
  );
  expect(exactHydrateSignature).toContain('signingGrantId: string;');
  expect(exactRestoreSelection).toContain("kind: 'exact_match'");
  expect(exactRestoreSelection).toContain("kind: 'duplicate_records'");
  expect(exactRestoreSelection).toContain("kind: 'not_found'");
  expect(exactHydrateImplementation).toContain(
    'selectSingleEd25519WorkerMaterialRestoreRecord(records)',
  );
  expect(exactHydrateImplementation).toContain(
    "pendingReason: 'duplicate_worker_material_records'",
  );
  expect(exactHydrateImplementation).not.toContain(
    'mostRecentEd25519SealedSessionRecord(records)',
  );
  expect(exactHydrateMatcher).toContain('signingGrantId: string;');
  expect(exactHydrateMatcher).toContain('normalizedRestoreString(args.record.signingGrantId)');
  expect(currentHydrateMatcher).toContain('normalizedRestoreString(sealed.signingGrantId)');
  expect(currentHydrateMatcher).toContain('normalizedRestoreString(current.signingGrantId)');
  expect(currentHydrateMatcher).toContain('ed25519ThresholdSessionIdFromSealedRecord(sealed)');
  expect(currentHydrateMatcher).toContain('normalizedRestoreString(current.thresholdSessionId)');
  expect(currentHydrateMatcher).toContain('current.ed25519WorkerMaterialBindingDigest');
  expect(currentHydrateMatcher).toContain('restore.ed25519WorkerMaterialBindingDigest');
  expect(currentHydrateImplementation).toContain(
    'selectSingleEd25519WorkerMaterialRestoreRecord(matchingRecords)',
  );
  expect(currentHydrateImplementation).toContain(
    "pendingReason: 'duplicate_worker_material_records'",
  );
  expect(currentHydrateImplementation).not.toContain(
    'mostRecentEd25519SealedSessionRecord(matchingRecords)',
  );
  expect(loginUnsealInstaller).toContain('signingGrantId: string;');
  expect(loginUnsealInstaller).toContain('recordSigningGrantId !== signingGrantId');
  expect(loginSource).toContain('resolveReusableEd25519WorkerMaterialForLoginSession');
  expect(loginSource).toContain('persistThresholdLoginEd25519ReusableMaterial');
  expect(loginSource).not.toContain(
    'hydrateAccountScopedDiscoveryEd25519SessionFromDurableSealedWorkerMaterial',
  );
});

test('Refactor 74 Phase 9 keeps PRF cache helpers out of normal Ed25519 signing restore', () => {
  const normalSigningRestoreFiles = [
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519MaterialRestoreAuthorization.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts',
  ] as const;
  const forbiddenPrfMarkers = [
    'cacheCredentialBoundarySetupExportPrfFirst',
    'claimWarmSessionPrfFirst',
    'WARM_SESSION_MATERIAL_CLAIM',
    'prfFirstB64u',
  ] as const;
  const offenders: string[] = [];
  for (const relativePath of normalSigningRestoreFiles) {
    const source = readRepoSource(relativePath);
    for (const marker of forbiddenPrfMarkers) {
      if (source.includes(marker)) offenders.push(`${relativePath} contains ${marker}`);
    }
  }
  expect(offenders, offenders.join('\n')).toEqual([]);
});

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test.describe('Email OTP operation split guard', () => {
  test('transaction signing APIs cannot request export challenges', () => {
    const transactionApiFiles = [
      'client/src/core/signingEngine/flows/signNear/signNear.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/authPlanning.ts',
      'client/src/core/signingEngine/assembly/ports/evmFamily.ts',
    ];
    const forbidden = [
      'requestEmailOtpChallengeForSigning',
      'requestChallengeForSigning',
      'WALLET_EMAIL_OTP_EXPORT_OPERATION',
      "'export_key'",
      '"export_key"',
      "operation?: 'transaction_sign' | 'export_key'",
      'operation?: "transaction_sign" | "export_key"',
    ];

    const violations: string[] = [];
    for (const relativePath of transactionApiFiles) {
      const source = readRepoFile(relativePath);
      for (const token of forbidden) {
        if (source.includes(token)) {
          violations.push(`${relativePath} contains ${token}`);
        }
      }
      if (!source.includes('requestEmailOtpTransactionSigningChallenge')) {
        violations.push(`${relativePath} does not use the transaction-specific challenge helper`);
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('Email OTP coordinator keeps export challenge issuance separate from signing challenge issuance', () => {
    const source = readRepoFile(
      'client/src/core/signingEngine/session/emailOtp/EmailOtpThresholdSessionCoordinator.ts',
    );
    const forbidden = [
      'requestEmailOtpChallengeForSigning',
      'requestChallengeForSigning',
      'createPasskeyWalletAuthAdapter',
      'createWalletAuthModeResolver',
      'WalletAuthPolicyError',
      'requestExportAuthorization',
      'requestUserConfirmation',
      'UserConfirmationType',
      "operation?: 'transaction_sign' | 'export_key'",
      'operation?: "transaction_sign" | "export_key"',
    ];
    const violations = forbidden
      .filter((token) => source.includes(token))
      .map((token) => `EmailOtpThresholdSessionCoordinator.ts contains ${token}`);

    expect(source).toContain('requestTransactionSigningChallenge');
    expect(source).toContain('requestExportChallenge');
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('Email OTP coordinator stays a thin runtime facade', () => {
    const source = readRepoFile(
      'client/src/core/signingEngine/session/emailOtp/EmailOtpThresholdSessionCoordinator.ts',
    );
    const lineCount = source.split(/\r?\n/).length;
    const forbidden = [
      'fetch(',
      'requestWorkerOperation',
      'sealEmailOtpWarmSessionMaterial',
      'requestEmailOtpTransactionSigningChallenge',
      'requestEmailOtpExportChallenge',
      'requestExportAuthorization',
      'requestUserConfirmation',
    ];
    const violations = forbidden
      .filter((token) => source.includes(token))
      .map((token) => `EmailOtpThresholdSessionCoordinator.ts contains ${token}`);

    expect(lineCount).toBeLessThanOrEqual(250);
    expect(source).toContain('EmailOtpThresholdSessionRuntime');
    expect(source).toContain('private readonly runtime');
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('ECDSA fresh Email OTP decisions stay planner-owned, not pre-sign guard-owned', () => {
    const source = readRepoFile('client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts');
    const executorSource = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
    );
    const retryIndex = source.indexOf('const retryWithFreshEmailOtpAuth');
    const executorIndex = source.indexOf('return await executeEvmFamilyTransactionSigning');
    const signIndex = executorSource.indexOf('const result = await signWithUiConfirm');

    expect(source).not.toContain('const assertEcdsaOperationAllowedForAttempt');
    expect(source).not.toContain('assertEcdsaOperationAllowedForSource');
    expect(executorSource).not.toContain('assertOperationAllowed');
    expect(retryIndex).toBeGreaterThanOrEqual(0);
    expect(executorIndex).toBeGreaterThan(retryIndex);
    expect(signIndex).toBeGreaterThanOrEqual(0);
  });

  test('ECDSA transaction signing selects an exact lane before material lookup', () => {
    const source = readRepoFile('client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts');
    const preparedSigningSource = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
    );
    const accountAuthSource = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/accountAuth.ts',
    );
    const lanesSource = readRepoFile('client/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts');
    const selectionModule = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts',
    );
    const store = readRepoFile(
      'client/src/core/signingEngine/session/persistence/records.ts',
    );
    const identitySource = readRepoFile(
      'client/src/core/signingEngine/session/identity/laneIdentity.ts',
    );
    const authResolver = accountAuthSource.indexOf(
      'export async function resolveEvmFamilyTransactionWalletAuth',
    );
    const exactSignerAuthLookup = accountAuthSource.indexOf(
      'getActiveWalletSignerForChainTarget',
      authResolver,
    );
    const ed25519Fallback = accountAuthSource.indexOf(
      'getStoredThresholdEd25519SessionRecordForAccount',
      authResolver,
    );
    const selectionResolver = preparedSigningSource.indexOf(
      'resolveEvmFamilyEcdsaSigningSelection({',
    );
    const selectionModuleResolver = selectionModule.indexOf(
      'export async function resolveEvmFamilyEcdsaSigningSelection',
    );
    const selectionSource = selectionModule.slice(selectionModuleResolver);
    const preparedAccountAuthResolution = preparedSigningSource.indexOf(
      'const accountAuth = await resolveEvmFamilyTransactionWalletAuth',
    );
    const snapshotCandidateSelection = preparedSigningSource.indexOf(
      'const selectedLane = selectTransactionLane({',
      preparedAccountAuthResolution,
    );
    const exactLaneSelection = selectionModule.indexOf(
      'const lane = signingLaneFromExactLaneCandidate(args.laneCandidate);',
      selectionModuleResolver,
    );
    const emailOtpCandidate = selectionModule.indexOf(
      'authMethod: SIGNER_AUTH_METHODS.emailOtp',
      selectionModuleResolver,
    );

    expect(selectionModule).toContain('tryGetEmailOtpThresholdEcdsaSessionRecordForSigning');
    expect(selectionModule).toContain('tryGetPasskeyThresholdEcdsaSessionRecordForSigning');
    expect(lanesSource).toContain(
      'export function tryGetEmailOtpThresholdEcdsaSessionRecordForSigning',
    );
    expect(lanesSource).toContain(
      'export function tryGetPasskeyThresholdEcdsaSessionRecordForSigning',
    );
    expect(identitySource).toContain('THRESHOLD_ECDSA_PASSKEY_SESSION_STORE_SOURCES');
    expect(selectionModule).toContain('findExactEcdsaSessionRecordForSelectedLane');
    expect(selectionModule).not.toContain('findExactEcdsaKeyRefForSelectedLane');
    expect(selectionModule).not.toContain('tryGetEmailOtpThresholdEcdsaKeyRefForSigning');
    expect(selectionModule).not.toContain('tryGetPasskeyThresholdEcdsaKeyRefForSigning');
    expect(selectionModule).toContain('buildEcdsaMaterialStateForCandidate');
    expect(selectionSource).not.toContain('genericRecord');
    expect(selectionSource).not.toContain('genericKeyRef');
    expect(exactSignerAuthLookup).toBeGreaterThan(authResolver);
    expect(ed25519Fallback).toBe(-1);
    expect(source).toContain('prepareEvmFamilyEcdsaSigningSession({');
    expect(selectionResolver).toBeGreaterThanOrEqual(0);
    expect(preparedAccountAuthResolution).toBeGreaterThanOrEqual(0);
    expect(snapshotCandidateSelection).toBeGreaterThan(preparedAccountAuthResolution);
    expect(exactLaneSelection).toBeGreaterThan(selectionModuleResolver);
    expect(emailOtpCandidate).toBeGreaterThan(exactLaneSelection);
  });

  test('Email OTP ECDSA helpers require the Email OTP source lane', () => {
    const store = readRepoFile(
      'client/src/core/signingEngine/session/persistence/records.ts',
    );
    const evmSigning = readRepoFile('client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts');
    const authPlanning = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/authPlanning.ts',
    );
    const ecdsaLanes = readRepoFile('client/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts');
    const ecdsaSelection = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts',
    );
    const preparedSigning = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
    );
    const ecdsaPublication = readRepoFile(
      'client/src/core/signingEngine/session/emailOtp/ecdsaPublication.ts',
    );
    const signingSessionReadiness = readRepoFile(
      'client/src/core/signingEngine/session/availability/readiness.ts',
    );
    const warmSessionStatusReader = readRepoFile(
      'client/src/core/signingEngine/session/warmCapabilities/statusReader.ts',
    );

    expect(store).toContain('getEmailOtpThresholdEcdsaSessionRecordForSigning');
    expect(store).toContain("source: 'email_otp'");
    expect(store).toContain('getPasskeyThresholdEcdsaSessionRecordForSigning');
    const evmSigningDeps = preparedSigning.slice(
      preparedSigning.indexOf('export type PrepareEvmFamilyEcdsaSigningDeps'),
    );
    expect(evmSigningDeps).not.toContain('getThresholdEcdsaKeyRefForLookup');
    expect(evmSigningDeps).not.toContain('getThresholdEcdsaSessionRecordForLookup');
    expect(evmSigningDeps).not.toContain('getEmailOtpThresholdEcdsaKeyRefForSigning');
    expect(evmSigningDeps).toContain('getEmailOtpThresholdEcdsaSessionRecordForSigning');
    expect(evmSigningDeps).not.toContain('getPasskeyThresholdEcdsaKeyRefForSigning');
    expect(evmSigningDeps).toContain('getPasskeyThresholdEcdsaSessionRecordForSigning');
    expect(evmSigning).not.toContain('type EcdsaSigningLaneContext');
    expect(ecdsaSelection).toContain('export type EvmFamilyEcdsaSigningSelection');
    expect(authPlanning).toContain('export type ResolveEvmFamilyTransactionStepUpArgs');
    expect(authPlanning).toContain('preparedOperation: PreparedThresholdSigningOperation');
    expect(authPlanning).not.toContain('ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane');
    expect(evmSigning).toContain('resolveEvmFamilyTransactionStepUp');
    expect(ecdsaLanes).toContain('requireResolvedEvmFamilyEcdsaSigningLane');
    expect(ecdsaSelection).toContain('source: SIGNER_AUTH_METHODS.emailOtp');
    expect(ecdsaSelection).toContain('PASSKEY_ECDSA_SIGNING_SOURCE_PRIORITY');
    expect(ecdsaSelection).toContain('listPasskeyVisibleMaterials');
    expect(ecdsaSelection).toContain('laneCandidate: EcdsaLaneCandidate');
    expect(preparedSigning).toContain('assertSelectionMatchesLaneCandidate');
    expect(preparedSigning).toContain('materialIdentityMatchesResolvedLane');
    expect(ecdsaSelection).toContain('findExactEcdsaSessionRecordForSelectedLane');
    expect(ecdsaSelection).not.toContain('findExactEcdsaKeyRefForSelectedLane');
    expect(ecdsaSelection).not.toContain('tryGetEmailOtpThresholdEcdsaKeyRefForSigning');
    expect(ecdsaSelection).not.toContain('tryGetPasskeyThresholdEcdsaKeyRefForSigning');
    expect(ecdsaSelection).toContain('signingLaneFromExactLaneCandidate');
    expect(ecdsaSelection).toContain('source,');
    expect(ecdsaSelection).toContain("storageSource: 'manual-bootstrap'");
    expect(ecdsaPublication).toContain('primaryChain: expectedTarget,');
    expect(ecdsaPublication).toContain("source: 'email_otp'");
    expect(warmSessionStatusReader).toContain(
      'if (args.source && candidate.source !== args.source) continue;',
    );
    expect(warmSessionStatusReader).toContain(
      'const record = resolveEcdsaRecordForSigningSession(args);',
    );
    expect(warmSessionStatusReader).toContain(
      'if (args.source && record.source !== args.source) return null;',
    );
    expect(signingSessionReadiness).toContain("source: 'passkey' | 'email_otp'");
    expect(signingSessionReadiness).toContain(
      "record.source === 'email_otp' ? 'email_otp' : 'passkey'",
    );
  });

  test('EVM-family ECDSA signing restores durable sealed sessions after selected lane material check', () => {
    const evmSigning = readRepoFile('client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts');
    const preparedSigning = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
    );
    const depsStart = preparedSigning.indexOf('export type PrepareEvmFamilyEcdsaSigningDeps');
    const preparedStart = preparedSigning.indexOf(
      'export async function prepareEvmFamilyEcdsaSigningSession',
    );
    const restoreCall = preparedSigning.indexOf(
      '.restorePersistedSessionForSigning({',
      preparedStart,
    );
    const selectionCall = preparedSigning.indexOf(
      'await resolveEvmFamilyEcdsaSigningSelection({',
      preparedStart,
    );

    expect(preparedSigning.slice(depsStart)).toContain(
      'restorePersistedSessionForSigning: (',
    );
    expect(preparedSigning.slice(depsStart)).toContain(
      "Extract<RestorePersistedSessionForSigningInput, { curve: 'ecdsa' }>",
    );
    expect(preparedSigning.slice(depsStart)).not.toContain(
      'restorePersistedEmailOtpSessionsForRead',
    );
    expect(evmSigning).toContain('prepareEvmFamilyEcdsaSigningSession({');
    expect(selectionCall).toBeGreaterThan(preparedStart);
    expect(restoreCall).toBeGreaterThan(selectionCall);
    const prepareBeforeSelection = preparedSigning.slice(preparedStart, selectionCall);
    expect(prepareBeforeSelection).toContain('const selectedLane = selectTransactionLane({');
    expect(prepareBeforeSelection).toContain('const authMethod = transactionLane.authMethod;');
    expect(prepareBeforeSelection).toContain(
      'walletSigningSessionId: laneCandidate.walletSigningSessionId',
    );
    expect(prepareBeforeSelection).toContain(
      'thresholdSessionId: laneCandidate.thresholdSessionId',
    );
    expect(prepareBeforeSelection).not.toContain("(['email_otp', 'passkey'] as const)");
    const selectionBeforeRestore = preparedSigning.slice(selectionCall, restoreCall);
    expect(selectionBeforeRestore).toContain('const shouldRestoreAvailableLane =');
    expect(selectionBeforeRestore).toContain("selection.kind === 'missing_material'");
  });

  test('EVM-family exhausted ECDSA lanes defer ready-material requirements until reauth', () => {
    const evmSigning = readRepoFile('client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts');
    const evmFamilyEcdsaIdentity = readRepoFile(
      'client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts',
    );
    const executorStart = evmSigning.indexOf('const preparedExecutorSession =');
    const executorEnd = evmSigning.indexOf('const executePayload =', executorStart);
    expect(executorStart).toBeGreaterThanOrEqual(0);
    expect(executorEnd).toBeGreaterThan(executorStart);
    const executorPreparation = evmSigning.slice(executorStart, executorEnd);

    expect(evmSigning).toContain('readSelectedEcdsaRecordForLane({');
    expect(evmSigning).not.toContain('readSelectedEcdsaKeyRefForLane({');
    expect(executorPreparation).toContain(
      "preparedExecutorSession?.material.kind === 'ready_to_sign'",
    );
    expect(executorPreparation).toContain(
      "preparedExecutorSession.budget.kind === 'BudgetAdmitted' && preparedExecutorSignerSession",
    );
    expect(executorPreparation).not.toContain(
      "requireReadyEcdsaMaterial(\n        preparedExecutorSession.material,\n        'prepared executor signer session'",
    );
    expect(executorPreparation).not.toContain('prepared executor requires ready signer material');
    expect(executorPreparation).toContain('toVerifiedEcdsaPublicFactsFromRecord({');
    expect(executorPreparation).not.toContain('toVerifiedEcdsaPublicFactsFromPairedRecordAndKeyRef({');
    expect(executorPreparation).not.toContain(
      'preparedExecutorSession.signingLane.key.thresholdOwnerAddress',
    );
    expect(evmFamilyEcdsaIdentity).toContain('function hasReadyThresholdEcdsaRecordClientShare');
    expect(evmFamilyEcdsaIdentity).toContain(
      '!hasReadyThresholdEcdsaRecordClientShare(input.record)',
    );
    expect(evmFamilyEcdsaIdentity).not.toContain('!hasReadyThresholdEcdsaClientShare(input.keyRef)');
  });

  test('EVM-family missing ECDSA material remains reauth-planned under active wallet budget', () => {
    const preparedSigning = readRepoFile('client/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts');
    const readinessStart = preparedSigning.indexOf('function readinessFromSelection');
    const readinessEnd = preparedSigning.indexOf('type PreparedEvmFamilyEcdsaMetadata', readinessStart);
    expect(readinessStart).toBeGreaterThanOrEqual(0);
    expect(readinessEnd).toBeGreaterThan(readinessStart);
    const readinessBlock = preparedSigning.slice(readinessStart, readinessEnd);

    expect(readinessBlock).toContain("selection.material.kind === 'public_identity_unavailable'");
    expect(readinessBlock).toContain("? 'missing_session'");
    expect(readinessBlock).toContain("selection.reason === 'exhausted'");
  });

  test('EVM-family selection diagnostics remain observational', () => {
    const files = [
      'client/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    ];
    const violations: string[] = [];
    for (const file of files) {
      const source = readRepoFile(file);
      const lines = source.split(/\r?\n/);
      lines.forEach((line, index) => {
        if (/\b(if|while)\s*\(.*diagnostics/.test(line)) {
          violations.push(`${file}:${index + 1}: ${line.trim()}`);
        }
      });
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });
});

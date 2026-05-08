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
      'client/src/core/signingEngine/sessionEmailOtp/EmailOtpThresholdSessionCoordinator.ts',
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
      'export async function resolveEvmFamilyTransactionAccountAuth',
    );
    const profileLookup = accountAuthSource.indexOf(
      'resolveProfileAccountContextFromCandidates',
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
      'const accountAuth = await resolveEvmFamilyTransactionAccountAuth',
    );
    const snapshotCandidateSelection = preparedSigningSource.indexOf(
      'const selectedLane = selectTransactionLane({',
      preparedAccountAuthResolution,
    );
    const selectedAuthMethod = selectionModule.indexOf(
      'const selectedAuthMethod = args.laneCandidate?.authMethod || args.authMethod',
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
    expect(selectionModule).toContain('pickUnambiguousEcdsaAuthRecord');
    expect(selectionSource).not.toContain('genericRecord');
    expect(selectionSource).not.toContain('genericKeyRef');
    expect(profileLookup).toBeGreaterThan(authResolver);
    expect(ed25519Fallback).toBe(-1);
    expect(source).toContain('prepareEvmFamilyEcdsaSigningSession({');
    expect(selectionResolver).toBeGreaterThanOrEqual(0);
    expect(preparedAccountAuthResolution).toBeGreaterThanOrEqual(0);
    expect(snapshotCandidateSelection).toBeGreaterThan(preparedAccountAuthResolution);
    expect(selectedAuthMethod).toBeGreaterThan(selectionModuleResolver);
    expect(emailOtpCandidate).toBeGreaterThan(selectedAuthMethod);
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
    const emailOtpCoordinator = readRepoFile(
      'client/src/core/signingEngine/sessionEmailOtp/EmailOtpThresholdSessionCoordinator.ts',
    );
    const signingSessionReadiness = readRepoFile(
      'client/src/core/signingEngine/session/availability/readiness.ts',
    );
    const warmSessionStatusReader = readRepoFile(
      'client/src/core/signingEngine/session/warmSigning/statusReader.ts',
    );

    expect(store).toContain('getEmailOtpThresholdEcdsaSessionRecordForSigning');
    expect(store).toContain("source: 'email_otp'");
    expect(store).toContain('getPasskeyThresholdEcdsaSessionRecordForSigning');
    const evmSigningDeps = preparedSigning.slice(
      preparedSigning.indexOf('export type PrepareEvmFamilyEcdsaSigningDeps'),
    );
    expect(evmSigningDeps).not.toContain('getThresholdEcdsaKeyRefForLookup');
    expect(evmSigningDeps).not.toContain('getThresholdEcdsaSessionRecordForLookup');
    expect(evmSigningDeps).toContain('getEmailOtpThresholdEcdsaKeyRefForSigning');
    expect(evmSigningDeps).toContain('getEmailOtpThresholdEcdsaSessionRecordForSigning');
    expect(evmSigningDeps).toContain('getPasskeyThresholdEcdsaKeyRefForSigning');
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
    expect(ecdsaSelection).toContain('listPasskeyEcdsaSigningCandidates');
    expect(ecdsaSelection).toContain('laneCandidate?: EcdsaLaneCandidate');
    expect(preparedSigning).toContain('assertSelectionMatchesLaneCandidate');
    expect(ecdsaSelection).toContain('ecdsaMaterialMatchesLaneCandidate');
    expect(ecdsaSelection).toContain('requireExactEcdsaCandidateMaterial');
    expect(ecdsaSelection).toContain('signingLaneFromExactLaneCandidate');
    expect(ecdsaSelection).toContain('source,');
    expect(ecdsaSelection).toContain(
      "const passkeySource = selectedPasskeyCandidate?.source || 'manual-bootstrap'",
    );
    expect(emailOtpCoordinator).toContain('primaryChain: expectedTarget,');
    expect(emailOtpCoordinator).toContain("source: 'email_otp'");
    expect(warmSessionStatusReader).toContain(
      'if (args.source && candidate.source !== args.source) continue;',
    );
    expect(warmSessionStatusReader).toContain(
      'if (fallback && (!args.source || fallback.source === args.source))',
    );
    expect(signingSessionReadiness).toContain("source: 'passkey' | 'email_otp'");
    expect(signingSessionReadiness).toContain(
      "record.source === 'email_otp' ? 'email_otp' : 'passkey'",
    );
  });

  test('EVM-family ECDSA signing restores durable sealed sessions before lane selection', () => {
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
      'const selection = await resolveEvmFamilyEcdsaSigningSelection',
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
    expect(restoreCall).toBeGreaterThan(preparedStart);
    expect(selectionCall).toBeGreaterThan(restoreCall);
    const prepareBeforeSelection = preparedSigning.slice(preparedStart, selectionCall);
    expect(prepareBeforeSelection).toContain('const selectedLane = selectTransactionLane({');
    expect(prepareBeforeSelection).toContain('authMethod,');
    expect(prepareBeforeSelection).toContain(
      'walletSigningSessionId: laneCandidate.walletSigningSessionId',
    );
    expect(prepareBeforeSelection).toContain(
      'thresholdSessionId: laneCandidate.thresholdSessionId',
    );
    expect(prepareBeforeSelection).not.toContain("(['email_otp', 'passkey'] as const)");
  });
});

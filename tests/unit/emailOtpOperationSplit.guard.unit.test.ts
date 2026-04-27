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
      'client/src/core/signingEngine/api/nearSigning.ts',
      'client/src/core/signingEngine/api/evmSigning.ts',
      'client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts',
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
      'client/src/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator.ts',
    );
    const forbidden = [
      'requestEmailOtpChallengeForSigning',
      'requestChallengeForSigning',
      'createPasskeyWalletAuthAdapter',
      'createWalletAuthModeResolver',
      'WalletAuthPolicyError',
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
    const source = readRepoFile('client/src/core/signingEngine/api/evmSigning.ts');
    const executorSource = readRepoFile(
      'client/src/core/signingEngine/api/evmFamily/transactionExecutor.ts',
    );
    const retryIndex = source.indexOf('const retryWithFreshEmailOtpAuth');
    const executorIndex = source.indexOf('return await executeEvmFamilyTransactionSigning');
    const evmSignIndex = executorSource.indexOf('const result = await signEvmWithTouchConfirm');
    const tempoSignIndex = executorSource.indexOf(
      'const result = await signTempoWithTouchConfirm',
    );

    expect(source).not.toContain('const assertEcdsaOperationAllowedForAttempt');
    expect(source).not.toContain('assertEcdsaOperationAllowedForSource');
    expect(executorSource).not.toContain('assertOperationAllowed');
    expect(retryIndex).toBeGreaterThanOrEqual(0);
    expect(executorIndex).toBeGreaterThan(retryIndex);
    expect(evmSignIndex).toBeGreaterThanOrEqual(0);
    expect(tempoSignIndex).toBeGreaterThanOrEqual(0);
  });

  test('ECDSA transaction signing selects an auth lane before choosing a lane record', () => {
    const source = readRepoFile('client/src/core/signingEngine/api/evmSigning.ts');
    const accountAuthSource = readRepoFile(
      'client/src/core/signingEngine/api/evmFamily/accountAuth.ts',
    );
    const lanesSource = readRepoFile(
      'client/src/core/signingEngine/api/evmFamily/ecdsaLanes.ts',
    );
    const selectionModule = readRepoFile(
      'client/src/core/signingEngine/api/evmFamily/ecdsaSelection.ts',
    );
    const store = readRepoFile(
      'client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.ts',
    );
    const authResolver = accountAuthSource.indexOf(
      'export async function resolveEvmFamilyTransactionAccountAuth',
    );
    const profileLookup = accountAuthSource.indexOf(
      'resolveProfileAccountContextFromCandidates',
      authResolver,
    );
    const ed25519Fallback = accountAuthSource.indexOf(
      'const ed25519Record = getStoredThresholdEd25519SessionRecordForAccount',
      authResolver,
    );
    const selectionResolver = source.indexOf(
      'resolveEvmFamilyEcdsaSigningSelection',
    );
    const selectionModuleResolver = selectionModule.indexOf(
      'export async function resolveEvmFamilyEcdsaSigningSelection',
    );
    const selectionSource = selectionModule.slice(selectionModuleResolver);
    const accountAuthResolution = selectionModule.indexOf(
      'const accountAuth = await resolveEvmFamilyTransactionAccountAuth',
      selectionModuleResolver,
    );
    const emailOtpBranch = selectionModule.indexOf(
      'if (accountAuth.primaryAuthMethod === SIGNER_AUTH_METHODS.emailOtp)',
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
    expect(store).toContain('THRESHOLD_ECDSA_PASSKEY_SESSION_STORE_SOURCES');
    expect(selectionModule).toContain('pickUnambiguousEcdsaAuthRecord');
    expect(selectionSource).not.toContain('genericRecord');
    expect(selectionSource).not.toContain('genericKeyRef');
    expect(profileLookup).toBeGreaterThan(authResolver);
    expect(ed25519Fallback).toBeGreaterThan(profileLookup);
    expect(selectionResolver).toBeGreaterThanOrEqual(0);
    expect(accountAuthResolution).toBeGreaterThan(selectionModuleResolver);
    expect(emailOtpBranch).toBeGreaterThan(accountAuthResolution);
  });

  test('Email OTP ECDSA helpers require the Email OTP source lane', () => {
    const store = readRepoFile(
      'client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.ts',
    );
    const evmSigning = readRepoFile('client/src/core/signingEngine/api/evmSigning.ts');
    const authPlanning = readRepoFile(
      'client/src/core/signingEngine/api/evmFamily/authPlanning.ts',
    );
    const ecdsaLanes = readRepoFile('client/src/core/signingEngine/api/evmFamily/ecdsaLanes.ts');
    const ecdsaSelection = readRepoFile(
      'client/src/core/signingEngine/api/evmFamily/ecdsaSelection.ts',
    );
    const emailOtpCoordinator = readRepoFile(
      'client/src/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator.ts',
    );
    const signingSessionReadiness = readRepoFile(
      'client/src/core/signingEngine/session/signingSession/readiness.ts',
    );
    const warmSessionStatusReader = readRepoFile(
      'client/src/core/signingEngine/session/warmSigning/statusReader.ts',
    );

    expect(store).toContain('getEmailOtpThresholdEcdsaSessionRecordForSigning');
    expect(store).toContain("source: 'email_otp'");
    expect(store).toContain('getPasskeyThresholdEcdsaSessionRecordForSigning');
    const evmSigningDeps = evmSigning.slice(
      evmSigning.indexOf('export type EvmFamilySigningDeps'),
      evmSigning.indexOf('type SignEvmFamilyArgs'),
    );
    expect(evmSigningDeps).not.toContain('getThresholdEcdsaKeyRefForLookup');
    expect(evmSigningDeps).not.toContain('getThresholdEcdsaSessionRecordForLookup');
    expect(evmSigningDeps).toContain('getEmailOtpThresholdEcdsaKeyRefForSigning');
    expect(evmSigningDeps).toContain('getEmailOtpThresholdEcdsaSessionRecordForSigning');
    expect(evmSigningDeps).toContain('getPasskeyThresholdEcdsaKeyRefForSigning');
    expect(evmSigningDeps).toContain('getPasskeyThresholdEcdsaSessionRecordForSigning');
    expect(evmSigning).not.toContain('type EcdsaSigningLaneContext');
    expect(ecdsaSelection).toContain('export type EvmFamilyEcdsaSigningSelection');
    expect(authPlanning).toContain('export type ResolveEvmFamilyTransactionWalletAuthArgs');
    expect(authPlanning).toContain('ecdsaSigningLane?: SigningLaneContext');
    expect(evmSigning).toContain('resolveEvmFamilyTransactionWalletAuth');
    expect(ecdsaLanes).toContain('requireEvmFamilyEcdsaSigningLane');
    expect(ecdsaSelection).toContain('source: SIGNER_AUTH_METHODS.emailOtp');
    expect(ecdsaSelection).toContain('PASSKEY_ECDSA_SIGNING_SOURCE_PRIORITY');
    expect(ecdsaSelection).toContain('listPasskeyEcdsaSigningCandidates');
    expect(ecdsaSelection).toContain('source,');
    expect(ecdsaSelection).toContain(
      "const passkeySource = passkeyCandidate?.source || 'manual-bootstrap'",
    );
    expect(emailOtpCoordinator).toContain(
      "chain: candidateChain,\n          source: 'email_otp'",
    );
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
});

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

  test('ECDSA consumed single-use checks stay inside the retryable Email OTP signing attempt', () => {
    const source = readRepoFile('client/src/core/signingEngine/api/evmSigning.ts');
    const helperIndex = source.indexOf('const assertEcdsaOperationAllowedForAttempt');
    const retryIndex = source.indexOf('const retryWithFreshEmailOtpAuth');
    const directAssertIndex = source.indexOf('await warmSessionManager.assertEcdsaOperationAllowed');
    const evmTryIndex = source.indexOf(
      'try {\n      await assertEcdsaOperationAllowedForAttempt();\n      const result = await signEvmWithTouchConfirm',
    );
    const tempoTryIndex = source.indexOf(
      'try {\n    await assertEcdsaOperationAllowedForAttempt();\n    const result = await signTempoWithTouchConfirm',
    );

    expect(helperIndex).toBeGreaterThanOrEqual(0);
    expect(retryIndex).toBeGreaterThan(helperIndex);
    expect(directAssertIndex).toBeGreaterThan(helperIndex);
    expect(directAssertIndex).toBeLessThan(retryIndex);
    expect(evmTryIndex).toBeGreaterThan(retryIndex);
    expect(tempoTryIndex).toBeGreaterThan(retryIndex);
  });

  test('ECDSA transaction signing selects an auth lane before choosing a lane record', () => {
    const source = readRepoFile('client/src/core/signingEngine/api/evmSigning.ts');
    const store = readRepoFile(
      'client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.ts',
    );
    const authResolver = source.indexOf('async function resolveEvmFamilyTransactionAccountAuth');
    const profileLookup = source.indexOf(
      'resolveProfileAccountContextFromCandidates',
      authResolver,
    );
    const ed25519Fallback = source.indexOf(
      'const ed25519Record = getStoredThresholdEd25519SessionRecordForAccount',
      authResolver,
    );
    const selectionResolver = source.indexOf(
      'async function resolveEvmFamilyEcdsaSigningSelection',
    );
    const selectionEnd = source.indexOf(
      'function createEvmFamilyWarmSessionManager',
      selectionResolver,
    );
    const selectionSource = source.slice(selectionResolver, selectionEnd);
    const accountAuthResolution = source.indexOf(
      'const accountAuth = await resolveEvmFamilyTransactionAccountAuth',
      selectionResolver,
    );
    const emailOtpBranch = source.indexOf(
      'if (accountAuth.primaryAuthMethod === SIGNER_AUTH_METHODS.emailOtp)',
      selectionResolver,
    );

    expect(source).toContain('tryGetEmailOtpThresholdEcdsaSessionRecordForSigning');
    expect(source).toContain('tryGetPasskeyThresholdEcdsaSessionRecordForSigning');
    expect(store).toContain('THRESHOLD_ECDSA_PASSKEY_SESSION_STORE_SOURCES');
    expect(source).toContain('pickUnambiguousEcdsaAuthRecord');
    expect(selectionSource).not.toContain('genericRecord');
    expect(selectionSource).not.toContain('genericKeyRef');
    expect(profileLookup).toBeGreaterThan(authResolver);
    expect(ed25519Fallback).toBeGreaterThan(profileLookup);
    expect(accountAuthResolution).toBeGreaterThan(selectionResolver);
    expect(emailOtpBranch).toBeGreaterThan(accountAuthResolution);
  });

  test('Email OTP ECDSA helpers require the Email OTP source lane', () => {
    const store = readRepoFile(
      'client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.ts',
    );
    const evmSigning = readRepoFile('client/src/core/signingEngine/api/evmSigning.ts');
    const emailOtpCoordinator = readRepoFile(
      'client/src/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator.ts',
    );
    const walletCoordinator = readRepoFile(
      'client/src/core/signingEngine/session/WalletSigningSessionCoordinator.ts',
    );
    const warmSessionManager = readRepoFile(
      'client/src/core/signingEngine/session/WarmSessionManager.ts',
    );

    expect(store).toContain('getEmailOtpThresholdEcdsaSessionRecordForSigning');
    expect(store).toContain("source: 'email_otp'");
    expect(store).toContain('getPasskeyThresholdEcdsaSessionRecordForSigning');
    const evmSigningDeps = evmSigning.slice(
      evmSigning.indexOf('export type EvmFamilySigningDeps'),
      evmSigning.indexOf('type EvmFamilyLifecycleEvent'),
    );
    expect(evmSigningDeps).not.toContain('getThresholdEcdsaKeyRefForSigning');
    expect(evmSigningDeps).not.toContain('getThresholdEcdsaSessionRecordForSigning');
    expect(evmSigningDeps).toContain('getEmailOtpThresholdEcdsaKeyRefForSigning');
    expect(evmSigningDeps).toContain('getEmailOtpThresholdEcdsaSessionRecordForSigning');
    expect(evmSigningDeps).toContain('getPasskeyThresholdEcdsaKeyRefForSigning');
    expect(evmSigningDeps).toContain('getPasskeyThresholdEcdsaSessionRecordForSigning');
    expect(evmSigning).toContain('type EcdsaSigningLaneContext');
    expect(evmSigning).toContain('ecdsaLane');
    expect(evmSigning).toContain('source: SIGNER_AUTH_METHODS.emailOtp');
    expect(evmSigning).toContain(
      "source: (warmRecord?.source || 'manual-bootstrap') as PasskeyEcdsaSessionStoreSource",
    );
    expect(emailOtpCoordinator).toContain(
      "chain: candidateChain,\n          source: 'email_otp'",
    );
    expect(warmSessionManager).toContain(
      'if (args.source && fallback?.source !== args.source) return null;',
    );
    expect(walletCoordinator).toContain("'email_otp'");
    expect(walletCoordinator).toContain("'manual-bootstrap'");
  });
});

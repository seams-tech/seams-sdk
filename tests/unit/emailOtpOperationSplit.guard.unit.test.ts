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
});

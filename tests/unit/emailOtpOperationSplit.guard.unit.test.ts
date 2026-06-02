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
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('ECDSA fresh Email OTP decisions stay planner-owned, not pre-sign guard-owned', () => {
    const source = readRepoFile('client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts');
    const executorSource = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
    );

    expect(source).not.toContain('const assertEcdsaOperationAllowedForAttempt');
    expect(source).not.toContain('assertEcdsaOperationAllowedForSource');
    expect(executorSource).not.toContain('assertOperationAllowed');
  });

  test('ECDSA transaction signing selects an exact lane before material lookup', () => {
    const selectionModule = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts',
    );
    const selectionModuleResolver = selectionModule.indexOf(
      'export async function resolveEvmFamilyEcdsaSigningSelection',
    );
    const selectionSource = selectionModule.slice(selectionModuleResolver);

    expect(selectionModule).not.toContain('findExactEcdsaKeyRefForSelectedLane');
    expect(selectionModule).not.toContain('tryGetEmailOtpThresholdEcdsaKeyRefForSigning');
    expect(selectionModule).not.toContain('tryGetPasskeyThresholdEcdsaKeyRefForSigning');
    expect(selectionSource).not.toContain('genericRecord');
    expect(selectionSource).not.toContain('genericKeyRef');
  });

  test('Email OTP ECDSA helpers require the Email OTP source lane', () => {
    const evmSigning = readRepoFile('client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts');
    const authPlanning = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/authPlanning.ts',
    );
    const ecdsaSelection = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts',
    );
    const preparedSigning = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
    );

    expect(preparedSigning).not.toContain('getThresholdEcdsaKeyRefForLookup');
    expect(preparedSigning).not.toContain('getThresholdEcdsaSessionRecordForLookup');
    expect(preparedSigning).not.toContain('getEmailOtpThresholdEcdsaKeyRefForSigning');
    expect(preparedSigning).not.toContain('getPasskeyThresholdEcdsaKeyRefForSigning');
    expect(evmSigning).not.toContain('type EcdsaSigningLaneContext');
    expect(authPlanning).not.toContain('ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane');
    expect(ecdsaSelection).not.toContain('findExactEcdsaKeyRefForSelectedLane');
    expect(ecdsaSelection).not.toContain('tryGetEmailOtpThresholdEcdsaKeyRefForSigning');
    expect(ecdsaSelection).not.toContain('tryGetPasskeyThresholdEcdsaKeyRefForSigning');
  });

  test('EVM-family ECDSA signing does not use legacy read-side restore fallback paths', () => {
    const preparedSigning = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
    );
    const depsStart = preparedSigning.indexOf('export type PrepareEvmFamilyEcdsaSigningDeps');

    expect(preparedSigning.slice(depsStart)).not.toContain(
      'restorePersistedEmailOtpSessionsForRead',
    );
    expect(preparedSigning).not.toContain("(['email_otp', 'passkey'] as const)");
  });

  test('EVM-family exhausted ECDSA lanes defer ready-material requirements until reauth', () => {
    const evmSigning = readRepoFile('client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts');
    const evmFamilyEcdsaIdentity = readRepoFile(
      'client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts',
    );
    const executorStart = evmSigning.indexOf('const preparedExecutorSession =');
    const executorEnd = evmSigning.indexOf('const executePayload =', executorStart);
    const executorPreparation = evmSigning.slice(executorStart, executorEnd);

    expect(evmSigning).not.toContain('readSelectedEcdsaKeyRefForLane({');
    expect(executorPreparation).not.toContain(
      "requireReadyEcdsaMaterial(\n        preparedExecutorSession.material,\n        'prepared executor signer session'",
    );
    expect(executorPreparation).not.toContain('prepared executor requires ready signer material');
    expect(executorPreparation).not.toContain('toVerifiedEcdsaPublicFactsFromPairedRecordAndKeyRef({');
    expect(executorPreparation).not.toContain(
      'preparedExecutorSession.signingLane.key.thresholdOwnerAddress',
    );
    expect(evmFamilyEcdsaIdentity).not.toContain('!hasReadyThresholdEcdsaClientShare(input.keyRef)');
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

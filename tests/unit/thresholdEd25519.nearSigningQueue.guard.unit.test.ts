import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

function readNearSigningSource(): string {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  const filePath = path.join(repoRoot, 'client/src/core/signingEngine/api/nearSigning.ts');
  return fs.readFileSync(filePath, 'utf8');
}

function readRepoSource(relativePath: string): string {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test.describe('threshold Ed25519 near signing queue guard', () => {
  test('threshold near signing routes through strict session-scoped queue wrapper', () => {
    const source = readNearSigningSource();
    const wrapperCalls = source.match(/withThresholdEd25519CommitQueue\(\{/g)?.length || 0;

    expect(source).toContain('resolveThresholdEd25519CommitQueueKey');
    expect(source).toContain('enabled: true,');
    expect(source).not.toContain('signerMode');
    expect(wrapperCalls).toBeGreaterThanOrEqual(3);
  });

  test('Email OTP NEAR signing waits for pending Ed25519 warm-up instead of falling through', () => {
    const nearSigning = readNearSigningSource();
    const transactionsFlow = readRepoSource(
      'client/src/core/signingEngine/orchestration/near/transactionsFlow.ts',
    );
    const signingFlow = readRepoSource(
      'client/src/core/signingEngine/touchConfirm/handlers/flows/signing.ts',
    );

    expect(nearSigning).toContain('isEmailOtpEd25519WarmupPending');
    expect(nearSigning).toContain('waitForPendingEmailOtpEd25519Warmup');
    expect(nearSigning).toContain('Finalizing NEAR signing session');
    expect(transactionsFlow).toContain('confirmationReadiness');
    expect(transactionsFlow).toContain('ed25519Warmup.waitForReady()');
    expect(signingFlow).toContain('consumeConfirmationReadiness');
    expect(signingFlow).toContain('confirmationReadinessPending');
    expect(signingFlow).toContain('loading: isConfirmationLoading()');
  });

  test('Email OTP NEAR transaction signing attempts sealed restore before OTP fallback', () => {
    const nearSigning = readNearSigningSource();
    const restoreStart = nearSigning.indexOf(
      'async function tryRestoreEmailOtpSigningSessionForNearTransaction',
    );
    const restoreCall = nearSigning.indexOf(
      'await tryRestoreEmailOtpSigningSessionForNearTransaction',
    );
    const authResolution = nearSigning.indexOf(
      'const { walletAuthPlan, emailOtpSigning } = await resolveNearTransactionWalletAuth',
    );

    expect(restoreStart).toBeGreaterThanOrEqual(0);
    expect(nearSigning).toContain('Restoring signing session...');
    expect(nearSigning).toContain(
      "interaction: { kind: 'transaction_confirmation', overlay: 'show' }",
    );
    expect(nearSigning).toContain('rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord');
    expect(restoreCall).toBeGreaterThan(restoreStart);
    expect(authResolution).toBeGreaterThan(restoreCall);
  });
});

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
      'const { signingAuthPlan, signingLane, emailOtpSigning } = await resolveNearTransactionWalletAuth',
    );

    expect(restoreStart).toBeGreaterThanOrEqual(0);
    expect(nearSigning).toContain('Restoring signing session...');
    expect(nearSigning).toContain(
      "interaction: { kind: 'transaction_confirmation', overlay: 'show' }",
    );
    expect(nearSigning).toContain('restoreEmailOtpEcdsaSigningSessionForNearTransaction');
    expect(nearSigning).not.toContain('listThresholdEcdsaSessionRecordsForLookup');
    expect(nearSigning).not.toContain('rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord');
    expect(restoreCall).toBeGreaterThan(restoreStart);
    expect(authResolution).toBeGreaterThan(restoreCall);
  });

  test('Email OTP NEAR warm-session planning does not treat sealed records as spendable auth', () => {
    const nearSigning = readNearSigningSource();

    expect(nearSigning).toContain('hasThresholdEd25519RouteAuth(args.record)');
    expect(nearSigning).toContain('new SigningSessionCoordinator()');
    expect(nearSigning).toContain("emitSigningPlannerDecisionTrace('near', event)");
    expect(nearSigning).not.toContain('readSigningSessionSealedRecord');
  });

  test('Email OTP NEAR cached client-base signing records wallet-session budget spend', () => {
    const nearSigning = readNearSigningSource();
    const transactionsFlow = readRepoSource(
      'client/src/core/signingEngine/orchestration/near/transactionsFlow.ts',
    );
    const signingSessionCoordinator = readRepoSource(
      'client/src/core/signingEngine/session/SigningSessionCoordinator.ts',
    );
    const emailOtpCoordinator = readRepoSource(
      'client/src/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator.ts',
    );
    const worker = readRepoSource(
      'client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
    );

    expect(nearSigning).toContain('signingSessionCoordinator');
    expect(nearSigning).not.toContain('consumeWalletSigningSessionUse');
    expect(transactionsFlow).toContain('recordSuccessfulWalletSigningSessionSpend');
    expect(transactionsFlow).toContain('signingSessionCoordinator');
    expect(transactionsFlow).toContain('cachedXClientBaseB64u');
    expect(signingSessionCoordinator).toContain('consumeWalletSigningSessionUse');
    expect(signingSessionCoordinator).toContain('consumeEmailOtpWarmSessionUses');
    expect(emailOtpCoordinator).toContain('consumeWarmSessionUses');
    expect(emailOtpCoordinator).toContain('consumeEmailOtpWarmSessionUses');
    expect(worker).toContain('consumeEmailOtpWarmSessionUses');
  });

  test('Email OTP NEAR cached client-base signing consumes shared session budgets without PRF claim', () => {
    const orchestrationDeps = readRepoSource(
      'client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts',
    );
    const touchConfirmTypes = readRepoSource('client/src/core/signingEngine/touchConfirm/types.ts');
    const touchConfirmManager = readRepoSource(
      'client/src/core/signingEngine/touchConfirm/TouchConfirmManager.ts',
    );
    const worker = readRepoSource(
      'client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts',
    );
    const signingSessionReadiness = readRepoSource(
      'client/src/core/signingEngine/session/signingSession/readiness.ts',
    );

    expect(orchestrationDeps).toContain('new SigningSessionCoordinator');
    expect(orchestrationDeps).toContain('signingSessionCoordinator');
    expect(orchestrationDeps).not.toContain('walletSigningBudgetLedger');
    expect(orchestrationDeps).not.toContain('consumeWalletSigningSessionUse');
    expect(signingSessionReadiness).toContain('clientAdditiveShareHandle');
    expect(signingSessionReadiness).toContain('walletSigningSessionId');
    expect(touchConfirmTypes).toContain('WarmSessionMaterialConsumer');
    expect(touchConfirmManager).toContain('WARM_SESSION_MATERIAL_CONSUME');
    expect(worker).toContain('consumeWarmSessionMaterialEntry');
    expect(worker).toContain('WARM_SESSION_MATERIAL_CONSUME');
    expect(signingSessionReadiness).toContain('consumeWarmSessionUses');
  });

  test('transaction signing does not consume worker warm-session budgets directly', () => {
    const transactionsFlow = readRepoSource(
      'client/src/core/signingEngine/orchestration/near/transactionsFlow.ts',
    );
    const evmSigning = readRepoSource('client/src/core/signingEngine/api/evmSigning.ts');

    expect(transactionsFlow).toContain('signingSessionCoordinator');
    expect(transactionsFlow).not.toContain('consumeWalletSigningSessionUse');
    expect(transactionsFlow).not.toContain('consumeWarmSessionUses');
    expect(evmSigning).toContain('signingSessionCoordinator');
    expect(evmSigning).not.toContain('consumeWalletSigningSessionUse');
    expect(evmSigning).not.toContain('.consumeWarmSessionUses');
  });

  test('export code cannot consume wallet signing-session budget', () => {
    const recovery = readRepoSource(
      'client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts',
    );

    expect(recovery).not.toContain('WalletSigningSessionCoordinator');
    expect(recovery).not.toContain('consumeWalletSigningSessionUse');
    expect(recovery).not.toContain('consumeUse(');
  });
});

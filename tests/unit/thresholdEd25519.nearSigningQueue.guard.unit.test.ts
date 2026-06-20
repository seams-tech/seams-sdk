import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

function readNearSigningSource(): string {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  const filePath = path.join(repoRoot, 'packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts');
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
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
    );
    const signingFlow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/signing.ts',
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

  test('Email OTP NEAR transaction signing does not perform ECDSA sealed restore as a read side effect', () => {
    const nearSigning = readNearSigningSource();

    expect(nearSigning).not.toContain('tryRestoreEmailOtpSigningSessionForNearTransaction');
    expect(nearSigning).not.toContain('restoreEmailOtpEcdsaSigningSessionForNearTransaction');
    expect(nearSigning).not.toContain('listThresholdEcdsaSessionRecordsForLookup');
    expect(nearSigning).not.toContain('rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord');
  });

  test('Email OTP NEAR warm-session planning does not treat sealed records as spendable auth', () => {
    const nearSigning = readNearSigningSource();
    const walletSessionCredential = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbWalletSessionCredential.ts',
    );

    expect(nearSigning).toContain('hasRouterAbEd25519SigningAuth(args.record)');
    expect(walletSessionCredential).toContain('record.routerAbNormalSigning');
    expect(nearSigning).not.toContain('new SigningSessionCoordinator()');
    expect(nearSigning).toContain("emitSigningPlannerDecisionTrace('near', event)");
    expect(nearSigning).not.toContain('readExactSealedSession');
  });

  test('Email OTP NEAR signing records wallet-session budget spend without raw client-base cache', () => {
    const nearSigning = readNearSigningSource();
    const transactionsFlow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
    );
    const signingSessionCoordinator = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/SigningSessionCoordinator.ts',
    );
    const emailOtpCoordinator = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator.ts',
    );
    const emailOtpWarmSessionRuntime = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/warmSessionRuntime.ts',
    );
    const worker = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
    );

    expect(nearSigning).toContain('signingSessionCoordinator');
    expect(nearSigning).not.toContain('consumeSigningGrantUse');
    expect(transactionsFlow).toContain('recordSuccessfulSigningGrantSpend');
    expect(transactionsFlow).toContain('signingSessionCoordinator');
    expect(transactionsFlow).not.toContain('cachedXClientBaseB64u');
    expect(signingSessionCoordinator).toContain('consumeSigningGrantUse');
    expect(signingSessionCoordinator).toContain('consumeEmailOtpWarmSessionUses');
    expect(emailOtpCoordinator).toContain('consumeWarmSessionUses');
    expect(emailOtpWarmSessionRuntime).toContain('consumeEmailOtpWarmSessionUses');
    expect(worker).toContain('consumeEmailOtpWarmSessionUses');
  });

  test('passkey unlock does not prewarm Ed25519 HSS material', () => {
    const loginFlow = readRepoSource('packages/sdk-web/src/SeamsWeb/operations/auth/login.ts');

    expect(loginFlow).not.toContain('prewarmThresholdEd25519ClientBaseFromCredential');
    expect(loginFlow).not.toContain('prewarmEd25519MaterialForWarmup');
    expect(loginFlow).toContain('parseWarmEd25519SigningSessionAuthorizationFromRecord');
    expect(loginFlow).not.toContain('ed25519HssMaterialHandle');
    expect(loginFlow).not.toContain('clientVerifyingShareB64u');
  });

  test('Email OTP NEAR cached client-base signing consumes shared session budgets without PRF claim', () => {
    const enginePorts = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/assembly/createPorts.ts',
    );
    const touchConfirmTypes = readRepoSource('packages/sdk-web/src/core/signingEngine/uiConfirm/uiConfirm.types.ts');
    const touchConfirmManager = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/uiConfirm/UiConfirmManager.ts',
    );
    const worker = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts',
    );
    const signingSessionReadiness = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/availability/readiness.ts',
    );

    expect(enginePorts).toContain('createSigningSessionCoordinatorPort({');
    expect(enginePorts).toContain('signingSessionCoordinator');
    expect(enginePorts).not.toContain('signingSessionBudget');
    expect(enginePorts).not.toContain('consumeSigningGrantUse');
    expect(signingSessionReadiness).toContain('clientAdditiveShareHandle');
    expect(signingSessionReadiness).toContain('signingGrantId');
    expect(touchConfirmTypes).toContain('WarmSessionMaterialConsumer');
    expect(touchConfirmManager).toContain('WARM_SESSION_MATERIAL_CONSUME');
    expect(worker).toContain('consumeWarmSessionMaterialEntry');
    expect(worker).toContain('WARM_SESSION_MATERIAL_CONSUME');
    expect(signingSessionReadiness).toContain('consumeWarmSessionUses');
  });

  test('transaction signing does not consume worker warm-session budgets directly', () => {
    const transactionsFlow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
    );
    const evmSigning = readRepoSource('packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts');

    expect(transactionsFlow).toContain('signingSessionCoordinator');
    expect(transactionsFlow).not.toContain('consumeSigningGrantUse');
    expect(transactionsFlow).not.toContain('consumeWarmSessionUses');
    expect(evmSigning).toContain('signingSessionCoordinator');
    expect(evmSigning).not.toContain('consumeSigningGrantUse');
    expect(evmSigning).not.toContain('.consumeWarmSessionUses');
  });

  test('export code cannot consume wallet signing-session budget', () => {
    const recovery = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/recovery/privateKeyExportRecovery.ts',
    );

    expect(recovery).not.toContain('SigningSessionCoordinator');
    expect(recovery).not.toContain('consumeSigningGrantUse');
    expect(recovery).not.toContain('consumeUse(');
  });

  test('user-facing Ed25519 signing flows stay on Router A/B normal signing', () => {
    const transactionFlow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
    );
    const nep413Flow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts',
    );
    const delegateFlow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts',
    );
    const normalSigningExecutor = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts',
    );
    const walletSessionCredential = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbWalletSessionCredential.ts',
    );
    const flows = [
      ['transaction', transactionFlow],
      ['nep413', nep413Flow],
      ['delegate', delegateFlow],
    ] as const;

    expect(transactionFlow).toContain('tryFinalizeRouterAbEd25519NearTransactionNormalSigning');
    expect(nep413Flow).toContain('tryFinalizeRouterAbEd25519SignatureOnlyNormalSigning');
    expect(delegateFlow).toContain('tryFinalizeRouterAbEd25519SignatureOnlyNormalSigning');
    for (const [label, source] of flows) {
      expect(source, `${label} flow must build Router A/B-ready state`).toContain(
        'requireRouterAbEd25519NormalSigningReadyState',
      );
      expect(source, `${label} flow must not call old public Ed25519 routes`).not.toContain(
        '/threshold-ed25519/',
      );
      expect(source, `${label} flow must not route normal signing through Derivers`).not.toMatch(
        /deriver|Deriver/,
      );
    }

    expect(normalSigningExecutor).toContain('prepareRouterAbNormalSigningV2');
    expect(normalSigningExecutor).toContain('finalizeRouterAbNormalSigningV2');
    expect(normalSigningExecutor).toContain('prepareRouterAbNormalSigningPresignPoolV2');
    expect(normalSigningExecutor).toContain('finalizeRouterAbNormalSigningPresignPoolHitV2');
    expect(normalSigningExecutor).toContain('requireRouterAbNormalSigningPrepareMatchesRequest');
    expect(normalSigningExecutor).toContain('requireRouterAbNormalSigningResponseMatchesRequest');
    expect(normalSigningExecutor).toContain('credential: routerAbReadyState.credential');
    expect(walletSessionCredential).toContain(
      "requireNonEmpty(signingWalletSession.auth.walletSessionJwt, 'Wallet Session bearer JWT')",
    );
    expect(normalSigningExecutor).not.toContain('/threshold-ed25519/');
    expect(normalSigningExecutor).not.toMatch(/deriver|Deriver/);
  });
});

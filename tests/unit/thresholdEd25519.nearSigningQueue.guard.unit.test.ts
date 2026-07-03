import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

function readNearSigningSource(): string {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  const filePath = path.join(
    repoRoot,
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts',
  );
  return fs.readFileSync(filePath, 'utf8');
}

function readRepoSource(relativePath: string): string {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function sourceBetween(source: string, start: string, end: string): string {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  expect(startIndex, `missing source marker ${start}`).toBeGreaterThanOrEqual(0);
  expect(endIndex, `missing source marker ${end}`).toBeGreaterThan(startIndex);
  return source.slice(startIndex, endIndex);
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

  test('NEAR transaction step-up uses material-aware auth planning', () => {
    const transactionsFlow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
    );
    const stepUpBlock = sourceBetween(
      transactionsFlow,
      'const preparedStepUp = await requireNearStepUpAuth({',
      'const confirmationAuthPayload = preparedStepUp.confirmationAuthPayload;',
    );

    expect(stepUpBlock).toContain('signingAuthPlan: materialAwareSigningAuthPlan');
    expect(stepUpBlock).not.toContain('signingAuthPlan: providedSigningAuthPlan');
  });

  test('Email OTP NEAR warm-session planning does not treat sealed records as spendable auth', () => {
    const nearSigning = readNearSigningSource();
    const walletSessionCredential = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbWalletSessionCredential.ts',
    );

    expect(nearSigning).toContain('hasRouterAbEd25519SigningAuth(args.record)');
    expect(walletSessionCredential).toContain('record.routerAbNormalSigning');
    expect(walletSessionCredential).toContain(
      'parseRouterAbEd25519WalletSessionAuthorityFromRecord(record)',
    );
    expect(walletSessionCredential).not.toContain('walletSessionJwtFromPersistedEd25519Record');
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
    expect(emailOtpCoordinator).toContain('consumeWarmSessionUses');
    expect(emailOtpWarmSessionRuntime).toContain('consumeEmailOtpWarmSessionUses');
    expect(worker).toContain('consumeEmailOtpWarmSessionUses');
  });

  test('passkey unlock does not prewarm Ed25519 HSS material', () => {
    const loginFlow = readRepoSource('packages/sdk-web/src/SeamsWeb/operations/auth/login.ts');
    const signingSurfacePorts = readRepoSource(
      'packages/sdk-web/src/SeamsWeb/signingSurface/ports.ts',
    );
    const loginSurfaceMatch = signingSurfacePorts.match(
      /export type LoginUnlockSigningSurface[\s\S]*?export type RecentUnlocksSigningSurface/,
    );
    const loginSurface = loginSurfaceMatch?.[0] || '';

    expect(loginFlow).not.toContain('prewarmThresholdEd25519ClientBaseFromCredential');
    expect(loginFlow).not.toContain('prewarmEd25519MaterialForWarmup');
    expect(loginFlow).toContain('parseWarmEd25519SigningSessionAuthorizationFromRecord');
    expect(loginFlow).toContain('resolveReusableEd25519WorkerMaterialForLoginSession');
    expect(loginFlow).not.toContain('ed25519WorkerMaterialHandle');
    expect(loginFlow).not.toContain('clientVerifyingShareB64u');
    expect(loginSurface).not.toContain('ThresholdEd25519HssClientSurface');
    expect(loginSurface).not.toContain('ThresholdEd25519HssCeremonySurface');
  });

  test('passkey Ed25519 unlock restores worker material from durable sealed metadata', () => {
    const loginFlow = readRepoSource('packages/sdk-web/src/SeamsWeb/operations/auth/login.ts');
    const sessionProvision = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/passkey/ed25519SessionProvision.ts',
    );
    const bootstrap = readRepoSource(
      'packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts',
    );
    const sealedStore = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts',
    );
    const reconnectRestore = sourceBetween(
      bootstrap,
      'export async function restoreThresholdEd25519WorkerMaterialFromCredential',
      'function parsePositiveInt',
    );
    const currentRestoreMetadata = sourceBetween(
      sealedStore,
      'export type CurrentEd25519RestoreMetadata',
      'export type CurrentEd25519SealedSessionRecord',
    );
    const durableLookup = sourceBetween(
      bootstrap,
      'function hasEd25519RestoreMetadata',
      'async function hydrateCurrentEd25519SessionFromDurableSealedWorkerMaterial',
    );
    const reconstruction = sourceBetween(
      bootstrap,
      'export async function reconstructThresholdEd25519SigningMaterialFromWarmSession',
      'export async function hydrateThresholdWarmSessionFromRelay',
    );
    const loginRestore = sourceBetween(
      loginFlow,
      'const resolution = await resolveReusableEd25519WorkerMaterialForLoginSession',
      "if (args.ecdsaContextResolution.kind === 'resolve_after_ed25519')",
    );

    expect(reconnectRestore).toContain(
      'restoreDurableThresholdEd25519WorkerMaterialFromCredential',
    );
    expect(sessionProvision).not.toContain("args.source === 'login'");
    expect(sessionProvision).toContain("curve: 'ed25519'");
    expect(durableLookup).toContain('hasEd25519RestoreMetadata');
    expect(durableLookup).toContain('listEcdsaSealedSessionsForWallet');
    expect(durableLookup).not.toContain("sealedRecord.curve === 'ed25519'");
    expect(currentRestoreMetadata).toContain('sealedWorkerMaterialRef: string');
    expect(currentRestoreMetadata).toContain('materialKeyId: string');
    expect(currentRestoreMetadata).toContain('routerAbNormalSigning: RouterAbEd25519NormalSigningState');
    expect(currentRestoreMetadata).toContain('sealedWorkerMaterialB64u?: string');
    expect(reconstruction).toContain('persistStoredThresholdEd25519SessionMaterialHandle');
    expect(reconstruction).toContain(
      'refreshDurableThresholdEd25519SealedSessionWithWorkerMaterial',
    );
    expect(
      reconstruction.indexOf('persistStoredThresholdEd25519SessionMaterialHandle'),
    ).toBeLessThan(
      reconstruction.indexOf('refreshDurableThresholdEd25519SealedSessionWithWorkerMaterial'),
    );
    expect(loginRestore).toContain('persistThresholdLoginEd25519ReusableMaterial');
    expect(loginRestore).not.toContain('restoreThresholdEd25519WorkerMaterialFromCredential');
  });

  test('wallet-session reads do not treat pending Ed25519 records as logged-in capability', () => {
    const loginFlow = readRepoSource('packages/sdk-web/src/SeamsWeb/operations/auth/login.ts');
    const loginStateReader = sourceBetween(
      loginFlow,
      'async function getLoginStateInternal',
      'export async function getRecentUnlocks',
    );

    expect(loginStateReader).toContain('hasThresholdEd25519SigningCapability');
    expect(loginStateReader).not.toContain('hasThresholdEd25519SessionRecord');
    expect(loginStateReader).not.toContain('getStoredThresholdEd25519SessionRecordForAccount(resolvedNearAccountId)');
  });

  test('normal Ed25519 signing flows do not run HSS material repair', () => {
    const transactionFlow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
    );
    const nep413Flow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts',
    );
    const delegateFlow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts',
    );
    const materialHandle = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/threshold/ed25519/workerMaterialHandle.ts',
    );
    const materialRestore = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519MaterialRestore.ts',
    );
    const materialReadiness = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness.ts',
    );
    const flows = [
      ['transaction', transactionFlow],
      ['nep413', nep413Flow],
      ['delegate', delegateFlow],
    ] as const;
    const forbiddenRepairMarkers = [
      'ensureThresholdEd25519HssSigningMaterial',
      'ensureThresholdEd25519HssClientBase',
      'runThresholdEd25519HssCeremonyWithSession',
      'runThresholdEd25519HssCeremonyWithMaterialHandle',
      'claimWarmSessionPrfFirstMaterial',
      'prewarmThresholdEd25519ClientBaseFromCredential',
    ] as const;

    expect(transactionFlow).toContain('ed25519MaterialRestoreRequiredError');
    expect(materialRestore).toContain('material_restore_required');
    expect(materialReadiness).toContain('requireSignableRouterAbEd25519WalletSessionState');
    expect(materialReadiness).toContain("case 'material_hint_unvalidated'");
    expect(materialReadiness).toContain("case 'auth_ready_material_pending'");
    expect(materialReadiness).toContain('throwEd25519MaterialRestoreRequired');
    expect(materialHandle).toContain('requireThresholdEd25519WorkerMaterialHandle');
    expect(materialHandle).toContain('validateThresholdEd25519WorkerMaterialNearSignerWasm');

    for (const [label, source] of flows) {
      expect(source, `${label} flow must use shared material readiness`).toContain(
        'requireOrRestoreRouterAbEd25519WalletSessionState',
      );
      for (const marker of forbiddenRepairMarkers) {
        expect(source, `${label} flow must not invoke ${marker}`).not.toContain(marker);
      }
    }

    for (const marker of forbiddenRepairMarkers) {
      expect(materialHandle, `material handle module must not expose ${marker}`).not.toContain(
        marker,
      );
    }
  });

  test('normal Ed25519 signing flows do not read raw client-base material', () => {
    const transactionFlow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
    );
    const nep413Flow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts',
    );
    const delegateFlow = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts',
    );
    const materialReadiness = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness.ts',
    );
    const materialHandle = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/threshold/ed25519/workerMaterialHandle.ts',
    );
    const flows = [
      ['transaction', transactionFlow],
      ['nep413', nep413Flow],
      ['delegate', delegateFlow],
      ['material-readiness', materialReadiness],
    ] as const;

    for (const [label, source] of flows) {
      expect(source, `${label} flow must not read raw client-base material`).not.toContain(
        'xClientBaseB64u',
      );
    }
    expect(materialHandle.match(/xClientBaseB64u/g)?.length || 0).toBe(1);
    expect(materialHandle).toContain('xClientBaseB64u?: never');
  });

  test('active NEAR Ed25519 signing planners use classified worker-material state', () => {
    const scannedPaths = [
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts',
    ] as const;
    const forbiddenRawMaterialFields = [
      'record.ed25519WorkerMaterialHandle',
      'record?.ed25519WorkerMaterialHandle',
      'record.ed25519WorkerMaterialBindingDigest',
      'record?.ed25519WorkerMaterialBindingDigest',
      'record.clientVerifyingShareB64u',
      'record?.clientVerifyingShareB64u',
    ] as const;
    const offenders: string[] = [];

    for (const relativePath of scannedPaths) {
      const source = readRepoSource(relativePath);
      if (
        (relativePath.endsWith('/signNear.ts') ||
          relativePath.endsWith('/signingSessionAuthMode.ts')) &&
        !source.includes('classifyRouterAbEd25519PersistedSigningRecord')
      ) {
        offenders.push(`${relativePath} does not use the Ed25519 material classifier`);
      }
      for (const marker of forbiddenRawMaterialFields) {
        if (source.includes(marker)) {
          offenders.push(`${relativePath} reads raw persisted material field ${marker}`);
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('Email OTP NEAR cached client-base signing consumes shared session budgets without PRF claim', () => {
    const enginePorts = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/assembly/createPorts.ts',
    );
    const touchConfirmTypes = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/uiConfirm/uiConfirm.types.ts',
    );
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
    const evmSigning = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    );

    expect(transactionsFlow).toContain('signingSessionCoordinator');
    expect(transactionsFlow).not.toContain('consumeSigningGrantUse');
    expect(transactionsFlow).not.toContain('consumeWarmSessionUses');
    expect(evmSigning).toContain('signingSessionCoordinator');
    expect(evmSigning).not.toContain('consumeSigningGrantUse');
    expect(evmSigning).not.toContain('.consumeWarmSessionUses');
  });

  test('export code cannot consume signing grant budget', () => {
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
      expect(source, `${label} flow must not call old public Ed25519 routes`).not.toContain(
        '/threshold-ed25519/',
      );
      expect(source, `${label} flow must not route normal signing through Derivers`).not.toMatch(
        /deriver|Deriver/,
      );
    }

    const activeFinalizer = sourceBetween(
      normalSigningExecutor,
      'async function tryFinalizeRouterAbEd25519NormalSigningSignature',
      'export async function tryFinalizeRouterAbEd25519SignatureOnlyNormalSigning',
    );

    expect(activeFinalizer).toContain('prepareRouterAbNormalSigningV2');
    expect(activeFinalizer).toContain('finalizeRouterAbNormalSigningV2');
    expect(activeFinalizer).toContain(
      'createThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandleNearSignerWasm',
    );
    expect(normalSigningExecutor).toContain('requireRouterAbEd25519NormalSigningReadyState');
    expect(activeFinalizer).toContain('requireRouterAbNormalSigningResponseMatchesRequest');
    expect(activeFinalizer).toContain('credential: routerAbReadyState.credential');
    expect(activeFinalizer).not.toContain('refillRouterAbEd25519ClientPresignPool');
    expect(activeFinalizer).not.toContain('prepareRouterAbNormalSigningPresignPoolV2');
    expect(activeFinalizer).not.toContain('finalizeRouterAbNormalSigningPresignPoolHitV2');
    expect(walletSessionCredential).toContain(
      "requireNonEmpty(signingWalletSession.auth.walletSessionJwt, 'Wallet Session bearer JWT')",
    );
    expect(normalSigningExecutor).not.toContain('/threshold-ed25519/');
    expect(normalSigningExecutor).not.toMatch(/deriver|Deriver/);
  });
});

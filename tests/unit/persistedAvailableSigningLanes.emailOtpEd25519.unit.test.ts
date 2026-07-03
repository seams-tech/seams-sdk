import { expect, test } from '@playwright/test';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { readPersistedAvailableSigningLanesForTargets } from '@/core/signingEngine/session/availability/persistedAvailableSigningLanes';
import { selectTransactionLane } from '@/core/signingEngine/session/identity/selectLane';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '@/core/signingEngine/session/identity/laneIdentity';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  type ThresholdEd25519SessionUpsertInput,
  upsertStoredThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { markRouterAbEd25519WorkerMaterialRuntimeValidated } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';

const WALLET_ID = 'email-otp-ed25519-lane.testnet';
const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-email-otp-ed25519',
  projectId: 'project-email-otp-ed25519',
  envId: 'dev',
  signingRootVersion: 'default',
} as const;
const SIGNING_ROOT_ID = `${RUNTIME_POLICY_SCOPE.projectId}:${RUNTIME_POLICY_SCOPE.envId}`;
const ECDSA_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
});

function jsonB64u(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function testEd25519WalletSessionJwt(args: {
  thresholdSessionId: string;
  signingGrantId: string;
}): string {
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u({
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    sub: WALLET_ID,
    walletId: WALLET_ID,
    nearAccountId: WALLET_ID,
    nearEd25519SigningKeyId: WALLET_ID,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    relayerKeyId: 'rk-email-otp-ed25519',
    rpId: 'localhost',
    thresholdExpiresAtMs: Date.now() + 120_000,
    participantIds: [1, 2],
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    routerAbNormalSigning: {
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: 'signing-worker-email-otp-ed25519',
    },
  })}.sig`;
}

function runtimeValidatedPasskeyEd25519RecordInput(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  nowMs: number;
}): ThresholdEd25519SessionUpsertInput {
  return {
    walletId: WALLET_ID,
    nearAccountId: WALLET_ID,
    nearEd25519SigningKeyId: WALLET_ID,
    rpId: 'localhost',
    passkeyCredentialIdB64u: 'credential-passkey-ed25519-login',
    relayerUrl: 'https://relay.example.test',
    relayerKeyId: 'rk-email-otp-ed25519',
    participantIds: [1, 2],
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
    clientVerifyingShareB64u: 'ed25519-login-client-verifier',
    ed25519WorkerMaterialHandle: 'ed25519-login-worker-material-handle',
    ed25519WorkerMaterialBindingDigest: 'ed25519-login-worker-material-binding',
    sealedWorkerMaterialRef: 'sealed-worker-material-ed25519-login',
    sealedWorkerMaterialB64u: 'sealed-worker-material-blob-ed25519-login',
    materialFormatVersion: 'ed25519_worker_material_v1',
    materialKeyId: 'material-key-ed25519-login',
    materialCreatedAtMs: args.nowMs,
    signerSlot: 1,
    routerAbNormalSigning: {
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: 'signing-worker-email-otp-ed25519',
    },
    thresholdSessionKind: 'jwt',
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    walletSessionJwt: testEd25519WalletSessionJwt(args),
    expiresAtMs: args.nowMs + 120_000,
    remainingUses: 3,
    updatedAtMs: args.nowMs,
    source: 'registration',
  };
}

test.describe('persisted Email OTP Ed25519 available signing lanes', () => {
  test.afterEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test('treats storage-ref sealed Email OTP material as restorable without worker status', async () => {
    const thresholdSessionId = 'ed25519-registration-session-storage-ref';
    const signingGrantId = 'signing-grant-ed25519-storage-ref';
    let emailOtpStatusReads = 0;

    clearAllStoredThresholdEd25519SessionRecords();
    upsertStoredThresholdEd25519SessionRecord({
      walletId: WALLET_ID,
      nearAccountId: WALLET_ID,
      nearEd25519SigningKeyId: WALLET_ID,
      rpId: 'localhost',
      relayerUrl: 'https://relay.example.test',
      relayerKeyId: 'rk-email-otp-ed25519',
      participantIds: [1, 2],
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
      clientVerifyingShareB64u: 'ed25519-registration-client-verifier',
      ed25519WorkerMaterialBindingDigest: 'ed25519-worker-material-binding',
      sealedWorkerMaterialRef: 'sealed-worker-material-ref',
      materialFormatVersion: 'ed25519_sealed_worker_material_v1',
      materialKeyId: 'material-key-email-otp-ed25519',
      materialCreatedAtMs: Date.now(),
      signerSlot: 1,
      keyVersion: 'threshold-ed25519-hss-v1',
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1',
        signingWorkerId: 'signing-worker-email-otp-ed25519',
      },
      thresholdSessionKind: 'jwt',
      thresholdSessionId,
      signingGrantId,
      walletSessionJwt: testEd25519WalletSessionJwt({ thresholdSessionId, signingGrantId }),
      expiresAtMs: Date.now() + 120_000,
      remainingUses: 2,
      emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
        policy: 'session',
        walletId: WALLET_ID,
        emailHashHex: 'email-hash-ed25519-lane',
        retention: 'session',
        reason: 'login',
        provider: 'google',
        providerUserId: 'email-otp-subject-ed25519-lane',
      }),
      updatedAtMs: Date.now(),
      source: 'email_otp',
    });

    const lanes = await readPersistedAvailableSigningLanesForTargets(
      {
        ecdsaSessions: {
          recordsByLane: new Map(),
          exportArtifactsByLane: new Map(),
        },
        statusReader: {
          getWarmSessionStatus: async () => ({ ok: false, code: 'not_found', message: 'missing' }),
        },
        getEmailOtpWarmSessionStatus: async () => {
          emailOtpStatusReads += 1;
          return { ok: false, code: 'not_found', message: 'missing' };
        },
      },
      {
        walletId: WALLET_ID,
        authMethod: 'email_otp',
        ecdsaChainTargets: [ECDSA_TARGET],
      },
    );

    expect(emailOtpStatusReads).toBe(0);
    expect(lanes.lanes.ed25519.near).toMatchObject({
      curve: 'ed25519',
      chain: 'near',
      state: 'restorable',
      source: 'runtime_session_record',
      signingGrantId,
      thresholdSessionId,
      remainingUses: 2,
      material: {
        kind: 'sealed_worker_material',
        identity: {
          materialKeyId: 'material-key-email-otp-ed25519',
          bindingDigest: 'ed25519-worker-material-binding',
        },
      },
    });
  });

  test('keeps runtime-validated Ed25519 material ready when warm status is not found', async () => {
    const thresholdSessionId = 'threshold-login-runtime-validated';
    const signingGrantId = 'wallet-session-runtime-validated';
    const nowMs = Date.now();
    let passkeyStatusReads = 0;

    clearAllStoredThresholdEd25519SessionRecords();
    const record = upsertStoredThresholdEd25519SessionRecord(
      runtimeValidatedPasskeyEd25519RecordInput({ thresholdSessionId, signingGrantId, nowMs }),
    );
    expect(markRouterAbEd25519WorkerMaterialRuntimeValidated(record)).toBe(true);

    const lanes = await readPersistedAvailableSigningLanesForTargets(
      {
        ecdsaSessions: {
          recordsByLane: new Map(),
          exportArtifactsByLane: new Map(),
        },
        statusReader: {
          getWarmSessionStatus: async () => {
            passkeyStatusReads += 1;
            return { ok: false, code: 'not_found', message: 'missing' };
          },
        },
        getEmailOtpWarmSessionStatus: async () => ({
          ok: false,
          code: 'not_found',
          message: 'missing',
        }),
      },
      {
        walletId: WALLET_ID,
        authMethod: 'passkey',
        ecdsaChainTargets: [ECDSA_TARGET],
      },
    );

    expect(passkeyStatusReads).toBe(1);
    expect(lanes.lanes.ed25519.near).toMatchObject({
      curve: 'ed25519',
      chain: 'near',
      state: 'ready',
      source: 'runtime_session_record',
      signingGrantId,
      thresholdSessionId,
      remainingUses: 3,
      material: {
        kind: 'loaded_worker_material',
        identity: {
          materialKeyId: 'material-key-ed25519-login',
          bindingDigest: 'ed25519-login-worker-material-binding',
        },
      },
    });
  });

  test('keeps runtime-validated Ed25519 material transaction-ready when warm reader throws', async () => {
    const thresholdSessionId = 'threshold-login-runtime-validated-reader-throws';
    const signingGrantId = 'wallet-session-runtime-validated-reader-throws';
    const nowMs = Date.now();

    clearAllStoredThresholdEd25519SessionRecords();
    const record = upsertStoredThresholdEd25519SessionRecord(
      runtimeValidatedPasskeyEd25519RecordInput({ thresholdSessionId, signingGrantId, nowMs }),
    );
    expect(markRouterAbEd25519WorkerMaterialRuntimeValidated(record)).toBe(true);

    const lanes = await readPersistedAvailableSigningLanesForTargets(
      {
        ecdsaSessions: {
          recordsByLane: new Map(),
          exportArtifactsByLane: new Map(),
        },
        statusReader: {
          getWarmSessionStatus: async () => {
            throw new Error('warm status iframe cache unavailable');
          },
        },
        getEmailOtpWarmSessionStatus: async () => {
          throw new Error('email otp warm status unavailable');
        },
      },
      {
        walletId: WALLET_ID,
        authMethod: 'passkey',
        ecdsaChainTargets: [ECDSA_TARGET],
      },
    );
    const selected = selectTransactionLane({
      intent: {
        walletId: toWalletId(WALLET_ID),
        curve: 'ed25519',
        chain: 'near',
        authSelectionPolicy: { kind: 'any' },
        operationUsesNeeded: 1,
      },
      availableLanes: lanes,
    });

    expect(lanes.lanes.ed25519.near).toMatchObject({
      state: 'ready',
      source: 'runtime_session_record',
      signingGrantId,
      thresholdSessionId,
      material: {
        kind: 'loaded_worker_material',
        identity: {
          materialKeyId: 'material-key-ed25519-login',
          bindingDigest: 'ed25519-login-worker-material-binding',
        },
      },
    });
    expect(selected).toMatchObject({
      ok: true,
      selectionCandidate: {
        kind: 'near_ed25519_transaction_ready_lane',
        material: {
          kind: 'loaded_worker_material',
          identity: {
            materialKeyId: 'material-key-ed25519-login',
            bindingDigest: 'ed25519-login-worker-material-binding',
          },
        },
      },
    });
  });

  test('keeps runtime-validated Ed25519 material transaction-ready when wallet budget is not found', async () => {
    const thresholdSessionId = 'threshold-login-runtime-validated-budget-not-found';
    const signingGrantId = 'wallet-session-runtime-validated-budget-not-found';
    const nowMs = Date.now();
    let budgetStatusReads = 0;

    clearAllStoredThresholdEd25519SessionRecords();
    const record = upsertStoredThresholdEd25519SessionRecord(
      runtimeValidatedPasskeyEd25519RecordInput({ thresholdSessionId, signingGrantId, nowMs }),
    );
    expect(markRouterAbEd25519WorkerMaterialRuntimeValidated(record)).toBe(true);

    const lanes = await readPersistedAvailableSigningLanesForTargets(
      {
        ecdsaSessions: {
          recordsByLane: new Map(),
          exportArtifactsByLane: new Map(),
        },
        statusReader: {
          getWarmSessionStatus: async () => ({
            ok: false,
            code: 'not_found',
            message: 'missing',
          }),
        },
        getWalletSigningBudgetStatus: async () => {
          budgetStatusReads += 1;
          return { status: 'not_found' };
        },
        getEmailOtpWarmSessionStatus: async () => ({
          ok: false,
          code: 'not_found',
          message: 'missing',
        }),
      },
      {
        walletId: WALLET_ID,
        authMethod: 'passkey',
        ecdsaChainTargets: [ECDSA_TARGET],
      },
    );
    const selected = selectTransactionLane({
      intent: {
        walletId: toWalletId(WALLET_ID),
        curve: 'ed25519',
        chain: 'near',
        authSelectionPolicy: { kind: 'any' },
        operationUsesNeeded: 1,
      },
      availableLanes: lanes,
    });

    expect(budgetStatusReads).toBe(1);
    expect(lanes.lanes.ed25519.near).toMatchObject({
      state: 'ready',
      source: 'runtime_session_record',
      signingGrantId,
      thresholdSessionId,
      remainingUses: 3,
      material: {
        kind: 'loaded_worker_material',
        identity: {
          materialKeyId: 'material-key-ed25519-login',
          bindingDigest: 'ed25519-login-worker-material-binding',
        },
      },
    });
    expect(selected).toMatchObject({
      ok: true,
      selectionCandidate: {
        kind: 'near_ed25519_transaction_ready_lane',
      },
    });
  });

  test('keeps auth-ready pending Email OTP material deferred even when warm status is active', async () => {
    const thresholdSessionId = 'ed25519-registration-session-deferred-client-base';
    const signingGrantId = 'signing-grant-ed25519-deferred-client-base';
    let emailOtpStatusReads = 0;

    clearAllStoredThresholdEd25519SessionRecords();
    upsertStoredThresholdEd25519SessionRecord({
      walletId: WALLET_ID,
      nearAccountId: WALLET_ID,
      nearEd25519SigningKeyId: WALLET_ID,
      rpId: 'localhost',
      relayerUrl: 'https://relay.example.test',
      relayerKeyId: 'rk-email-otp-ed25519',
      participantIds: [1, 2],
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
      signerSlot: 1,
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1',
        signingWorkerId: 'signing-worker-email-otp-ed25519',
      },
      thresholdSessionKind: 'jwt',
      thresholdSessionId,
      signingGrantId,
      walletSessionJwt: testEd25519WalletSessionJwt({ thresholdSessionId, signingGrantId }),
      expiresAtMs: Date.now() + 120_000,
      remainingUses: 3,
      emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
        policy: 'session',
        walletId: WALLET_ID,
        emailHashHex: 'email-hash-ed25519-lane',
        retention: 'session',
        reason: 'login',
        provider: 'google',
        providerUserId: 'email-otp-subject-ed25519-lane',
      }),
      updatedAtMs: Date.now(),
      source: 'email_otp',
    });

    const lanes = await readPersistedAvailableSigningLanesForTargets(
      {
        ecdsaSessions: {
          recordsByLane: new Map(),
          exportArtifactsByLane: new Map(),
        },
        statusReader: {
          getWarmSessionStatus: async () => ({ ok: false, code: 'not_found', message: 'missing' }),
        },
        getEmailOtpWarmSessionStatus: async () => {
          emailOtpStatusReads += 1;
          return {
            ok: true,
            remainingUses: 3,
            expiresAtMs: Date.now() + 120_000,
          };
        },
      },
      {
        walletId: WALLET_ID,
        authMethod: 'email_otp',
        ecdsaChainTargets: [ECDSA_TARGET],
      },
    );

    expect(emailOtpStatusReads).toBe(0);
    expect(lanes.lanes.ed25519.near).toMatchObject({
      curve: 'ed25519',
      chain: 'near',
      state: 'deferred',
      source: 'runtime_session_record',
      signingGrantId,
      thresholdSessionId,
      remainingUses: 3,
    });
  });
});

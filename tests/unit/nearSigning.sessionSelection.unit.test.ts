import { expect, test } from '@playwright/test';
import {
  buildNearSigningSessionAuthPlan,
  createNearSigningSessionCoordinator,
  resolveNearSigningSessionAuthContext,
} from '@/core/signingEngine/flows/signNear/shared/signingSessionAuthMode';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import { SigningAuthPlanKind } from '@/core/signingEngine/stepUpConfirmation/types';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmCapabilities/persistence';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
} from '@/core/signingEngine/session/persistence/records';
import {
  parseEd25519ClientVerifyingShareB64u,
  parseEd25519SealedWorkerMaterialRef,
  parseEd25519WorkerMaterialBindingDigest,
  parseEd25519WorkerMaterialKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';
import type { SigningSessionStatus } from '@/core/types/seams';
import {
  nearAccountRefFromAccountId,
  toWalletId,
  type NearCommandSubject,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

function nearCommandSubject(walletIdRaw: string, nearAccountIdRaw = walletIdRaw): NearCommandSubject {
  return {
    walletSession: {
      walletId: toWalletId(walletIdRaw),
      walletSessionUserId: walletIdRaw,
    },
    nearAccount: nearAccountRefFromAccountId(nearAccountIdRaw),
  };
}

function base64UrlEncodeJsonFixture(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function buildUnsignedJwtFixture(payload: Record<string, unknown>): string {
  return `${base64UrlEncodeJsonFixture({ alg: 'none', typ: 'JWT' })}.${base64UrlEncodeJsonFixture(payload)}.fixture`;
}

function buildRouterAbEd25519WalletSessionJwtFixture(args: {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  thresholdSessionId: string;
  signingGrantId: string;
  relayerKeyId: string;
}): string {
  return buildUnsignedJwtFixture({
    kind: 'router_ab_ed25519_wallet_session_v1',
    sub: args.walletId,
    walletId: args.walletId,
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    relayerKeyId: args.relayerKeyId,
    rpId: 'example.localhost',
    participantIds: [1, 2],
  });
}

function createStatusBackedPasskeyEd25519WarmSessionReader(args: {
  walletId?: string;
  nearAccountId: string;
  nearEd25519SigningKeyId?: string;
  signingGrantId: string;
  thresholdSessionId: string;
  expiresAtMs: number;
  status: SigningSessionStatus;
}) {
  const walletId = args.walletId || args.nearAccountId;
  const nearEd25519SigningKeyId = args.nearEd25519SigningKeyId || walletId;
  const record = {
    walletId,
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId,
    signerSlot: 1,
    rpId: 'example.localhost',
    passkeyCredentialIdB64u: 'credential-ed25519-session-selection',
    relayerUrl: 'https://relay.example.test',
    relayerKeyId: 'ed25519:relayer-key-id',
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt',
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    expiresAtMs: args.expiresAtMs,
    remainingUses: 3,
    source: 'login',
    updatedAtMs: Date.now(),
  };

  return {
    getWarmSession: async () => ({
      accountId: walletId,
      updatedAtMs: Date.now(),
      capabilities: {
        ed25519: {
          capability: 'ed25519',
          state: 'prf_missing',
          record,
          auth: null,
          prfClaim: null,
        },
        ecdsa: {
          evm: {
            capability: 'ecdsa',
            state: 'missing',
            record: null,
            key: null,
            lane: null,
            auth: null,
            prfClaim: null,
          },
          tempo: {
            capability: 'ecdsa',
            state: 'missing',
            record: null,
            key: null,
            lane: null,
            auth: null,
            prfClaim: null,
          },
        },
      },
    }),
    getEd25519SigningSessionStatusForSession: async () => args.status,
  } as any;
}

test.describe('near signing session selection', () => {
  test.afterEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test('treats passkey Ed25519 auth-missing state as step-up reauthable', async () => {
    const nearAccountId = 'passkey-ed25519-auth-missing.testnet';
    const signingGrantId = 'wallet-passkey-ed25519-auth-missing';
    const thresholdSessionId = 'threshold-passkey-ed25519-auth-missing';
    const expiresAtMs = Date.now() + 60_000;
    const warmSessionReader = {
      getWarmSession: async () => ({
        accountId: nearAccountId,
        updatedAtMs: Date.now(),
        capabilities: {
          ed25519: {
            capability: 'ed25519',
            state: 'auth_missing',
            record: {
              walletId: nearAccountId,
              nearAccountId,
              nearEd25519SigningKeyId: nearAccountId,
              signerSlot: 1,
              rpId: 'example.localhost',
              passkeyCredentialIdB64u: 'credential-ed25519-auth-missing',
              relayerUrl: 'https://relay.example.test',
              relayerKeyId: 'ed25519:relayer-key-id',
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId,
              signingGrantId,
              expiresAtMs,
              remainingUses: 0,
              source: 'login',
              updatedAtMs: Date.now(),
            },
            auth: null,
            prfClaim: null,
          },
          ecdsa: {
            evm: {
              capability: 'ecdsa',
              state: 'missing',
              record: null,
              key: null,
              lane: null,
              auth: null,
              prfClaim: null,
            },
            tempo: {
              capability: 'ecdsa',
              state: 'missing',
              record: null,
              key: null,
              lane: null,
              auth: null,
              prfClaim: null,
            },
          },
        },
      }),
      getEd25519SigningSessionStatusForSession: async () => ({
        sessionId: thresholdSessionId,
        status: 'unavailable',
        statusCode: 'auth_missing',
      }),
    } as any;

    const context = await resolveNearSigningSessionAuthContext({
      warmSessionReader,
      commandSubject: nearCommandSubject(nearAccountId),
      operationLabel: 'transaction signing',
      requiredSignatureUses: 1,
    });
    const coordinator = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: signingGrantId,
        status: 'active',
        remainingUses: 1,
        expiresAtMs,
        projectionVersion: 'projection:passkey-ed25519-auth-missing',
      }),
    } as any);
    const resolved = await coordinator.resolveAuthPlanFromReadiness(context.coordinatorInput);
    const plan = buildNearSigningSessionAuthPlan({ context, resolvedSigningSession: resolved });

    expect(plan.signingAuthPlan?.kind).toBe(SigningAuthPlanKind.PasskeyReauth);
    expect(plan.warmSessionReady).toBe(false);
  });

  test('plans passkey Ed25519 sealed pending material as warm-session repair without reauth', async () => {
    clearAllStoredThresholdEd25519SessionRecords();
    const nearAccountId = 'pending-material-passkey-ed25519.testnet';
    const walletId = nearAccountId;
    const nearEd25519SigningKeyId = nearAccountId;
    const signingGrantId = 'wallet-pending-material-passkey-ed25519';
    const thresholdSessionId = 'threshold-pending-material-passkey-ed25519';
    const expiresAtMs = Date.now() + 60_000;
    const relayerKeyId = 'ed25519:pending-material-relayer-key';
    const walletSessionJwt = buildRouterAbEd25519WalletSessionJwtFixture({
      walletId,
      nearAccountId,
      nearEd25519SigningKeyId,
      thresholdSessionId,
      signingGrantId,
      relayerKeyId,
    });
    persistWarmSessionEd25519Capability({
      kind: 'jwt_passkey' as const,
      passkeyCredentialIdB64u: 'credential-ed25519-session-selection',
      walletId: walletId as any,
      nearAccountId: nearAccountId as any,
      nearEd25519SigningKeyId,
      rpId: 'localhost',
      relayerUrl: 'https://localhost:9444',
      relayerKeyId,
      participantIds: [1, 2],
      sessionKind: 'jwt' as const,
      sessionId: thresholdSessionId,
      signingGrantId,
      expiresAtMs,
      remainingUses: 2,
      signerSlot: 1,
      clientVerifyingShareB64u: parseEd25519ClientVerifyingShareB64u(
        'pending-material-client-verifying-share',
      ),
      ed25519WorkerMaterialBindingDigest: parseEd25519WorkerMaterialBindingDigest(
        'pending-material-binding-digest',
      ),
      sealedWorkerMaterialRef: parseEd25519SealedWorkerMaterialRef(
        'pending-material-sealed-ref',
      ),
      sealedWorkerMaterialB64u: 'pending-material-sealed-blob',
      materialFormatVersion: 'ed25519_worker_material_v1',
      materialKeyId: parseEd25519WorkerMaterialKeyId('pending-material-key-id'),
      materialCreatedAtMs: Date.now(),
      keyVersion: 'kek-s-test',
      jwt: walletSessionJwt,
      runtimePolicyScope: {
        orgId: 'org-pending-material',
        projectId: 'project-pending-material',
        envId: 'dev',
        signingRootVersion: 'default',
      },
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1' as const,
        signingWorkerId: 'signing-worker-local',
      },
      source: 'registration' as const,
    });

    const warmSessionReader = createNearSigningSessionCoordinator({
      getWarmSessionStatus: async () => ({ ok: true as const, remainingUses: 2, expiresAtMs }),
      getWarmSessionStatuses: async ({ sessionIds }: { sessionIds: string[] }) => ({
        results: sessionIds.map((sessionId) => ({
          sessionId,
          result: { ok: true as const, remainingUses: 2, expiresAtMs },
        })),
      }),
    } as any);

    const context = await resolveNearSigningSessionAuthContext({
      warmSessionReader,
      commandSubject: nearCommandSubject(nearAccountId),
      operationLabel: 'transaction signing',
      requiredSignatureUses: 1,
    });
    const coordinator = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: signingGrantId,
        status: 'active',
        remainingUses: 2,
        expiresAtMs,
        projectionVersion: 'projection:pending-material-passkey-ed25519',
      }),
    } as any);
    const resolved = await coordinator.resolveAuthPlanFromReadiness(context.coordinatorInput);
    const plan = buildNearSigningSessionAuthPlan({ context, resolvedSigningSession: resolved });

    expect(plan.signingAuthPlan?.kind).toBe(SigningAuthPlanKind.WarmSession);
    expect(plan.warmSessionReady).toBe(true);
  });

  test('plans passkey Ed25519 auth-only pending material as reauth instead of warm repair', async () => {
    clearAllStoredThresholdEd25519SessionRecords();
    const nearAccountId = 'auth-only-pending-passkey-ed25519.testnet';
    const walletId = nearAccountId;
    const nearEd25519SigningKeyId = nearAccountId;
    const signingGrantId = 'wallet-auth-only-pending-passkey-ed25519';
    const thresholdSessionId = 'threshold-auth-only-pending-passkey-ed25519';
    const expiresAtMs = Date.now() + 60_000;
    const relayerKeyId = 'ed25519:auth-only-pending-relayer-key';
    const walletSessionJwt = buildRouterAbEd25519WalletSessionJwtFixture({
      walletId,
      nearAccountId,
      nearEd25519SigningKeyId,
      thresholdSessionId,
      signingGrantId,
      relayerKeyId,
    });
    persistWarmSessionEd25519Capability({
      kind: 'jwt_passkey' as const,
      passkeyCredentialIdB64u: 'credential-ed25519-session-selection',
      walletId: walletId as any,
      nearAccountId: nearAccountId as any,
      nearEd25519SigningKeyId,
      rpId: 'localhost',
      relayerUrl: 'https://localhost:9444',
      relayerKeyId,
      participantIds: [1, 2],
      sessionKind: 'jwt' as const,
      sessionId: thresholdSessionId,
      signingGrantId,
      expiresAtMs,
      remainingUses: 2,
      signerSlot: 1,
      jwt: walletSessionJwt,
      runtimePolicyScope: {
        orgId: 'org-auth-only-pending',
        projectId: 'project-auth-only-pending',
        envId: 'dev',
        signingRootVersion: 'default',
      },
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1' as const,
        signingWorkerId: 'signing-worker-local',
      },
      source: 'login' as const,
    });

    const warmSessionReader = createNearSigningSessionCoordinator({
      getWarmSessionStatus: async () => ({ ok: true as const, remainingUses: 2, expiresAtMs }),
      getWarmSessionStatuses: async ({ sessionIds }: { sessionIds: string[] }) => ({
        results: sessionIds.map((sessionId) => ({
          sessionId,
          result: { ok: true as const, remainingUses: 2, expiresAtMs },
        })),
      }),
    } as any);

    const context = await resolveNearSigningSessionAuthContext({
      warmSessionReader,
      commandSubject: nearCommandSubject(nearAccountId),
      operationLabel: 'transaction signing',
      requiredSignatureUses: 1,
    });
    const coordinator = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: signingGrantId,
        status: 'active',
        remainingUses: 2,
        expiresAtMs,
        projectionVersion: 'projection:auth-only-pending-passkey-ed25519',
      }),
    } as any);
    const resolved = await coordinator.resolveAuthPlanFromReadiness(context.coordinatorInput);
    const plan = buildNearSigningSessionAuthPlan({ context, resolvedSigningSession: resolved });

    expect(plan.signingAuthPlan?.kind).toBe(SigningAuthPlanKind.PasskeyReauth);
    expect(plan.warmSessionReady).toBe(false);
  });

  test('fails closed when restored passkey Ed25519 material cannot be refreshed', async () => {
    const nearAccountId = 'refresh-failed-passkey-ed25519.testnet';
    const walletId = nearAccountId;
    const nearEd25519SigningKeyId = nearAccountId;
    const signingGrantId = 'wallet-refresh-failed-passkey-ed25519';
    const thresholdSessionId = 'threshold-refresh-failed-passkey-ed25519';
    const expiresAtMs = Date.now() + 60_000;
    const relayerKeyId = 'ed25519:refresh-failed-relayer-key';
    const walletSessionJwt = buildRouterAbEd25519WalletSessionJwtFixture({
      walletId,
      nearAccountId,
      nearEd25519SigningKeyId,
      thresholdSessionId,
      signingGrantId,
      relayerKeyId,
    });
    const record = {
      walletId,
      nearAccountId,
      nearEd25519SigningKeyId,
      rpId: 'localhost',
      passkeyCredentialIdB64u: 'credential-ed25519-refresh-failed',
      relayerUrl: 'https://localhost:9444',
      relayerKeyId,
      participantIds: [1, 2],
      thresholdSessionKind: 'jwt',
      thresholdSessionId,
      signingGrantId,
      expiresAtMs,
      remainingUses: 2,
      signerSlot: 1,
      clientVerifyingShareB64u: parseEd25519ClientVerifyingShareB64u(
        'refresh-failed-client-verifying-share',
      ),
      ed25519WorkerMaterialBindingDigest: parseEd25519WorkerMaterialBindingDigest(
        'refresh-failed-binding-digest',
      ),
      sealedWorkerMaterialRef: parseEd25519SealedWorkerMaterialRef(
        'refresh-failed-sealed-ref',
      ),
      sealedWorkerMaterialB64u: 'refresh-failed-sealed-blob',
      materialFormatVersion: 'ed25519_worker_material_v1',
      materialKeyId: parseEd25519WorkerMaterialKeyId('refresh-failed-material-key-id'),
      materialCreatedAtMs: Date.now(),
      keyVersion: 'kek-s-test',
      jwt: walletSessionJwt,
      walletSessionJwt,
      runtimePolicyScope: {
        orgId: 'org-refresh-failed',
        projectId: 'project-refresh-failed',
        envId: 'dev',
        signingRootVersion: 'default',
      },
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1' as const,
        signingWorkerId: 'signing-worker-local',
      },
      source: 'login' as const,
      updatedAtMs: Date.now(),
    };
    const warmSessionReader = {
      getWarmSession: async () => ({
        accountId: nearAccountId,
        updatedAtMs: Date.now(),
        capabilities: {
          ed25519: {
            capability: 'ed25519',
            state: 'prf_missing',
            record,
            auth: null,
            prfClaim: null,
          },
          ecdsa: {
            evm: {
              capability: 'ecdsa',
              state: 'missing',
              record: null,
              key: null,
              lane: null,
              auth: null,
              prfClaim: null,
            },
            tempo: {
              capability: 'ecdsa',
              state: 'missing',
              record: null,
              key: null,
              lane: null,
              auth: null,
              prfClaim: null,
            },
          },
        },
      }),
      restorePersistedSessionForSigning: async () => ({ attempted: 1, restored: 1, deferred: 0 }),
      getEd25519CapabilityByThresholdSessionId: async () => {
        throw new Error('refreshed capability unavailable');
      },
      getEd25519SigningSessionStatusForSession: async () => {
        throw new Error('status should not be read after refresh failure');
      },
    } as any;

    await expect(
      resolveNearSigningSessionAuthContext({
        warmSessionReader,
        commandSubject: nearCommandSubject(nearAccountId),
        operationLabel: 'transaction signing',
        requiredSignatureUses: 1,
      }),
    ).rejects.toThrow(
      'worker_restore_failed: pre_confirm:capability_refresh_failed:refreshed capability unavailable',
    );
  });

  test('uses server-available budget for passkey Ed25519 admission', async () => {
    const nearAccountId = 'server-available-budget-passkey-ed25519.testnet';
    const signingGrantId = 'wallet-server-available-budget-passkey-ed25519';
    const thresholdSessionId = 'threshold-server-available-budget-passkey-ed25519';
    const expiresAtMs = Date.now() + 60_000;
    const context = await resolveNearSigningSessionAuthContext({
      warmSessionReader: createStatusBackedPasskeyEd25519WarmSessionReader({
        nearAccountId,
        signingGrantId,
        thresholdSessionId,
        expiresAtMs,
        status: {
          sessionId: thresholdSessionId,
          status: 'active',
          remainingUses: 3,
          committedRemainingUses: 3,
          inFlightReservedUses: 3,
          availableUses: 0,
          expiresAtMs,
          projectionVersion: 'projection:server-available-budget-passkey-ed25519',
        },
      }),
      commandSubject: nearCommandSubject(nearAccountId),
      operationLabel: 'transaction signing',
      requiredSignatureUses: 1,
    });

    expect(context.coordinatorInput.readiness.status).toBe('exhausted');
    expect(context.coordinatorInput.remainingUses).toBe(0);
  });

  test('rejects malformed active Ed25519 budget status before warm-session admission', async () => {
    const nearAccountId = 'malformed-active-budget-passkey-ed25519.testnet';
    const signingGrantId = 'wallet-malformed-active-budget-passkey-ed25519';
    const thresholdSessionId = 'threshold-malformed-active-budget-passkey-ed25519';
    const expiresAtMs = Date.now() + 60_000;
    const context = await resolveNearSigningSessionAuthContext({
      warmSessionReader: createStatusBackedPasskeyEd25519WarmSessionReader({
        nearAccountId,
        signingGrantId,
        thresholdSessionId,
        expiresAtMs,
        status: {
          sessionId: thresholdSessionId,
          status: 'active',
          remainingUses: 3,
          expiresAtMs,
          projectionVersion: 'projection:malformed-active-budget-passkey-ed25519',
        },
      }),
      commandSubject: nearCommandSubject(nearAccountId),
      operationLabel: 'transaction signing',
      requiredSignatureUses: 1,
    });

    expect(context.coordinatorInput.readiness.status).toBe('missing_session');
    expect(context.coordinatorInput.remainingUses).toBe(0);
  });

  test('uses generated wallet id for implicit NEAR signing lane while preserving NEAR account id', async () => {
    const walletId = 'frost-vermillion-k7p9m2';
    const nearAccountId = 'a'.repeat(64);
    const signingGrantId = 'wallet-implicit-ed25519-direct-signing';
    const thresholdSessionId = 'threshold-implicit-ed25519-direct-signing';
    const expiresAtMs = Date.now() + 60_000;
    const context = await resolveNearSigningSessionAuthContext({
      warmSessionReader: createStatusBackedPasskeyEd25519WarmSessionReader({
        walletId,
        nearAccountId,
        signingGrantId,
        thresholdSessionId,
        expiresAtMs,
        status: {
          sessionId: thresholdSessionId,
          status: 'active',
          remainingUses: 3,
          committedRemainingUses: 3,
          inFlightReservedUses: 0,
          availableUses: 3,
          expiresAtMs,
          projectionVersion: 'projection:implicit-ed25519-direct-signing',
        },
      }),
      commandSubject: nearCommandSubject(walletId, nearAccountId),
      operationLabel: 'transaction signing',
      requiredSignatureUses: 1,
    });

    expect(walletId).not.toBe(nearAccountId);
    expect(context.walletId).toBe(walletId);
    expect(context.nearAccountId).toBe(nearAccountId);
    expect(String(context.lane.walletId)).toBe(walletId);
    expect(String(context.lane.nearAccountId)).toBe(nearAccountId);
    expect(String(context.lane.nearEd25519SigningKeyId)).toBe(walletId);
    expect(context.coordinatorInput.lane.curve).toBe('ed25519');
    if (context.coordinatorInput.lane.curve !== 'ed25519') {
      throw new Error('expected Ed25519 coordinator lane');
    }
    expect(String(context.coordinatorInput.lane.walletId)).toBe(walletId);
    expect(String(context.coordinatorInput.lane.nearAccountId)).toBe(nearAccountId);
    expect(String(context.coordinatorInput.lane.nearEd25519SigningKeyId)).toBe(walletId);
  });

  test('retains prior same-account Ed25519 worker material when minting a new login session', () => {
    clearAllStoredThresholdEd25519SessionRecords();
    const nearAccountId = 'retain-material-passkey-ed25519.testnet';
    const runtimePolicyScope = {
      orgId: 'org-retain-material',
      projectId: 'project-retain-material',
      envId: 'dev',
      signingRootVersion: 'default',
    } as const;
    const common = {
      kind: 'jwt_passkey' as const,
      passkeyCredentialIdB64u: 'credential-ed25519-session-selection',
      walletId: nearAccountId as any,
      nearAccountId: nearAccountId as any,
      nearEd25519SigningKeyId: nearAccountId,
      rpId: 'localhost',
      relayerUrl: 'https://localhost:9444',
      relayerKeyId: 'ed25519:retain-material-relayer-key',
      participantIds: [1, 2],
      sessionKind: 'jwt' as const,
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 2,
      signerSlot: 1,
      runtimePolicyScope,
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1' as const,
        signingWorkerId: 'signing-worker-local',
      },
    };
    persistWarmSessionEd25519Capability({
      ...common,
      sessionId: 'threshold-retain-material-old',
      signingGrantId: 'wallet-retain-material-old',
      jwt: 'router-ab-ed25519-retain-material-old-jwt',
      clientVerifyingShareB64u: parseEd25519ClientVerifyingShareB64u(
        'retain-material-client-verifying-share',
      ),
      ed25519WorkerMaterialBindingDigest: parseEd25519WorkerMaterialBindingDigest(
        'retain-material-binding-digest',
      ),
      sealedWorkerMaterialRef: parseEd25519SealedWorkerMaterialRef('retain-material-sealed-ref'),
      sealedWorkerMaterialB64u: 'retain-material-sealed-blob',
      materialFormatVersion: 'ed25519_worker_material_v1',
      materialKeyId: parseEd25519WorkerMaterialKeyId('retain-material-key-id'),
      materialCreatedAtMs: Date.now(),
      keyVersion: 'kek-s-test',
      source: 'registration' as const,
      updatedAtMs: 1,
    });

    persistWarmSessionEd25519Capability({
      ...common,
      sessionId: 'threshold-retain-material-new',
      signingGrantId: 'wallet-retain-material-new',
      jwt: 'router-ab-ed25519-retain-material-new-jwt',
      source: 'login' as const,
      updatedAtMs: 2,
    });

    const newRecord = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
      'threshold-retain-material-new',
    );
    expect(newRecord).toMatchObject({
      clientVerifyingShareB64u: 'retain-material-client-verifying-share',
      ed25519WorkerMaterialBindingDigest: 'retain-material-binding-digest',
      sealedWorkerMaterialRef: 'retain-material-sealed-ref',
      sealedWorkerMaterialB64u: 'retain-material-sealed-blob',
      materialFormatVersion: 'ed25519_worker_material_v1',
      materialKeyId: 'retain-material-key-id',
      keyVersion: 'kek-s-test',
    });
  });

});

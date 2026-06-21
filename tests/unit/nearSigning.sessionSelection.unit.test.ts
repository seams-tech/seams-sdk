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
              nearAccountId,
              rpId: 'example.localhost',
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
      nearAccount: { kind: 'named', accountId: nearAccountId as any },
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
    const signingGrantId = 'wallet-pending-material-passkey-ed25519';
    const thresholdSessionId = 'threshold-pending-material-passkey-ed25519';
    const expiresAtMs = Date.now() + 60_000;
    persistWarmSessionEd25519Capability({
      kind: 'jwt_passkey' as const,
      nearAccountId: nearAccountId as any,
      rpId: 'localhost',
      relayerUrl: 'https://localhost:9444',
      relayerKeyId: 'ed25519:pending-material-relayer-key',
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
      jwt: 'router-ab-ed25519-pending-material-wallet-session-jwt',
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
      nearAccount: { kind: 'named', accountId: nearAccountId as any },
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
    const signingGrantId = 'wallet-auth-only-pending-passkey-ed25519';
    const thresholdSessionId = 'threshold-auth-only-pending-passkey-ed25519';
    const expiresAtMs = Date.now() + 60_000;
    persistWarmSessionEd25519Capability({
      kind: 'jwt_passkey' as const,
      nearAccountId: nearAccountId as any,
      rpId: 'localhost',
      relayerUrl: 'https://localhost:9444',
      relayerKeyId: 'ed25519:auth-only-pending-relayer-key',
      participantIds: [1, 2],
      sessionKind: 'jwt' as const,
      sessionId: thresholdSessionId,
      signingGrantId,
      expiresAtMs,
      remainingUses: 2,
      signerSlot: 1,
      jwt: 'router-ab-ed25519-auth-only-pending-wallet-session-jwt',
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
      nearAccount: { kind: 'named', accountId: nearAccountId as any },
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
      nearAccountId: nearAccountId as any,
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

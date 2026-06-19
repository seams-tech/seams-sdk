import { expect, test } from '@playwright/test';
import {
  buildNearSigningSessionAuthPlan,
  createNearSigningSessionCoordinator,
  resolveNearSigningSessionAuthContext,
} from '@/core/signingEngine/flows/signNear/shared/signingSessionAuthMode';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import { SigningAuthPlanKind } from '@/core/signingEngine/stepUpConfirmation/types';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmCapabilities/persistence';
import { clearAllStoredThresholdEd25519SessionRecords } from '@/core/signingEngine/session/persistence/records';

test.describe('near signing session selection', () => {
  test.afterEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test('treats passkey Ed25519 auth-missing state as step-up reauthable', async () => {
    const nearAccountId = 'passkey-ed25519-auth-missing.testnet';
    const walletSigningSessionId = 'wallet-passkey-ed25519-auth-missing';
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
              walletSigningSessionId,
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
        sessionId: walletSigningSessionId,
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

  test('plans passkey Ed25519 pending material as warm-session repair without reauth', async () => {
    clearAllStoredThresholdEd25519SessionRecords();
    const nearAccountId = 'pending-material-passkey-ed25519.testnet';
    const walletSigningSessionId = 'wallet-pending-material-passkey-ed25519';
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
      walletSigningSessionId,
      expiresAtMs,
      remainingUses: 2,
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
        sessionId: walletSigningSessionId,
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

  test('does not double-consume passkey Ed25519 material immediately after sealed restore', async () => {
    const consumeFlags: Array<boolean | undefined> = [];
    const restoreCalls: string[] = [];
    let statusOk = false;
    const coordinator = createNearSigningSessionCoordinator({
      getWarmSessionStatus: async () =>
        statusOk
          ? { ok: true as const, remainingUses: 2, expiresAtMs: Date.now() + 60_000 }
          : { ok: false as const, code: 'not_found', message: 'missing before restore' },
      getWarmSessionStatuses: async ({ sessionIds }: { sessionIds: string[] }) => ({
        results: sessionIds.map((sessionId) => ({
          sessionId,
          result: statusOk
            ? { ok: true as const, remainingUses: 2, expiresAtMs: Date.now() + 60_000 }
            : { ok: false as const, code: 'not_found', message: 'missing before restore' },
        })),
      }),
      restorePersistedSessionForSigning: async ({ thresholdSessionId }: any) => {
        restoreCalls.push(String(thresholdSessionId));
        statusOk = true;
      },
      claimWarmSessionMaterial: async ({ consume }: { consume?: boolean }) => {
        consumeFlags.push(consume);
        return {
          ok: true as const,
          prfFirstB64u: 'AQ',
          remainingUses: 2,
          expiresAtMs: Date.now() + 60_000,
        };
      },
    } as any);

    await coordinator.claimPrfFirstByThresholdSessionId({
      kind: 'wallet_scoped_ed25519_claim',
      thresholdSessionId: 'restored-passkey-ed25519',
      errorContext: 'test restored Ed25519 signing',
      uses: 1,
      walletId: 'alice.testnet',
      authMethod: 'passkey',
      curve: 'ed25519',
      chain: 'near',
      walletSigningSessionId: 'wallet-session',
    });
    await coordinator.claimPrfFirstByThresholdSessionId({
      kind: 'wallet_scoped_ed25519_claim',
      thresholdSessionId: 'restored-passkey-ed25519',
      errorContext: 'test hot Ed25519 signing',
      uses: 1,
      walletId: 'alice.testnet',
      authMethod: 'passkey',
      curve: 'ed25519',
      chain: 'near',
      walletSigningSessionId: 'wallet-session',
    });

    expect(restoreCalls).toEqual(['restored-passkey-ed25519', 'restored-passkey-ed25519']);
    expect(consumeFlags).toEqual([false, true]);
  });

  test('claims Email OTP Ed25519 warm material without passkey restore', async () => {
    const restoreCalls: string[] = [];
    const claimCurves: Array<string | undefined> = [];
    const coordinator = createNearSigningSessionCoordinator({
      getWarmSessionStatus: async () => ({
        ok: true as const,
        remainingUses: 2,
        expiresAtMs: Date.now() + 60_000,
      }),
      claimWarmSessionMaterial: async ({ curve }: { curve?: string }) => {
        claimCurves.push(curve);
        return {
          ok: true as const,
          prfFirstB64u: 'AQ',
          remainingUses: 2,
          expiresAtMs: Date.now() + 60_000,
        };
      },
      restorePersistedSessionForSigning: async ({ thresholdSessionId }: any) => {
        restoreCalls.push(String(thresholdSessionId));
      },
    } as any);

    await coordinator.claimPrfFirstByThresholdSessionId({
      kind: 'wallet_scoped_ed25519_claim',
      thresholdSessionId: 'email-otp-ed25519-session',
      errorContext: 'test Email OTP Ed25519 signing',
      uses: 1,
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      curve: 'ed25519',
      chain: 'near',
      walletSigningSessionId: 'wallet-session',
    });

    expect(restoreCalls).toEqual([]);
    expect(claimCurves).toEqual(['ed25519']);
  });
});

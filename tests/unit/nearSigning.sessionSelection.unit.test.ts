import { expect, test } from '@playwright/test';
import {
  buildNearSigningSessionAuthPlan,
  resolveNearSigningSessionAuthContext,
} from '@/core/signingEngine/flows/signNear/shared/signingSessionAuthMode';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import { SigningAuthPlanKind } from '@/core/signingEngine/stepUpConfirmation/types';
import { clearAllStoredThresholdEd25519SessionRecords } from '@/core/signingEngine/session/persistence/records';
import type { SigningSessionStatus } from '@/core/types/seams';
import {
  nearAccountRefFromAccountId,
  toWalletId,
  type NearCommandSubject,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

function nearCommandSubject(
  walletIdRaw: string,
  nearAccountIdRaw = walletIdRaw,
): NearCommandSubject {
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

function withExactNearAccountCapabilityReader<T extends { getWarmSession: () => Promise<any> }>(
  reader: T,
): T & {
  getEd25519CapabilityForNearAccount: (nearAccountId: string) => Promise<any>;
} {
  return {
    ...reader,
    getEd25519CapabilityForNearAccount: async (nearAccountId: string) => {
      const warmSession = await reader.getWarmSession();
      const capability = warmSession.capabilities.ed25519;
      return String(capability.record?.nearAccountId || '') === String(nearAccountId)
        ? capability
        : null;
    },
  };
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

  return withExactNearAccountCapabilityReader({
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
  } as any);
}

test.describe('near signing session selection', () => {
  test.afterEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test('resolves the Ed25519 capability by requested NEAR account', async () => {
    const requestedNearAccountId = 'requested-account.testnet';
    const reader = createStatusBackedPasskeyEd25519WarmSessionReader({
      walletId: 'shared-wallet',
      nearAccountId: requestedNearAccountId,
      signingGrantId: 'requested-account-grant',
      thresholdSessionId: 'requested-account-session',
      expiresAtMs: Date.now() + 60_000,
      status: {
        sessionId: 'requested-account-session',
        status: 'active',
        remainingUses: 3,
        committedRemainingUses: 3,
        inFlightReservedUses: 0,
        availableUses: 3,
        expiresAtMs: Date.now() + 60_000,
        projectionVersion: 'requested-account-projection',
      },
    });
    let walletDefaultReads = 0;
    const exactReader = {
      ...reader,
      getWarmSession: async () => {
        walletDefaultReads += 1;
        throw new Error('wallet-default Ed25519 capability must not drive NEAR signing');
      },
    } as any;

    const context = await resolveNearSigningSessionAuthContext({
      warmSessionReader: exactReader,
      commandSubject: nearCommandSubject('shared-wallet', requestedNearAccountId),
      operationLabel: 'exact account signing',
      requiredSignatureUses: 1,
    });

    expect(walletDefaultReads).toBe(0);
    expect(context.nearAccountId).toBe(requestedNearAccountId);
    expect(String(context.lane.identity.signer.account.nearAccountId)).toBe(requestedNearAccountId);
    expect(String(context.lane.thresholdSessionId)).toBe('requested-account-session');
  });

  test('treats passkey Ed25519 auth-missing state as step-up reauthable', async () => {
    const nearAccountId = 'passkey-ed25519-auth-missing.testnet';
    const signingGrantId = 'wallet-passkey-ed25519-auth-missing';
    const thresholdSessionId = 'threshold-passkey-ed25519-auth-missing';
    const expiresAtMs = Date.now() + 60_000;
    const warmSessionReader = withExactNearAccountCapabilityReader({
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

  test('uses committed budget for passkey Ed25519 admission despite server in-flight reservations', async () => {
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

    expect(context.coordinatorInput.readiness.status).toBe('ready');
    expect(context.coordinatorInput.readiness.remainingUses).toBe(3);
    expect(context.coordinatorInput.remainingUses).toBe(3);
    expect(context.coordinatorInput.usesNeeded).toBe(1);
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

  test('uses server-allocated wallet id for implicit NEAR signing lane while preserving NEAR account id', async () => {
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
    expect(String(context.lane.identity.signer.account.wallet.walletId)).toBe(walletId);
    expect(String(context.lane.identity.signer.account.nearAccountId)).toBe(nearAccountId);
    expect(String(context.lane.identity.signer.nearEd25519SigningKeyId)).toBe(walletId);
    expect(context.coordinatorInput.lane.curve).toBe('ed25519');
    if (context.coordinatorInput.lane.curve !== 'ed25519') {
      throw new Error('expected Ed25519 coordinator lane');
    }
    expect(String(context.coordinatorInput.lane.identity.signer.account.wallet.walletId)).toBe(
      walletId,
    );
    expect(String(context.coordinatorInput.lane.identity.signer.account.nearAccountId)).toBe(
      nearAccountId,
    );
    expect(String(context.coordinatorInput.lane.identity.signer.nearEd25519SigningKeyId)).toBe(
      walletId,
    );
  });

});

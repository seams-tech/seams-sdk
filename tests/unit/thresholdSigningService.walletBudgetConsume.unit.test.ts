import { expect, test } from '@playwright/test';
import { walletSigningBudgetSessionId } from '@server/core/ThresholdService/walletSigningBudget';
import { createThresholdSigningServiceForUnitTests } from '../helpers/thresholdEd25519TestUtils';

const WALLET_SIGNING_SESSION_ID = 'ws-server-budget-atomic';
const WALLET_BUDGET_SESSION_ID = walletSigningBudgetSessionId(WALLET_SIGNING_SESSION_ID);

test.describe('ThresholdSigningService wallet budget consume', () => {
  test('Ed25519 authorization budget key is scoped to confirmed payload, not each digest', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({
      accessKeysOnChain: [],
    });
    const deriveKey = (signingDigest32: Uint8Array, signingPayload: unknown) =>
      (
        svc as unknown as {
          thresholdEd25519AuthorizationBudgetIdempotencyKey(input: {
            relayerKeyId: string;
            purpose: string;
            signingDigest32?: Uint8Array;
            signingPayload: unknown;
          }): Promise<string>;
        }
      ).thresholdEd25519AuthorizationBudgetIdempotencyKey({
        relayerKeyId: 'relayer-ed25519',
        purpose: 'near_tx',
        signingDigest32,
        signingPayload,
      });
    const signingPayload = {
      kind: 'near_tx',
      txSigningRequests: [
        { nearAccountId: 'alice.testnet', receiverId: 'app.testnet', actions: [{ type: 'Call' }] },
        { nearAccountId: 'alice.testnet', receiverId: 'app.testnet', actions: [{ type: 'Call' }] },
      ],
      transactionContext: { nextNonce: '7', txBlockHeight: '42' },
    };

    await expect(deriveKey(new Uint8Array(32).fill(1), signingPayload)).resolves.toBe(
      await deriveKey(new Uint8Array(32).fill(2), signingPayload),
    );
    await expect(
      deriveKey(new Uint8Array(32).fill(1), {
        ...signingPayload,
        transactionContext: { nextNonce: '8', txBlockHeight: '42' },
      }),
    ).resolves.not.toBe(await deriveKey(new Uint8Array(32).fill(1), signingPayload));
  });

  test('wallet-level budget consume is fail-closed without an idempotency key', async () => {
    const { svc, authSessionStore } = createThresholdSigningServiceForUnitTests({
      accessKeysOnChain: [],
    });
    await authSessionStore.putSession(
      WALLET_BUDGET_SESSION_ID,
      {
        expiresAtMs: Date.now() + 60_000,
        relayerKeyId: 'wallet-signing-budget',
        userId: 'budget-fail-closed.testnet',
        rpId: 'localhost',
        participantIds: [1, 2],
      },
      { ttlMs: 60_000, remainingUses: 1 },
    );

    const consumed = await (
      svc as unknown as {
        consumeWalletOrCurveSessionUse(input: {
          walletSigningSessionId?: string;
          curveSessionId: string;
          curveStore: typeof authSessionStore;
          idempotencyKey?: string;
        }): Promise<{ ok: boolean; code?: string; message?: string; remainingUses?: number }>;
      }
    ).consumeWalletOrCurveSessionUse({
      walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
      curveSessionId: 'curve-session-unused',
      curveStore: authSessionStore,
    });

    expect(consumed).toEqual({
      ok: false,
      code: 'internal',
      message: 'wallet signing-session budget consume requires an idempotency key',
    });
    await expect(authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID)).resolves.toMatchObject(
      {
        remainingUses: 1,
      },
    );
  });

  test('wallet-level budget consume is idempotent for replay and exhausted for a distinct operation', async () => {
    const { svc, authSessionStore } = createThresholdSigningServiceForUnitTests({
      accessKeysOnChain: [],
    });
    await authSessionStore.putSession(
      WALLET_BUDGET_SESSION_ID,
      {
        expiresAtMs: Date.now() + 60_000,
        relayerKeyId: 'wallet-signing-budget',
        userId: 'budget-idempotent.testnet',
        rpId: 'localhost',
        participantIds: [1, 2],
      },
      { ttlMs: 60_000, remainingUses: 1 },
    );
    const consume = (idempotencyKey: string) =>
      (
        svc as unknown as {
          consumeWalletOrCurveSessionUse(input: {
            walletSigningSessionId?: string;
            curveSessionId: string;
            curveStore: typeof authSessionStore;
            idempotencyKey?: string;
          }): Promise<{ ok: boolean; code?: string; message?: string; remainingUses?: number }>;
        }
      ).consumeWalletOrCurveSessionUse({
        walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
        curveSessionId: 'curve-session-unused',
        curveStore: authSessionStore,
        idempotencyKey,
      });

    await expect(consume('operation-a')).resolves.toEqual({ ok: true, remainingUses: 0 });
    await expect(consume('operation-a')).resolves.toEqual({ ok: true, remainingUses: 0 });
    await expect(consume('operation-b')).resolves.toEqual({
      ok: false,
      code: 'unauthorized',
      message: 'threshold session exhausted',
    });
    await expect(authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID)).resolves.toMatchObject(
      {
        remainingUses: 0,
      },
    );
  });
});

import { expect, test } from '@playwright/test';
import { walletSigningBudgetSessionId } from '@server/core/ThresholdService/walletSigningBudget';
import { createThresholdSigningServiceForUnitTests } from '../helpers/thresholdEd25519TestUtils';

const WALLET_SIGNING_SESSION_ID = 'ws-server-budget-atomic';
const CURVE_SESSION_ID = 'curve-session-bound';
const WALLET_BUDGET_SESSION_ID = walletSigningBudgetSessionId(WALLET_SIGNING_SESSION_ID);

test.describe('ThresholdSigningService wallet budget consume', () => {
  test('wallet-level budget consume is fail-closed without an idempotency key', async () => {
    const { svc, walletSessionStore } = createThresholdSigningServiceForUnitTests({
      accessKeysOnChain: [],
    });
    await walletSessionStore.putSession(
      CURVE_SESSION_ID,
      {
        expiresAtMs: Date.now() + 60_000,
        relayerKeyId: 'curve-session-relayer',
        userId: 'budget-fail-closed.testnet',
        rpId: 'localhost',
        participantIds: [1, 2],
      },
      { ttlMs: 60_000, remainingUses: 1 },
    );
    await walletSessionStore.putSession(
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
          signingGrantId?: string;
          curve: 'ed25519' | 'ecdsa';
          curveSessionId: string;
          curveStore: typeof walletSessionStore;
          idempotencyKey?: string;
        }): Promise<{ ok: boolean; code?: string; message?: string; remainingUses?: number }>;
      }
    ).consumeWalletOrCurveSessionUse({
      signingGrantId: WALLET_SIGNING_SESSION_ID,
      curve: 'ed25519',
      curveSessionId: CURVE_SESSION_ID,
      curveStore: walletSessionStore,
    });

    expect(consumed).toEqual({
      ok: false,
      code: 'internal',
      message: 'wallet signing-session budget consume requires an idempotency key',
    });
    await expect(walletSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID)).resolves.toMatchObject(
      {
        remainingUses: 1,
      },
    );
  });

  test('wallet-level budget consume is idempotent for replay and exhausted for a distinct operation', async () => {
    const { svc, walletSessionStore } = createThresholdSigningServiceForUnitTests({
      accessKeysOnChain: [],
    });
    await walletSessionStore.putSession(
      CURVE_SESSION_ID,
      {
        expiresAtMs: Date.now() + 60_000,
        relayerKeyId: 'curve-session-relayer',
        userId: 'budget-idempotent.testnet',
        rpId: 'localhost',
        participantIds: [1, 2],
      },
      { ttlMs: 60_000, remainingUses: 1 },
    );
    await walletSessionStore.putSession(
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
            signingGrantId?: string;
            curve: 'ed25519' | 'ecdsa';
            curveSessionId: string;
            curveStore: typeof walletSessionStore;
            idempotencyKey?: string;
          }): Promise<{ ok: boolean; code?: string; message?: string; remainingUses?: number }>;
        }
      ).consumeWalletOrCurveSessionUse({
        signingGrantId: WALLET_SIGNING_SESSION_ID,
        curve: 'ed25519',
        curveSessionId: CURVE_SESSION_ID,
        curveStore: walletSessionStore,
        idempotencyKey,
      });

    await expect(consume('operation-a')).resolves.toEqual({ ok: true, remainingUses: 0 });
    await expect(consume('operation-a')).resolves.toEqual({ ok: true, remainingUses: 0 });
    await expect(consume('operation-b')).resolves.toEqual({
      ok: false,
      code: 'unauthorized',
      message: 'threshold session exhausted',
    });
    await expect(walletSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID)).resolves.toMatchObject(
      {
        remainingUses: 0,
      },
    );
  });
});

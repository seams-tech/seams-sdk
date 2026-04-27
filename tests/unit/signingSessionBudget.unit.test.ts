import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import { inferSigningSessionBudgetZeroSpendReason } from '@/core/signingEngine/session/signingSession/budgetFinalizer';
import { buildTempoTransactionSigningLane } from '@/core/signingEngine/session/signingSession/lanes';
import { buildWalletSigningSpendPlan } from '@/core/signingEngine/session/signingSession/budget';
import { SigningSessionIds } from '@/core/signingEngine/session/signingSession/types';

test.describe('SigningSessionBudget', () => {
  test('records one spend per successful operation id', async () => {
    const calls: unknown[] = [];
    const operationId = SigningSessionIds.signingOperation('op-budget-once');
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('budget.testnet'),
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-budget'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-budget'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const spend = buildWalletSigningSpendPlan({ operationId, intent: 'transaction_sign' }, lane);
    const budget = new SigningSessionCoordinator({
      consumeUse: async (args) => {
        calls.push(args);
        return {
          sessionId: String(args.walletSigningSessionId),
          status: 'active',
          remainingUses: 4,
          expiresAtMs: Date.now() + 60_000,
        };
      },
    });

    await budget.recordSuccess({
      spend,
      alreadyConsumedThresholdSessionIds: ['tsess-budget'],
    });
    await budget.recordSuccess({
      spend,
      alreadyConsumedThresholdSessionIds: ['tsess-budget'],
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      nearAccountId: 'budget.testnet',
      walletSigningSessionId: 'wsess-budget',
      uses: 1,
      reason: 'transaction_sign',
      targetThresholdSessionIds: ['tsess-budget'],
      alreadyConsumedThresholdSessionIds: ['tsess-budget'],
    });
    expect(budget.hasRecorded(operationId)).toBe(true);
  });

  test('does not record failed spends as completed', async () => {
    const operationId = SigningSessionIds.signingOperation('op-budget-retry');
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('budget.testnet'),
      authMethod: 'passkey',
      storageSource: 'login',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-budget'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-budget'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const spend = buildWalletSigningSpendPlan({ operationId, intent: 'transaction_sign' }, lane);
    let attempts = 0;
    const budget = new SigningSessionCoordinator({
      consumeUse: async () => {
        attempts += 1;
        if (attempts === 1) throw new Error('transient spend failure');
        return {
          sessionId: 'wsess-budget',
          status: 'active',
          remainingUses: 3,
          expiresAtMs: Date.now() + 60_000,
        };
      },
    });

    await expect(budget.recordSuccess({ spend })).rejects.toThrow('transient spend failure');
    expect(budget.hasRecorded(operationId)).toBe(false);
    await budget.recordSuccess({ spend });

    expect(attempts).toBe(2);
    expect(budget.hasRecorded(operationId)).toBe(true);
  });

  test('does not record wrong wallet signing-session spends returned as not_found', async () => {
    const operationId = SigningSessionIds.signingOperation('op-budget-wrong-wallet');
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('budget.testnet'),
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-wrong-wallet'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-budget'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const spend = buildWalletSigningSpendPlan({ operationId, intent: 'transaction_sign' }, lane);
    let attempts = 0;
    const budget = new SigningSessionCoordinator({
      consumeUse: async (args) => {
        attempts += 1;
        return {
          sessionId: String(args.walletSigningSessionId),
          status: 'not_found',
        };
      },
    });

    await expect(budget.recordSuccess({ spend })).rejects.toThrow(
      'wallet signing-session spend returned not_found',
    );
    expect(budget.hasRecorded(operationId)).toBe(false);
    await expect(budget.recordSuccess({ spend })).rejects.toThrow(
      'wallet signing-session spend returned not_found',
    );
    expect(attempts).toBe(2);
  });

  test('rejects malformed spend plans before calling the coordinator', async () => {
    const calls: unknown[] = [];
    const operationId = SigningSessionIds.signingOperation('op-budget-malformed-spend');
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('budget.testnet'),
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-budget'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-budget'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const spend = {
      ...buildWalletSigningSpendPlan({ operationId, intent: 'transaction_sign' }, lane),
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-other'),
    };
    const budget = new SigningSessionCoordinator({
      consumeUse: async (args) => {
        calls.push(args);
        return {
          sessionId: String(args.walletSigningSessionId),
          status: 'active',
        };
      },
    });

    await expect(budget.recordSuccess({ spend })).rejects.toThrow(
      'walletSigningSessionId does not match lane',
    );
    expect(budget.hasRecorded(operationId)).toBe(false);
    expect(calls).toEqual([]);
  });

  test('fails closed when consumeUse returns no status', async () => {
    const calls: unknown[] = [];
    const traces: unknown[] = [];
    const operationId = SigningSessionIds.signingOperation('op-budget-void-status');
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('budget.testnet'),
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-budget'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-budget'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const spend = buildWalletSigningSpendPlan({ operationId, intent: 'transaction_sign' }, lane);
    const budget = new SigningSessionCoordinator({
      onTrace: (event) => traces.push(event),
      consumeUse: async (args) => {
        calls.push(args);
        return undefined as any;
      },
    });

    await expect(budget.recordSuccess({ spend })).rejects.toThrow(
      'wallet signing-session spend returned no status',
    );
    await expect(budget.recordSuccess({ spend })).rejects.toThrow(
      'wallet signing-session spend returned no status',
    );

    expect(calls).toHaveLength(2);
    expect(traces).toMatchObject([
      { event: 'wallet_signing_budget_spend_started' },
      { event: 'wallet_signing_budget_spend_failed' },
      { event: 'wallet_signing_budget_spend_started' },
      { event: 'wallet_signing_budget_spend_failed' },
    ]);
    expect(budget.hasRecorded(operationId)).toBe(false);
  });

  test('rejects the same operation id when the operation fingerprint changes', async () => {
    const operationId = SigningSessionIds.signingOperation('op-budget-fingerprint-reuse');
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('budget.testnet'),
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-budget'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-budget'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const firstSpend = buildWalletSigningSpendPlan(
      {
        operationId,
        operationFingerprint: SigningSessionIds.signingOperationFingerprint('sha256:first'),
        intent: 'transaction_sign',
      },
      lane,
    );
    const secondSpend = buildWalletSigningSpendPlan(
      {
        operationId,
        operationFingerprint: SigningSessionIds.signingOperationFingerprint('sha256:second'),
        intent: 'transaction_sign',
      },
      lane,
    );
    const budget = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: 'wsess-budget',
        status: 'active',
        remainingUses: 2,
        expiresAtMs: Date.now() + 60_000,
      }),
      consumeUse: async (args) => ({
        sessionId: String(args.walletSigningSessionId),
        status: 'active',
        remainingUses: 1,
        expiresAtMs: Date.now() + 60_000,
      }),
    });

    await budget.reserve({ spend: firstSpend });
    await expect(budget.reserve({ spend: secondSpend })).rejects.toThrow(
      'signing operation id reused for a different operation',
    );
    await budget.recordSuccess({ spend: firstSpend });
    await expect(budget.recordSuccess({ spend: secondSpend })).rejects.toThrow(
      'signing operation id reused for a different operation',
    );
  });

  test('records zero-spend outcomes without consuming or completing the operation', async () => {
    const calls: unknown[] = [];
    const traces: unknown[] = [];
    const operationId = SigningSessionIds.signingOperation('op-budget-zero-spend');
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('budget.testnet'),
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-budget'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-budget'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const spend = buildWalletSigningSpendPlan({ operationId, intent: 'transaction_sign' }, lane);
    const budget = new SigningSessionCoordinator({
      onTrace: (event) => traces.push(event),
      consumeUse: async (args) => {
        calls.push(args);
        return {
          sessionId: String(args.walletSigningSessionId),
          status: 'active',
          remainingUses: 2,
          expiresAtMs: Date.now() + 60_000,
        };
      },
    });

    budget.recordZeroSpend({
      spend,
      reason: 'email_otp_failed',
      error: new Error('user rejected OTP'),
    });

    expect(calls).toEqual([]);
    expect(budget.hasRecorded(operationId)).toBe(false);
    expect(traces).toMatchObject([
      {
        event: 'wallet_signing_budget_zero_spend_recorded',
        operationId: 'op-budget-zero-spend',
        zeroSpendReason: 'email_otp_failed',
        error: 'user rejected OTP',
        lane: {
          authMethod: 'email_otp',
          curve: 'ecdsa',
          keyKind: 'threshold_ecdsa_secp256k1',
          chainFamily: 'tempo',
        },
      },
    ]);

    await budget.recordSuccess({ spend });
    expect(calls).toHaveLength(1);
    expect(budget.hasRecorded(operationId)).toBe(true);
  });

  test('emits redacted budget-spend trace events', async () => {
    const traces: unknown[] = [];
    const operationId = SigningSessionIds.signingOperation('op-budget-trace');
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('budget.testnet'),
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-budget'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-budget'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const spend = buildWalletSigningSpendPlan({ operationId, intent: 'transaction_sign' }, lane);
    const budget = new SigningSessionCoordinator({
      onTrace: (event) => traces.push(event),
      consumeUse: async (args) => ({
        sessionId: String(args.walletSigningSessionId),
        status: 'active',
        remainingUses: 2,
        expiresAtMs: Date.now() + 60_000,
      }),
    });

    await budget.recordSuccess({ spend });
    await budget.recordSuccess({ spend });

    expect(traces).toMatchObject([
      {
        event: 'wallet_signing_budget_spend_started',
        operationId: 'op-budget-trace',
        nearAccountId: 'budget.testnet',
        reason: 'transaction_sign',
        uses: 1,
        thresholdSessionCount: 1,
        backingMaterialSessionCount: 0,
        lane: {
          authMethod: 'email_otp',
          curve: 'ecdsa',
          keyKind: 'threshold_ecdsa_secp256k1',
          chainFamily: 'tempo',
          retention: 'session',
        },
      },
      {
        event: 'wallet_signing_budget_spend_succeeded',
        operationId: 'op-budget-trace',
        status: {
          status: 'active',
          remainingUses: 2,
        },
      },
      {
        event: 'wallet_signing_budget_spend_deduped',
        operationId: 'op-budget-trace',
      },
    ]);
    expect(JSON.stringify(traces)).not.toContain('wsess-budget');
    expect(JSON.stringify(traces)).not.toContain('tsess-budget');
  });

  test('classifies zero-spend failure reasons from terminal signing errors', () => {
    expect(
      inferSigningSessionBudgetZeroSpendReason({
        error: Object.assign(new Error('replacement transaction underpriced'), { code: -32000 }),
        authMethod: 'email_otp',
      }),
    ).toBe('nonce_preparation_failed');
    expect(
      inferSigningSessionBudgetZeroSpendReason({
        error: Object.assign(new Error('Request cancelled'), { code: 'cancelled' }),
        authMethod: 'email_otp',
      }),
    ).toBe('confirmation_cancelled');
    expect(
      inferSigningSessionBudgetZeroSpendReason({
        error: new Error('Fresh Email OTP verification is required'),
        authMethod: 'email_otp',
      }),
    ).toBe('email_otp_failed');
    expect(
      inferSigningSessionBudgetZeroSpendReason({
        error: new Error('The operation either timed out or was not allowed'),
        authMethod: 'passkey',
      }),
    ).toBe('passkey_failed');
  });

  test('blocks a second concurrent operation when remaining wallet budget is reserved', async () => {
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('budget.testnet'),
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-budget'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-budget'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const firstSpend = buildWalletSigningSpendPlan(
      {
        operationId: SigningSessionIds.signingOperation('op-budget-reserve-first'),
        intent: 'transaction_sign',
      },
      lane,
    );
    const secondSpend = buildWalletSigningSpendPlan(
      {
        operationId: SigningSessionIds.signingOperation('op-budget-reserve-second'),
        intent: 'transaction_sign',
      },
      lane,
    );
    const budget = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: 'wsess-budget',
        status: 'active',
        remainingUses: 1,
        expiresAtMs: Date.now() + 60_000,
      }),
      consumeUse: async (args) => ({
        sessionId: String(args.walletSigningSessionId),
        status: 'exhausted',
        remainingUses: 0,
        expiresAtMs: Date.now() + 60_000,
      }),
    });

    const reservation = await budget.reserve({ spend: firstSpend });
    await expect(budget.reserve({ spend: secondSpend })).rejects.toThrow(
      'wallet signing-session budget is exhausted',
    );
    reservation?.release('confirmation_cancelled');
    await budget.reserve({ spend: secondSpend });
  });

  test('dedupes reservation retries for the same operation id', async () => {
    const traces: unknown[] = [];
    const operationId = SigningSessionIds.signingOperation('op-budget-reserve-retry');
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('budget.testnet'),
      authMethod: 'passkey',
      storageSource: 'login',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-budget'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-budget'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const spend = buildWalletSigningSpendPlan({ operationId, intent: 'transaction_sign' }, lane);
    const budget = new SigningSessionCoordinator({
      onTrace: (event) => traces.push(event),
      getStatus: async () => ({
        sessionId: 'wsess-budget',
        status: 'active',
        remainingUses: 1,
        expiresAtMs: Date.now() + 60_000,
      }),
      consumeUse: async (args) => ({
        sessionId: String(args.walletSigningSessionId),
        status: 'exhausted',
        remainingUses: 0,
        expiresAtMs: Date.now() + 60_000,
      }),
    });

    await budget.reserve({ spend });
    await budget.reserve({ spend });
    await budget.recordSuccess({ spend });
    await budget.reserve({ spend });

    expect(traces).toMatchObject([
      { event: 'wallet_signing_budget_reservation_started' },
      { event: 'wallet_signing_budget_reservation_succeeded' },
      { event: 'wallet_signing_budget_reservation_deduped' },
      { event: 'wallet_signing_budget_spend_started' },
      { event: 'wallet_signing_budget_spend_succeeded' },
      { event: 'wallet_signing_budget_reservation_released' },
      { event: 'wallet_signing_budget_reservation_deduped' },
    ]);
  });

  test('allows concurrent reservations up to remainingUses greater than one, then blocks the next operation', async () => {
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('budget.testnet'),
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-budget'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-budget'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const spends = ['first', 'second', 'third'].map((label) =>
      buildWalletSigningSpendPlan(
        {
          operationId: SigningSessionIds.signingOperation(`op-budget-reserve-n-${label}`),
          intent: 'transaction_sign',
        },
        lane,
      ),
    );
    const budget = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: 'wsess-budget',
        status: 'active',
        remainingUses: 2,
        expiresAtMs: Date.now() + 60_000,
      }),
    });

    const results = await Promise.allSettled(spends.map((spend) => budget.reserve({ spend })));

    expect(results.map((result) => result.status)).toEqual(['fulfilled', 'fulfilled', 'rejected']);
    expect(results[2]).toMatchObject({
      status: 'rejected',
      reason: expect.objectContaining({
        message: expect.stringContaining('wallet signing-session budget is exhausted'),
      }),
    });

    const firstReservation = results[0].status === 'fulfilled' ? results[0].value : null;
    firstReservation?.release('confirmation_cancelled');
    await expect(budget.reserve({ spend: spends[2]! })).resolves.toBeTruthy();
  });

  test('reports remaining budget net of in-flight reservations', async () => {
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('budget.testnet'),
      authMethod: 'passkey',
      storageSource: 'login',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-budget-available'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-budget-available'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const firstSpend = buildWalletSigningSpendPlan(
      {
        operationId: SigningSessionIds.signingOperation('op-budget-available-first'),
        intent: 'transaction_sign',
      },
      lane,
    );
    const secondSpend = buildWalletSigningSpendPlan(
      {
        operationId: SigningSessionIds.signingOperation('op-budget-available-second'),
        intent: 'transaction_sign',
      },
      lane,
    );
    const budget = new SigningSessionCoordinator({
      getStatus: async (args) => ({
        sessionId: String(args.walletSigningSessionId),
        status: 'active',
        remainingUses: 2,
        expiresAtMs: Date.now() + 60_000,
      }),
    });

    await expect(
      budget.getAvailableStatus({
        nearAccountId: 'budget.testnet',
        walletSigningSessionId: 'wsess-budget-available',
      }),
    ).resolves.toMatchObject({ status: 'active', remainingUses: 2 });

    const firstReservation = await budget.reserve({ spend: firstSpend });
    await expect(
      budget.getAvailableStatus({
        nearAccountId: 'budget.testnet',
        walletSigningSessionId: 'wsess-budget-available',
      }),
    ).resolves.toMatchObject({ status: 'active', remainingUses: 1 });

    const secondReservation = await budget.reserve({ spend: secondSpend });
    await expect(
      budget.getAvailableStatus({
        nearAccountId: 'budget.testnet',
        walletSigningSessionId: 'wsess-budget-available',
      }),
    ).resolves.toMatchObject({ status: 'exhausted', remainingUses: 0 });

    firstReservation?.release('confirmation_cancelled');
    secondReservation?.release('confirmation_cancelled');
  });

  test('mixed Email OTP and passkey lanes sharing one wallet session compete for the same remaining-use budget', async () => {
    const walletSigningSessionId = SigningSessionIds.walletSigningSession('wsess-shared-budget');
    const accountId = toAccountId('budget.testnet');
    const emailOtpLane = buildTempoTransactionSigningLane({
      accountId,
      authMethod: 'email_otp',
      walletSigningSessionId,
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-otp-budget'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const passkeyLane = buildTempoTransactionSigningLane({
      accountId,
      authMethod: 'passkey',
      storageSource: 'login',
      walletSigningSessionId,
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-passkey-budget'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const emailOtpSpend = buildWalletSigningSpendPlan(
      {
        operationId: SigningSessionIds.signingOperation('op-budget-mixed-otp'),
        intent: 'transaction_sign',
      },
      emailOtpLane,
    );
    const passkeySpend = buildWalletSigningSpendPlan(
      {
        operationId: SigningSessionIds.signingOperation('op-budget-mixed-passkey'),
        intent: 'transaction_sign',
      },
      passkeyLane,
    );
    const thirdPasskeySpend = buildWalletSigningSpendPlan(
      {
        operationId: SigningSessionIds.signingOperation('op-budget-mixed-passkey-third'),
        intent: 'transaction_sign',
      },
      passkeyLane,
    );
    const budget = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: 'wsess-shared-budget',
        status: 'active',
        remainingUses: 2,
        expiresAtMs: Date.now() + 60_000,
      }),
    });

    const results = await Promise.allSettled([
      budget.reserve({ spend: emailOtpSpend }),
      budget.reserve({ spend: passkeySpend }),
      budget.reserve({ spend: thirdPasskeySpend }),
    ]);

    expect(results.map((result) => result.status)).toEqual(['fulfilled', 'fulfilled', 'rejected']);
    expect(results[2]).toMatchObject({
      status: 'rejected',
      reason: expect.objectContaining({
        message: expect.stringContaining('wallet signing-session budget is exhausted'),
      }),
    });
  });

  test('mixed Email OTP and passkey lanes on different wallet sessions do not reserve against each other', async () => {
    const accountId = toAccountId('budget.testnet');
    const emailOtpLane = buildTempoTransactionSigningLane({
      accountId,
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-otp-budget'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-otp-budget'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const passkeyLane = buildTempoTransactionSigningLane({
      accountId,
      authMethod: 'passkey',
      storageSource: 'login',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-passkey-budget'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-passkey-budget'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const emailOtpSpend = buildWalletSigningSpendPlan(
      {
        operationId: SigningSessionIds.signingOperation('op-budget-independent-otp'),
        intent: 'transaction_sign',
      },
      emailOtpLane,
    );
    const passkeySpend = buildWalletSigningSpendPlan(
      {
        operationId: SigningSessionIds.signingOperation('op-budget-independent-passkey'),
        intent: 'transaction_sign',
      },
      passkeyLane,
    );
    const budget = new SigningSessionCoordinator({
      getStatus: async (args) => ({
        sessionId: String(args.walletSigningSessionId),
        status: 'active',
        remainingUses: 1,
        expiresAtMs: Date.now() + 60_000,
      }),
    });

    const results = await Promise.allSettled([
      budget.reserve({ spend: emailOtpSpend }),
      budget.reserve({ spend: passkeySpend }),
    ]);

    expect(results.map((result) => result.status)).toEqual(['fulfilled', 'fulfilled']);
  });
});

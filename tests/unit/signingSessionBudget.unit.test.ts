import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import { inferSigningSessionBudgetZeroSpendReason } from '@/core/signingEngine/session/signingSession/budgetFinalizer';
import {
  buildNearTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from '@/core/signingEngine/session/signingSession/lanes';
import { buildWalletSigningSpendPlan } from '@/core/signingEngine/session/signingSession/budget';
import {
  createWalletBudgetProjection,
  projectionToSigningSessionStatus,
  reduceWalletBudgetProjection,
} from '@/core/signingEngine/session/signingSession/budgetProjection';
import { applyWalletBudgetStatusToSigningSessionReadiness } from '@/core/signingEngine/session/signingSession/readiness';
import { SigningSessionIds } from '@/core/signingEngine/session/signingSession/types';

function activeBudgetStatus(sessionId: string, remainingUses: number) {
  return {
    sessionId,
    status: 'active' as const,
    remainingUses,
    expiresAtMs: Date.now() + 60_000,
    projectionVersion: `test-projection:${sessionId}:${remainingUses}`,
  };
}

function preparedBudgetInput<TSpend extends { walletSigningSessionId: string }>(
  spend: TSpend,
  remainingUses: number,
) {
  return {
    spend,
    expectedBudgetProjectionVersion: `test-projection:${spend.walletSigningSessionId}:${remainingUses}`,
  };
}

test.describe('SigningSessionBudget', () => {
  test('budget projection treats local reservations as temporary availability only', async () => {
    const projection = createWalletBudgetProjection({
      nearAccountId: 'budget.testnet',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-projection'),
    });
    const withServerStatus = reduceWalletBudgetProjection(projection, {
      type: 'server_status_observed',
      status: {
        source: 'server_status',
        sessionId: 'wsess-projection',
        status: 'active',
        remainingUses: 1,
        expiresAtMs: Date.now() + 60_000,
        projectionVersion: 'projection:wsess-projection:1',
      },
    });
    const reserved = reduceWalletBudgetProjection(withServerStatus, {
      type: 'reserve_requested',
      reservation: {
        operationId: SigningSessionIds.signingOperation('op-projection-reserve'),
        operationFingerprint: SigningSessionIds.signingOperationFingerprint(
          'sha256:projection',
        ),
        uses: 1,
        reservedAgainstProjectionVersion: 'projection:wsess-projection:1',
        reservedAgainstRemainingUses: 1,
      },
    });

    expect(reserved.trustedStatus).toMatchObject({ status: 'active', remainingUses: 1 });
    expect(reserved).toMatchObject({ localReservedUses: 1, effectiveRemainingUses: 0 });
    expect(projectionToSigningSessionStatus(reserved)).toMatchObject({
      status: 'active',
      remainingUses: 1,
      inFlightReservedUses: 1,
      availableUses: 0,
      projectionVersion: 'projection:wsess-projection:1',
    });

    const released = reduceWalletBudgetProjection(reserved, {
      type: 'reservation_released',
      operationId: SigningSessionIds.signingOperation('op-projection-reserve'),
    });
    expect(released).toMatchObject({ localReservedUses: 0, effectiveRemainingUses: 1 });
  });

  test('budget projection preserves unknown budget as an explicit non-terminal state', async () => {
    const projection = createWalletBudgetProjection({
      nearAccountId: 'budget.testnet',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-unknown'),
    });
    const unknown = reduceWalletBudgetProjection(projection, {
      type: 'budget_unknown_observed',
      unknown: {
        source: 'budget_unknown',
        sessionId: 'wsess-unknown',
        status: 'budget_unknown',
        reason: 'missing_trusted_status',
      },
    });

    expect(projectionToSigningSessionStatus(unknown)).toMatchObject({
      status: 'budget_unknown',
      statusCode: 'missing_trusted_status',
    });
  });

  test('budget_unknown does not mask exhausted material readiness', async () => {
    const merged = applyWalletBudgetStatusToSigningSessionReadiness({
      status: 'exhausted',
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session('tsess-exhausted'),
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 0,
      walletBudgetStatus: {
        sessionId: 'wsess-budget-unknown',
        status: 'budget_unknown',
        statusCode: 'missing_trusted_status',
      },
      usesNeeded: 1,
    });

    expect(merged.readiness.status).toBe('exhausted');
  });

  test('trusted active budget keeps the final remaining use available', async () => {
    const merged = applyWalletBudgetStatusToSigningSessionReadiness({
      status: 'exhausted',
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session('tsess-local-exhausted'),
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 0,
      walletBudgetStatus: activeBudgetStatus('wsess-active-budget', 1),
      usesNeeded: 1,
    });

    expect(merged.readiness.status).toBe('ready');
    expect(merged.remainingUses).toBe(1);
  });

  test('readiness does not turn local availability into terminal exhaustion', async () => {
    const merged = applyWalletBudgetStatusToSigningSessionReadiness({
      status: 'ready',
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session('tsess-local-hold'),
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 1,
      walletBudgetStatus: {
        ...activeBudgetStatus('wsess-local-hold', 1),
        inFlightReservedUses: 1,
        availableUses: 0,
      },
      usesNeeded: 1,
    });

    expect(merged.readiness.status).toBe('ready');
    expect(merged.remainingUses).toBe(1);
  });

  test('keeps missing trusted budget status explicit and fails closed', async () => {
    const operationId = SigningSessionIds.signingOperation('op-budget-no-status-adapter');
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
      getStatus: async () => ({
        sessionId: 'wsess-budget',
        status: 'budget_unknown',
        statusCode: 'adapter_unavailable',
      }),
    });

    await expect(budget.reserve(preparedBudgetInput(spend, 1))).rejects.toThrow(
      'wallet signing-session budget is budget_unknown',
    );
    await expect(
      budget.reserve({
        ...preparedBudgetInput(
          buildWalletSigningSpendPlan(
            {
              operationId: SigningSessionIds.signingOperation(
                'op-budget-no-status-adapter-second',
              ),
              intent: 'transaction_sign',
            },
            lane,
          ),
          1,
        ),
      }),
    ).rejects.toThrow('wallet signing-session budget is budget_unknown');
    await expect(
      budget.getAvailableStatus({
        nearAccountId: 'budget.testnet',
        walletSigningSessionId: 'wsess-budget',
      }),
    ).resolves.toMatchObject({
      status: 'budget_unknown',
      statusCode: 'adapter_unavailable',
    });
  });

  test('classifies absent trusted status as budget_unknown, not not_found', async () => {
    const operationId = SigningSessionIds.signingOperation('op-budget-missing-status');
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
      getStatus: async () => null,
    });

    await expect(budget.reserve(preparedBudgetInput(spend, 1))).rejects.toThrow(
      'wallet signing-session budget is budget_unknown',
    );
    await expect(
      budget.getAvailableStatus({
        nearAccountId: 'budget.testnet',
        walletSigningSessionId: 'wsess-budget',
      }),
    ).resolves.toMatchObject({
      status: 'budget_unknown',
      statusCode: 'missing_trusted_status',
    });
  });

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
      getStatus: async () => activeBudgetStatus('wsess-budget', 4),
      consumeUse: async (args) => {
        calls.push(args);
        return activeBudgetStatus(String(args.walletSigningSessionId), 4);
      },
    });

    await budget.recordSuccess({
      ...preparedBudgetInput(spend, 4),
      alreadyConsumedThresholdSessionIds: ['tsess-budget'],
    });
    await budget.recordSuccess({
      ...preparedBudgetInput(spend, 4),
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

  test('syncs externally consumed Ed25519 spends without requiring the old projection version', async () => {
    const calls: unknown[] = [];
    const operationId = SigningSessionIds.signingOperation('op-budget-ed25519-external');
    const lane = buildNearTransactionSigningLane({
      accountId: toAccountId('budget.testnet'),
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-ed25519-external'),
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session('tsess-ed25519-external'),
      retention: 'session',
      sessionOrigin: 'login',
    });
    const spend = buildWalletSigningSpendPlan({ operationId, intent: 'transaction_sign' }, lane);
    const budget = new SigningSessionCoordinator({
      getStatus: async () => activeBudgetStatus('wsess-ed25519-external', 2),
      consumeUse: async (args) => {
        calls.push(args);
        return activeBudgetStatus(String(args.walletSigningSessionId), 2);
      },
    });

    await budget.recordSuccess({
      ...preparedBudgetInput(spend, 3),
      alreadyConsumedThresholdSessionIds: ['tsess-ed25519-external'],
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      alreadyConsumedThresholdSessionIds: ['tsess-ed25519-external'],
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
      getStatus: async () => activeBudgetStatus('wsess-budget', 3),
      consumeUse: async () => {
        attempts += 1;
        if (attempts === 1) throw new Error('transient spend failure');
        return activeBudgetStatus('wsess-budget', 3);
      },
    });

    await expect(budget.recordSuccess(preparedBudgetInput(spend, 3))).rejects.toThrow(
      'transient spend failure',
    );
    expect(budget.hasRecorded(operationId)).toBe(false);
    await budget.recordSuccess(preparedBudgetInput(spend, 3));

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
      getStatus: async () => activeBudgetStatus('wsess-wrong-wallet', 1),
      consumeUse: async (args) => {
        attempts += 1;
        return {
          sessionId: String(args.walletSigningSessionId),
          status: 'not_found',
        };
      },
    });

    await expect(budget.recordSuccess(preparedBudgetInput(spend, 1))).rejects.toThrow(
      'wallet signing-session spend returned not_found',
    );
    expect(budget.hasRecorded(operationId)).toBe(false);
    await expect(budget.recordSuccess(preparedBudgetInput(spend, 1))).rejects.toThrow(
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
      getStatus: async () => activeBudgetStatus('wsess-other', 1),
      consumeUse: async (args) => {
        calls.push(args);
        return activeBudgetStatus(String(args.walletSigningSessionId), 1);
      },
    });

    await expect(budget.recordSuccess(preparedBudgetInput(spend, 1))).rejects.toThrow(
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
      getStatus: async () => activeBudgetStatus('wsess-budget', 1),
      consumeUse: async (args) => {
        calls.push(args);
        return undefined as any;
      },
    });

    await expect(budget.recordSuccess(preparedBudgetInput(spend, 1))).rejects.toThrow(
      'wallet signing-session spend returned no status',
    );
    await expect(budget.recordSuccess(preparedBudgetInput(spend, 1))).rejects.toThrow(
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
      getStatus: async () => activeBudgetStatus('wsess-budget', 2),
      consumeUse: async (args) => activeBudgetStatus(String(args.walletSigningSessionId), 1),
    });

    await budget.reserve(preparedBudgetInput(firstSpend, 2));
    await expect(budget.reserve(preparedBudgetInput(secondSpend, 2))).rejects.toThrow(
      'signing operation id reused for a different operation',
    );
    await budget.recordSuccess(preparedBudgetInput(firstSpend, 2));
    await expect(budget.recordSuccess(preparedBudgetInput(secondSpend, 2))).rejects.toThrow(
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
      getStatus: async () => activeBudgetStatus('wsess-budget', 2),
      consumeUse: async (args) => {
        calls.push(args);
        return activeBudgetStatus(String(args.walletSigningSessionId), 2);
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

    await budget.recordSuccess(preparedBudgetInput(spend, 2));
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
      getStatus: async () => activeBudgetStatus('wsess-budget', 2),
      consumeUse: async (args) => activeBudgetStatus(String(args.walletSigningSessionId), 2),
    });

    await budget.recordSuccess(preparedBudgetInput(spend, 2));
    await budget.recordSuccess(preparedBudgetInput(spend, 2));

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
      getStatus: async () => activeBudgetStatus('wsess-budget', 1),
      consumeUse: async (args) => ({
        ...activeBudgetStatus(String(args.walletSigningSessionId), 0),
        status: 'exhausted' as const,
      }),
    });

    const reservation = await budget.reserve(preparedBudgetInput(firstSpend, 1));
    await expect(budget.reserve(preparedBudgetInput(secondSpend, 1))).rejects.toThrow(
      'wallet signing-session budget is reserved by in-flight operations',
    );
    reservation?.release('confirmation_cancelled');
    await budget.reserve(preparedBudgetInput(secondSpend, 1));
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
      getStatus: async () => activeBudgetStatus('wsess-budget', 1),
      consumeUse: async (args) => ({
        ...activeBudgetStatus(String(args.walletSigningSessionId), 0),
        status: 'exhausted',
      }),
    });

    await budget.reserve(preparedBudgetInput(spend, 1));
    await budget.reserve(preparedBudgetInput(spend, 1));
    await budget.recordSuccess(preparedBudgetInput(spend, 1));
    await budget.reserve(preparedBudgetInput(spend, 1));

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
      getStatus: async () => activeBudgetStatus('wsess-budget', 2),
    });

    const results = await Promise.allSettled(
      spends.map((spend) => budget.reserve(preparedBudgetInput(spend, 2))),
    );

    expect(results.map((result) => result.status)).toEqual(['fulfilled', 'fulfilled', 'rejected']);
    expect(results[2]).toMatchObject({
      status: 'rejected',
      reason: expect.objectContaining({
        message: expect.stringContaining(
          'wallet signing-session budget is reserved by in-flight operations',
        ),
      }),
    });

    const firstReservation = results[0].status === 'fulfilled' ? results[0].value : null;
    firstReservation?.release('confirmation_cancelled');
    await expect(budget.reserve(preparedBudgetInput(spends[2]!, 2))).resolves.toBeTruthy();
  });

  test('reports authoritative remaining budget separately from in-flight availability', async () => {
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
      getStatus: async (args) => activeBudgetStatus(String(args.walletSigningSessionId), 2),
    });

    await expect(
      budget.getAvailableStatus({
        nearAccountId: 'budget.testnet',
        walletSigningSessionId: 'wsess-budget-available',
      }),
    ).resolves.toMatchObject({ status: 'active', remainingUses: 2 });

    const firstReservation = await budget.reserve(preparedBudgetInput(firstSpend, 2));
    await expect(
      budget.getAvailableStatus({
        nearAccountId: 'budget.testnet',
        walletSigningSessionId: 'wsess-budget-available',
      }),
    ).resolves.toMatchObject({
      status: 'active',
      remainingUses: 2,
      inFlightReservedUses: 1,
      availableUses: 1,
    });

    const secondReservation = await budget.reserve(preparedBudgetInput(secondSpend, 2));
    await expect(
      budget.getAvailableStatus({
        nearAccountId: 'budget.testnet',
        walletSigningSessionId: 'wsess-budget-available',
      }),
    ).resolves.toMatchObject({
      status: 'active',
      remainingUses: 2,
      inFlightReservedUses: 2,
      availableUses: 0,
    });

    firstReservation?.release('confirmation_cancelled');
    secondReservation?.release('confirmation_cancelled');
  });

  test('does not subtract stale reservations from a newer server projection', async () => {
    let serverRemainingUses = 3;
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('budget.testnet'),
      authMethod: 'passkey',
      storageSource: 'login',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-budget-causal'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-budget-causal'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const firstSpend = buildWalletSigningSpendPlan(
      {
        operationId: SigningSessionIds.signingOperation('op-budget-causal-first'),
        intent: 'transaction_sign',
      },
      lane,
    );
    const secondSpend = buildWalletSigningSpendPlan(
      {
        operationId: SigningSessionIds.signingOperation('op-budget-causal-second'),
        intent: 'transaction_sign',
      },
      lane,
    );
    const budget = new SigningSessionCoordinator({
      getStatus: async (args) =>
        activeBudgetStatus(String(args.walletSigningSessionId), serverRemainingUses),
    });

    const firstReservation = await budget.reserve(preparedBudgetInput(firstSpend, 3));
    serverRemainingUses = 2;

    await expect(
      budget.getAvailableStatus({
        nearAccountId: 'budget.testnet',
        walletSigningSessionId: 'wsess-budget-causal',
      }),
    ).resolves.toMatchObject({
      status: 'active',
      remainingUses: 2,
      inFlightReservedUses: 0,
      availableUses: 2,
    });
    const secondReservation = await budget.reserve(preparedBudgetInput(secondSpend, 2));

    firstReservation?.release('confirmation_cancelled');
    secondReservation?.release('confirmation_cancelled');
  });

  test('admits a stale prepared projection when fresh trusted budget still has capacity', async () => {
    let serverRemainingUses = 3;
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('budget.testnet'),
      authMethod: 'passkey',
      storageSource: 'login',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-budget-stale-prepare'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-budget-stale-prepare'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const firstSpend = buildWalletSigningSpendPlan(
      {
        operationId: SigningSessionIds.signingOperation('op-budget-stale-prepare-first'),
        intent: 'transaction_sign',
      },
      lane,
    );
    const secondSpend = buildWalletSigningSpendPlan(
      {
        operationId: SigningSessionIds.signingOperation('op-budget-stale-prepare-second'),
        intent: 'transaction_sign',
      },
      lane,
    );
    const budget = new SigningSessionCoordinator({
      getStatus: async (args) =>
        activeBudgetStatus(String(args.walletSigningSessionId), serverRemainingUses),
    });

    const firstReservation = await budget.reserve(preparedBudgetInput(firstSpend, 3));
    serverRemainingUses = 2;

    const secondReservation = await budget.reserve(preparedBudgetInput(secondSpend, 3));
    await expect(
      budget.getAvailableStatus({
        nearAccountId: 'budget.testnet',
        walletSigningSessionId: 'wsess-budget-stale-prepare',
      }),
    ).resolves.toMatchObject({
      status: 'active',
      remainingUses: 2,
      inFlightReservedUses: 1,
      availableUses: 1,
    });

    firstReservation?.release('confirmation_cancelled');
    secondReservation?.release('confirmation_cancelled');
  });

  test('keeps the third fast operation warm when server reports one remaining use', async () => {
    let serverRemainingUses = 3;
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('budget.testnet'),
      authMethod: 'passkey',
      storageSource: 'login',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-budget-fast-third'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-budget-fast-third'),
      signingRootId: 'proj_budget:dev',
      signingRootVersion: 'default',
    });
    const spends = ['first', 'second'].map((label) =>
      buildWalletSigningSpendPlan(
        {
          operationId: SigningSessionIds.signingOperation(`op-budget-fast-third-${label}`),
          intent: 'transaction_sign',
        },
        lane,
      ),
    );
    const budget = new SigningSessionCoordinator({
      getStatus: async (args) =>
        activeBudgetStatus(String(args.walletSigningSessionId), serverRemainingUses),
    });

    const firstReservation = await budget.reserve(preparedBudgetInput(spends[0]!, 3));
    serverRemainingUses = 2;
    const secondReservation = await budget.reserve(preparedBudgetInput(spends[1]!, 2));
    serverRemainingUses = 1;

    const status = await budget.getAvailableStatus({
      nearAccountId: 'budget.testnet',
      walletSigningSessionId: 'wsess-budget-fast-third',
    });
    const merged = applyWalletBudgetStatusToSigningSessionReadiness({
      status: 'ready',
      thresholdSessionId: lane.thresholdSessionId,
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 1,
      walletBudgetStatus: status,
      usesNeeded: 1,
    });

    expect(status).toMatchObject({
      status: 'active',
      remainingUses: 1,
      inFlightReservedUses: 0,
      availableUses: 1,
    });
    expect(merged.readiness.status).toBe('ready');

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
      getStatus: async () => activeBudgetStatus('wsess-shared-budget', 2),
    });

    const results = await Promise.allSettled([
      budget.reserve(preparedBudgetInput(emailOtpSpend, 2)),
      budget.reserve(preparedBudgetInput(passkeySpend, 2)),
      budget.reserve(preparedBudgetInput(thirdPasskeySpend, 2)),
    ]);

    expect(results.map((result) => result.status)).toEqual(['fulfilled', 'fulfilled', 'rejected']);
    expect(results[2]).toMatchObject({
      status: 'rejected',
      reason: expect.objectContaining({
        message: expect.stringContaining(
          'wallet signing-session budget is reserved by in-flight operations',
        ),
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
      getStatus: async (args) => activeBudgetStatus(String(args.walletSigningSessionId), 1),
    });

    const results = await Promise.allSettled([
      budget.reserve(preparedBudgetInput(emailOtpSpend, 1)),
      budget.reserve(preparedBudgetInput(passkeySpend, 1)),
    ]);

    expect(results.map((result) => result.status)).toEqual(['fulfilled', 'fulfilled']);
  });
});

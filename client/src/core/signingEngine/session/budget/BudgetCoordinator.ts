import type { SigningSessionStatus } from '@/core/types/seams';
import { normalizeWalletSigningSpendPlan } from '../operationState/types';
import {
  applySigningSessionBudgetReservationsToStatus,
  assertBudgetStatusCheckHasConcreteLaneIdentity,
  assertSigningSessionBudgetReservationAvailable,
  buildSigningBudgetReservationIdentity,
  buildSigningSessionBudgetStatusCheckForSpend,
  createZeroSpendTraceEvent,
  createSigningSessionBudgetTraceEvent,
  normalizeRequired,
  normalizeWalletBudgetSuccessInput,
  normalizeStringList,
  resolveWalletSigningOperationFingerprint,
  signingBudgetReservationKey,
  walletBudgetOwnerForLane,
  type SigningBudgetReservationIdentity,
  type SigningBudgetReservationKey,
  type SigningBudgetFinalizationResult,
  type SigningSessionBudget,
  type SigningSessionBudgetConsumer,
  type SigningSessionBudgetReservation,
  type SigningSessionBudgetReservationConflict,
  type SigningSessionBudgetReservationRecord,
  type SigningSessionBudgetReserveInput,
  type SigningSessionBudgetSuccessInput,
  type SigningSessionBudgetTraceEvent,
  type SigningSessionBudgetZeroSpendReason,
  type WalletBudgetSpend,
  type ZeroWalletBudgetSpend,
} from './budget';

type SuccessfulSpendRecord = {
  operationFingerprint: string;
  reservationIdentity: SigningBudgetReservationIdentity;
  reservationIdentityKey: SigningBudgetReservationKey;
  promise: Promise<SigningBudgetFinalizationResult>;
};

export type BudgetCoordinatorDeps = {
  readStatus: (
    args: Parameters<SigningSessionBudget['getAvailableStatus']>[0],
  ) => Promise<SigningSessionStatus>;
  consumeUse?: SigningSessionBudgetConsumer;
  onTrace?: (event: SigningSessionBudgetTraceEvent) => void;
};

export class BudgetCoordinator implements SigningSessionBudget {
  private readonly successfulSpendsByOperationId = new Map<string, SuccessfulSpendRecord>();
  private readonly reservationsByOperationId = new Map<
    string,
    SigningSessionBudgetReservationRecord
  >();
  private readonly zeroSpendFinalizationsByReservationKey = new Set<string>();
  private readonly walletReservationQueues = new Map<string, Promise<unknown>>();

  constructor(private readonly deps: BudgetCoordinatorDeps) {}

  async reserve(
    input: Parameters<SigningSessionBudget['reserve']>[0],
  ): ReturnType<SigningSessionBudget['reserve']> {
    const normalizedInput: SigningSessionBudgetReserveInput = {
      ...input,
      spend: normalizeWalletSigningSpendPlan(input.spend),
    };
    const spend = normalizedInput.spend;
    const operationId = normalizeRequired(spend.operationId, 'operationId');
    const walletSigningSessionId = normalizeRequired(
      spend.walletSigningSessionId,
      'walletSigningSessionId',
    );
    const existingSpend = this.successfulSpendsByOperationId.get(operationId);
    if (existingSpend) {
      const conflict = reserveConflictForRecordedSuccess({
        recorded: existingSpend,
        spend,
        projectionVersion: existingSpend.reservationIdentity.admittedProjection.version,
      });
      if (conflict) return conflict;
      this.emitTrace(normalizedInput, 'wallet_signing_budget_reservation_deduped');
      return null;
    }
    const existingReservation = this.reservationsByOperationId.get(operationId);
    if (existingReservation) {
      const conflict = reserveConflictForReservation({
        reservation: existingReservation,
        spend,
      });
      if (conflict) return conflict;
      this.emitTrace(normalizedInput, 'wallet_signing_budget_reservation_deduped');
      return null;
    }

    return await this.enqueueWalletReservation(walletSigningSessionId, async () => {
      const admittedReservation = this.reservationsByOperationId.get(operationId);
      if (admittedReservation) {
        const conflict = reserveConflictForReservation({
          reservation: admittedReservation,
          spend,
        });
        if (conflict) return conflict;
        this.emitTrace(normalizedInput, 'wallet_signing_budget_reservation_deduped');
        return null;
      }

      this.emitTrace(normalizedInput, 'wallet_signing_budget_reservation_started');
      let admittedStatus: Awaited<
        ReturnType<typeof assertSigningSessionBudgetReservationAvailable>
      >;
      try {
        admittedStatus = await assertSigningSessionBudgetReservationAvailable({
          getStatus: (statusArgs) => this.deps.readStatus(statusArgs),
          input: normalizedInput,
          reservationsByOperationId: this.reservationsByOperationId,
        });
      } catch (error) {
        this.emitTrace(normalizedInput, 'wallet_signing_budget_reservation_failed', {
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
        throw error;
      }

      const reservationIdentity = buildSigningBudgetReservationIdentity({
        spend,
        projectionVersion: admittedStatus.projectionVersion,
      });
      this.reservationsByOperationId.set(operationId, {
        ...normalizedInput,
        expectedBudgetProjectionVersion: admittedStatus.projectionVersion,
        operationFingerprint: resolveWalletSigningOperationFingerprint(spend),
        walletSigningSessionId,
        reservationIdentity,
        reservationIdentityKey: signingBudgetReservationKey(reservationIdentity),
        reservedAgainstProjectionVersion: admittedStatus.projectionVersion,
        reservedAgainstRemainingUses: Math.max(
          0,
          Math.floor(Number(admittedStatus.remainingUses) || 0),
        ),
        createdAtMs: Date.now(),
      });
      this.emitTrace(normalizedInput, 'wallet_signing_budget_reservation_succeeded');
      return this.createReservation(spend.operationId, (reason) => {
        this.releaseReservation(normalizedInput, reason);
      });
    });
  }

  async getAvailableStatus(
    input: Parameters<SigningSessionBudget['getAvailableStatus']>[0],
  ): ReturnType<SigningSessionBudget['getAvailableStatus']> {
    assertBudgetStatusCheckHasConcreteLaneIdentity(input);
    const walletSigningSessionId = normalizeRequired(
      input.walletSigningSessionId,
      'walletSigningSessionId',
    );
    const status = await this.deps.readStatus({
      ...input,
      walletSigningSessionId,
    });
    return applySigningSessionBudgetReservationsToStatus({
      status,
      walletSigningSessionId,
      reservationsByOperationId: this.reservationsByOperationId,
    });
  }

  async recordSuccess(
    input: SigningSessionBudgetSuccessInput,
  ): ReturnType<SigningSessionBudget['recordSuccess']> {
    const normalizedInput = normalizeWalletBudgetSuccessInput(input);
    const operationId = normalizeRequired(normalizedInput.spend.operationId, 'operationId');
    const existing = this.successfulSpendsByOperationId.get(operationId);
    if (existing) {
      const actualRecordedIdentity = buildSigningBudgetReservationIdentity({
        spend: normalizedInput.spend,
        projectionVersion: existing.reservationIdentity.admittedProjection.version,
      });
      const commandMismatch = finalizationCommandIdentityMismatch({
        expected: normalizedInput.finalizationCommand.reservation,
        actual: actualRecordedIdentity,
      });
      if (commandMismatch) {
        this.emitFinalizationTrace(normalizedInput, commandMismatch);
        return commandMismatch;
      }
      if (existing.reservationIdentityKey !== signingBudgetReservationKey(actualRecordedIdentity)) {
        return {
          kind: 'reservation_identity_mismatch',
          expected: existing.reservationIdentity,
          actual: actualRecordedIdentity,
        };
      }
      this.emitTrace(normalizedInput, 'wallet_signing_budget_spend_deduped');
      const result = await existing.promise;
      const dedupedResult: SigningBudgetFinalizationResult =
        result.kind === 'finalized' ? { ...result, kind: 'already_finalized' } : result;
      this.emitFinalizationTrace(normalizedInput, dedupedResult);
      return dedupedResult;
    }
    const reservation = this.reservationsByOperationId.get(operationId);
    if (reservation) {
      const actualReservationIdentity = buildSigningBudgetReservationIdentity({
        spend: normalizedInput.spend,
        projectionVersion: reservation.reservedAgainstProjectionVersion,
      });
      const commandMismatch = finalizationCommandIdentityMismatch({
        expected: normalizedInput.finalizationCommand.reservation,
        actual: actualReservationIdentity,
      });
      if (commandMismatch) {
        this.emitFinalizationTrace(normalizedInput, commandMismatch);
        return commandMismatch;
      }
      if (
        reservation.reservationIdentityKey !==
        signingBudgetReservationKey(actualReservationIdentity)
      ) {
        const result: SigningBudgetFinalizationResult = {
          kind: 'reservation_identity_mismatch',
          expected: reservation.reservationIdentity,
          actual: actualReservationIdentity,
        };
        this.emitFinalizationTrace(normalizedInput, result);
        return result;
      }
      if (normalizedInput.kind === 'unreserved_success') {
        const result: SigningBudgetFinalizationResult = {
          kind: 'reservation_identity_mismatch',
          expected: reservation.reservationIdentity,
          actual: actualReservationIdentity,
        };
        this.emitFinalizationTrace(normalizedInput, result);
        return result;
      }
    } else if (normalizedInput.kind === 'reserved_success') {
      const result: SigningBudgetFinalizationResult = {
        kind: 'missing_reservation',
        reservation: normalizedInput.finalizationCommand.reservation,
      };
      this.emitFinalizationTrace(normalizedInput, result);
      return result;
    }
    let successIdentity = reservation?.reservationIdentity || null;
    if (!reservation) {
      const status = await this.deps.readStatus(
        buildSigningSessionBudgetStatusCheckForSpend({
          spend: normalizedInput.spend,
          trustedStatusAuth: normalizedInput.trustedStatusAuth,
        }),
      );
      if (status.status === 'budget_unknown' || status.status === 'not_found') {
        const result: SigningBudgetFinalizationResult = {
          kind: 'budget_status_unavailable',
          reservation: buildSigningBudgetReservationIdentity({
            spend: normalizedInput.spend,
            projectionVersion:
              normalizedInput.kind === 'externally_consumed_success'
                ? 'budget-status-unavailable'
                : normalizedInput.expectedBudgetProjectionVersion,
          }),
          status: status.status,
        };
        this.emitFinalizationTrace(normalizedInput, result);
        return result;
      }
      if (status.status !== 'active') {
        throw new Error(`[SigningSessionBudget] wallet signing-session budget is ${status.status}`);
      }
      if (normalizedInput.kind !== 'externally_consumed_success') {
        const expected = normalizeRequired(
          normalizedInput.expectedBudgetProjectionVersion,
          'expectedBudgetProjectionVersion',
        );
        const actual = normalizeRequired(status.projectionVersion, 'projectionVersion');
        if (actual !== expected) {
          const result: SigningBudgetFinalizationResult = {
            kind: 'projection_mismatch',
            reservation: buildSigningBudgetReservationIdentity({
              spend: normalizedInput.spend,
              projectionVersion: expected,
            }),
            expectedProjectionVersion: expected,
            actualProjectionVersion: actual,
          };
          this.emitFinalizationTrace(normalizedInput, result);
          return result;
        }
      }
      const successProjectionVersion =
        normalizedInput.kind === 'externally_consumed_success'
          ? normalizeRequired(status.projectionVersion, 'projectionVersion')
          : normalizeRequired(
              normalizedInput.expectedBudgetProjectionVersion,
              'expectedBudgetProjectionVersion',
            );
      successIdentity = buildSigningBudgetReservationIdentity({
        spend: normalizedInput.spend,
        projectionVersion: successProjectionVersion,
      });
      const commandMismatch = finalizationCommandIdentityMismatch({
        expected: normalizedInput.finalizationCommand.reservation,
        actual: successIdentity,
      });
      if (commandMismatch) {
        this.emitFinalizationTrace(normalizedInput, commandMismatch);
        return commandMismatch;
      }
    }
    if (!successIdentity) {
      throw new Error('[SigningSessionBudget] successful spend identity is required');
    }
    const successIdentityKey = signingBudgetReservationKey(successIdentity);

    const spendPromise = this.recordSpend(normalizedInput)
      .then((status) => {
        const result = finalizationResultFromStatus(successIdentity, status);
        this.emitFinalizationTrace(normalizedInput, result);
        return result;
      })
      .catch((error) => {
        this.successfulSpendsByOperationId.delete(operationId);
        this.emitTrace(normalizedInput, 'wallet_signing_budget_spend_failed', {
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
        throw error;
      })
      .finally(() => {
        this.releaseReservation(normalizedInput);
      });
    this.successfulSpendsByOperationId.set(operationId, {
      operationFingerprint: resolveWalletSigningOperationFingerprint(normalizedInput.spend),
      reservationIdentity: successIdentity,
      reservationIdentityKey: successIdentityKey,
      promise: spendPromise,
    });
    return await spendPromise;
  }

  recordZeroSpend(input: ZeroWalletBudgetSpend): void {
    const finalizationKey = signingBudgetReservationKey(input.finalizationCommand.reservation);
    if (this.zeroSpendFinalizationsByReservationKey.has(finalizationKey)) return;
    this.releaseZeroSpendReservation(input, finalizationKey);
    this.zeroSpendFinalizationsByReservationKey.add(finalizationKey);
    this.deps.onTrace?.(
      createZeroSpendTraceEvent(input, 'wallet_signing_budget_zero_spend_recorded', {
        zeroSpendReason: input.reason,
        ...(input.error
          ? { error: input.error instanceof Error ? input.error.message : String(input.error) }
          : {}),
      }),
    );
  }

  hasRecorded(operationId: string): boolean {
    return this.successfulSpendsByOperationId.has(String(operationId));
  }

  private async enqueueWalletReservation<TValue>(
    walletSigningSessionId: string,
    task: () => Promise<TValue>,
  ): Promise<TValue> {
    const previous = this.walletReservationQueues.get(walletSigningSessionId) || Promise.resolve();
    const next = previous.catch(() => undefined).then(task);
    const queueEntry = next
      .catch(() => undefined)
      .then(() => {
        if (this.walletReservationQueues.get(walletSigningSessionId) === queueEntry) {
          this.walletReservationQueues.delete(walletSigningSessionId);
        }
      });
    this.walletReservationQueues.set(walletSigningSessionId, queueEntry);
    return await next;
  }

  private createReservation(
    operationId: SigningSessionBudgetReservation['operationId'],
    release: (reason?: SigningSessionBudgetZeroSpendReason) => void,
  ): SigningSessionBudgetReservation {
    let released = false;
    return {
      kind: 'reserved',
      operationId,
      release(reason) {
        if (released) return;
        released = true;
        release(reason);
      },
    };
  }

  private releaseReservation(
    input: { spend: WalletBudgetSpend },
    reason?: SigningSessionBudgetZeroSpendReason,
  ): void {
    const operationId = normalizeRequired(input.spend.operationId, 'operationId');
    const reservation = this.reservationsByOperationId.get(operationId);
    if (!reservation) return;
    this.reservationsByOperationId.delete(operationId);
    this.emitTrace(
      reservation,
      'wallet_signing_budget_reservation_released',
      reason ? { zeroSpendReason: reason } : {},
    );
  }

  private releaseZeroSpendReservation(
    input: ZeroWalletBudgetSpend,
    finalizationKey: SigningBudgetReservationKey,
  ): void {
    const reservation = this.reservationsByOperationId.get(input.operationId);
    if (!reservation) return;
    if (reservation.reservationIdentityKey !== finalizationKey) {
      throw new Error(
        `[SigningSessionBudget] zero_spend reservation identity does not match reservation: ${input.operationId}`,
      );
    }
    this.reservationsByOperationId.delete(input.operationId);
    this.deps.onTrace?.(
      createZeroSpendTraceEvent(input, 'wallet_signing_budget_reservation_released', {
        zeroSpendReason: input.reason,
      }),
    );
  }

  private async recordSpend(
    input: SigningSessionBudgetSuccessInput,
  ): Promise<SigningSessionStatus> {
    if (!this.deps.consumeUse) {
      throw new Error(
        '[SigningSessionBudget] consumeUse is required to record wallet signing-session spend',
      );
    }
    const spend = input.spend;
    const walletSigningSessionId = normalizeRequired(
      spend.walletSigningSessionId,
      'walletSigningSessionId',
    );
    this.emitTrace(input, 'wallet_signing_budget_spend_started');
    const budgetStatusCheck = buildSigningSessionBudgetStatusCheckForSpend({
      spend,
      trustedStatusAuth: input.trustedStatusAuth,
    });
    const status = await this.deps.consumeUse({
      owner: walletBudgetOwnerForLane(spend.lane),
      walletSigningSessionId,
      uses: spend.uses,
      reason: spend.reason,
      budgetStatusCheck,
      ...(input.kind === 'externally_consumed_success'
        ? {
            alreadyConsumedBackingMaterialSessionIds: normalizeStringList(
              input.alreadyConsumedBackingMaterialSessionIds,
            ),
            alreadyConsumedThresholdSessionIds: normalizeStringList(
              input.alreadyConsumedThresholdSessionIds,
            ),
          }
        : {}),
    });
    if (!status) {
      return budgetStatusUnavailable('missing_status', spend.walletSigningSessionId);
    }
    if (status.status === 'not_found') {
      return status;
    }
    if (status.status === 'budget_unknown') {
      return status;
    }
    this.emitTrace(input, 'wallet_signing_budget_spend_succeeded', {
      status: {
        status: status.status,
        remainingUses: status.remainingUses,
        expiresAtMs: status.expiresAtMs,
      },
    });
    return status;
  }

  private emitTrace(
    input: { spend: WalletBudgetSpend },
    event: SigningSessionBudgetTraceEvent['event'],
    extra: Pick<
      SigningSessionBudgetTraceEvent,
      'status' | 'error' | 'finalizationResult' | 'zeroSpendReason'
    > = {},
  ): void {
    this.deps.onTrace?.(createSigningSessionBudgetTraceEvent(input, event, extra));
  }

  private emitFinalizationTrace(
    input: { spend: WalletBudgetSpend },
    result: SigningBudgetFinalizationResult,
  ): void {
    this.emitTrace(input, finalizationTraceEvent(result), {
      finalizationResult: result.kind,
      ...(result.kind === 'finalized' || result.kind === 'already_finalized'
        ? {
            status: {
              status: 'active',
              remainingUses: result.remainingUses,
            },
          }
        : {}),
      ...(result.kind === 'projection_mismatch'
        ? {
            error: `expected ${result.expectedProjectionVersion}, got ${result.actualProjectionVersion}`,
          }
        : {}),
      ...(result.kind === 'budget_status_unavailable' ? { error: result.status } : {}),
    });
  }
}

function reserveConflictForReservation(args: {
  reservation: SigningSessionBudgetReservationRecord;
  spend: WalletBudgetSpend;
}): SigningSessionBudgetReservationConflict | null {
  const nextIdentity = buildSigningBudgetReservationIdentity({
    spend: args.spend,
    projectionVersion: args.reservation.reservedAgainstProjectionVersion,
  });
  if (args.reservation.reservationIdentityKey === signingBudgetReservationKey(nextIdentity)) {
    return null;
  }
  return {
    kind: 'reservation_identity_mismatch',
    expected: args.reservation.reservationIdentity,
    actual: nextIdentity,
  };
}

function reserveConflictForRecordedSuccess(args: {
  recorded: SuccessfulSpendRecord;
  spend: WalletBudgetSpend;
  projectionVersion: string;
}): SigningSessionBudgetReservationConflict | null {
  const nextIdentity = buildSigningBudgetReservationIdentity({
    spend: args.spend,
    projectionVersion: args.projectionVersion,
  });
  if (args.recorded.reservationIdentityKey === signingBudgetReservationKey(nextIdentity)) {
    return null;
  }
  return {
    kind: 'reservation_identity_mismatch',
    expected: args.recorded.reservationIdentity,
    actual: nextIdentity,
  };
}

function finalizationCommandIdentityMismatch(args: {
  expected: SigningBudgetReservationIdentity;
  actual: SigningBudgetReservationIdentity;
}): SigningBudgetFinalizationResult | null {
  if (signingBudgetReservationKey(args.expected) === signingBudgetReservationKey(args.actual)) {
    return null;
  }
  return {
    kind: 'reservation_identity_mismatch',
    expected: args.expected,
    actual: args.actual,
  };
}

function finalizationResultFromStatus(
  reservation: SigningBudgetReservationIdentity,
  status: SigningSessionStatus,
): SigningBudgetFinalizationResult {
  if (status.status === 'not_found' || status.status === 'budget_unknown') {
    return {
      kind: 'budget_status_unavailable',
      reservation,
      status: status.status,
    };
  }
  const projectionVersion =
    String(status.projectionVersion || '').trim() || reservation.admittedProjection.version;
  return {
    kind: 'finalized',
    reservation,
    remainingUses: Math.max(0, Math.floor(Number(status.remainingUses) || 0)),
    projectionVersion: normalizeRequired(projectionVersion, 'projectionVersion'),
  };
}

function finalizationTraceEvent(
  result: SigningBudgetFinalizationResult,
): SigningSessionBudgetTraceEvent['event'] {
  switch (result.kind) {
    case 'finalized':
      return 'wallet_signing_budget_finalization_finalized';
    case 'already_finalized':
      return 'wallet_signing_budget_finalization_already_finalized';
    case 'projection_mismatch':
      return 'wallet_signing_budget_finalization_projection_mismatch';
    case 'missing_reservation':
      return 'wallet_signing_budget_finalization_missing_reservation';
    case 'reservation_identity_mismatch':
      return 'wallet_signing_budget_finalization_identity_mismatch';
    case 'budget_status_unavailable':
      return 'wallet_signing_budget_finalization_status_unavailable';
  }
}

function budgetStatusUnavailable(
  status: Extract<SigningBudgetFinalizationResult, { kind: 'budget_status_unavailable' }>['status'],
  sessionId: string,
): SigningSessionStatus {
  return {
    sessionId,
    status: 'budget_unknown',
    statusCode: status,
  };
}

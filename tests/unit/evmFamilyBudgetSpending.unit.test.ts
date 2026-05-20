import { expect, test } from '@playwright/test';
import { toAccountId } from '../../client/src/core/types/accountIds';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
  type TempoChainTarget,
} from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';
import { selectedEcdsaLane, type SelectedEcdsaLane } from '../../client/src/core/signingEngine/session/identity/laneIdentity';
import { buildTempoTransactionSigningLane } from '../../client/src/core/signingEngine/session/operationState/lanes';
import { SigningSessionCoordinator } from '../../client/src/core/signingEngine/session/SigningSessionCoordinator';
import {
  SigningOperationIntent,
  SigningSessionIds,
} from '../../client/src/core/signingEngine/session/operationState/types';
import { requireResolvedEvmFamilyEcdsaSigningLane } from '../../client/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
} from '../../client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  recordSuccessfulEvmFamilyWalletSigningSessionSpend,
  reserveEvmFamilyWalletSigningSessionBudget,
} from '../../client/src/core/signingEngine/flows/signEvmFamily/budgetSpending';
import { SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR } from '../../client/src/core/signingEngine/session/budget/budget';
import type { BudgetAdmittedOperation } from '../../client/src/core/signingEngine/session/operationState/transactionState';
import type { SigningSessionStatus } from '../../client/src/core/types/seams';

const WALLET_ID = toAccountId('budget-refresh.testnet');
const CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-moderato',
}) as TempoChainTarget;
const EXPIRES_AT_MS = 1_900_000_000_000;
const ECDSA_KEY = buildBaseEvmFamilyEcdsaKeyIdentity({
  walletId: WALLET_ID,
  rpId: 'localhost',
  ecdsaThresholdKeyId: 'ehss-shared-key',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
});
const ECDSA_KEY_HANDLE = toEvmFamilyEcdsaKeyHandle('ehss-key-handle-budget');

function makeBudgetStatus(args: {
  walletSigningSessionId: string;
  status: SigningSessionStatus['status'];
  projectionVersion?: string;
  remainingUses?: number;
}): SigningSessionStatus {
  return {
    sessionId: args.walletSigningSessionId,
    status: args.status,
    ...(typeof args.remainingUses === 'number' ? { remainingUses: args.remainingUses } : {}),
    ...(args.projectionVersion ? { projectionVersion: args.projectionVersion } : {}),
    ...(args.status !== 'not_found' ? { expiresAtMs: EXPIRES_AT_MS } : {}),
  };
}

function makeAdmittedOperation(args: {
  exhaustedWalletSigningSessionId: string;
  exhaustedThresholdSessionId: string;
  refreshedWalletSigningSessionId: string;
  projectionVersion: string;
}): BudgetAdmittedOperation<SelectedEcdsaLane> {
  return {
    intent: {
      curve: 'ecdsa',
      chain: 'tempo',
      chainTarget: CHAIN_TARGET,
      walletId: toWalletId(WALLET_ID),
      authSelectionPolicy: { kind: 'explicit', authMethod: 'email_otp' },
      operationUsesNeeded: 1,
    },
    lane: selectedEcdsaLane({
      key: ECDSA_KEY,
      keyHandle: ECDSA_KEY_HANDLE,
      walletId: WALLET_ID,
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession(
        args.exhaustedWalletSigningSessionId,
      ),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(args.exhaustedThresholdSessionId),
      chainTarget: CHAIN_TARGET,
    }),
    readiness: {
      status: 'ready',
      remainingUses: 1,
      expiresAtMs: EXPIRES_AT_MS,
    },
    budgetAdmission: {
      budgetIdentity: {
        walletSigningSessionId: args.refreshedWalletSigningSessionId,
        projectionVersion: args.projectionVersion,
        status: {
          sessionId: args.refreshedWalletSigningSessionId,
          status: 'active',
          projectionVersion: args.projectionVersion,
          remainingUses: 1,
          expiresAtMs: EXPIRES_AT_MS,
        },
      },
    },
  };
}

function makeResolvedFinalizedLane(args: {
  walletSigningSessionId: string;
  thresholdSessionId: string;
}) {
  return requireResolvedEvmFamilyEcdsaSigningLane({
    lane: buildTempoTransactionSigningLane({
      authMethod: 'email_otp',
      key: ECDSA_KEY,
      keyHandle: ECDSA_KEY_HANDLE,
      walletId: WALLET_ID,
      chainTarget: CHAIN_TARGET,
      walletSigningSessionId: SigningSessionIds.walletSigningSession(args.walletSigningSessionId),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(args.thresholdSessionId),
    }),
    chain: 'tempo',
    context: 'evmFamilyBudgetSpending.unit',
  });
}

test.describe('EVM-family budget finalization spending', () => {
  test('admits fresh unlock budget status for a ready Email OTP ECDSA lane', async () => {
    const freshWalletSigningSessionId = 'wallet-session-fresh-unlock';
    const freshThresholdSessionId = 'threshold-session-fresh-unlock';
    const statusChecks: Array<{ walletSigningSessionId: string; budgetStatusCheck: unknown }> = [];
    const coordinator = new SigningSessionCoordinator({
      getStatus: async (args) => {
        statusChecks.push({
          walletSigningSessionId: String(args.walletSigningSessionId),
          budgetStatusCheck: args,
        });
        return makeBudgetStatus({
          walletSigningSessionId: String(args.walletSigningSessionId),
          status: 'active',
          projectionVersion: 'projection-fresh-unlock',
          remainingUses: 2,
        });
      },
      consumeUse: async () => {
        throw new Error('consumeUse is not expected during reservation');
      },
    });

    const reservation = await reserveEvmFamilyWalletSigningSessionBudget({
      signingSessionCoordinator: coordinator,
      walletSession: {
        walletId: toWalletId(WALLET_ID),
        walletSessionUserId: String(WALLET_ID),
      },
      operation: {
        operationId: SigningSessionIds.signingOperation('operation-fresh-unlock'),
        operationFingerprint: SigningSessionIds.signingOperationFingerprint(
          'fingerprint-fresh-unlock',
        ),
        intent: SigningOperationIntent.TransactionSign,
      },
      admittedTransaction: makeAdmittedOperation({
        exhaustedWalletSigningSessionId: freshWalletSigningSessionId,
        exhaustedThresholdSessionId: freshThresholdSessionId,
        refreshedWalletSigningSessionId: freshWalletSigningSessionId,
        projectionVersion: 'projection-fresh-unlock',
      }),
      finalizedSigningLane: makeResolvedFinalizedLane({
        walletSigningSessionId: freshWalletSigningSessionId,
        thresholdSessionId: freshThresholdSessionId,
      }),
      key: ECDSA_KEY,
    });

    expect(reservation).not.toBeNull();
    expect(statusChecks).toHaveLength(1);
    expect(statusChecks[0]).toMatchObject({
      walletSigningSessionId: freshWalletSigningSessionId,
      budgetStatusCheck: {
        kind: 'ecdsa_lane_budget_status_check',
        walletSigningSessionId: freshWalletSigningSessionId,
        thresholdSessionId: freshThresholdSessionId,
      },
    });
  });

  test('records one spend per operation id after reauth', async () => {
    const exhaustedWalletSigningSessionId = 'wallet-session-exhausted';
    const exhaustedThresholdSessionId = 'threshold-session-exhausted';
    const refreshedWalletSigningSessionId = 'wallet-session-refreshed';
    const refreshedThresholdSessionId = 'threshold-session-refreshed';
    const consumeCalls: string[] = [];
    const coordinator = new SigningSessionCoordinator({
      getStatus: async ({ walletSigningSessionId }) =>
        makeBudgetStatus({
          walletSigningSessionId: String(walletSigningSessionId),
          status: 'active',
          projectionVersion: 'projection-refreshed',
          remainingUses: 1,
        }),
      consumeUse: async ({ walletSigningSessionId }) => {
        consumeCalls.push(String(walletSigningSessionId));
        return makeBudgetStatus({
          walletSigningSessionId: String(walletSigningSessionId),
          status: 'exhausted',
          projectionVersion: 'projection-refreshed-consumed',
          remainingUses: 0,
        });
      },
    });
    const commonArgs = {
      signingSessionCoordinator: coordinator,
      walletSession: {
        walletId: toWalletId(WALLET_ID),
        walletSessionUserId: String(WALLET_ID),
      },
      operation: {
        operationId: SigningSessionIds.signingOperation('operation-one-spend'),
        operationFingerprint: SigningSessionIds.signingOperationFingerprint(
          'fingerprint-one-spend',
        ),
        intent: SigningOperationIntent.TransactionSign,
      },
      admittedTransaction: makeAdmittedOperation({
        exhaustedWalletSigningSessionId,
        exhaustedThresholdSessionId,
        refreshedWalletSigningSessionId,
        projectionVersion: 'projection-refreshed',
      }),
      finalizedSigningLane: makeResolvedFinalizedLane({
        walletSigningSessionId: refreshedWalletSigningSessionId,
        thresholdSessionId: refreshedThresholdSessionId,
      }),
      key: ECDSA_KEY,
    } as const;

    await recordSuccessfulEvmFamilyWalletSigningSessionSpend(commonArgs);
    await recordSuccessfulEvmFamilyWalletSigningSessionSpend(commonArgs);

    expect(consumeCalls).toEqual([refreshedWalletSigningSessionId]);
  });

  test('reserves budget against the refreshed lane before signing after reauth', async () => {
    const exhaustedWalletSigningSessionId = 'wallet-session-exhausted';
    const exhaustedThresholdSessionId = 'threshold-session-exhausted';
    const refreshedWalletSigningSessionId = 'wallet-session-refreshed';
    const refreshedThresholdSessionId = 'threshold-session-refreshed';
    const statusChecks: string[] = [];
    const coordinator = new SigningSessionCoordinator({
      getStatus: async ({ walletSigningSessionId }) => {
        const sessionId = String(walletSigningSessionId);
        statusChecks.push(sessionId);
        return sessionId === refreshedWalletSigningSessionId
          ? makeBudgetStatus({
              walletSigningSessionId: refreshedWalletSigningSessionId,
              status: 'active',
              projectionVersion: 'projection-refreshed',
              remainingUses: 1,
            })
          : makeBudgetStatus({
              walletSigningSessionId: sessionId,
              status: 'not_found',
            });
      },
      consumeUse: async () => {
        throw new Error('consumeUse is not expected during reservation');
      },
    });

    const reservation = await reserveEvmFamilyWalletSigningSessionBudget({
      signingSessionCoordinator: coordinator,
      walletSession: {
        walletId: toWalletId(WALLET_ID),
        walletSessionUserId: String(WALLET_ID),
      },
      operation: {
        operationId: SigningSessionIds.signingOperation('operation-reserve-refreshed'),
        operationFingerprint: SigningSessionIds.signingOperationFingerprint(
          'fingerprint-reserve-refreshed',
        ),
        intent: SigningOperationIntent.TransactionSign,
      },
      admittedTransaction: makeAdmittedOperation({
        exhaustedWalletSigningSessionId,
        exhaustedThresholdSessionId,
        refreshedWalletSigningSessionId,
        projectionVersion: 'projection-refreshed',
      }),
      finalizedSigningLane: makeResolvedFinalizedLane({
        walletSigningSessionId: refreshedWalletSigningSessionId,
        thresholdSessionId: refreshedThresholdSessionId,
      }),
      key: ECDSA_KEY,
    });

    expect(reservation).not.toBeNull();
    expect(statusChecks).toEqual([refreshedWalletSigningSessionId]);
  });

  test('fails reservation when the refreshed lane is already exhausted', async () => {
    const exhaustedWalletSigningSessionId = 'wallet-session-exhausted';
    const exhaustedThresholdSessionId = 'threshold-session-exhausted';
    const refreshedWalletSigningSessionId = 'wallet-session-refreshed';
    const refreshedThresholdSessionId = 'threshold-session-refreshed';
    const coordinator = new SigningSessionCoordinator({
      getStatus: async ({ walletSigningSessionId }) =>
        makeBudgetStatus({
          walletSigningSessionId: String(walletSigningSessionId),
          status: 'exhausted',
          projectionVersion: 'projection-exhausted',
          remainingUses: 0,
        }),
      consumeUse: async () => {
        throw new Error('consumeUse is not expected for exhausted reservation');
      },
    });

    await expect(
      reserveEvmFamilyWalletSigningSessionBudget({
        signingSessionCoordinator: coordinator,
        walletSession: {
          walletId: toWalletId(WALLET_ID),
          walletSessionUserId: String(WALLET_ID),
        },
        operation: {
          operationId: SigningSessionIds.signingOperation('operation-exhausted-reservation'),
          operationFingerprint: SigningSessionIds.signingOperationFingerprint(
            'fingerprint-exhausted-reservation',
          ),
          intent: SigningOperationIntent.TransactionSign,
        },
        admittedTransaction: makeAdmittedOperation({
          exhaustedWalletSigningSessionId,
          exhaustedThresholdSessionId,
          refreshedWalletSigningSessionId,
          projectionVersion: 'projection-exhausted',
        }),
        finalizedSigningLane: makeResolvedFinalizedLane({
          walletSigningSessionId: refreshedWalletSigningSessionId,
          thresholdSessionId: refreshedThresholdSessionId,
        }),
        key: ECDSA_KEY,
      }),
    ).rejects.toThrow(SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR);
  });

  test('uses refreshed Email OTP wallet session for consume/finalize and records consumed threshold ids', async () => {
    const exhaustedWalletSigningSessionId = 'wallet-session-exhausted';
    const exhaustedThresholdSessionId = 'threshold-session-exhausted';
    const refreshedWalletSigningSessionId = 'wallet-session-refreshed';
    const refreshedThresholdSessionId = 'threshold-session-refreshed';
    const operationId = SigningSessionIds.signingOperation('operation-budget-refresh');
    const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
      'fingerprint-budget-refresh',
    );
    const statusChecks: string[] = [];
    const consumeCalls: Array<{
      walletSigningSessionId: string;
      budgetStatusCheck: unknown;
      alreadyConsumedThresholdSessionIds?: string[];
    }> = [];
    const coordinator = new SigningSessionCoordinator({
      getStatus: async ({ walletSigningSessionId }) => {
        const sessionId = String(walletSigningSessionId);
        statusChecks.push(sessionId);
        return sessionId === refreshedWalletSigningSessionId
          ? makeBudgetStatus({
              walletSigningSessionId: refreshedWalletSigningSessionId,
              status: 'active',
              projectionVersion: 'projection-refreshed',
              remainingUses: 1,
            })
          : makeBudgetStatus({
              walletSigningSessionId: sessionId,
              status: 'not_found',
            });
      },
      consumeUse: async (args) => {
        consumeCalls.push({
          walletSigningSessionId: args.walletSigningSessionId,
          budgetStatusCheck: args.budgetStatusCheck,
          alreadyConsumedThresholdSessionIds: args.alreadyConsumedThresholdSessionIds,
        });
        if (args.walletSigningSessionId !== refreshedWalletSigningSessionId) {
          return makeBudgetStatus({
            walletSigningSessionId: args.walletSigningSessionId,
            status: 'not_found',
          });
        }
        return makeBudgetStatus({
          walletSigningSessionId: refreshedWalletSigningSessionId,
          status: 'exhausted',
          projectionVersion: 'projection-refreshed-consumed',
          remainingUses: 0,
        });
      },
    });

    await recordSuccessfulEvmFamilyWalletSigningSessionSpend({
      signingSessionCoordinator: coordinator,
      walletSession: {
        walletId: toWalletId(WALLET_ID),
        walletSessionUserId: String(WALLET_ID),
      },
      operation: {
        operationId,
        operationFingerprint,
        intent: SigningOperationIntent.TransactionSign,
      },
      admittedTransaction: makeAdmittedOperation({
        exhaustedWalletSigningSessionId,
        exhaustedThresholdSessionId,
        refreshedWalletSigningSessionId,
        projectionVersion: 'projection-refreshed',
      }),
      finalizedSigningLane: makeResolvedFinalizedLane({
        walletSigningSessionId: refreshedWalletSigningSessionId,
        thresholdSessionId: refreshedThresholdSessionId,
      }),
      key: ECDSA_KEY,
    });

    expect(statusChecks).toEqual([refreshedWalletSigningSessionId]);
    expect(consumeCalls).toHaveLength(1);
    expect(consumeCalls[0].walletSigningSessionId).toBe(refreshedWalletSigningSessionId);
    expect(consumeCalls[0].alreadyConsumedThresholdSessionIds).toEqual([
      refreshedThresholdSessionId,
    ]);
    expect(consumeCalls[0].budgetStatusCheck).toMatchObject({
      kind: 'ecdsa_lane_budget_status_check',
      walletSigningSessionId: refreshedWalletSigningSessionId,
      thresholdSessionId: refreshedThresholdSessionId,
    });
  });

  test('rejects stale exhausted finalization lane when budget identity points at refreshed session', async () => {
    const exhaustedWalletSigningSessionId = 'wallet-session-exhausted';
    const exhaustedThresholdSessionId = 'threshold-session-exhausted';
    const refreshedWalletSigningSessionId = 'wallet-session-refreshed';
    const coordinator = new SigningSessionCoordinator({
      getStatus: async () => {
        throw new Error('getStatus should not be called for stale finalization');
      },
      consumeUse: async () => {
        throw new Error('consumeUse should not be called for stale finalization');
      },
    });

    await expect(
      recordSuccessfulEvmFamilyWalletSigningSessionSpend({
        signingSessionCoordinator: coordinator,
        walletSession: {
          walletId: toWalletId(WALLET_ID),
          walletSessionUserId: String(WALLET_ID),
        },
        operation: {
          operationId: SigningSessionIds.signingOperation('operation-stale-finalization'),
          operationFingerprint: SigningSessionIds.signingOperationFingerprint(
            'fingerprint-stale-finalization',
          ),
          intent: SigningOperationIntent.TransactionSign,
        },
        admittedTransaction: makeAdmittedOperation({
          exhaustedWalletSigningSessionId,
          exhaustedThresholdSessionId,
          refreshedWalletSigningSessionId,
          projectionVersion: 'projection-refreshed',
        }),
        finalizedSigningLane: makeResolvedFinalizedLane({
          walletSigningSessionId: exhaustedWalletSigningSessionId,
          thresholdSessionId: exhaustedThresholdSessionId,
        }),
        key: ECDSA_KEY,
      }),
    ).rejects.toThrow('[SigningSessionBudget] prepared budget identity does not match spend lane');
  });
});

import { expect, test } from '@playwright/test';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
  type TempoChainTarget,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import { selectedEcdsaLane, type SelectedEcdsaLane } from '../../packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity';
import { buildTempoTransactionSigningLane } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/lanes';
import { SigningSessionCoordinator } from '../../packages/sdk-web/src/core/signingEngine/session/SigningSessionCoordinator';
import {
  SigningOperationIntent,
  SigningSessionIds,
} from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import { requireResolvedEvmFamilyEcdsaSigningLane } from '../../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  recordSuccessfulEvmFamilySigningGrantSpend,
  reserveEvmFamilySigningGrantBudget,
} from '../../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/budgetSpending';
import {
  SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR,
} from '../../packages/sdk-web/src/core/signingEngine/session/budget/budget';
import type { BudgetAdmittedOperation } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/transactionState';
import type { SigningSessionStatus } from '../../packages/sdk-web/src/core/types/seams';

const WALLET_ID = toWalletId('budget-refresh.testnet');
const SIGNING_ROOT_ID = 'project:dev';
const SIGNING_ROOT_VERSION = 'default';
const EVM_FAMILY_SIGNING_KEY_SLOT_ID = deriveEvmFamilySigningKeySlotId({
  walletId: WALLET_ID,
  signingRootId: SIGNING_ROOT_ID,
  signingRootVersion: SIGNING_ROOT_VERSION,
});
const EMAIL_OTP_AUTH = {
  kind: 'email_otp',
  providerSubjectId: 'google:budget-refresh',
} as const;
const CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-moderato',
}) as TempoChainTarget;
const EXPIRES_AT_MS = 1_900_000_000_000;
const ECDSA_KEY = buildBaseEvmFamilyEcdsaKeyIdentity({
  walletId: WALLET_ID,
  evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
  ecdsaThresholdKeyId: 'ederivation-shared-key',
  signingRootId: SIGNING_ROOT_ID,
  signingRootVersion: SIGNING_ROOT_VERSION,
  participantIds: [1, 2],
  thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
});
const ECDSA_KEY_HANDLE = toEvmFamilyEcdsaKeyHandle('ederivation-key-handle-budget');

function makeBudgetStatus(args: {
  signingGrantId: string;
  status: SigningSessionStatus['status'];
  projectionVersion?: string;
  remainingUses?: number;
  availableUses?: number;
  inFlightReservedUses?: number;
}): SigningSessionStatus {
  return {
    sessionId: args.signingGrantId,
    status: args.status,
    ...(typeof args.remainingUses === 'number' ? { remainingUses: args.remainingUses } : {}),
    ...(typeof args.availableUses === 'number' ? { availableUses: args.availableUses } : {}),
    ...(typeof args.inFlightReservedUses === 'number'
      ? { inFlightReservedUses: args.inFlightReservedUses }
      : {}),
    ...(args.projectionVersion ? { projectionVersion: args.projectionVersion } : {}),
    ...(args.status !== 'not_found' ? { expiresAtMs: EXPIRES_AT_MS } : {}),
  };
}

function makeAdmittedOperation(args: {
  exhaustedSigningGrantId: string;
  exhaustedThresholdSessionId: string;
  refreshedSigningGrantId: string;
  projectionVersion: string;
  remainingUses?: number;
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
      auth: EMAIL_OTP_AUTH,
      signingGrantId: SigningSessionIds.signingGrant(
        args.exhaustedSigningGrantId,
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
        signingGrantId: args.refreshedSigningGrantId,
        projectionVersion: args.projectionVersion,
        status: {
          sessionId: args.refreshedSigningGrantId,
          status: 'active',
          projectionVersion: args.projectionVersion,
          remainingUses: args.remainingUses ?? 1,
          expiresAtMs: EXPIRES_AT_MS,
        },
      },
    },
  };
}

function makeResolvedFinalizedLane(args: {
  signingGrantId: string;
  thresholdSessionId: string;
}) {
  return requireResolvedEvmFamilyEcdsaSigningLane({
    lane: buildTempoTransactionSigningLane({
      auth: EMAIL_OTP_AUTH,
      key: ECDSA_KEY,
      keyHandle: ECDSA_KEY_HANDLE,
      walletId: WALLET_ID,
      chainTarget: CHAIN_TARGET,
      signingGrantId: SigningSessionIds.signingGrant(args.signingGrantId),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(args.thresholdSessionId),
    }),
    chain: 'tempo',
    context: 'evmFamilyBudgetSpending.unit',
  });
}

test.describe('EVM-family budget finalization spending', () => {
  test('admits fresh unlock budget status for a ready Email OTP ECDSA lane', async () => {
    const freshSigningGrantId = 'wallet-session-fresh-unlock';
    const freshThresholdSessionId = 'threshold-session-fresh-unlock';
    const statusChecks: Array<{ signingGrantId: string; budgetStatusCheck: unknown }> = [];
    const coordinator = new SigningSessionCoordinator({
      getStatus: async (args) => {
        statusChecks.push({
          signingGrantId: String(args.signingGrantId),
          budgetStatusCheck: args,
        });
        return makeBudgetStatus({
          signingGrantId: String(args.signingGrantId),
          status: 'active',
          projectionVersion: 'projection-fresh-unlock',
          remainingUses: 2,
        });
      },
      consumeUse: async () => {
        throw new Error('consumeUse is not expected during reservation');
      },
    });

    const reservation = await reserveEvmFamilySigningGrantBudget({
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
        exhaustedSigningGrantId: freshSigningGrantId,
        exhaustedThresholdSessionId: freshThresholdSessionId,
        refreshedSigningGrantId: freshSigningGrantId,
        projectionVersion: 'projection-fresh-unlock',
      }),
      finalizedSigningLane: makeResolvedFinalizedLane({
        signingGrantId: freshSigningGrantId,
        thresholdSessionId: freshThresholdSessionId,
      }),
    });

    expect(reservation).not.toBeNull();
    expect(statusChecks).toHaveLength(0);
  });

  test('admits budget identity when committed uses remain despite server in-flight reservations', async () => {
    const signingGrantId = 'wallet-session-server-inflight';
    const thresholdSessionId = 'threshold-session-server-inflight';
    const lane = buildTempoTransactionSigningLane({
      auth: EMAIL_OTP_AUTH,
      key: ECDSA_KEY,
      keyHandle: ECDSA_KEY_HANDLE,
      walletId: WALLET_ID,
      chainTarget: CHAIN_TARGET,
      signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(thresholdSessionId),
    });
    const coordinator = new SigningSessionCoordinator({
      getStatus: async ({ signingGrantId: requestedSigningGrantId }) =>
        makeBudgetStatus({
          signingGrantId: String(requestedSigningGrantId),
          status: 'active',
          projectionVersion: 'projection-server-inflight',
          remainingUses: 3,
          availableUses: 0,
          inFlightReservedUses: 3,
        }),
      consumeUse: async () => {
        throw new Error('consumeUse is not expected during admission');
      },
    });

    await expect(
      coordinator.prepareBudgetIdentity({
        lane,
        operationUsesNeeded: 1,
      }),
    ).resolves.toMatchObject({
      signingGrantId,
      status: {
        status: 'active',
        remainingUses: 3,
        availableUses: 3,
      },
    });
  });

  test('rejects the fourth signing admission after three committed server spends', async () => {
    const signingGrantId = 'wallet-session-server-exhausted';
    const thresholdSessionId = 'threshold-session-server-exhausted';
    const lane = buildTempoTransactionSigningLane({
      auth: EMAIL_OTP_AUTH,
      key: ECDSA_KEY,
      keyHandle: ECDSA_KEY_HANDLE,
      walletId: WALLET_ID,
      chainTarget: CHAIN_TARGET,
      signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(thresholdSessionId),
    });
    const coordinator = new SigningSessionCoordinator({
      getStatus: async ({ signingGrantId: requestedSigningGrantId }) =>
        makeBudgetStatus({
          signingGrantId: String(requestedSigningGrantId),
          status: 'active',
          projectionVersion: 'projection-server-exhausted-after-third-spend',
          remainingUses: 0,
          availableUses: 0,
        }),
      consumeUse: async () => {
        throw new Error('consumeUse is not expected during admission');
      },
    });

    await expect(
      coordinator.prepareBudgetIdentity({
        lane,
        operationUsesNeeded: 1,
      }),
    ).rejects.toThrow(SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR);
  });

  test('records one spend per operation id after reauth', async () => {
    const exhaustedSigningGrantId = 'wallet-session-exhausted';
    const exhaustedThresholdSessionId = 'threshold-session-exhausted';
    const refreshedSigningGrantId = 'wallet-session-refreshed';
    const refreshedThresholdSessionId = 'threshold-session-refreshed';
    const consumeCalls: string[] = [];
    const coordinator = new SigningSessionCoordinator({
      getStatus: async ({ signingGrantId }) =>
        makeBudgetStatus({
          signingGrantId: String(signingGrantId),
          status: 'active',
          projectionVersion: 'projection-refreshed',
          remainingUses: 1,
        }),
      consumeUse: async ({ signingGrantId }) => {
        consumeCalls.push(String(signingGrantId));
        return makeBudgetStatus({
          signingGrantId: String(signingGrantId),
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
        exhaustedSigningGrantId,
        exhaustedThresholdSessionId,
        refreshedSigningGrantId,
        projectionVersion: 'projection-refreshed',
      }),
      finalizedSigningLane: makeResolvedFinalizedLane({
        signingGrantId: refreshedSigningGrantId,
        thresholdSessionId: refreshedThresholdSessionId,
      }),
    } as const;

    await recordSuccessfulEvmFamilySigningGrantSpend(commonArgs);
    await recordSuccessfulEvmFamilySigningGrantSpend(commonArgs);

    expect(consumeCalls).toEqual([refreshedSigningGrantId]);
  });

  test('reserves budget against the refreshed lane before signing after reauth', async () => {
    const exhaustedSigningGrantId = 'wallet-session-exhausted';
    const exhaustedThresholdSessionId = 'threshold-session-exhausted';
    const refreshedSigningGrantId = 'wallet-session-refreshed';
    const refreshedThresholdSessionId = 'threshold-session-refreshed';
    const statusChecks: string[] = [];
    const coordinator = new SigningSessionCoordinator({
      getStatus: async ({ signingGrantId }) => {
        const sessionId = String(signingGrantId);
        statusChecks.push(sessionId);
        return sessionId === refreshedSigningGrantId
          ? makeBudgetStatus({
              signingGrantId: refreshedSigningGrantId,
              status: 'active',
              projectionVersion: 'projection-refreshed',
              remainingUses: 1,
            })
          : makeBudgetStatus({
              signingGrantId: sessionId,
              status: 'not_found',
            });
      },
      consumeUse: async () => {
        throw new Error('consumeUse is not expected during reservation');
      },
    });

    const reservation = await reserveEvmFamilySigningGrantBudget({
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
        exhaustedSigningGrantId,
        exhaustedThresholdSessionId,
        refreshedSigningGrantId,
        projectionVersion: 'projection-refreshed',
      }),
      finalizedSigningLane: makeResolvedFinalizedLane({
        signingGrantId: refreshedSigningGrantId,
        thresholdSessionId: refreshedThresholdSessionId,
      }),
    });

    expect(reservation).not.toBeNull();
    expect(statusChecks).toEqual([]);
  });

  test('fails reservation when the refreshed lane is already exhausted', async () => {
    const exhaustedSigningGrantId = 'wallet-session-exhausted';
    const exhaustedThresholdSessionId = 'threshold-session-exhausted';
    const refreshedSigningGrantId = 'wallet-session-refreshed';
    const refreshedThresholdSessionId = 'threshold-session-refreshed';
    const coordinator = new SigningSessionCoordinator({
      getStatus: async ({ signingGrantId }) =>
        makeBudgetStatus({
          signingGrantId: String(signingGrantId),
          status: 'exhausted',
          projectionVersion: 'projection-exhausted',
          remainingUses: 0,
        }),
      consumeUse: async () => {
        throw new Error('consumeUse is not expected for exhausted reservation');
      },
    });

    await expect(
      reserveEvmFamilySigningGrantBudget({
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
          exhaustedSigningGrantId,
          exhaustedThresholdSessionId,
          refreshedSigningGrantId,
          projectionVersion: 'projection-exhausted',
          remainingUses: 0,
        }),
        finalizedSigningLane: makeResolvedFinalizedLane({
          signingGrantId: refreshedSigningGrantId,
          thresholdSessionId: refreshedThresholdSessionId,
        }),
      }),
    ).rejects.toThrow(SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR);
  });

  test('uses refreshed Email OTP wallet session for consume/finalize and records consumed threshold ids', async () => {
    const exhaustedSigningGrantId = 'wallet-session-exhausted';
    const exhaustedThresholdSessionId = 'threshold-session-exhausted';
    const refreshedSigningGrantId = 'wallet-session-refreshed';
    const refreshedThresholdSessionId = 'threshold-session-refreshed';
    const operationId = SigningSessionIds.signingOperation('operation-budget-refresh');
    const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
      'fingerprint-budget-refresh',
    );
    const statusChecks: string[] = [];
    const consumeCalls: Array<{
      signingGrantId: string;
      budgetStatusCheck: unknown;
      alreadyConsumedThresholdSessionIds?: string[];
    }> = [];
    const coordinator = new SigningSessionCoordinator({
      getStatus: async ({ signingGrantId }) => {
        const sessionId = String(signingGrantId);
        statusChecks.push(sessionId);
        return sessionId === refreshedSigningGrantId
          ? makeBudgetStatus({
              signingGrantId: refreshedSigningGrantId,
              status: 'active',
              projectionVersion: 'projection-refreshed',
              remainingUses: 1,
            })
          : makeBudgetStatus({
              signingGrantId: sessionId,
              status: 'not_found',
            });
      },
      consumeUse: async (args) => {
        consumeCalls.push({
          signingGrantId: args.signingGrantId,
          budgetStatusCheck: args.budgetStatusCheck,
          alreadyConsumedThresholdSessionIds: args.alreadyConsumedThresholdSessionIds,
        });
        if (args.signingGrantId !== refreshedSigningGrantId) {
          return makeBudgetStatus({
            signingGrantId: args.signingGrantId,
            status: 'not_found',
          });
        }
        return makeBudgetStatus({
          signingGrantId: refreshedSigningGrantId,
          status: 'exhausted',
          projectionVersion: 'projection-refreshed-consumed',
          remainingUses: 0,
        });
      },
    });

    await recordSuccessfulEvmFamilySigningGrantSpend({
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
        exhaustedSigningGrantId,
        exhaustedThresholdSessionId,
        refreshedSigningGrantId,
        projectionVersion: 'projection-refreshed',
      }),
      finalizedSigningLane: makeResolvedFinalizedLane({
        signingGrantId: refreshedSigningGrantId,
        thresholdSessionId: refreshedThresholdSessionId,
      }),
    });

    expect(statusChecks).toEqual([refreshedSigningGrantId]);
    expect(consumeCalls).toHaveLength(1);
    expect(consumeCalls[0].signingGrantId).toBe(refreshedSigningGrantId);
    expect(consumeCalls[0].alreadyConsumedThresholdSessionIds).toEqual([
      refreshedThresholdSessionId,
    ]);
    expect(consumeCalls[0].budgetStatusCheck).toMatchObject({
      kind: 'ecdsa_lane_budget_status_check',
      signingGrantId: refreshedSigningGrantId,
      thresholdSessionId: refreshedThresholdSessionId,
    });
  });

  test('rejects stale exhausted finalization lane when budget identity points at refreshed session', async () => {
    const exhaustedSigningGrantId = 'wallet-session-exhausted';
    const exhaustedThresholdSessionId = 'threshold-session-exhausted';
    const refreshedSigningGrantId = 'wallet-session-refreshed';
    const coordinator = new SigningSessionCoordinator({
      getStatus: async () => {
        throw new Error('getStatus should not be called for stale finalization');
      },
      consumeUse: async () => {
        throw new Error('consumeUse should not be called for stale finalization');
      },
    });

    await expect(
      recordSuccessfulEvmFamilySigningGrantSpend({
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
          exhaustedSigningGrantId,
          exhaustedThresholdSessionId,
          refreshedSigningGrantId,
          projectionVersion: 'projection-refreshed',
        }),
        finalizedSigningLane: makeResolvedFinalizedLane({
          signingGrantId: exhaustedSigningGrantId,
          thresholdSessionId: exhaustedThresholdSessionId,
        }),
      }),
    ).rejects.toThrow('[SigningSessionBudget] prepared budget identity does not match spend lane');
  });
});

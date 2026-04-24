import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import { createTransactionSigningBudgetFinalizer } from '../../session/TransactionSigningBudgetFinalizer';
import type { WalletSigningBudgetLedger } from '../../session/WalletSigningBudgetLedger';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type SigningLaneContext,
  type SigningOperationId,
} from '../../session/signingSessionTypes';
import {
  readSelectedEcdsaRecordForLane,
  type EvmFamilyEcdsaSessionReaderDeps,
} from './ecdsaLanes';
import type { ThresholdEcdsaSessionRecord } from '../thresholdLifecycle/thresholdSessionStore';
import type {
  EvmFamilyChain,
  EvmFamilySenderSignatureAlgorithm,
} from './types';

type EvmFamilyWalletSigningSessionBudgetArgs = {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  walletSigningBudgetLedger: WalletSigningBudgetLedger;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  nearAccountId: string;
  chain: EvmFamilyChain;
  confirmationOperationId: SigningOperationId;
  ecdsaSigningLane?: SigningLaneContext;
  thresholdEcdsaRecord?: ThresholdEcdsaSessionRecord;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
};

function createEvmFamilyTransactionBudgetFinalizer(
  args: EvmFamilyWalletSigningSessionBudgetArgs,
) {
  if (args.senderSignatureAlgorithm !== 'secp256k1') return;

  const selectedSigningLane = args.ecdsaSigningLane;
  if (!selectedSigningLane) {
    throw new Error('[SigningEngine][ecdsa] missing selected signing lane for budget finalizer');
  }
  const currentRecord =
    args.thresholdEcdsaRecord ||
    readSelectedEcdsaRecordForLane({
      deps: args.deps,
      lane: selectedSigningLane,
    });

  const thresholdSessionId = String(
    selectedSigningLane.thresholdSessionId ||
      currentRecord?.thresholdSessionId ||
      args.thresholdEcdsaKeyRef?.thresholdSessionId ||
      '',
  ).trim();
  const walletSigningSessionId = String(selectedSigningLane.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId) {
    throw new Error('[SigningEngine][ecdsa] missing wallet signing session id for budget finalizer');
  }

  return {
    finalizer: createTransactionSigningBudgetFinalizer({
      walletSigningBudgetLedger: args.walletSigningBudgetLedger,
      operation: {
        operationId: args.confirmationOperationId,
        intent: SigningOperationIntent.TransactionSign,
      },
      lane: selectedSigningLane,
      ...(thresholdSessionId
        ? { thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(thresholdSessionId) }
        : {}),
      onRecordSuccessError: (error) => {
        console.warn('[SigningEngine][ecdsa] failed to update wallet signing-session budget', {
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          walletSigningSessionId,
          thresholdSessionId,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      },
      onRecordZeroSpendError: (error) => {
        console.warn('[SigningEngine][ecdsa] failed to record wallet signing-session zero spend', {
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      },
    }),
    thresholdSessionId,
    selectedSigningLane,
  };
}

export async function recordSuccessfulEvmFamilyWalletSigningSessionSpend(
  args: EvmFamilyWalletSigningSessionBudgetArgs,
): Promise<void> {
  const result = createEvmFamilyTransactionBudgetFinalizer(args);
  if (!result) return;
  await result.finalizer.recordSuccess({
    ...(result.selectedSigningLane.authMethod === 'email_otp' && result.thresholdSessionId
      ? { alreadyConsumedThresholdSessionIds: [result.thresholdSessionId] }
      : {}),
  });
}

export async function reserveEvmFamilyWalletSigningSessionBudget(
  args: EvmFamilyWalletSigningSessionBudgetArgs,
): Promise<void> {
  const result = createEvmFamilyTransactionBudgetFinalizer(args);
  if (!result) return;
  await result.finalizer.reserve();
}

export function recordFailedEvmFamilyWalletSigningSessionSpend(
  args: EvmFamilyWalletSigningSessionBudgetArgs & { error: unknown },
): void {
  const result = createEvmFamilyTransactionBudgetFinalizer(args);
  if (!result) return;
  result.finalizer.recordZeroSpend(args.error);
}

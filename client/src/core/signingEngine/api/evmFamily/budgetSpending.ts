import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import { createTransactionSigningBudgetFinalizer } from '../../session/TransactionSigningBudgetFinalizer';
import type { WalletSigningBudgetReservation } from '../../session/signingSession/budget';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import {
  SigningSessionIds,
  type SigningLaneContext,
  type SigningOperationFingerprint,
  type SigningOperationContext,
} from '../../session/signingSessionTypes';
import { readSelectedEcdsaRecordForLane, type EvmFamilyEcdsaSessionReaderDeps } from './ecdsaLanes';
import type { ThresholdEcdsaSessionRecord } from '../thresholdLifecycle/thresholdSessionStore';
import type { EvmFamilyChain, EvmFamilySenderSignatureAlgorithm } from './types';

export type EvmFamilyTransactionSigningOperationContext = SigningOperationContext & {
  operationFingerprint: SigningOperationFingerprint;
};

type EvmFamilyWalletSigningSessionBudgetArgs = {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  signingSessionCoordinator?: SigningSessionCoordinator;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  nearAccountId: string;
  chain: EvmFamilyChain;
  operation: EvmFamilyTransactionSigningOperationContext;
  ecdsaSigningLane?: SigningLaneContext;
  thresholdEcdsaRecord?: ThresholdEcdsaSessionRecord;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
};

function createEvmFamilyTransactionBudgetFinalizer(args: EvmFamilyWalletSigningSessionBudgetArgs) {
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
    args.thresholdEcdsaKeyRef?.thresholdSessionId ||
      currentRecord?.thresholdSessionId ||
      selectedSigningLane.thresholdSessionId ||
      '',
  ).trim();
  const walletSigningSessionId = String(
    args.thresholdEcdsaKeyRef?.walletSigningSessionId ||
      currentRecord?.walletSigningSessionId ||
      selectedSigningLane.walletSigningSessionId ||
      '',
  ).trim();
  if (!walletSigningSessionId) {
    throw new Error(
      '[SigningEngine][ecdsa] missing wallet signing session id for budget finalizer',
    );
  }
  const budgetLane =
    walletSigningSessionId !== String(selectedSigningLane.walletSigningSessionId || '').trim() ||
    (thresholdSessionId &&
      thresholdSessionId !== String(selectedSigningLane.thresholdSessionId || '').trim())
      ? {
          ...selectedSigningLane,
          walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
          ...(thresholdSessionId
            ? { thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(thresholdSessionId) }
            : {}),
        }
      : selectedSigningLane;
  const resolvedThresholdSessionId = String(
    budgetLane.thresholdSessionId ||
      currentRecord?.thresholdSessionId ||
      args.thresholdEcdsaKeyRef?.thresholdSessionId ||
      '',
  ).trim();

  return {
    finalizer: createTransactionSigningBudgetFinalizer({
      walletSigningBudgetLedger: args.signingSessionCoordinator,
      operation: args.operation,
      // Passkey reauth can replace the ECDSA threshold session after the
      // confirmation. Budget finalization must follow the refreshed keyRef,
      // not the exhausted lane that was selected during pre-confirm planning.
      lane: budgetLane,
      ...(resolvedThresholdSessionId
        ? {
            thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(resolvedThresholdSessionId),
          }
        : {}),
      onRecordSuccessError: (error) => {
        console.warn('[SigningEngine][ecdsa] failed to update wallet signing-session budget', {
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          walletSigningSessionId,
          thresholdSessionId: resolvedThresholdSessionId,
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
    thresholdSessionId: resolvedThresholdSessionId,
    selectedSigningLane: budgetLane,
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
): Promise<WalletSigningBudgetReservation | null> {
  const result = createEvmFamilyTransactionBudgetFinalizer(args);
  if (!result) return null;
  return await result.finalizer.reserve();
}

export function recordFailedEvmFamilyWalletSigningSessionSpend(
  args: EvmFamilyWalletSigningSessionBudgetArgs & { error: unknown },
): void {
  const result = createEvmFamilyTransactionBudgetFinalizer(args);
  if (!result) return;
  result.finalizer.recordZeroSpend(args.error);
}

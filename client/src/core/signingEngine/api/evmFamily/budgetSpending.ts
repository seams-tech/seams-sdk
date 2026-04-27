import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import { createSigningSessionBudgetFinalizer } from '../../session/signingSession/budgetFinalizer';
import type { SigningSessionBudgetReservation } from '../../session/signingSession/budget';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import {
  type SigningOperationFingerprint,
  type SigningOperationContext,
} from '../../session/signingSession/types';
import {
  logEvmFamilyEcdsaLaneDiagnostic,
  requireResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaKeyRef,
  summarizeEvmFamilyEcdsaLane,
  summarizeEvmFamilyEcdsaSessionRecord,
  type EvmFamilyEcdsaSessionReaderDeps,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
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
  ecdsaSigningLane?: ResolvedEvmFamilyEcdsaSigningLane;
  thresholdEcdsaRecord?: ThresholdEcdsaSessionRecord;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
};

function createEvmFamilyTransactionBudgetFinalizer(args: EvmFamilyWalletSigningSessionBudgetArgs) {
  if (args.senderSignatureAlgorithm !== 'secp256k1') return;

  const selectedSigningLane = args.ecdsaSigningLane;
  if (!selectedSigningLane) {
    logEvmFamilyEcdsaLaneDiagnostic('missing selected signing lane for budget finalizer', {
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      operationId: String(args.operation.operationId || ''),
      thresholdEcdsaRecord: summarizeEvmFamilyEcdsaSessionRecord(args.thresholdEcdsaRecord),
      thresholdEcdsaKeyRef: summarizeEvmFamilyEcdsaKeyRef(args.thresholdEcdsaKeyRef),
    });
    throw new Error('[SigningEngine][ecdsa] missing selected signing lane for budget finalizer');
  }
  const budgetLane = requireResolvedEvmFamilyEcdsaSigningLane({
    lane: selectedSigningLane,
    chain: args.chain,
    // Reauth/reconnect may replace the threshold session after initial lane
    // selection; budget accounting must bind to the fresh keyRef identity.
    thresholdSessionId:
      args.thresholdEcdsaKeyRef?.thresholdSessionId || args.thresholdEcdsaRecord?.thresholdSessionId,
    walletSigningSessionId:
      args.thresholdEcdsaKeyRef?.walletSigningSessionId ||
      args.thresholdEcdsaRecord?.walletSigningSessionId,
    context: 'budget finalizer',
    diagnostics: {
      nearAccountId: args.nearAccountId,
      operationId: String(args.operation.operationId || ''),
      selectedLane: summarizeEvmFamilyEcdsaLane(selectedSigningLane),
      thresholdEcdsaRecord: summarizeEvmFamilyEcdsaSessionRecord(args.thresholdEcdsaRecord),
      thresholdEcdsaKeyRef: summarizeEvmFamilyEcdsaKeyRef(args.thresholdEcdsaKeyRef),
    },
  });
  const resolvedThresholdSessionId = String(budgetLane.thresholdSessionId).trim();

  return {
    finalizer: createSigningSessionBudgetFinalizer({
      signingSessionBudget: args.signingSessionCoordinator,
      operation: args.operation,
      // Passkey reauth can replace the ECDSA threshold session after the
      // confirmation. Budget finalization must follow the refreshed keyRef,
      // not the exhausted lane that was selected during pre-confirm planning.
      lane: budgetLane,
      thresholdSessionId: budgetLane.thresholdSessionId,
      onRecordSuccessError: (error) => {
        console.warn('[SigningEngine][ecdsa] failed to update wallet signing-session budget', {
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          walletSigningSessionId: String(budgetLane.walletSigningSessionId),
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
): Promise<SigningSessionBudgetReservation | null> {
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

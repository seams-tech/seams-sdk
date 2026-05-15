import { toAccountId } from '@/core/types/accountIds';
import { SigningOperationIntent, SigningSessionIds } from '../operationState/types';
import type {
  AuthenticatedThresholdBudgetStatusCheck,
  ExternallyConsumedWalletBudgetSpend,
  ReservedBudgetFinalizationSpend,
  ThresholdBudgetStatusCheck,
  ZeroWalletBudgetSpend,
} from './budget';

const validThresholdCheck: ThresholdBudgetStatusCheck = {
  kind: 'threshold_budget_status_check',
  walletId: 'wallet.testnet',
  walletSigningSessionId: 'wallet-signing-session-1',
  targetThresholdSessionIds: ['threshold-session-1'],
};
void validThresholdCheck;

// @ts-expect-error authenticated threshold status checks require trustedStatusAuth
const missingTrustedStatusAuth: AuthenticatedThresholdBudgetStatusCheck = {
  kind: 'authenticated_threshold_budget_status_check',
  walletId: 'wallet.testnet',
  walletSigningSessionId: 'wallet-signing-session-1',
  targetThresholdSessionIds: ['threshold-session-1'],
};
void missingTrustedStatusAuth;

const emptyThresholdTargets: ThresholdBudgetStatusCheck = {
  kind: 'threshold_budget_status_check',
  walletId: 'wallet.testnet',
  walletSigningSessionId: 'wallet-signing-session-1',
  // @ts-expect-error scoped threshold status checks require a non-empty target id tuple
  targetThresholdSessionIds: [],
};
void emptyThresholdTargets;

const externallyConsumedSpend: ExternallyConsumedWalletBudgetSpend = {
  kind: 'externally_consumed_success',
  spend: {} as ExternallyConsumedWalletBudgetSpend['spend'],
  alreadyConsumedThresholdSessionIds: [
    SigningSessionIds.thresholdEd25519Session('threshold-session-1'),
  ],
};
void externallyConsumedSpend;

// @ts-expect-error externally consumed spends must include at least one consumed session id list
const invalidExternallyConsumedSpend: ExternallyConsumedWalletBudgetSpend = {
  kind: 'externally_consumed_success',
  spend: {} as ExternallyConsumedWalletBudgetSpend['spend'],
};
void invalidExternallyConsumedSpend;

const zeroSpend: ZeroWalletBudgetSpend = {
  kind: 'zero_spend',
  operationId: 'operation-1' as ZeroWalletBudgetSpend['operationId'],
  lane: {} as ZeroWalletBudgetSpend['lane'],
  reason: 'signing_failed',
};
void zeroSpend;

const invalidZeroSpend: ZeroWalletBudgetSpend = {
  kind: 'zero_spend',
  operationId: 'operation-1' as ZeroWalletBudgetSpend['operationId'],
  lane: {} as ZeroWalletBudgetSpend['lane'],
  reason: 'signing_failed',
  // @ts-expect-error zero-spend branches cannot carry full wallet spend identity
  spend: externallyConsumedSpend.spend,
};
void invalidZeroSpend;

// @ts-expect-error budget finalization spend requires selected lane identity
const walletOnlyBudgetFinalizationSpend: ReservedBudgetFinalizationSpend['spend'] = {
  operationId: SigningSessionIds.signingOperation('operation-1'),
  walletId: toAccountId('wallet.testnet'),
  walletSigningSessionId: SigningSessionIds.walletSigningSession('wallet-signing-session-1'),
  thresholdSessionIds: [SigningSessionIds.thresholdEcdsaSession('threshold-session-1')],
  backingMaterialSessionIds: [],
  uses: 1,
  reason: SigningOperationIntent.TransactionSign,
};
void walletOnlyBudgetFinalizationSpend;

export {};

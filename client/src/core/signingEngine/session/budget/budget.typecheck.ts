import { toAccountId } from '@/core/types/accountIds';
import { SigningOperationIntent, SigningSessionIds } from '../operationState/types';
import type {
  BudgetAdmittedLifecycle,
  PreparedTransactionOperation,
  TransactionBudgetAdmittedState,
  WalletSigningBudgetLifecycle,
} from '../operationState/transactionState';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { buildEvmFamilyEcdsaKeyIdentity } from '../identity/evmFamilyEcdsaIdentity';
import type {
  EcdsaLaneBudgetStatusCheck,
  AuthenticatedThresholdBudgetStatusCheck,
  ExternallyConsumedWalletBudgetSpend,
  ReservedBudgetFinalizationSpend,
  ThresholdBudgetStatusCheck,
  ZeroWalletBudgetSpend,
} from './budget';

const ecdsaChainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-moderato',
});

const ecdsaKey = buildEvmFamilyEcdsaKeyIdentity({
  walletId: 'wallet.testnet',
  subjectId: 'wallet.testnet',
  rpId: 'localhost',
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
});

const validThresholdCheck: ThresholdBudgetStatusCheck = {
  kind: 'threshold_budget_status_check',
  walletId: 'wallet.testnet',
  walletSigningSessionId: 'wallet-signing-session-1',
  targetThresholdSessionIds: ['threshold-session-1'],
};
void validThresholdCheck;

const validEcdsaLaneCheck: EcdsaLaneBudgetStatusCheck = {
  kind: 'ecdsa_lane_budget_status_check',
  key: ecdsaKey,
  chainTarget: ecdsaChainTarget,
  walletSigningSessionId: 'wallet-signing-session-1',
  thresholdSessionId: 'threshold-session-1',
};
void validEcdsaLaneCheck;

const invalidEcdsaLaneCheck: EcdsaLaneBudgetStatusCheck = {
  kind: 'ecdsa_lane_budget_status_check',
  key: ecdsaKey,
  chainTarget: ecdsaChainTarget,
  walletSigningSessionId: 'wallet-signing-session-1',
  thresholdSessionId: 'threshold-session-1',
  // @ts-expect-error ECDSA budget checks require concrete lane threshold identity
  targetThresholdSessionIds: ['threshold-session-1'],
};
void invalidEcdsaLaneCheck;

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

declare const preparedTransactionOperation: PreparedTransactionOperation;
declare const budgetAdmittedOperation: BudgetAdmittedLifecycle['operation'];
declare const budgetAdmittedState: TransactionBudgetAdmittedState;

const preparedNoBudgetLifecycle: WalletSigningBudgetLifecycle = {
  kind: 'PreparedNoBudget',
  operation: preparedTransactionOperation,
  reason: 'budget_identity_not_prepared',
};
void preparedNoBudgetLifecycle;

// @ts-expect-error prepared no-budget lifecycle cannot carry a signed result
const invalidPreparedNoBudgetLifecycle: WalletSigningBudgetLifecycle = {
  kind: 'PreparedNoBudget',
  operation: preparedTransactionOperation,
  reason: 'budget_identity_not_prepared',
  result: {},
};
void invalidPreparedNoBudgetLifecycle;

const invalidBudgetAdmittedLifecycle: WalletSigningBudgetLifecycle = {
  kind: 'BudgetAdmitted',
  operation: budgetAdmittedOperation,
  state: budgetAdmittedState,
  // @ts-expect-error budget-admitted lifecycle cannot carry a no-budget reason
  reason: 'budget_identity_not_prepared',
};
void invalidBudgetAdmittedLifecycle;

// @ts-expect-error step-up-confirmed lifecycle must carry the confirmed auth plan
const invalidStepUpConfirmedLifecycle: WalletSigningBudgetLifecycle = {
  kind: 'StepUpConfirmed',
  operation: {
    ...budgetAdmittedOperation,
    authPlan: {},
  },
};
void invalidStepUpConfirmedLifecycle;

export {};

import { toAccountId } from '@/core/types/accountIds';
import { SigningOperationIntent, SigningSessionIds } from '../operationState/types';
import type {
  BudgetAdmittedLifecycle,
  PreparedTransactionOperation,
  TransactionBudgetAdmittedState,
  WalletSigningBudgetLifecycle,
} from '../operationState/transactionState';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  AuthenticatedThresholdBudgetStatusCheck,
  ExternallyConsumedWalletBudgetSpend,
  ReservedBudgetFinalizationSpend,
  SigningSessionBudgetStatusAuth,
  ThresholdBudgetStatusCheck,
  WalletBudgetStatusCheck,
  WalletBudgetOwner,
  ZeroBudgetFinalizationSpend,
  ZeroWalletBudgetSpend,
} from './budget';
const walletId = toWalletId('wallet.testnet');
const accountId = toAccountId('wallet.testnet');
const ed25519Owner = {
  curve: 'ed25519',
  walletId,
} satisfies WalletBudgetOwner;

const invalidRawEd25519Owner: WalletBudgetOwner = {
  curve: 'ed25519',
  // @ts-expect-error shared Ed25519 budget owner requires normalized WalletId branding.
  walletId: 'wallet.testnet',
};
void invalidRawEd25519Owner;

const validThresholdCheck: ThresholdBudgetStatusCheck = {
  kind: 'threshold_budget_status_check',
  owner: ed25519Owner,
  signingGrantId: 'signing-grant-1',
  targetThresholdSessionIds: ['threshold-session-1'],
};
void validThresholdCheck;

const invalidWalletBudgetOwnerWithBothBranches: WalletBudgetStatusCheck = {
  kind: 'wallet_budget_status_check',
  owner: {
    curve: 'ed25519',
    walletId,
    // @ts-expect-error shared budget owners cannot carry NEAR account identity.
    accountId,
  },
  signingGrantId: 'signing-grant-1',
};
void invalidWalletBudgetOwnerWithBothBranches;

// @ts-expect-error shared wallet budget checks require owner identity.
const invalidWalletBudgetCheckWithoutOwner: WalletBudgetStatusCheck = {
  kind: 'wallet_budget_status_check',
  signingGrantId: 'signing-grant-1',
};
void invalidWalletBudgetCheckWithoutOwner;

// @ts-expect-error authenticated threshold status checks require trustedStatusAuth
const missingTrustedStatusAuth: AuthenticatedThresholdBudgetStatusCheck = {
  kind: 'authenticated_threshold_budget_status_check',
  owner: ed25519Owner,
  signingGrantId: 'signing-grant-1',
  targetThresholdSessionIds: ['threshold-session-1'],
};
void missingTrustedStatusAuth;

const emptyThresholdTargets: ThresholdBudgetStatusCheck = {
  kind: 'threshold_budget_status_check',
  owner: ed25519Owner,
  signingGrantId: 'signing-grant-1',
  // @ts-expect-error scoped threshold status checks require a non-empty target id tuple
  targetThresholdSessionIds: [],
};
void emptyThresholdTargets;

const validWalletSessionBudgetStatusAuth: SigningSessionBudgetStatusAuth = {
  relayerUrl: 'https://router.example',
  thresholdSessionId: 'threshold-session-1',
  walletSessionJwt: 'wallet-session-jwt',
};
void validWalletSessionBudgetStatusAuth;

const invalidThresholdSessionBudgetStatusAuth: SigningSessionBudgetStatusAuth = {
  relayerUrl: 'https://router.example',
  thresholdSessionId: 'threshold-session-1',
  walletSessionJwt: 'wallet-session-jwt',
  // @ts-expect-error active budget auth uses Wallet Session JWT naming.
  thresholdSessionAuthToken: 'threshold-session-jwt',
};
void invalidThresholdSessionBudgetStatusAuth;

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
  operationFingerprint: 'fingerprint-1' as ZeroWalletBudgetSpend['operationFingerprint'],
  lane: {} as ZeroWalletBudgetSpend['lane'],
  reason: 'signing_failed',
  finalizationCommand: {} as ZeroWalletBudgetSpend['finalizationCommand'],
};
void zeroSpend;

const invalidZeroSpend: ZeroWalletBudgetSpend = {
  kind: 'zero_spend',
  operationId: 'operation-1' as ZeroWalletBudgetSpend['operationId'],
  operationFingerprint: 'fingerprint-1' as ZeroWalletBudgetSpend['operationFingerprint'],
  lane: {} as ZeroWalletBudgetSpend['lane'],
  reason: 'signing_failed',
  finalizationCommand: {} as ZeroWalletBudgetSpend['finalizationCommand'],
  // @ts-expect-error zero-spend branches cannot carry full wallet spend identity
  spend: externallyConsumedSpend.spend,
};
void invalidZeroSpend;

const zeroSpendFinalization: ZeroBudgetFinalizationSpend = {
  kind: 'zero_spend',
  operationId: 'operation-1' as ZeroBudgetFinalizationSpend['operationId'],
  operationFingerprint: 'fingerprint-1' as ZeroBudgetFinalizationSpend['operationFingerprint'],
  lane: {} as ZeroBudgetFinalizationSpend['lane'],
  reason: 'signing_failed',
};
void zeroSpendFinalization;

// @ts-expect-error wallet-budget zero spend requires a typed finalization command.
const invalidZeroWalletSpendWithoutCommand: ZeroWalletBudgetSpend = {
  kind: 'zero_spend',
  operationId: 'operation-1' as ZeroWalletBudgetSpend['operationId'],
  operationFingerprint: 'fingerprint-1' as ZeroWalletBudgetSpend['operationFingerprint'],
  lane: {} as ZeroWalletBudgetSpend['lane'],
  reason: 'signing_failed',
};
void invalidZeroWalletSpendWithoutCommand;

// @ts-expect-error budget finalization spend requires selected lane identity
const walletOnlyBudgetFinalizationSpend: ReservedBudgetFinalizationSpend['spend'] = {
  operationId: SigningSessionIds.signingOperation('operation-1'),
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

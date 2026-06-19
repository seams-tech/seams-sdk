import { toAccountId } from '@/core/types/accountIds';
import { SigningOperationIntent, SigningSessionIds } from '../operationState/types';
import { createWalletBudgetProjection } from './budgetProjection';
import type {
  BudgetAdmittedLifecycle,
  PreparedTransactionOperation,
  TransactionBudgetAdmittedState,
  WalletSigningBudgetLifecycle,
} from '../operationState/transactionState';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
} from '../identity/evmFamilyEcdsaIdentity';
import type {
  EcdsaLaneBudgetStatusCheck,
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

const ecdsaChainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-moderato',
});

const ecdsaKey = buildBaseEvmFamilyEcdsaKeyIdentity({
  walletId: 'wallet.testnet',
  rpId: 'localhost',
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
});
const ecdsaKeyHandle = toEvmFamilyEcdsaKeyHandle('ecdsa-budget-key-handle');
const accountId = toAccountId('wallet.testnet');
const ed25519Owner = {
  curve: 'ed25519',
  accountId,
} satisfies WalletBudgetOwner;

const invalidRawEd25519Owner: WalletBudgetOwner = {
  curve: 'ed25519',
  // @ts-expect-error shared budget NEAR owner requires normalized AccountId branding.
  accountId: 'wallet.testnet',
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
  // @ts-expect-error shared budget owners cannot carry wrong-branch walletId.
  owner: {
    curve: 'ed25519',
    accountId,
    walletId: ecdsaKey.walletId,
  },
  signingGrantId: 'signing-grant-1',
};
void invalidWalletBudgetOwnerWithBothBranches;

const invalidEcdsaOwnerWithAccountId: WalletBudgetStatusCheck = {
  kind: 'wallet_budget_status_check',
  // @ts-expect-error ECDSA budget owners cannot carry accountId.
  owner: {
    curve: 'ecdsa',
    walletId: ecdsaKey.walletId,
    accountId,
  },
  signingGrantId: 'signing-grant-1',
};
void invalidEcdsaOwnerWithAccountId;

// @ts-expect-error shared wallet budget checks require owner identity.
const invalidWalletBudgetCheckWithoutOwner: WalletBudgetStatusCheck = {
  kind: 'wallet_budget_status_check',
  signingGrantId: 'signing-grant-1',
};
void invalidWalletBudgetCheckWithoutOwner;

const validEcdsaLaneCheck: EcdsaLaneBudgetStatusCheck = {
  kind: 'ecdsa_lane_budget_status_check',
  key: ecdsaKey,
  keyHandle: ecdsaKeyHandle,
  chainTarget: ecdsaChainTarget,
  signingGrantId: 'signing-grant-1',
  thresholdSessionId: 'threshold-session-1',
};
void validEcdsaLaneCheck;

const invalidEcdsaLaneCheck: EcdsaLaneBudgetStatusCheck = {
  kind: 'ecdsa_lane_budget_status_check',
  key: ecdsaKey,
  keyHandle: ecdsaKeyHandle,
  chainTarget: ecdsaChainTarget,
  signingGrantId: 'signing-grant-1',
  thresholdSessionId: 'threshold-session-1',
  // @ts-expect-error ECDSA budget checks require concrete lane threshold identity
  targetThresholdSessionIds: ['threshold-session-1'],
};
void invalidEcdsaLaneCheck;

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

const walletBudgetProjection = createWalletBudgetProjection({
  walletId: accountId,
  signingGrantId: 'signing-grant-1',
});
void walletBudgetProjection;

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
  walletId: toAccountId('wallet.testnet'),
  signingGrantId: SigningSessionIds.signingGrant('signing-grant-1'),
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

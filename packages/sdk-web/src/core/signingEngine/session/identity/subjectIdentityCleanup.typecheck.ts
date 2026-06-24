import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
} from './evmFamilyEcdsaIdentity';
import {
  exactEcdsaSigningLaneIdentity,
  type ExactEcdsaSigningLaneIdentity,
} from './exactSigningLaneIdentity';
import {
  buildFreshStepUpRequired,
  type FreshStepUpRequired,
} from '../operationState/stepUpFreshness';
import {
  buildSigningBudgetReservationIdentity,
  type SigningBudgetReservationIdentity,
} from '../budget/budget';
import {
  emailOtpRefreshIdentity,
  type EmailOtpRefreshIdentity,
} from '../emailOtp/appSessionJwtCache';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type WalletSigningSpendPlan,
} from '../operationState/types';

const walletId = toWalletId('wallet.testnet');
const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 4242,
});
const key = buildBaseEvmFamilyEcdsaKeyIdentity({
  walletId,
  walletKeyId: 'wallet-key-localhost',
  ecdsaThresholdKeyId: 'ehss-subject-cleanup',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
});

const validPublicKeyIdentity = buildEvmFamilyEcdsaKeyIdentity({
  walletId,
  walletKeyId: 'wallet-key-localhost',
  ecdsaThresholdKeyId: 'ehss-subject-cleanup',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
});
void validPublicKeyIdentity;

const invalidPublicKeyIdentity = buildEvmFamilyEcdsaKeyIdentity({
  walletId,
  // @ts-expect-error ECDSA public key identity builder derives subject identity from walletId.
  subjectId: 'wallet.testnet',
  walletKeyId: 'wallet-key-localhost',
  ecdsaThresholdKeyId: 'ehss-subject-cleanup',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
});
void invalidPublicKeyIdentity;

const laneIdentity = exactEcdsaSigningLaneIdentity({
  walletId,
  auth: {
    kind: 'email_otp',
    providerSubjectId: 'google:subject-1',
  },
  chainTarget,
  key,
  keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle'),
  signingGrantId: SigningSessionIds.signingGrant('wallet-session'),
  thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('threshold-session'),
});

const invalidExactIdentity: ExactEcdsaSigningLaneIdentity = {
  ...laneIdentity,
  // @ts-expect-error exact ECDSA lane identity rejects subjectId.
  subjectId: 'wallet.testnet',
};
void invalidExactIdentity;

const operationId = SigningSessionIds.signingOperation('operation-1');
const operationFingerprint = SigningSessionIds.signingOperationFingerprint('fingerprint-1');
const freshness = buildFreshStepUpRequired({
  walletId,
  operationId,
  operationFingerprint,
  laneIdentity,
  projection: { kind: 'unavailable', reason: 'budget_status_unavailable' },
  expiry: { kind: 'unavailable', reason: 'budget_status_unavailable' },
  provenance: {
    kind: 'trusted_server_budget_status',
    projectionVersion: 'projection-1',
    observedAtMs: 1,
  },
  reason: 'wallet_budget_exhausted',
});
void freshness;

const invalidFreshness: FreshStepUpRequired = {
  ...freshness,
  // @ts-expect-error freshness state rejects subjectId.
  subjectId: 'wallet.testnet',
};
void invalidFreshness;

const ecdsaSpendPlan: WalletSigningSpendPlan = {
  operationId,
  operationFingerprint,
  lane: {
    auth: laneIdentity.auth,
    curve: 'ecdsa',
    keyKind: 'threshold_ecdsa_secp256k1',
    chainFamily: 'tempo',
    walletId,
    key,
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle'),
    chainTarget,
    signingGrantId: laneIdentity.signingGrantId,
	    thresholdSessionId: laneIdentity.thresholdSessionId,
	    runtimeState: 'no_runtime_material',
	    sessionOrigin: 'per_operation',
    storageSource: 'email_otp',
    retention: 'single_use',
  },
  backingMaterialSessionIds: [],
  uses: 1,
  reason: SigningOperationIntent.TransactionSign,
};
void ecdsaSpendPlan;

const invalidEcdsaSpendPlanWithKey = {
  ...ecdsaSpendPlan,
  // @ts-expect-error ECDSA spend derives key identity from the selected lane.
  ecdsaKey: key,
} satisfies WalletSigningSpendPlan;
void invalidEcdsaSpendPlanWithKey;

const reservationIdentity = buildSigningBudgetReservationIdentity({
  spend: ecdsaSpendPlan,
  projectionVersion: 'projection-1',
});
void reservationIdentity;

const invalidReservationIdentity: SigningBudgetReservationIdentity = {
  ...reservationIdentity,
  // @ts-expect-error budget reservation identity rejects subjectId.
  subjectId: 'wallet.testnet',
};
void invalidReservationIdentity;

const refreshIdentity = emailOtpRefreshIdentity({
  walletId,
  walletSessionUserId: 'wallet.testnet',
  operationId,
  operationFingerprint,
  laneIdentity,
});
void refreshIdentity;

const invalidRefreshIdentity: EmailOtpRefreshIdentity = {
  ...refreshIdentity,
  // @ts-expect-error Email OTP refresh identity rejects subjectId.
  subjectId: 'wallet.testnet',
};
void invalidRefreshIdentity;

declare const persistedEcdsaRecord: ThresholdEcdsaSessionRecord;
const invalidPersistedEcdsaRecord: ThresholdEcdsaSessionRecord = {
  ...persistedEcdsaRecord,
  // @ts-expect-error persisted ECDSA session records reject subjectId.
  subjectId: 'wallet.testnet',
};
void invalidPersistedEcdsaRecord;

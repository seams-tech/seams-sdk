import { toAccountId } from '@/core/types/accountIds';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
} from '../identity/evmFamilyEcdsaIdentity';
import { exactEcdsaSigningLaneIdentity } from '../identity/exactSigningLaneIdentity';
import { SigningSessionIds } from './types';
import {
  buildFreshStepUpRequired,
  buildFreshStepUpSatisfied,
  buildFreshStepUpSatisfiedForAdmission,
  type FreshStepUpSatisfiedForAdmission,
  type FreshStepUpRequired,
} from './stepUpFreshness';

const walletId = toAccountId('wallet.testnet');
const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 4242,
});
const key = buildBaseEvmFamilyEcdsaKeyIdentity({
  walletId,
  rpId: 'localhost',
  ecdsaThresholdKeyId: 'ehss-step-up',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
});
const laneIdentity = exactEcdsaSigningLaneIdentity({
  kind: 'selected_lane',
  curve: 'ecdsa',
  chain: 'tempo',
  chainFamily: 'tempo',
  keyKind: 'threshold_ecdsa_secp256k1',
  sessionOrigin: 'per_operation',
  storageSource: 'email_otp',
  retention: 'single_use',
  walletId,
  authMethod: 'email_otp',
  chainTarget,
  key,
  keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle'),
  signingGrantId: SigningSessionIds.signingGrant('wallet-session'),
  thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('threshold-session'),
});

const satisfied = buildFreshStepUpSatisfied({
  walletId,
  operationId: SigningSessionIds.signingOperation('operation-1'),
  operationFingerprint: SigningSessionIds.signingOperationFingerprint('fingerprint-1'),
  laneIdentity,
  projection: { kind: 'known', version: 'projection-1' },
  expiry: { kind: 'known', expiresAtMs: 1_900_000_000_000 },
  remainingUses: 1,
  provenance: {
    kind: 'trusted_server_budget_status',
    projectionVersion: 'projection-1',
    observedAtMs: 1,
  },
});
const admission = buildFreshStepUpSatisfiedForAdmission(satisfied);
void admission;

// @ts-expect-error admission freshness requires the admission-specific branch.
const invalidAdmission: FreshStepUpSatisfiedForAdmission = satisfied;
void invalidAdmission;

const required = buildFreshStepUpRequired({
  walletId,
  operationId: SigningSessionIds.signingOperation('operation-1'),
  operationFingerprint: SigningSessionIds.signingOperationFingerprint('fingerprint-1'),
  laneIdentity,
  projection: { kind: 'known', version: 'projection-1' },
  expiry: { kind: 'known', expiresAtMs: 1_900_000_000_000 },
  provenance: {
    kind: 'trusted_server_budget_status',
    projectionVersion: 'projection-1',
    observedAtMs: 1,
  },
  reason: 'wallet_budget_exhausted',
});
void required;

const missingWalletId: FreshStepUpRequired = {
  ...required,
  // @ts-expect-error freshness state requires walletId.
  walletId: undefined,
};
void missingWalletId;

const missingOperationId: FreshStepUpRequired = {
  ...required,
  // @ts-expect-error freshness state requires operationId.
  operationId: undefined,
};
void missingOperationId;

// @ts-expect-error required freshness requires operationFingerprint.
const missingOperationFingerprint: FreshStepUpRequired = {
  kind: 'fresh_step_up_required',
  walletId,
  operationId: SigningSessionIds.signingOperation('operation-1'),
  authMethod: 'email_otp',
  curve: 'ecdsa',
  laneIdentity,
  laneIdentityKey: satisfied.laneIdentityKey,
  signingGrantId: satisfied.signingGrantId,
  thresholdSessionIds: satisfied.thresholdSessionIds,
  projection: { kind: 'unavailable', reason: 'email_otp_refresh_rejected' },
  expiry: { kind: 'unavailable', reason: 'email_otp_refresh_rejected' },
  provenance: { kind: 'email_otp_refresh_boundary', httpStatus: 401, observedAtMs: 1 },
  reason: 'email_otp_refresh_rejected',
};
void missingOperationFingerprint;

const missingLaneIdentity: FreshStepUpRequired = {
  ...required,
  // @ts-expect-error freshness state requires exact lane identity.
  laneIdentity: undefined,
};
void missingLaneIdentity;

const missingLaneIdentityKey: FreshStepUpRequired = {
  ...required,
  // @ts-expect-error freshness state requires lane identity key.
  laneIdentityKey: undefined,
};
void missingLaneIdentityKey;

const missingProjection: FreshStepUpRequired = {
  ...required,
  // @ts-expect-error freshness state requires projection state.
  projection: undefined,
};
void missingProjection;

const missingExpiry: FreshStepUpRequired = {
  ...required,
  // @ts-expect-error freshness state requires expiry state.
  expiry: undefined,
};
void missingExpiry;

const missingProvenance: FreshStepUpRequired = {
  ...required,
  // @ts-expect-error freshness state requires provenance.
  provenance: undefined,
};
void missingProvenance;

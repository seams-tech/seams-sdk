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
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
  type ExactEcdsaSigningLaneIdentity,
} from './exactSigningLaneIdentity';
import {
  buildFreshStepUpRequired,
  type FreshStepUpRequired,
} from '../operationState/stepUpFreshness';
import {
  SigningOperationIntent,
  SigningSessionIds,
} from '../operationState/types';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';

const walletId = toWalletId('wallet.testnet');
const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 4242,
});
const key = buildBaseEvmFamilyEcdsaKeyIdentity({
  walletId,
  ecdsaThresholdKeyId: 'ederivation-subject-cleanup',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
});

const validPublicKeyIdentity = buildEvmFamilyEcdsaKeyIdentity({
  walletId,
  ecdsaThresholdKeyId: 'ederivation-subject-cleanup',
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
  ecdsaThresholdKeyId: 'ederivation-subject-cleanup',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
});
void invalidPublicKeyIdentity;
declare const materialActivation: MpcMaterialActivationRef;

const laneIdentity = exactEcdsaSigningLaneIdentity({
  signer: buildEvmFamilyEcdsaSignerBinding({
    walletId,
    chainTarget,
    key,
    materialActivation,
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle'),
  }),
  auth: {
    kind: 'email_otp',
    providerSubjectId: 'google:subject-1',
  },
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

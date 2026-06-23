import type { AccountId } from '@/core/types/accountIds';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { SigningSessionIds } from '../operationState/types';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyIdentity,
} from './evmFamilyEcdsaIdentity';
import {
  exactEcdsaSigningLaneIdentity,
  exactEd25519SigningLaneIdentity,
  exactSigningLaneIdentityKey,
  thresholdSessionIdsFromExactSigningLaneIdentity,
  type ExactEcdsaSigningLaneIdentity,
  type ExactEd25519SigningLaneIdentity,
  type ExactSigningLaneIdentity,
  type NonEmptyThresholdSessionIds,
} from './exactSigningLaneIdentity';

const accountId = 'alice.testnet' as AccountId;
const walletId = toWalletId(accountId);
const signingGrantId = SigningSessionIds.signingGrant('wallet-session-1');
const ed25519ThresholdSessionId = SigningSessionIds.thresholdEd25519Session(
  'ed25519-threshold-session-1',
);
const ecdsaThresholdSessionId = SigningSessionIds.thresholdEcdsaSession(
  'ecdsa-threshold-session-1',
);
const evmTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
} as const satisfies ThresholdEcdsaChainTarget;
const ecdsaKey = buildBaseEvmFamilyEcdsaKeyIdentity({
  walletId,
  rpId: 'localhost',
  ecdsaThresholdKeyId: 'ehss-exact-key',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
});

const ed25519Identity = exactEd25519SigningLaneIdentity({
  kind: 'selected_lane',
  curve: 'ed25519',
  chain: 'near',
  accountId,
  authMethod: 'passkey',
  signingGrantId,
  thresholdSessionId: ed25519ThresholdSessionId,
});
exactSigningLaneIdentityKey(ed25519Identity);

const ecdsaIdentity = exactEcdsaSigningLaneIdentity({
  kind: 'selected_lane',
  curve: 'ecdsa',
  chain: 'evm',
  chainFamily: 'evm',
  keyKind: 'threshold_ecdsa_secp256k1',
  sessionOrigin: 'per_operation',
  storageSource: 'email_otp',
  retention: 'single_use',
  walletId,
  authMethod: 'email_otp',
  chainTarget: evmTarget,
  key: ecdsaKey,
  keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle'),
  signingGrantId,
  thresholdSessionId: ecdsaThresholdSessionId,
});
const thresholdSessionIds: NonEmptyThresholdSessionIds =
  thresholdSessionIdsFromExactSigningLaneIdentity(ecdsaIdentity);
void thresholdSessionIds;

const invalidEd25519WithEcdsaKey: ExactEd25519SigningLaneIdentity = {
  ...ed25519Identity,
  // @ts-expect-error exact Ed25519 identity cannot carry ECDSA key identity.
  key: ecdsaKey,
};
void invalidEd25519WithEcdsaKey;

const invalidEcdsaWithAccountId: ExactEcdsaSigningLaneIdentity = {
  ...ecdsaIdentity,
  // @ts-expect-error exact ECDSA identity uses walletId, not accountId.
  accountId,
};
void invalidEcdsaWithAccountId;

const invalidEcdsaWithSubjectId: ExactEcdsaSigningLaneIdentity = {
  ...ecdsaIdentity,
  // @ts-expect-error exact ECDSA identity rejects raw subjectId.
  subjectId: 'wallet:alice.testnet',
};
void invalidEcdsaWithSubjectId;

// @ts-expect-error exact ECDSA identity cannot carry Ed25519 accountId.
const invalidMixedBranch: ExactSigningLaneIdentity = {
  kind: 'exact_ecdsa_signing_lane_identity',
  curve: 'ecdsa',
  chainFamily: 'evm',
  walletId,
  authMethod: 'passkey',
  chainTarget: evmTarget,
  keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle'),
  key: ecdsaKey,
  signingGrantId,
  thresholdSessionId: ecdsaThresholdSessionId,
  accountId,
};
void invalidMixedBranch;

// @ts-expect-error exact ECDSA identity requires exact key identity.
const invalidEcdsaWithoutKey: ExactEcdsaSigningLaneIdentity = {
  kind: 'exact_ecdsa_signing_lane_identity',
  curve: 'ecdsa',
  chainFamily: 'evm',
  walletId,
  authMethod: 'passkey',
  chainTarget: evmTarget,
  keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle'),
  signingGrantId,
  thresholdSessionId: ecdsaThresholdSessionId,
};
void invalidEcdsaWithoutKey;

// @ts-expect-error exact ECDSA identity requires the selected key handle.
const invalidEcdsaWithoutKeyHandle: ExactEcdsaSigningLaneIdentity = {
  kind: 'exact_ecdsa_signing_lane_identity',
  curve: 'ecdsa',
  chainFamily: 'evm',
  walletId,
  authMethod: 'passkey',
  chainTarget: evmTarget,
  key: ecdsaKey,
  signingGrantId,
  thresholdSessionId: ecdsaThresholdSessionId,
};
void invalidEcdsaWithoutKeyHandle;

const keyWithSession: EvmFamilyEcdsaKeyIdentity = {
  ...ecdsaKey,
  // @ts-expect-error shared key identity cannot include thresholdSessionId.
  thresholdSessionId: ecdsaThresholdSessionId,
};
void keyWithSession;

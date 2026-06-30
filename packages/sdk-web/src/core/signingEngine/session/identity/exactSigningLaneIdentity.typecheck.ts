import { parseNamedNearAccountId } from '@shared/utils/near';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import {
  buildNamedNearAccountBinding,
  buildNearEd25519SignerBinding,
  buildWalletIdentity,
} from '@shared/utils/walletCapabilityBindings';
import { SigningSessionIds } from '../operationState/types';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
  type EvmFamilyEcdsaKeyIdentity,
} from './evmFamilyEcdsaIdentity';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
  exactEd25519SigningLaneIdentity,
  exactSigningLaneIdentityKey,
  isExactEcdsaSigningLaneIdentity,
  isExactEd25519SigningLaneIdentity,
  thresholdSessionIdsFromExactSigningLaneIdentity,
  type ExactEcdsaSigningLaneIdentity,
  type ExactEd25519SigningLaneIdentity,
  type ExactSigningLaneIdentity,
  type NonEmptyThresholdSessionIds,
} from './exactSigningLaneIdentity';

const accountIdResult = parseNamedNearAccountId('alice.testnet');
if (!accountIdResult.ok) {
  throw new Error(accountIdResult.message);
}
const accountId = accountIdResult.value;
const walletId = toWalletId('frost-vermillion-k7p9m2');
const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString('scope-frost-vermillion-k7p9m2');
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
  evmFamilySigningKeySlotId: 'wallet-key-localhost',
  ecdsaThresholdKeyId: 'ehss-exact-key',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
});
const passkeyAuth = {
  kind: 'passkey',
  rpId: toRpId('localhost'),
  credentialIdB64u: 'credential-id',
} as const;
const emailOtpAuth = {
  kind: 'email_otp',
  providerSubjectId: 'google:alice',
} as const;
const wallet = buildWalletIdentity({ walletId });
const nearAccount = buildNamedNearAccountBinding({
  wallet,
  nearAccountId: accountId,
});
const nearSigner = buildNearEd25519SignerBinding({
  account: nearAccount,
  nearEd25519SigningKeyId,
  signerSlot: 1,
});

const ed25519Identity = exactEd25519SigningLaneIdentity({
  signer: nearSigner,
  auth: passkeyAuth,
  signingGrantId,
  thresholdSessionId: ed25519ThresholdSessionId,
});
exactSigningLaneIdentityKey(ed25519Identity);

const ecdsaIdentity = exactEcdsaSigningLaneIdentity({
  signer: buildEvmFamilyEcdsaSignerBinding({
    walletId,
    chainTarget: evmTarget,
    key: ecdsaKey,
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle'),
  }),
  auth: emailOtpAuth,
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

const invalidMixedBranch: ExactSigningLaneIdentity = {
  kind: 'exact_signing_lane',
  signer: ecdsaIdentity.signer,
  auth: passkeyAuth,
  signingGrantId,
  thresholdSessionId: ecdsaThresholdSessionId,
  // @ts-expect-error exact ECDSA identity cannot carry Ed25519 accountId.
  accountId,
};
void invalidMixedBranch;

const invalidEcdsaWithoutKey: ExactEcdsaSigningLaneIdentity = {
  kind: 'exact_signing_lane',
  // @ts-expect-error exact ECDSA signer requires exact key identity.
  signer: {
    kind: 'evm_family_ecdsa_signer',
    walletId,
    chainTarget: evmTarget,
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle'),
  },
  auth: passkeyAuth,
  signingGrantId,
  thresholdSessionId: ecdsaThresholdSessionId,
};
void invalidEcdsaWithoutKey;

const invalidEcdsaWithoutKeyHandle: ExactEcdsaSigningLaneIdentity = {
  kind: 'exact_signing_lane',
  // @ts-expect-error exact ECDSA signer requires the selected key handle.
  signer: {
    kind: 'evm_family_ecdsa_signer',
    walletId,
    chainTarget: evmTarget,
    key: ecdsaKey,
  },
  auth: passkeyAuth,
  signingGrantId,
  thresholdSessionId: ecdsaThresholdSessionId,
};
void invalidEcdsaWithoutKeyHandle;

const invalidEd25519RootNearAccountId: ExactEd25519SigningLaneIdentity = {
  ...ed25519Identity,
  // @ts-expect-error exact Ed25519 lane keeps NEAR account under signer.account.
  nearAccountId: accountId,
};
void invalidEd25519RootNearAccountId;

const invalidEd25519RootSigningKeyId: ExactEd25519SigningLaneIdentity = {
  ...ed25519Identity,
  // @ts-expect-error exact Ed25519 lane keeps signing-key id under signer.
  nearEd25519SigningKeyId,
};
void invalidEd25519RootSigningKeyId;

const invalidEcdsaRootChainTarget: ExactEcdsaSigningLaneIdentity = {
  ...ecdsaIdentity,
  // @ts-expect-error exact ECDSA lane keeps chain target under signer.
  chainTarget: evmTarget,
};
void invalidEcdsaRootChainTarget;

const invalidEcdsaRootKeyHandle: ExactEcdsaSigningLaneIdentity = {
  ...ecdsaIdentity,
  // @ts-expect-error exact ECDSA lane keeps key handle under signer.
  keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle'),
};
void invalidEcdsaRootKeyHandle;

const invalidEcdsaRootKey: ExactEcdsaSigningLaneIdentity = {
  ...ecdsaIdentity,
  // @ts-expect-error exact ECDSA lane keeps key identity under signer.
  key: ecdsaKey,
};
void invalidEcdsaRootKey;

function requireEd25519ThresholdSessionId(identity: ExactSigningLaneIdentity) {
  if (!isExactEd25519SigningLaneIdentity(identity)) return null;
  return identity.thresholdSessionId;
}
void requireEd25519ThresholdSessionId(ed25519Identity);

function requireEcdsaThresholdSessionId(identity: ExactSigningLaneIdentity) {
  if (!isExactEcdsaSigningLaneIdentity(identity)) return null;
  return identity.thresholdSessionId;
}
void requireEcdsaThresholdSessionId(ecdsaIdentity);

const keyWithSession: EvmFamilyEcdsaKeyIdentity = {
  ...ecdsaKey,
  // @ts-expect-error shared key identity cannot include thresholdSessionId.
  thresholdSessionId: ecdsaThresholdSessionId,
};
void keyWithSession;

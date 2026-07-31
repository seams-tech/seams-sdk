import type {
  SealedSigningSessionEcdsaRestoreMetadata,
  SealedSigningSessionEcdsaRoleLocalMaterialRef,
  SealedSigningSessionEd25519RestoreMetadata,
  SealedSigningSessionRecord,
} from './signingSessionSeal';
import type {
  RouterAbEcdsaDerivationNormalSigningStateV1,
  RouterAbEcdsaDerivationPublicCapabilityV1,
} from './routerAbEcdsaDerivation';
import type { EmailOtpWalletAuthAuthority, WalletAuthAuthorityRef } from './walletAuthAuthority';

declare const routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
declare const publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
declare const roleLocalMaterialRef: SealedSigningSessionEcdsaRoleLocalMaterialRef;
declare const authority: WalletAuthAuthorityRef;
declare const emailOtpAuthority: EmailOtpWalletAuthAuthority;

const validEcdsaSealedSessionRecord = {
  v: 2,
  alg: 'shamir3pass-v2',
  groupId: 'rfc2409-group2',
  keyVersion: 'seal-v2',
  storageScope: 'iframe_origin_indexeddb',
  authMethod: 'email_otp',
  secretKind: 'signing_session_secret32',
  storeKey: 'wallet-session-1:email_otp:ecdsa',
  signingGrantId: 'wallet-session-1',
  thresholdSessionIds: {
    ecdsa: 'ec-session',
  },
  sealedSecretB64u: 'sealed-k',
  curve: 'ecdsa',
  walletId: 'alice.testnet',
  relayerUrl: 'https://relay.example',
  ecdsaRestore: {
    chainTarget: {
      kind: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    },
    source: 'email_otp',
    signingRootId: 'root',
    signingRootVersion: 'v1',
    provider: 'google',
    providerSubjectId: 'google:alice',
    emailHashHex: 'email-hash',
    authority,
    emailOtpAuthority,
    keyHandle: 'key-handle',
    ecdsaThresholdKeyId: 'ecdsa-key',
    ethereumAddress: `0x${'11'.repeat(20)}`,
    relayerKeyId: 'relayer-key',
    roleLocalMaterialRef,
    participantIds: [1, 2],
    routerAbEcdsaDerivationNormalSigning,
    publicCapability,
  },
  issuedAtMs: 1,
  expiresAtMs: 2,
  remainingUses: 3,
  updatedAtMs: 4,
} satisfies SealedSigningSessionRecord;
void validEcdsaSealedSessionRecord;

const validEd25519SealedSessionRecord = {
  v: 2,
  alg: 'shamir3pass-v2',
  groupId: 'rfc2409-group2',
  keyVersion: 'seal-v2',
  storageScope: 'iframe_origin_indexeddb',
  authMethod: 'passkey',
  secretKind: 'signing_session_secret32',
  storeKey: 'wallet-session-1:passkey:ed25519',
  signingGrantId: 'wallet-session-1',
  thresholdSessionIds: {
    ed25519: 'ed-session',
  },
  sealedSecretB64u: 'sealed-k',
  curve: 'ed25519',
  walletId: 'alice.testnet',
  signingRootId: 'near-root',
  signingRootVersion: 'near-root-v1',
  relayerUrl: 'https://relay.example',
  ed25519Restore: {
    nearAccountId: 'alice.testnet',
    nearEd25519SigningKeyId: 'alice.testnet',
    rpId: 'wallet.example.localhost',
    credentialIdB64u: 'credential-id',
    relayerKeyId: 'relayer-key',
    participantIds: [1, 2],
    signerSlot: 1,
  },
  issuedAtMs: 1,
  expiresAtMs: 2,
  remainingUses: 3,
  updatedAtMs: 4,
} satisfies SealedSigningSessionRecord;
void validEd25519SealedSessionRecord;

const { groupId: _groupId, ...recordMissingGroupId } = validEd25519SealedSessionRecord;
// @ts-expect-error v2 sealed records require the crate-owned group identifier.
const invalidRecordMissingGroupId: SealedSigningSessionRecord = recordMissingGroupId;
void invalidRecordMissingGroupId;

const { keyVersion: _keyVersion, ...recordMissingKeyVersion } = validEd25519SealedSessionRecord;
// @ts-expect-error v2 sealed records require the exact server key version used to seal them.
const invalidRecordMissingKeyVersion: SealedSigningSessionRecord = recordMissingKeyVersion;
void invalidRecordMissingKeyVersion;

const invalidRecordWithRawPrime = {
  ...validEd25519SealedSessionRecord,
  // @ts-expect-error v2 records identify a built-in group and never persist a raw prime.
  shamirPrimeB64u: 'prime',
} satisfies SealedSigningSessionRecord;
void invalidRecordWithRawPrime;

const invalidEcdsaSealedSessionRecordWithSubject = {
  ...validEcdsaSealedSessionRecord,
  // @ts-expect-error typed sealed records use walletId and reject stale subjectId.
  subjectId: 'wallet:alice',
} satisfies SealedSigningSessionRecord;
void invalidEcdsaSealedSessionRecordWithSubject;

const invalidEcdsaSealedSessionRecordWithUser = {
  ...validEcdsaSealedSessionRecord,
  // @ts-expect-error typed sealed records use walletId and reject stale userId.
  userId: 'google:alice',
} satisfies SealedSigningSessionRecord;
void invalidEcdsaSealedSessionRecordWithUser;

const invalidEcdsaSealedSessionRecordWithSigningRoot = {
  ...validEcdsaSealedSessionRecord,
  signingRootId: 'legacy-root',
  // @ts-expect-error ECDSA sealed records derive signing root from restore metadata.
} satisfies SealedSigningSessionRecord;
void invalidEcdsaSealedSessionRecordWithSigningRoot;

const { signingRootId: _ecdsaRestoreSigningRootId, ...ecdsaRestoreMissingSigningRootId } =
  validEcdsaSealedSessionRecord.ecdsaRestore;
// @ts-expect-error ECDSA sealed restore metadata carries signingRootId with the wallet key slot.
const invalidEcdsaRestoreMissingSigningRootId: SealedSigningSessionEcdsaRestoreMetadata =
  ecdsaRestoreMissingSigningRootId;
void invalidEcdsaRestoreMissingSigningRootId;

const {
  signingRootVersion: _ecdsaRestoreSigningRootVersion,
  ...ecdsaRestoreMissingSigningRootVersion
} = validEcdsaSealedSessionRecord.ecdsaRestore;
// @ts-expect-error ECDSA sealed restore metadata carries signingRootVersion with the wallet key slot.
const invalidEcdsaRestoreMissingSigningRootVersion: SealedSigningSessionEcdsaRestoreMetadata =
  ecdsaRestoreMissingSigningRootVersion;
void invalidEcdsaRestoreMissingSigningRootVersion;

const { provider: _ecdsaRestoreProvider, ...ecdsaRestoreMissingProvider } =
  validEcdsaSealedSessionRecord.ecdsaRestore;
// @ts-expect-error Email OTP ECDSA restore metadata carries its explicit provider identity.
const invalidEcdsaRestoreMissingProvider: SealedSigningSessionEcdsaRestoreMetadata =
  ecdsaRestoreMissingProvider;
void invalidEcdsaRestoreMissingProvider;


const { walletId: _ecdsaWalletId, ...ecdsaSealedSessionRecordWithoutWallet } =
  validEcdsaSealedSessionRecord;
// @ts-expect-error typed sealed records require wallet identity.
const invalidEcdsaSealedSessionRecordWithoutWallet: SealedSigningSessionRecord =
  ecdsaSealedSessionRecordWithoutWallet;
void invalidEcdsaSealedSessionRecordWithoutWallet;

const { ecdsaRestore: _ecdsaRestore, ...ecdsaSealedSessionRecordWithoutRestore } =
  validEcdsaSealedSessionRecord;
// @ts-expect-error ECDSA sealed records require ECDSA restore metadata.
const invalidEcdsaSealedSessionRecordWithoutRestore: SealedSigningSessionRecord =
  ecdsaSealedSessionRecordWithoutRestore;
void invalidEcdsaSealedSessionRecordWithoutRestore;

const invalidEd25519SealedSessionRecordWithUser = {
  ...validEd25519SealedSessionRecord,
  // @ts-expect-error typed sealed records use walletId and reject stale userId.
  userId: 'google:alice',
} satisfies SealedSigningSessionRecord;
void invalidEd25519SealedSessionRecordWithUser;

const { ed25519Restore: _ed25519Restore, ...ed25519SealedSessionRecordWithoutRestore } =
  validEd25519SealedSessionRecord;
// @ts-expect-error Ed25519 sealed records require Ed25519 restore metadata.
const invalidEd25519SealedSessionRecordWithoutRestore: SealedSigningSessionRecord =
  ed25519SealedSessionRecordWithoutRestore;
void invalidEd25519SealedSessionRecordWithoutRestore;

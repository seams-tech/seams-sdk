import type {
  SealedSigningSessionEcdsaRestoreMetadata,
  SealedSigningSessionEd25519RestoreMetadata,
  SealedSigningSessionRecord,
} from './signingSessionSeal';
import type { RouterAbEcdsaHssNormalSigningStateV1 } from './routerAbEcdsaHss';

declare const routerAbEcdsaHssNormalSigning: RouterAbEcdsaHssNormalSigningStateV1;

const validEcdsaSealedSessionRecord = {
  v: 1,
  alg: 'shamir3pass-v1',
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
    evmFamilySigningKeySlotId: 'wallet-key:evm-family:alice.testnet:root:v1',
    providerSubjectId: 'google:alice',
    emailHashHex: 'email-hash',
    sessionKind: 'jwt',
    walletSessionJwt: 'wallet-session-jwt',
    keyHandle: 'key-handle',
    ecdsaThresholdKeyId: 'ecdsa-key',
    ethereumAddress: `0x${'11'.repeat(20)}`,
    relayerKeyId: 'relayer-key',
    participantIds: [1, 2],
    routerAbEcdsaHssNormalSigning,
  },
  issuedAtMs: 1,
  expiresAtMs: 2,
  remainingUses: 3,
  updatedAtMs: 4,
} satisfies SealedSigningSessionRecord;
void validEcdsaSealedSessionRecord;

const validEd25519SealedSessionRecord = {
  v: 1,
  alg: 'shamir3pass-v1',
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
    sessionKind: 'cookie',
    signerSlot: 1,
  },
  issuedAtMs: 1,
  expiresAtMs: 2,
  remainingUses: 3,
  updatedAtMs: 4,
} satisfies SealedSigningSessionRecord;
void validEd25519SealedSessionRecord;

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

const { walletSessionJwt: _ecdsaRestoreJwt, ...ecdsaRestoreMissingJwt } =
  validEcdsaSealedSessionRecord.ecdsaRestore;
// @ts-expect-error JWT sealed restore auth requires walletSessionJwt.
const invalidEcdsaRestoreMissingJwt: SealedSigningSessionEcdsaRestoreMetadata =
  ecdsaRestoreMissingJwt;
void invalidEcdsaRestoreMissingJwt;

// @ts-expect-error cookie sealed restore auth rejects walletSessionJwt.
const invalidEcdsaRestoreCookieWithJwt: SealedSigningSessionEcdsaRestoreMetadata = {
  ...validEcdsaSealedSessionRecord.ecdsaRestore,
  sessionKind: 'cookie',
  walletSessionJwt: 'wallet-session-jwt',
};
void invalidEcdsaRestoreCookieWithJwt;

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

// @ts-expect-error JWT sealed restore auth requires walletSessionJwt.
const invalidEd25519RestoreMissingJwt: SealedSigningSessionEd25519RestoreMetadata = {
  ...validEd25519SealedSessionRecord.ed25519Restore,
  sessionKind: 'jwt',
};
void invalidEd25519RestoreMissingJwt;

// @ts-expect-error cookie sealed restore auth rejects walletSessionJwt.
const invalidEd25519RestoreCookieWithJwt: SealedSigningSessionEd25519RestoreMetadata = {
  ...validEd25519SealedSessionRecord.ed25519Restore,
  walletSessionJwt: 'wallet-session-jwt',
};
void invalidEd25519RestoreCookieWithJwt;

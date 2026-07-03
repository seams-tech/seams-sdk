import type {
  BuildCurrentEd25519SealedSessionRecordInput,
  BuildCurrentEcdsaSealedSessionRecordInput,
  CurrentEd25519SealedSessionRecord,
  CurrentEcdsaSealedSessionRecord,
} from './sealedSessionStore';
import type { SealedSigningSessionEcdsaRestoreMetadata } from '@shared/utils/signingSessionSeal';
import type { SealedSigningSessionEd25519RestoreMetadata } from '@shared/utils/signingSessionSeal';

declare const currentEd25519Record: CurrentEd25519SealedSessionRecord;
declare const currentEcdsaRecord: CurrentEcdsaSealedSessionRecord;
void currentEd25519Record;
void currentEcdsaRecord;

const invalidCurrentEd25519Record: CurrentEd25519SealedSessionRecord = {
  ...({} as CurrentEd25519SealedSessionRecord),
  ed25519Restore: {
    ...currentEd25519Record.ed25519Restore,
    // @ts-expect-error current Ed25519 sealed records do not carry raw client-base material.
    xClientBaseB64u: 'raw-client-base',
  },
};
void invalidCurrentEd25519Record;

const invalidCurrentEd25519SubjectRecord: CurrentEd25519SealedSessionRecord = {
  ...({} as CurrentEd25519SealedSessionRecord),
  // @ts-expect-error current Ed25519 sealed records use walletId, never subjectId.
  subjectId: 'wallet-alice',
};
void invalidCurrentEd25519SubjectRecord;

const invalidCurrentEd25519UserRecord: CurrentEd25519SealedSessionRecord = {
  ...({} as CurrentEd25519SealedSessionRecord),
  // @ts-expect-error current Ed25519 sealed records use walletId, never userId.
  userId: 'wallet-alice',
};
void invalidCurrentEd25519UserRecord;

const invalidEd25519WriteInput: BuildCurrentEd25519SealedSessionRecordInput = {
  thresholdSessionId: 'tsess-ed25519',
  thresholdSessionIds: { ed25519: 'tsess-ed25519' },
  sealedSecretB64u: 'sealed-secret',
  curve: 'ed25519',
  authMethod: 'passkey',
  signingGrantId: 'wsess-ed25519',
  walletId: 'wallet.testnet',
  relayerUrl: 'https://relay.example',
  ed25519Restore: {
    nearAccountId: 'wallet.testnet',
    nearEd25519SigningKeyId: 'wallet.testnet',
    rpId: 'wallet.example.localhost',
    credentialIdB64u: 'credential-id',
    relayerKeyId: 'relayer-key',
    participantIds: [1, 2, 3],
    sessionKind: 'cookie',
    signerSlot: 1,
    // @ts-expect-error current Ed25519 sealed writes do not accept raw client-base material.
    xClientBaseB64u: 'raw-client-base',
  },
  issuedAtMs: 1,
  expiresAtMs: 1,
  remainingUses: 1,
  updatedAtMs: 1,
};
void invalidEd25519WriteInput;

const invalidEd25519WriteWithoutIssuedAtMs = {
  ...invalidEd25519WriteInput,
  // @ts-expect-error current Ed25519 sealed writes require explicit issuedAtMs.
  issuedAtMs: undefined,
} satisfies BuildCurrentEd25519SealedSessionRecordInput;
void invalidEd25519WriteWithoutIssuedAtMs;

const invalidEd25519WriteWithoutUpdatedAtMs = {
  ...invalidEd25519WriteInput,
  // @ts-expect-error current Ed25519 sealed writes require explicit updatedAtMs.
  updatedAtMs: undefined,
} satisfies BuildCurrentEd25519SealedSessionRecordInput;
void invalidEd25519WriteWithoutUpdatedAtMs;

const invalidEd25519WriteWithoutThresholdSessionIds = {
  ...invalidEd25519WriteInput,
  // @ts-expect-error sealed Ed25519 writes require canonical thresholdSessionIds.
  thresholdSessionIds: undefined,
} satisfies BuildCurrentEd25519SealedSessionRecordInput;
void invalidEd25519WriteWithoutThresholdSessionIds;

const invalidEd25519WriteUserInput: BuildCurrentEd25519SealedSessionRecordInput = {
  ...invalidEd25519WriteInput,
  // @ts-expect-error current Ed25519 sealed writes do not carry top-level userId.
  userId: 'wallet-alice',
};
void invalidEd25519WriteUserInput;

const invalidEmailOtpEd25519RestoreWithoutProviderSubject = {
  nearAccountId: 'wallet.testnet',
  nearEd25519SigningKeyId: 'wallet.testnet',
  rpId: 'wallet.example.localhost',
  relayerKeyId: 'relayer-key',
  participantIds: [1, 2, 3],
  sessionKind: 'jwt',
  signerSlot: 1,
  // @ts-expect-error Ed25519 sealed restore metadata requires an auth identity branch.
} satisfies SealedSigningSessionEd25519RestoreMetadata;
void invalidEmailOtpEd25519RestoreWithoutProviderSubject;

const invalidEmailOtpEd25519RestoreWithAuthSubjectAlias = {
  nearAccountId: 'wallet.testnet',
  nearEd25519SigningKeyId: 'wallet.testnet',
  rpId: 'wallet.example.localhost',
  providerSubjectId: 'google:alice',
  // @ts-expect-error Ed25519 sealed restore metadata rejects authSubjectId.
  authSubjectId: 'google:legacy-alias',
  relayerKeyId: 'relayer-key',
  participantIds: [1, 2, 3],
  sessionKind: 'jwt',
  signerSlot: 1,
} satisfies SealedSigningSessionEd25519RestoreMetadata;
void invalidEmailOtpEd25519RestoreWithAuthSubjectAlias;

const invalidEd25519RestoreWithMixedAuthBranches = {
  nearAccountId: 'wallet.testnet',
  nearEd25519SigningKeyId: 'wallet.testnet',
  rpId: 'wallet.example.localhost',
  credentialIdB64u: 'credential-id',
  providerSubjectId: 'google:alice',
  relayerKeyId: 'relayer-key',
  participantIds: [1, 2, 3],
  sessionKind: 'jwt',
  signerSlot: 1,
  // @ts-expect-error Ed25519 sealed restore metadata requires exactly one auth branch.
} satisfies SealedSigningSessionEd25519RestoreMetadata;
void invalidEd25519RestoreWithMixedAuthBranches;

const invalidCurrentEcdsaRecord: CurrentEcdsaSealedSessionRecord = {
  ...({} as CurrentEcdsaSealedSessionRecord),
  // @ts-expect-error current ECDSA sealed records do not carry subjectId.
  subjectId: 'wallet-alice',
};
void invalidCurrentEcdsaRecord;

const invalidCurrentEcdsaUserRecord: CurrentEcdsaSealedSessionRecord = {
  ...({} as CurrentEcdsaSealedSessionRecord),
  // @ts-expect-error current ECDSA sealed records do not carry userId.
  userId: 'wallet-alice',
};
void invalidCurrentEcdsaUserRecord;

const invalidCurrentEcdsaSigningRootRecord: CurrentEcdsaSealedSessionRecord = {
  ...({} as CurrentEcdsaSealedSessionRecord),
  // @ts-expect-error current ECDSA sealed records do not carry signingRootId.
  signingRootId: 'root-ecdsa',
};
void invalidCurrentEcdsaSigningRootRecord;

const invalidCurrentEcdsaSigningRootVersionRecord: CurrentEcdsaSealedSessionRecord = {
  ...({} as CurrentEcdsaSealedSessionRecord),
  // @ts-expect-error current ECDSA sealed records do not carry signingRootVersion.
  signingRootVersion: 'root-version-ecdsa',
};
void invalidCurrentEcdsaSigningRootVersionRecord;

const invalidEcdsaWriteInput: BuildCurrentEcdsaSealedSessionRecordInput = {
  thresholdSessionId: 'tsess-ecdsa',
  thresholdSessionIds: { ecdsa: 'tsess-ecdsa' },
  sealedSecretB64u: 'sealed-secret',
  curve: 'ecdsa',
  authMethod: 'passkey',
  signingGrantId: 'wsess-ecdsa',
  walletId: 'wallet.testnet',
  relayerUrl: 'https://relay.example',
  ecdsaRestore: {
    chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
    evmFamilySigningKeySlotId: 'wallet-key:evm-family:wallet.testnet:project%3Adev:default',
    rpId: 'wallet.example.localhost',
    credentialIdB64u: 'credential-id',
    sessionKind: 'cookie',
    keyHandle: 'key-handle-ecdsa',
    ethereumAddress: `0x${'11'.repeat(20)}`,
    relayerKeyId: 'relayer-key',
    participantIds: [1, 2, 3],
  },
  issuedAtMs: 1,
  expiresAtMs: 1,
  remainingUses: 1,
  updatedAtMs: 1,
  // @ts-expect-error ECDSA sealed writes derive subject from walletId at restore boundaries.
  subjectId: 'wallet-alice',
};
void invalidEcdsaWriteInput;

const invalidEcdsaWriteWithoutIssuedAtMs = {
  ...invalidEcdsaWriteInput,
  // @ts-expect-error current ECDSA sealed writes require explicit issuedAtMs.
  issuedAtMs: undefined,
} satisfies BuildCurrentEcdsaSealedSessionRecordInput;
void invalidEcdsaWriteWithoutIssuedAtMs;

const invalidEcdsaWriteWithoutUpdatedAtMs = {
  ...invalidEcdsaWriteInput,
  // @ts-expect-error current ECDSA sealed writes require explicit updatedAtMs.
  updatedAtMs: undefined,
} satisfies BuildCurrentEcdsaSealedSessionRecordInput;
void invalidEcdsaWriteWithoutUpdatedAtMs;

const invalidEcdsaWriteWithoutThresholdSessionIds = {
  ...invalidEcdsaWriteInput,
  // @ts-expect-error sealed ECDSA writes require canonical thresholdSessionIds.
  thresholdSessionIds: undefined,
} satisfies BuildCurrentEcdsaSealedSessionRecordInput;
void invalidEcdsaWriteWithoutThresholdSessionIds;

const invalidEcdsaWriteUserInput: BuildCurrentEcdsaSealedSessionRecordInput = {
  ...invalidEcdsaWriteInput,
  // @ts-expect-error current ECDSA sealed writes do not carry top-level userId.
  userId: 'wallet-alice',
};
void invalidEcdsaWriteUserInput;

const invalidEcdsaWriteSigningRootInput: BuildCurrentEcdsaSealedSessionRecordInput = {
  ...invalidEcdsaWriteInput,
  // @ts-expect-error ECDSA sealed writes do not carry top-level signingRootId.
  signingRootId: 'root-ecdsa',
};
void invalidEcdsaWriteSigningRootInput;

const invalidEcdsaWriteSigningRootVersionInput: BuildCurrentEcdsaSealedSessionRecordInput = {
  ...invalidEcdsaWriteInput,
  // @ts-expect-error ECDSA sealed writes do not carry top-level signingRootVersion.
  signingRootVersion: 'root-version-ecdsa',
};
void invalidEcdsaWriteSigningRootVersionInput;

const invalidEmailOtpEcdsaRestoreWithoutProviderSubject = {
  chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
  evmFamilySigningKeySlotId: 'wallet-key:evm-family:wallet.testnet:project%3Adev:default',
  sessionKind: 'jwt',
  keyHandle: 'key-handle-ecdsa',
  ethereumAddress: `0x${'11'.repeat(20)}`,
  relayerKeyId: 'relayer-key',
  participantIds: [1, 2, 3],
  // @ts-expect-error Email OTP ECDSA sealed restore metadata requires providerSubjectId.
} satisfies SealedSigningSessionEcdsaRestoreMetadata;
void invalidEmailOtpEcdsaRestoreWithoutProviderSubject;

const invalidEmailOtpEcdsaRestoreWithAuthSubjectAlias = {
  chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
  evmFamilySigningKeySlotId: 'wallet-key:evm-family:wallet.testnet:project%3Adev:default',
  providerSubjectId: 'google:alice',
  // @ts-expect-error Email OTP ECDSA sealed restore metadata rejects authSubjectId.
  authSubjectId: 'google:legacy-alias',
  sessionKind: 'jwt',
  keyHandle: 'key-handle-ecdsa',
  ethereumAddress: `0x${'11'.repeat(20)}`,
  relayerKeyId: 'relayer-key',
  participantIds: [1, 2, 3],
} satisfies SealedSigningSessionEcdsaRestoreMetadata;
void invalidEmailOtpEcdsaRestoreWithAuthSubjectAlias;

const validCurrentEcdsaRestoreKeyId: BuildCurrentEcdsaSealedSessionRecordInput = {
  ...invalidEcdsaWriteInput,
  ecdsaRestore: {
    ...invalidEcdsaWriteInput.ecdsaRestore,
    ecdsaThresholdKeyId: 'legacy-key-id',
  },
};
void validCurrentEcdsaRestoreKeyId;

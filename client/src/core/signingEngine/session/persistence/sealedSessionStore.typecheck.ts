import type {
  BuildCurrentEcdsaSealedSessionRecordInput,
  CurrentEcdsaSealedSessionRecord,
} from './sealedSessionStore';

declare const currentEcdsaRecord: CurrentEcdsaSealedSessionRecord;
void currentEcdsaRecord;

const invalidCurrentEcdsaRecord: CurrentEcdsaSealedSessionRecord = {
  ...({} as CurrentEcdsaSealedSessionRecord),
  // @ts-expect-error current ECDSA sealed records do not carry subjectId.
  subjectId: 'wallet-subject-alice',
};
void invalidCurrentEcdsaRecord;

const invalidCurrentEcdsaSigningRootRecord: CurrentEcdsaSealedSessionRecord = {
  ...({} as CurrentEcdsaSealedSessionRecord),
  // @ts-expect-error current ECDSA sealed records do not carry signingRootId.
  signingRootId: 'root-ecdsa',
};
void invalidCurrentEcdsaSigningRootRecord;

const invalidEcdsaWriteInput: BuildCurrentEcdsaSealedSessionRecordInput = {
  thresholdSessionId: 'tsess-ecdsa',
  sealedSecretB64u: 'sealed-secret',
  curve: 'ecdsa',
  authMethod: 'passkey',
  walletSigningSessionId: 'wsess-ecdsa',
  walletId: 'wallet.testnet',
  signingRootId: 'root-ecdsa',
  relayerUrl: 'https://relay.example',
  ecdsaRestore: {
    chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
    rpId: 'wallet.example.localhost',
    sessionKind: 'cookie',
    keyHandle: 'key-handle-ecdsa',
    ethereumAddress: `0x${'11'.repeat(20)}`,
    relayerKeyId: 'relayer-key',
    participantIds: [1, 2, 3],
  },
  expiresAtMs: 1,
  remainingUses: 1,
  // @ts-expect-error ECDSA sealed writes derive subject from walletId at restore boundaries.
  subjectId: 'wallet-subject-alice',
};
void invalidEcdsaWriteInput;

const invalidCurrentEcdsaRestoreKeyId: BuildCurrentEcdsaSealedSessionRecordInput = {
  ...invalidEcdsaWriteInput,
  ecdsaRestore: {
    ...invalidEcdsaWriteInput.ecdsaRestore,
    // @ts-expect-error current ECDSA sealed restore metadata no longer persists key ids.
    ecdsaThresholdKeyId: 'legacy-key-id',
  },
};
void invalidCurrentEcdsaRestoreKeyId;

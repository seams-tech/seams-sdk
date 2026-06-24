import type {
  BuildCurrentEd25519SealedSessionRecordInput,
  BuildCurrentEcdsaSealedSessionRecordInput,
  CurrentEd25519SealedSessionRecord,
  CurrentEcdsaSealedSessionRecord,
} from './sealedSessionStore';

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

const invalidEd25519WriteInput: BuildCurrentEd25519SealedSessionRecordInput = {
  thresholdSessionId: 'tsess-ed25519',
  sealedSecretB64u: 'sealed-secret',
  curve: 'ed25519',
  authMethod: 'passkey',
  signingGrantId: 'wsess-ed25519',
  walletId: 'wallet.testnet',
  relayerUrl: 'https://relay.example',
	  ed25519Restore: {
	    nearAccountId: 'wallet.testnet',
	    ed25519KeyScopeId: 'wallet.testnet',
	    rpId: 'wallet.example.localhost',
    relayerKeyId: 'relayer-key',
    participantIds: [1, 2, 3],
    sessionKind: 'cookie',
    signerSlot: 1,
    // @ts-expect-error current Ed25519 sealed writes do not accept raw client-base material.
    xClientBaseB64u: 'raw-client-base',
  },
  expiresAtMs: 1,
  remainingUses: 1,
};
void invalidEd25519WriteInput;

const invalidCurrentEcdsaRecord: CurrentEcdsaSealedSessionRecord = {
  ...({} as CurrentEcdsaSealedSessionRecord),
  // @ts-expect-error current ECDSA sealed records do not carry subjectId.
  subjectId: 'wallet-alice',
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
  signingGrantId: 'wsess-ecdsa',
  walletId: 'wallet.testnet',
  relayerUrl: 'https://relay.example',
	  ecdsaRestore: {
	    chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
	    rpId: 'wallet.example.localhost',
	    credentialIdB64u: 'credential-id',
	    sessionKind: 'cookie',
	    keyHandle: 'key-handle-ecdsa',
    ethereumAddress: `0x${'11'.repeat(20)}`,
    relayerKeyId: 'relayer-key',
    participantIds: [1, 2, 3],
  },
  expiresAtMs: 1,
  remainingUses: 1,
  // @ts-expect-error ECDSA sealed writes derive subject from walletId at restore boundaries.
  subjectId: 'wallet-alice',
};
void invalidEcdsaWriteInput;

const invalidEcdsaWriteSigningRootInput: BuildCurrentEcdsaSealedSessionRecordInput = {
  ...invalidEcdsaWriteInput,
  // @ts-expect-error ECDSA sealed writes do not carry top-level signingRootId.
  signingRootId: 'root-ecdsa',
};
void invalidEcdsaWriteSigningRootInput;

const validCurrentEcdsaRestoreKeyId: BuildCurrentEcdsaSealedSessionRecordInput = {
  ...invalidEcdsaWriteInput,
  ecdsaRestore: {
    ...invalidEcdsaWriteInput.ecdsaRestore,
    ecdsaThresholdKeyId: 'legacy-key-id',
  },
};
void validCurrentEcdsaRestoreKeyId;

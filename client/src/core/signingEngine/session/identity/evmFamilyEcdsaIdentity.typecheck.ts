import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaSessionLane,
  buildEvmFamilyEcdsaSessionLanePolicy,
  toThresholdOwnerAddress,
  type EvmFamilyEcdsaKeyIdentity,
  type EvmFamilyEcdsaSessionLane,
  type EvmFamilyEcdsaSessionLanePolicy,
  type ReadyEvmFamilyEcdsaMaterial,
} from './evmFamilyEcdsaIdentity';

const evmTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
} as const;

const key = buildEvmFamilyEcdsaKeyIdentity({
  walletId: 'alice.testnet',
  subjectId: 'wallet-subject-alice',
  rpId: 'localhost',
  ecdsaThresholdKeyId: 'ehss-shared-key',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
});

const lane = buildEvmFamilyEcdsaSessionLane({
  key,
  chainTarget: evmTarget,
  authMethod: 'passkey',
  source: 'login',
  thresholdSessionId: 'threshold-session-1',
  walletSigningSessionId: 'wallet-signing-session-1',
  thresholdSessionKind: 'jwt',
  thresholdSessionAuthToken: 'threshold-auth-token',
  remainingUses: 1,
  expiresAtMs: 1_900_000_000_000,
});

const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
  chainTarget: evmTarget,
  thresholdSessionId: 'threshold-session-1',
  walletSigningSessionId: 'wallet-signing-session-1',
  thresholdSessionKind: 'jwt',
  ttlMs: 60_000,
  remainingUses: 1,
});

const invalidKeyWithSession: EvmFamilyEcdsaKeyIdentity = {
  ...key,
  // @ts-expect-error shared key identity rejects volatile threshold session ids.
  thresholdSessionId: 'threshold-session-1',
};
void invalidKeyWithSession;

const invalidKeyWithTarget: EvmFamilyEcdsaKeyIdentity = {
  ...key,
  // @ts-expect-error shared key identity rejects concrete targets.
  chainTarget: evmTarget,
};
void invalidKeyWithTarget;

const invalidLaneWithDuplicateKeyId: EvmFamilyEcdsaSessionLane = {
  ...lane,
  // @ts-expect-error session lanes must use lane.key.ecdsaThresholdKeyId.
  ecdsaThresholdKeyId: 'ehss-other-key',
};
void invalidLaneWithDuplicateKeyId;

const invalidLanePolicyWithDuplicateKeyId: EvmFamilyEcdsaSessionLanePolicy = {
  ...lanePolicy,
  // @ts-expect-error session lane policy must use lanePolicy.key.ecdsaThresholdKeyId.
  ecdsaThresholdKeyId: 'ehss-other-key',
};
void invalidLanePolicyWithDuplicateKeyId;

// @ts-expect-error session lanes require a shared key identity.
const laneWithoutKey: EvmFamilyEcdsaSessionLane = {
  chainTarget: evmTarget,
  authMethod: 'passkey',
  source: 'login',
  thresholdSessionId: lane.thresholdSessionId,
  walletSigningSessionId: lane.walletSigningSessionId,
  thresholdSessionKind: 'jwt',
  thresholdSessionAuthToken: lane.thresholdSessionAuthToken,
  remainingUses: 1,
  expiresAtMs: 1_900_000_000_000,
};
void laneWithoutKey;

// @ts-expect-error key identity requires rpId.
const keyWithoutRpId: EvmFamilyEcdsaKeyIdentity = {
  walletId: key.walletId,
  subjectId: key.subjectId,
  keyScope: 'evm-family',
  ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
  signingRootId: key.signingRootId,
  signingRootVersion: key.signingRootVersion,
  participantIds: key.participantIds,
  thresholdOwnerAddress: key.thresholdOwnerAddress,
};
void keyWithoutRpId;

const keyWithTargetScope: EvmFamilyEcdsaKeyIdentity = {
  ...key,
  // @ts-expect-error shared key identity accepts only evm-family scope.
  keyScope: 'tempo',
};
void keyWithTargetScope;

const ownerAddress = toThresholdOwnerAddress('0x1111111111111111111111111111111111111111');
declare function acceptsRawEip1559Sender(address: typeof ownerAddress): void;
acceptsRawEip1559Sender(ownerAddress);

// @ts-expect-error ready material requires a keyRef.
const readyMaterialMissingKeyRef: ReadyEvmFamilyEcdsaMaterial = {
  kind: 'ready_evm_family_ecdsa_material',
  key,
  lane,
  record: {} as ThresholdEcdsaSessionRecord,
};
void readyMaterialMissingKeyRef;

// @ts-expect-error ready material requires a record.
const readyMaterialMissingRecord: ReadyEvmFamilyEcdsaMaterial = {
  kind: 'ready_evm_family_ecdsa_material',
  key,
  lane,
  keyRef: {} as ThresholdEcdsaSecp256k1KeyRef,
};
void readyMaterialMissingRecord;

export {};

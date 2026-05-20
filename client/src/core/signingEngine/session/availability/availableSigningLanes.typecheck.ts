import {
  buildEmailOtpEcdsaAuthBinding,
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildPasskeyEcdsaAuthBinding,
  buildResolvedEvmFamilyEcdsaKey,
  buildVerifiedEcdsaPublicFacts,
} from '../identity/evmFamilyEcdsaIdentity';
import type { EvmFamilyEcdsaKeyHandle } from '../identity/evmFamilyEcdsaIdentity';
import type {
  ConcreteAvailableEcdsaSigningLane,
  EcdsaAvailableLaneIdentityInput,
  ReadAvailableSigningLanesInput,
} from './availableSigningLanes';

const chainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
} as const;

const key = buildBaseEvmFamilyEcdsaKeyIdentity({
  walletId: 'alice.testnet',
  rpId: 'localhost',
  ecdsaThresholdKeyId: 'ehss-shared-key',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
});

declare const keyHandle: EvmFamilyEcdsaKeyHandle;

const publicFacts = buildVerifiedEcdsaPublicFacts({
  keyHandle,
  publicKeyB64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  participantIds: [1, 2],
  thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
});

const resolvedKey = buildResolvedEvmFamilyEcdsaKey({
  walletId: key.walletId,
  publicFacts,
  authBinding: buildPasskeyEcdsaAuthBinding({ rpId: key.rpId }),
});

const emailOtpResolvedKey = buildResolvedEvmFamilyEcdsaKey({
  walletId: key.walletId,
  publicFacts,
  authBinding: buildEmailOtpEcdsaAuthBinding({
    authSubjectId: 'google:alice',
    providerId: 'google',
  }),
});

const passkeyLane: ConcreteAvailableEcdsaSigningLane = {
  key,
  publicFacts,
  authMethod: 'passkey',
  resolvedKey,
  curve: 'ecdsa',
  chainTarget,
  state: 'ready',
  source: 'runtime_session_record',
  walletSigningSessionId: 'wallet-signing-session-1',
  thresholdSessionId: 'threshold-session-1',
};
void passkeyLane;

const availableSigningLanesInput: ReadAvailableSigningLanesInput = {
  walletId: key.walletId,
  ecdsaChainTargets: [chainTarget],
};
void availableSigningLanesInput;

const invalidAvailableSigningLanesInputWithSubjectId: ReadAvailableSigningLanesInput = {
  walletId: key.walletId,
  ecdsaChainTargets: [chainTarget],
  // @ts-expect-error available-lane reads derive subject from wallet identity.
  subjectId: 'alice.testnet',
};
void invalidAvailableSigningLanesInputWithSubjectId;

const passkeyLaneIdentity: EcdsaAvailableLaneIdentityInput = {
  key,
  publicFacts,
  authMethod: 'passkey',
  resolvedKey,
  curve: 'ecdsa',
  chainTarget,
  walletSigningSessionId: 'wallet-signing-session-1',
  thresholdSessionId: 'threshold-session-1',
};
void passkeyLaneIdentity;

const invalidPasskeyLaneWithSubjectId: ConcreteAvailableEcdsaSigningLane = {
  ...passkeyLane,
  // @ts-expect-error available ECDSA lanes derive subject from the shared key identity.
  subjectId: 'alice.testnet',
};
void invalidPasskeyLaneWithSubjectId;

const invalidPasskeyLaneIdentityWithSubjectId: EcdsaAvailableLaneIdentityInput = {
  ...passkeyLaneIdentity,
  // @ts-expect-error available-lane identity input derives subject from the shared key identity.
  subjectId: 'alice.testnet',
};
void invalidPasskeyLaneIdentityWithSubjectId;

// @ts-expect-error passkey available lanes require a resolved EVM-family key.
const passkeyLaneMissingResolvedKey: ConcreteAvailableEcdsaSigningLane = {
  key,
  publicFacts,
  authMethod: 'passkey',
  curve: 'ecdsa',
  chainTarget,
  state: 'ready',
  source: 'runtime_session_record',
  walletSigningSessionId: 'wallet-signing-session-1',
  thresholdSessionId: 'threshold-session-1',
};
void passkeyLaneMissingResolvedKey;

const passkeyLaneWithEmailOtpResolvedKey: ConcreteAvailableEcdsaSigningLane = {
  key,
  publicFacts,
  authMethod: 'passkey',
  // @ts-expect-error passkey lanes reject Email OTP auth bindings.
  resolvedKey: emailOtpResolvedKey,
  curve: 'ecdsa',
  chainTarget,
  state: 'ready',
  source: 'runtime_session_record',
  walletSigningSessionId: 'wallet-signing-session-1',
  thresholdSessionId: 'threshold-session-1',
};
void passkeyLaneWithEmailOtpResolvedKey;

// @ts-expect-error passkey availability identity keys require resolved auth binding.
const passkeyLaneIdentityMissingResolvedKey: EcdsaAvailableLaneIdentityInput = {
  key,
  publicFacts,
  authMethod: 'passkey',
  curve: 'ecdsa',
  chainTarget,
  walletSigningSessionId: 'wallet-signing-session-1',
  thresholdSessionId: 'threshold-session-1',
};
void passkeyLaneIdentityMissingResolvedKey;

// @ts-expect-error Email OTP available lanes need provider identity before resolved-key binding.
const emailOtpLaneWithResolvedKey: ConcreteAvailableEcdsaSigningLane = {
  key,
  publicFacts,
  authMethod: 'email_otp',
  resolvedKey,
  curve: 'ecdsa',
  chainTarget,
  state: 'ready',
  source: 'runtime_session_record',
  walletSigningSessionId: 'wallet-signing-session-1',
  thresholdSessionId: 'threshold-session-1',
};
void emailOtpLaneWithResolvedKey;

export {};

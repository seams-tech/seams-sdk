import {
  buildEmailOtpEcdsaAuthBinding,
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildPasskeyEcdsaAuthBinding,
  buildResolvedEvmFamilyEcdsaKey,
  buildVerifiedEcdsaPublicFacts,
  toRpId,
} from '../identity/evmFamilyEcdsaIdentity';
import type { EvmFamilyEcdsaKeyHandle } from '../identity/evmFamilyEcdsaIdentity';
import type {
  ConcreteAvailableEcdsaSigningLane,
  ConcreteAvailableEd25519SigningLane,
  EcdsaAvailableLaneIdentityInput,
  ReadAvailableSigningLanesInput,
  AvailableLaneStateAdvisory,
  AvailableSigningLanesRuntimeEd25519Record,
} from './availableSigningLanes';
import { toAccountId } from '../../../types/accountIds';
import { toWalletId } from '../../interfaces/ecdsaChainTarget';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';

const chainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
} as const;
const ed25519WalletId = toWalletId('frost-vermillion-k7p9m2');
const ed25519NearAccountId = toAccountId('alice.testnet');
const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString('scope-frost-vermillion-k7p9m2');
const key = buildBaseEvmFamilyEcdsaKeyIdentity({
  walletId: 'alice.testnet',
  ecdsaThresholdKeyId: 'ederivation-shared-key',
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

declare const keyHandle: EvmFamilyEcdsaKeyHandle;
declare const materialActivation: MpcMaterialActivationRef;
declare const ed25519RouterAbNormalSigning: AvailableSigningLanesRuntimeEd25519Record['routerAbNormalSigning'];

const publicFacts = buildVerifiedEcdsaPublicFacts({
  keyHandle,
  publicKeyB64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  participantIds: [1, 2],
  thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
});

const resolvedKey = buildResolvedEvmFamilyEcdsaKey({
  walletId: key.walletId,
  publicFacts,
  authBinding: buildPasskeyEcdsaAuthBinding({
    rpId: passkeyAuth.rpId,
    credentialIdB64u: passkeyAuth.credentialIdB64u,
  }),
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
  materialActivation,
  publicFacts,
  auth: passkeyAuth,
  resolvedKey,
  curve: 'ecdsa',
  chainTarget,
  state: 'deferred',
  source: 'canonical_capability',
};
void passkeyLane;

const canonicalAuthorizationRequiredLane: ConcreteAvailableEcdsaSigningLane = {
  key,
  materialActivation,
  publicFacts,
  auth: passkeyAuth,
  resolvedKey,
  curve: 'ecdsa',
  chainTarget,
  state: 'deferred',
  source: 'canonical_capability',
};
void canonicalAuthorizationRequiredLane;

const invalidCanonicalLaneWithSessionAlias: ConcreteAvailableEcdsaSigningLane = {
  ...canonicalAuthorizationRequiredLane,
  // @ts-expect-error canonical ECDSA availability never carries session aliases.
  thresholdSessionId: 'threshold-session-legacy',
};
void invalidCanonicalLaneWithSessionAlias;

const invalidCanonicalLaneWithGrantAlias: ConcreteAvailableEcdsaSigningLane = {
  ...canonicalAuthorizationRequiredLane,
  // @ts-expect-error canonical ECDSA availability never carries grant aliases.
  signingGrantId: 'signing-grant-legacy',
};
void invalidCanonicalLaneWithGrantAlias;

const invalidRestorableCanonicalEcdsaLane: ConcreteAvailableEcdsaSigningLane = {
  ...canonicalAuthorizationRequiredLane,
  // @ts-expect-error ECDSA hydration uses explicit outcomes; restorable remains Ed25519-only.
  state: 'restorable',
};
void invalidRestorableCanonicalEcdsaLane;

// @ts-expect-error authorization-required canonical material is always deferred.
const invalidReadyCanonicalLaneWithoutAuthorization: ConcreteAvailableEcdsaSigningLane = {
  ...canonicalAuthorizationRequiredLane,
  state: 'ready',
};
void invalidReadyCanonicalLaneWithoutAuthorization;

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
  materialActivation,
  publicFacts,
  auth: passkeyAuth,
  resolvedKey,
  curve: 'ecdsa',
  chainTarget,
};
void passkeyLaneIdentity;

const invalidLaneIdentityWithSessionAlias: EcdsaAvailableLaneIdentityInput = {
  ...passkeyLaneIdentity,
  // @ts-expect-error ECDSA availability identity is independent of authorization sessions.
  thresholdSessionId: 'threshold-session-legacy',
};
void invalidLaneIdentityWithSessionAlias;

const invalidLaneIdentityWithGrantAlias: EcdsaAvailableLaneIdentityInput = {
  ...passkeyLaneIdentity,
  // @ts-expect-error ECDSA availability identity is independent of grants.
  signingGrantId: 'signing-grant-legacy',
};
void invalidLaneIdentityWithGrantAlias;

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
  materialActivation,
  publicFacts,
  auth: passkeyAuth,
  curve: 'ecdsa',
  chainTarget,
  state: 'deferred',
  source: 'canonical_capability',
};
void passkeyLaneMissingResolvedKey;

const passkeyLaneWithEmailOtpResolvedKey: ConcreteAvailableEcdsaSigningLane = {
  key,
  materialActivation,
  publicFacts,
  auth: passkeyAuth,
  // @ts-expect-error passkey lanes reject Email OTP auth bindings.
  resolvedKey: emailOtpResolvedKey,
  curve: 'ecdsa',
  chainTarget,
  state: 'deferred',
  source: 'canonical_capability',
};
void passkeyLaneWithEmailOtpResolvedKey;

// @ts-expect-error passkey availability identity keys require resolved auth binding.
const passkeyLaneIdentityMissingResolvedKey: EcdsaAvailableLaneIdentityInput = {
  key,
  materialActivation,
  publicFacts,
  auth: passkeyAuth,
  curve: 'ecdsa',
  chainTarget,
};
void passkeyLaneIdentityMissingResolvedKey;

// @ts-expect-error Email OTP available lanes need provider identity before resolved-key binding.
const emailOtpLaneWithResolvedKey: ConcreteAvailableEcdsaSigningLane = {
  key,
  materialActivation,
  publicFacts,
  auth: emailOtpAuth,
  resolvedKey,
  curve: 'ecdsa',
  chainTarget,
  state: 'deferred',
  source: 'canonical_capability',
};
void emailOtpLaneWithResolvedKey;

const ed25519Lane: ConcreteAvailableEd25519SigningLane = {
  auth: passkeyAuth,
  curve: 'ed25519',
  chain: 'near',
  walletId: ed25519WalletId,
  nearAccountId: ed25519NearAccountId,
  nearEd25519SigningKeyId,
  signerSlot: 1,
  state: 'ready',
  signingGrantId: 'signing-grant-1',
  thresholdSessionId: 'threshold-session-1',
};
void ed25519Lane;

const invalidEd25519LaneWithMaterial: ConcreteAvailableEd25519SigningLane = {
  ...ed25519Lane,
  // @ts-expect-error Yao-backed Ed25519 lanes reject worker material.
  material: { kind: 'loaded_worker_material' },
};
void invalidEd25519LaneWithMaterial;

const runtimeEd25519Record: AvailableSigningLanesRuntimeEd25519Record = {
  auth: passkeyAuth,
  curve: 'ed25519',
  chain: 'near',
  walletId: ed25519WalletId,
  nearAccountId: ed25519NearAccountId,
  nearEd25519SigningKeyId,
  signerSlot: 1,
  routerAbNormalSigning: ed25519RouterAbNormalSigning,
  thresholdSessionId: 'threshold-session-1',
  signingGrantId: 'signing-grant-1',
  source: 'runtime_session_record',
};
void runtimeEd25519Record;

const runtimeEd25519RecordWithMaterial: AvailableSigningLanesRuntimeEd25519Record = {
  ...runtimeEd25519Record,
  // @ts-expect-error Yao-backed runtime Ed25519 records reject worker material.
  material: { kind: 'loaded_worker_material' },
};
void runtimeEd25519RecordWithMaterial;

const readyEd25519LaneWithStoredAuthMethod: ConcreteAvailableEd25519SigningLane = {
  ...ed25519Lane,
  // @ts-expect-error Ed25519 lanes derive auth method from the auth binding.
  authMethod: 'passkey',
};
void readyEd25519LaneWithStoredAuthMethod;

const readyEd25519LaneMissingSigningGrantId: ConcreteAvailableEd25519SigningLane = {
  ...ed25519Lane,
  // @ts-expect-error ready Ed25519 lanes require a signing grant id.
  signingGrantId: undefined,
};
void readyEd25519LaneMissingSigningGrantId;

const readyEd25519LaneMissingThresholdSessionId: ConcreteAvailableEd25519SigningLane = {
  ...ed25519Lane,
  // @ts-expect-error ready Ed25519 lanes require a threshold session id.
  thresholdSessionId: undefined,
};
void readyEd25519LaneMissingThresholdSessionId;

const durablePolicyAdvisory: AvailableLaneStateAdvisory = {
  kind: 'durable_policy',
  remainingUses: 1,
  expiresAtMs: 1_900_000_000_000,
  state: 'restorable',
};
void durablePolicyAdvisory;

const activeAdvisoryWithLaneState: AvailableLaneStateAdvisory = {
  kind: 'warm_status',
  status: 'active',
  remainingUses: 1,
  expiresAtMs: 1_900_000_000_000,
  // @ts-expect-error active advisories are runtime-ready and cannot carry durable-policy lane state.
  laneState: 'restorable',
};
void activeAdvisoryWithLaneState;

const cacheMissAdvisoryWithLaneState: AvailableLaneStateAdvisory = {
  kind: 'warm_status',
  status: 'cache_miss',
  // @ts-expect-error cache-miss advisories cannot choose a lane state by themselves.
  laneState: 'deferred',
};
void cacheMissAdvisoryWithLaneState;

// @ts-expect-error durable-policy advisories must state the durable lane they represent.
const durablePolicyAdvisoryMissingState: AvailableLaneStateAdvisory = {
  kind: 'durable_policy',
  remainingUses: 1,
  expiresAtMs: 1_900_000_000_000,
};
void durablePolicyAdvisoryMissingState;

const durablePolicyAdvisoryWithLaneState: AvailableLaneStateAdvisory = {
  kind: 'durable_policy',
  remainingUses: 1,
  expiresAtMs: 1_900_000_000_000,
  state: 'restorable',
  // @ts-expect-error durable-policy advisories use state, not the old laneState field.
  laneState: 'restorable',
};
void durablePolicyAdvisoryWithLaneState;

export {};

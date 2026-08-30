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
} from './availableSigningLanes';
import { toAccountId } from '../../../types/accountIds';
import { toWalletId } from '../../interfaces/ecdsaChainTarget';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { ExactNearEd25519WalletSessionAuthorization } from '../material/nearEd25519YaoSigningPreparation';
import type { CanonicalEvmFamilyEcdsaSigningCapability } from '../material/ecdsaSigningCapability';

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
declare const canonicalCapability: CanonicalEvmFamilyEcdsaSigningCapability;
declare const ed25519Authorization: ExactNearEd25519WalletSessionAuthorization;

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
  capability: canonicalCapability,
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
  capability: canonicalCapability,
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
  capability: canonicalCapability,
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
  capability: canonicalCapability,
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
  capability: canonicalCapability,
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
  materialActivation,
  walletId: ed25519WalletId,
  nearAccountId: ed25519NearAccountId,
  nearEd25519SigningKeyId,
  signerSlot: 1,
  authorizationState: 'authorized',
  authorization: ed25519Authorization,
  state: 'ready',
  thresholdSessionId: 'threshold-session-1',
};
void ed25519Lane;

const invalidEd25519LaneWithMaterial: ConcreteAvailableEd25519SigningLane = {
  ...ed25519Lane,
  // @ts-expect-error Yao-backed Ed25519 lanes reject worker material.
  material: { kind: 'loaded_worker_material' },
};
void invalidEd25519LaneWithMaterial;

const readyEd25519LaneWithStoredAuthMethod: ConcreteAvailableEd25519SigningLane = {
  ...ed25519Lane,
  // @ts-expect-error Ed25519 lanes derive auth method from the auth binding.
  authMethod: 'passkey',
};
void readyEd25519LaneWithStoredAuthMethod;

const readyEd25519LaneMissingQuotaId: ConcreteAvailableEd25519SigningLane = {
  ...ed25519Lane,
  authorization: {
    ...ed25519Authorization,
    // @ts-expect-error authorized Ed25519 lanes require an exact quota identity.
    quotaId: undefined,
  },
};
void readyEd25519LaneMissingQuotaId;

const deferredEd25519Lane: ConcreteAvailableEd25519SigningLane = {
  auth: passkeyAuth,
  curve: 'ed25519',
  chain: 'near',
  materialActivation,
  walletId: ed25519WalletId,
  nearAccountId: ed25519NearAccountId,
  nearEd25519SigningKeyId,
  signerSlot: 1,
  authorizationState: 'authorization_required',
  state: 'deferred',
  thresholdSessionId: 'threshold-session-1',
};
void deferredEd25519Lane;

const readyEd25519LaneMissingThresholdSessionId: ConcreteAvailableEd25519SigningLane = {
  ...ed25519Lane,
  // @ts-expect-error ready Ed25519 lanes require a threshold session id.
  thresholdSessionId: undefined,
};
void readyEd25519LaneMissingThresholdSessionId;

export {};

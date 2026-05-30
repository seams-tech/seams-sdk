import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type {
  ReadyEcdsaSignerSession,
  ReadyEvmFamilyEcdsaMaterial,
  VerifiedEcdsaPublicFacts,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type {
  EcdsaSessionIdentity,
  EcdsaSigningKeyContext,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import type {
  EvmFamilySharedEcdsaPublicIdentityOnlyState,
  EvmFamilySharedEcdsaReadyState,
  EvmFamilySharedEcdsaSignerMaterial,
  FutureEpochMs,
  PositiveSignatureUses,
  PublicIdentityAvailableEcdsaMaterial,
  TargetSpecificEvmFamilyEcdsaLaneState,
  ReadyEcdsaMaterial,
} from './ecdsaMaterialState';

declare const publicFacts: VerifiedEcdsaPublicFacts;
declare const record: ThresholdEcdsaSessionRecord;
declare const keyRef: ThresholdEcdsaSecp256k1KeyRef;
declare const identity: EcdsaSessionIdentity;
declare const signingKeyContext: EcdsaSigningKeyContext;
declare const readyMaterial: ReadyEvmFamilyEcdsaMaterial;
declare const signerSession: ReadyEcdsaSignerSession;
declare const sharedReadyState: EvmFamilySharedEcdsaReadyState;
declare const sharedSignerMaterial: EvmFamilySharedEcdsaSignerMaterial;
declare const remainingSignatureUses: PositiveSignatureUses;
declare const expiresAtMs: FutureEpochMs;

void ({
  kind: 'ready_to_sign',
  authMethod: 'passkey',
  source: 'login',
  chainTarget: record.chainTarget,
  identity,
  publicFacts,
  signingKeyContext,
  readyMaterial,
  signerSession,
  sharedKeyState: sharedReadyState,
  record,
} satisfies ReadyEcdsaMaterial);

void ({
  kind: 'public_identity_available',
  authMethod: 'passkey',
  source: 'login',
  chainTarget: record.chainTarget,
  identity,
  publicFacts,
  record,
} satisfies PublicIdentityAvailableEcdsaMaterial);

const readyWithoutSignerSession = {
  kind: 'ready_to_sign',
  authMethod: 'passkey',
  source: 'login',
  chainTarget: record.chainTarget,
  identity,
  publicFacts,
  signingKeyContext,
  readyMaterial,
  sharedKeyState: sharedReadyState,
  record,
};

// @ts-expect-error ready-to-sign material requires hot signer-session material
void (readyWithoutSignerSession satisfies ReadyEcdsaMaterial);

const publicIdentityWithSignerSession = {
  kind: 'public_identity_available',
  authMethod: 'passkey',
  source: 'login',
  chainTarget: record.chainTarget,
  identity,
  publicFacts,
  record,
  signerSession,
};

// @ts-expect-error public identity material must not carry signer-session material
void (publicIdentityWithSignerSession satisfies PublicIdentityAvailableEcdsaMaterial);

const publicIdentityAsReadyMaterial = {
  kind: 'public_identity_available',
  authMethod: 'passkey',
  source: 'login',
  chainTarget: record.chainTarget,
  identity,
  publicFacts,
  record,
};

// @ts-expect-error public ECDSA identity is not ready signer material
void (publicIdentityAsReadyMaterial satisfies ReadyEcdsaMaterial);

const readyWithKeyRef = {
  kind: 'ready_to_sign',
  authMethod: 'passkey',
  source: 'login',
  chainTarget: record.chainTarget,
  identity,
  publicFacts,
  signingKeyContext,
  readyMaterial,
  signerSession,
  sharedKeyState: sharedReadyState,
  record,
  keyRef,
};

// @ts-expect-error ECDSA material state keeps transport key refs out of core material payloads
void (readyWithKeyRef satisfies ReadyEcdsaMaterial);

void ({
  kind: 'ready_to_sign',
  walletId: record.walletId,
  authMethod: 'email_otp',
  sourceChainTarget: record.chainTarget,
  publishedTargets: [record.chainTarget],
  sharedPublicFacts: publicFacts,
  walletSigningSessionId: identity.walletSigningSessionId,
  thresholdSessionId: identity.thresholdSessionId,
  remainingSignatureUses,
  expiresAtMs,
  signerMaterial: sharedSignerMaterial,
} satisfies EvmFamilySharedEcdsaReadyState);

void ({
  kind: 'public_identity_only',
  walletId: record.walletId,
  authMethod: 'email_otp',
  sourceChainTarget: record.chainTarget,
  publishedTargets: [record.chainTarget],
  sharedPublicFacts: publicFacts,
} satisfies EvmFamilySharedEcdsaPublicIdentityOnlyState);

void ({
  kind: 'target_specific_evm_family_ecdsa_lane_state',
  targetChainTarget: record.chainTarget,
  sharedKeyState: sharedReadyState,
} satisfies TargetSpecificEvmFamilyEcdsaLaneState);

const sharedReadyWithoutMaterial = {
  kind: 'ready_to_sign',
  walletId: record.walletId,
  authMethod: 'email_otp',
  sourceChainTarget: record.chainTarget,
  publishedTargets: [record.chainTarget],
  sharedPublicFacts: publicFacts,
  walletSigningSessionId: identity.walletSigningSessionId,
  thresholdSessionId: identity.thresholdSessionId,
  remainingSignatureUses,
  expiresAtMs,
};

// @ts-expect-error shared ECDSA ready state requires concrete signer material.
void (sharedReadyWithoutMaterial satisfies EvmFamilySharedEcdsaReadyState);

const sharedPublicIdentityWithMaterial = {
  kind: 'public_identity_only',
  walletId: record.walletId,
  authMethod: 'email_otp',
  sourceChainTarget: record.chainTarget,
  publishedTargets: [record.chainTarget],
  sharedPublicFacts: publicFacts,
  signerMaterial: sharedSignerMaterial,
};

// @ts-expect-error public identity is not signer material.
void (sharedPublicIdentityWithMaterial satisfies EvmFamilySharedEcdsaPublicIdentityOnlyState);

const sharedPublicIdentityWithSession = {
  kind: 'public_identity_only',
  walletId: record.walletId,
  authMethod: 'email_otp',
  sourceChainTarget: record.chainTarget,
  publishedTargets: [record.chainTarget],
  sharedPublicFacts: publicFacts,
  walletSigningSessionId: identity.walletSigningSessionId,
  thresholdSessionId: identity.thresholdSessionId,
};

// @ts-expect-error public identity cannot carry volatile threshold session ids.
void (sharedPublicIdentityWithSession satisfies EvmFamilySharedEcdsaPublicIdentityOnlyState);

const targetLaneWithPublicIdentity = {
  kind: 'target_specific_evm_family_ecdsa_lane_state',
  targetChainTarget: record.chainTarget,
  sharedKeyState: {
    kind: 'public_identity_only',
    walletId: record.walletId,
    authMethod: 'email_otp',
    sourceChainTarget: record.chainTarget,
    publishedTargets: [record.chainTarget],
    sharedPublicFacts: publicFacts,
  },
};

// @ts-expect-error target-specific signing lanes require ready shared-key material.
void (targetLaneWithPublicIdentity satisfies TargetSpecificEvmFamilyEcdsaLaneState);

export {};

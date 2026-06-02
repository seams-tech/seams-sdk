import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { VerifiedEcdsaPublicFacts } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { EcdsaSessionIdentity } from '../../session/warmCapabilities/ecdsaProvisionPlan';
import type {
  EvmFamilySharedEcdsaPublicIdentityOnlyState,
  EvmFamilySharedEcdsaReadyState,
  EvmFamilySharedEcdsaSignerMaterial,
  FutureEpochMs,
  PositiveSignatureUses,
  TargetSpecificEvmFamilyEcdsaLaneState,
} from './ecdsaMaterialState';

declare const sourceChainTarget: ThresholdEcdsaChainTarget;
declare const targetChainTarget: ThresholdEcdsaChainTarget;
declare const publishedTargets: readonly ThresholdEcdsaChainTarget[];
declare const sharedPublicFacts: VerifiedEcdsaPublicFacts;
declare const remainingSignatureUses: PositiveSignatureUses;
declare const expiresAtMs: FutureEpochMs;
declare const walletSigningSessionId: EcdsaSessionIdentity['walletSigningSessionId'];
declare const thresholdSessionId: EcdsaSessionIdentity['thresholdSessionId'];
declare const signerMaterial: EvmFamilySharedEcdsaSignerMaterial;

const publicIdentityOnly: EvmFamilySharedEcdsaPublicIdentityOnlyState = {
  kind: 'public_identity_only',
  walletId: 'wallet.testnet',
  authMethod: 'email_otp',
  sourceChainTarget,
  publishedTargets,
  sharedPublicFacts,
};
void publicIdentityOnly;

const invalidPublicIdentityWithSignerMaterial: EvmFamilySharedEcdsaPublicIdentityOnlyState = {
  kind: 'public_identity_only',
  walletId: 'wallet.testnet',
  authMethod: 'email_otp',
  sourceChainTarget,
  publishedTargets,
  sharedPublicFacts,
  // @ts-expect-error public-identity-only state cannot carry signing material.
  signerMaterial,
};
void invalidPublicIdentityWithSignerMaterial;

const readyToSign: EvmFamilySharedEcdsaReadyState = {
  kind: 'ready_to_sign',
  walletId: 'wallet.testnet',
  authMethod: 'email_otp',
  sourceChainTarget,
  publishedTargets,
  sharedPublicFacts,
  walletSigningSessionId,
  thresholdSessionId,
  remainingSignatureUses,
  expiresAtMs,
  signerMaterial,
};
void readyToSign;

// @ts-expect-error ready-to-sign state requires signing material.
const invalidReadyWithoutSignerMaterial: EvmFamilySharedEcdsaReadyState = {
  kind: 'ready_to_sign',
  walletId: 'wallet.testnet',
  authMethod: 'email_otp',
  sourceChainTarget,
  publishedTargets,
  sharedPublicFacts,
  walletSigningSessionId,
  thresholdSessionId,
  remainingSignatureUses,
  expiresAtMs,
};
void invalidReadyWithoutSignerMaterial;

const invalidReadyWithRestore: EvmFamilySharedEcdsaReadyState = {
  kind: 'ready_to_sign',
  walletId: 'wallet.testnet',
  authMethod: 'email_otp',
  sourceChainTarget,
  publishedTargets,
  sharedPublicFacts,
  walletSigningSessionId,
  thresholdSessionId,
  remainingSignatureUses,
  expiresAtMs,
  signerMaterial,
  // @ts-expect-error ready-to-sign state cannot carry restore instructions.
  restore: { kind: 'email_otp_worker', workerSessionId: 'worker-session' },
};
void invalidReadyWithRestore;

const targetSpecificReady: TargetSpecificEvmFamilyEcdsaLaneState = {
  kind: 'target_specific_evm_family_ecdsa_lane_state',
  targetChainTarget,
  sharedKeyState: readyToSign,
};
void targetSpecificReady;

const invalidTargetSpecificPublicIdentity: TargetSpecificEvmFamilyEcdsaLaneState = {
  kind: 'target_specific_evm_family_ecdsa_lane_state',
  targetChainTarget,
  // @ts-expect-error target-specific ECDSA lanes require ready shared key state.
  sharedKeyState: publicIdentityOnly,
};
void invalidTargetSpecificPublicIdentity;

export {};

import type {
  ThresholdEcdsaBackendBinding,
  ThresholdEcdsaDerivationRoleLocalClientState,
} from '../../interfaces/signing';
import type { EcdsaRoleLocalReadyRecord } from '@/core/platform/types';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaWalletKey,
  buildEvmFamilyEcdsaSessionLanePolicy,
  buildEmailOtpEcdsaAuthBinding,
  buildPasskeyEcdsaAuthBinding,
  buildResolvedEvmFamilyEcdsaKey,
  deriveBaseEcdsaSubjectIdFromWalletId,
  toThresholdOwnerAddress,
  type BaseEcdsaSubjectId,
  type EvmFamilyEcdsaWalletKeyFacts,
  type EcdsaWalletSignerRecord,
  type EvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyIdentity,
  type EvmFamilyEcdsaSessionLanePolicy,
  type EvmFamilyEcdsaWalletKey,
  type HydratedEcdsaSignerMaterial,
  type EmailOtpEcdsaAuthBinding,
  type PasskeyEcdsaAuthBinding,
  type ResolvedEvmFamilyEcdsaKey,
  type ThresholdEcdsaPublicKeyB64u,
  type VerifiedEcdsaPublicFacts,
} from './evmFamilyEcdsaIdentity';
import { walletIdFromWalletProfile } from '../../interfaces/ecdsaChainTarget';

const evmTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
} as const;
const runtimePolicyScope = {
  orgId: 'org-1',
  projectId: 'project-1',
  envId: 'env-1',
  signingRootVersion: 'default',
};
const key = buildBaseEvmFamilyEcdsaKeyIdentity({
  walletId: 'alice.testnet',
  ecdsaThresholdKeyId: 'ederivation-shared-key',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
});

const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
  chainTarget: evmTarget,
  thresholdSessionId: 'threshold-session-1',
  ttlMs: 60_000,
  remainingUses: 1,
  runtimePolicyScope,
});

// @ts-expect-error a session lane policy requires its exact runtime policy scope.
buildEvmFamilyEcdsaSessionLanePolicy({
  chainTarget: evmTarget,
  thresholdSessionId: 'threshold-session-1',
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

const invalidKeyWithSubjectId: EvmFamilyEcdsaKeyIdentity = {
  ...key,
  // @ts-expect-error shared key identity derives the base ECDSA subject from wallet identity.
  subjectId: 'wallet-alice',
};
void invalidKeyWithSubjectId;

const baseEcdsaSubjectId = deriveBaseEcdsaSubjectIdFromWalletId(key.walletId);
const validBaseEcdsaSubjectId: BaseEcdsaSubjectId = baseEcdsaSubjectId;
void validBaseEcdsaSubjectId;

const registrationWalletId = walletIdFromWalletProfile({ walletId: key.walletId });
// @ts-expect-error protocol-local ECDSA DERIVATION subject identity requires its narrow builder.
const invalidBaseEcdsaSubjectId: BaseEcdsaSubjectId = registrationWalletId;
void invalidBaseEcdsaSubjectId;

const invalidLanePolicyWithDuplicateKeyId: EvmFamilyEcdsaSessionLanePolicy = {
  ...lanePolicy,
  // @ts-expect-error session lane policy must use lanePolicy.key.ecdsaThresholdKeyId.
  ecdsaThresholdKeyId: 'ederivation-other-key',
};
void invalidLanePolicyWithDuplicateKeyId;

const keyWithProvisioningSlot: EvmFamilyEcdsaKeyIdentity = {
  ...key,
  // @ts-expect-error runtime key identity rejects the provisioning reservation slot.
  evmFamilySigningKeySlotId: 'wallet-key-localhost',
};
void keyWithProvisioningSlot;

const keyWithTargetScope: EvmFamilyEcdsaKeyIdentity = {
  ...key,
  // @ts-expect-error shared key identity accepts only evm-family scope.
  keyScope: 'tempo',
};
void keyWithTargetScope;

const ownerAddress = toThresholdOwnerAddress('0x1111111111111111111111111111111111111111');
declare function acceptsRawEip1559Sender(address: typeof ownerAddress): void;
acceptsRawEip1559Sender(ownerAddress);

declare const keyHandle: EvmFamilyEcdsaKeyHandle;
declare const publicKeyB64u: ThresholdEcdsaPublicKeyB64u;

const publicFacts: VerifiedEcdsaPublicFacts = {
  kind: 'verified_ecdsa_public_facts',
  keyHandle,
  publicKeyB64u,
  participantIds: key.participantIds,
  thresholdOwnerAddress: key.thresholdOwnerAddress,
};
void publicFacts;

const walletKey = buildEvmFamilyEcdsaWalletKey({
  walletId: key.walletId,
  keyHandle,
  chainTarget: evmTarget,
  ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
  signingRootId: key.signingRootId,
  signingRootVersion: key.signingRootVersion,
  participantIds: key.participantIds,
  thresholdOwnerAddress: key.thresholdOwnerAddress,
  thresholdEcdsaPublicKeyB64u: publicKeyB64u,
});
void walletKey;

const invalidWalletKeyWithIdentityProjection: EvmFamilyEcdsaWalletKey = {
  ...walletKey,
  // @ts-expect-error wallet keys carry keyFacts, not a separate key identity projection.
  key,
};
void invalidWalletKeyWithIdentityProjection;

const invalidWalletKeyWithPublicFactsProjection: EvmFamilyEcdsaWalletKey = {
  ...walletKey,
  // @ts-expect-error wallet keys carry keyFacts, not a separate public facts projection.
  publicFacts,
};
void invalidWalletKeyWithPublicFactsProjection;

const invalidWalletKeyWithDuplicateThresholdKeyId: EvmFamilyEcdsaWalletKey = {
  ...walletKey,
  // @ts-expect-error wallet keys require threshold key ids under keyFacts.
  ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
};
void invalidWalletKeyWithDuplicateThresholdKeyId;

const ecdsaKeyFacts: EvmFamilyEcdsaWalletKeyFacts = walletKey.keyFacts;
void ecdsaKeyFacts;

const ecdsaWalletSignerRecord: EcdsaWalletSignerRecord = {
  kind: 'ecdsa_wallet_signer_record',
  walletKey,
  authBinding: buildPasskeyEcdsaAuthBinding({
    rpId: 'localhost',
    credentialIdB64u: 'credential-id',
  }),
};
void ecdsaWalletSignerRecord;

const invalidEcdsaWalletSignerRecordWithLooseKeyHandle: EcdsaWalletSignerRecord = {
  ...ecdsaWalletSignerRecord,
  // @ts-expect-error signer records carry the complete wallet key, not loose key-handle fields.
  keyHandle,
};
void invalidEcdsaWalletSignerRecordWithLooseKeyHandle;

const invalidPublicFactsWithKeyId: VerifiedEcdsaPublicFacts = {
  ...publicFacts,
  // @ts-expect-error public facts expose only the opaque key handle.
  ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
};
void invalidPublicFactsWithKeyId;

const invalidPublicFactsWithSubject: VerifiedEcdsaPublicFacts = {
  ...publicFacts,
  // @ts-expect-error public facts reject auth/session subject fields.
  subjectId: 'wallet-alice',
};
void invalidPublicFactsWithSubject;

const invalidPublicFactsWithSessionId: VerifiedEcdsaPublicFacts = {
  ...publicFacts,
  // @ts-expect-error public facts reject volatile threshold session ids.
  thresholdSessionId: 'threshold-session-1',
};
void invalidPublicFactsWithSessionId;

const invalidPublicFactsWithTarget: VerifiedEcdsaPublicFacts = {
  ...publicFacts,
  // @ts-expect-error public facts reject concrete signing targets.
  chainTarget: evmTarget,
};
void invalidPublicFactsWithTarget;

const invalidPublicFactsWithAuthMethod: VerifiedEcdsaPublicFacts = {
  ...publicFacts,
  // @ts-expect-error public facts reject auth-method binding.
  authMethod: 'passkey',
};
void invalidPublicFactsWithAuthMethod;

const invalidPublicFactsWithRawPublicKey: VerifiedEcdsaPublicFacts = {
  ...publicFacts,
  // @ts-expect-error public facts require a boundary-verified compressed ECDSA public key.
  publicKeyB64u: 'raw-public-key',
};
void invalidPublicFactsWithRawPublicKey;

const passkeyBinding = buildPasskeyEcdsaAuthBinding({
  rpId: 'localhost',
  credentialIdB64u: 'credential-id',
});
const emailOtpBinding = buildEmailOtpEcdsaAuthBinding({
  authSubjectId: 'google:alice',
  providerId: 'google',
});

const resolvedPasskeyKey = buildResolvedEvmFamilyEcdsaKey({
  walletId: key.walletId,
  publicFacts,
  authBinding: passkeyBinding,
});
const resolvedEmailOtpKey = buildResolvedEvmFamilyEcdsaKey({
  walletId: key.walletId,
  publicFacts,
  authBinding: emailOtpBinding,
});
void resolvedPasskeyKey;
void resolvedEmailOtpKey;

const invalidPasskeyBindingWithProvider: PasskeyEcdsaAuthBinding = {
  ...passkeyBinding,
  // @ts-expect-error passkey auth binding carries rpId only.
  providerId: 'google',
};
void invalidPasskeyBindingWithProvider;

const invalidEmailOtpBindingWithRpId: EmailOtpEcdsaAuthBinding = {
  ...emailOtpBinding,
  // @ts-expect-error Email OTP auth binding carries provider/user identity, not rpId.
  rpId: 'localhost',
};
void invalidEmailOtpBindingWithRpId;

const invalidPasskeyBindingWithOwnerAddress: PasskeyEcdsaAuthBinding = {
  ...passkeyBinding,
  // @ts-expect-error auth bindings reject public owner facts.
  thresholdOwnerAddress: key.thresholdOwnerAddress,
};
void invalidPasskeyBindingWithOwnerAddress;

const invalidEmailOtpBindingWithParticipants: EmailOtpEcdsaAuthBinding = {
  ...emailOtpBinding,
  // @ts-expect-error auth bindings reject public participant facts.
  participantIds: key.participantIds,
};
void invalidEmailOtpBindingWithParticipants;

const invalidResolvedKeyWithSharedIdentity: ResolvedEvmFamilyEcdsaKey = {
  ...resolvedPasskeyKey,
  // @ts-expect-error resolved key facade rejects broad shared key identity.
  key,
};
void invalidResolvedKeyWithSharedIdentity;

const invalidResolvedKeyWithSigningRoot: ResolvedEvmFamilyEcdsaKey = {
  ...resolvedPasskeyKey,
  // @ts-expect-error resolved key facade exposes public facts through keyHandle only.
  signingRootId: key.signingRootId,
};
void invalidResolvedKeyWithSigningRoot;

const invalidResolvedKeyWithSubjectId: ResolvedEvmFamilyEcdsaKey = {
  ...resolvedPasskeyKey,
  // @ts-expect-error resolved key facade derives the base ECDSA subject from wallet identity.
  subjectId: 'wallet-alice',
};
void invalidResolvedKeyWithSubjectId;

declare const roleLocalReadyRecord: EcdsaRoleLocalReadyRecord;

const validOpaqueRoleLocalClientState = {
  kind: 'role_local_ready',
  artifactKind: 'ecdsa-derivation-role-local-client-state',
  stateBlob: roleLocalReadyRecord.stateBlob,
  publicFacts: roleLocalReadyRecord.publicFacts,
} satisfies ThresholdEcdsaDerivationRoleLocalClientState;
void validOpaqueRoleLocalClientState;

const invalidMetadataBackendBindingWithMaterial = {
  materialKind: 'metadata_only',
  relayerKeyId: 'relayer-key',
  clientVerifyingShareB64u: 'client-verifying-share',
  stateBlob: roleLocalReadyRecord.stateBlob,
};
// @ts-expect-error metadata-only backend bindings reject signing material.
void (invalidMetadataBackendBindingWithMaterial satisfies ThresholdEcdsaBackendBinding);

declare const hydratedSignerMaterial: HydratedEcdsaSignerMaterial;

const invalidHydratedMaterialWithCredential = {
  ...hydratedSignerMaterial,
  // @ts-expect-error hydrated material cannot carry an authorization credential.
  credential: { kind: 'wallet_session_opaque', walletSessionToken: 'wallet-session-token' },
} satisfies HydratedEcdsaSignerMaterial;
void invalidHydratedMaterialWithCredential;

const invalidHydratedMaterialWithAuthorization = {
  ...hydratedSignerMaterial,
  // @ts-expect-error hydrated material cannot carry reusable or step-up authority.
  authorization: { kind: 'reusable_wallet_session', wallet_session_id: 'wallet-session' },
} satisfies HydratedEcdsaSignerMaterial;
void invalidHydratedMaterialWithAuthorization;

const invalidHydratedMaterialWithThresholdSession = {
  ...hydratedSignerMaterial,
  // @ts-expect-error auth-neutral material is not identified by a threshold session.
  thresholdSessionId: 'threshold-session',
} satisfies HydratedEcdsaSignerMaterial;
void invalidHydratedMaterialWithThresholdSession;

const invalidHydratedMaterialWithReusableAllowance = {
  ...hydratedSignerMaterial,
  // @ts-expect-error auth-neutral material carries no reusable-session allowance.
  remainingUses: 3,
} satisfies HydratedEcdsaSignerMaterial;
void invalidHydratedMaterialWithReusableAllowance;

const invalidHydratedMaterialWithReusableExpiry = {
  ...hydratedSignerMaterial,
  // @ts-expect-error auth-neutral material carries no reusable-session expiry.
  expiresAtMs: 1,
} satisfies HydratedEcdsaSignerMaterial;
void invalidHydratedMaterialWithReusableExpiry;

export {};

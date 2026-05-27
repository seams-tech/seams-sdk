import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaWalletKey,
  buildEvmFamilyEcdsaSessionLane,
  buildEvmFamilyEcdsaSessionLanePolicy,
  buildEmailOtpEcdsaAuthBinding,
  buildPasskeyEcdsaAuthBinding,
  buildKnownReadyThresholdEcdsaSessionPolicy,
  buildResolvedEvmFamilyEcdsaKey,
  buildThresholdEcdsaSessionTransportAuth,
  deriveBaseEcdsaSubjectIdFromWalletId,
  toThresholdOwnerAddress,
  type BaseEcdsaSubjectId,
  type EcdsaKeyFacts,
  type EcdsaWalletSignerRecord,
  type EvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyIdentity,
  type EvmFamilyEcdsaSessionLane,
  type EvmFamilyEcdsaSessionLanePolicy,
  type EvmFamilyEcdsaWalletKey,
  type DurableEvmFamilyEcdsaPublicFactsRecord,
  type EmailOtpEcdsaAuthBinding,
  type PasskeyEcdsaAuthBinding,
  type ReadyEcdsaSignerSession,
  type ReadyThresholdEcdsaSession,
  type ReadyThresholdEcdsaSessionPolicy,
  type ReadyEvmFamilyEcdsaMaterial,
  type ResolvedEvmFamilyEcdsaKey,
  type ThresholdEcdsaPublicKeyB64u,
  type ThresholdEcdsaSessionTransportAuth,
  type VerifiedEcdsaPublicFacts,
} from './evmFamilyEcdsaIdentity';
import { walletSubjectIdFromWalletProfile } from '../../interfaces/ecdsaChainTarget';

const evmTarget = {
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

const invalidKeyWithSubjectId: EvmFamilyEcdsaKeyIdentity = {
  ...key,
  // @ts-expect-error shared key identity derives the base ECDSA subject from wallet identity.
  subjectId: 'wallet-subject-alice',
};
void invalidKeyWithSubjectId;

const baseEcdsaSubjectId = deriveBaseEcdsaSubjectIdFromWalletId(key.walletId);
const validBaseEcdsaSubjectId: BaseEcdsaSubjectId = baseEcdsaSubjectId;
void validBaseEcdsaSubjectId;

const registrationWalletSubjectId = walletSubjectIdFromWalletProfile({ walletId: key.walletId });
// @ts-expect-error protocol-local ECDSA HSS subject identity requires its narrow builder.
const invalidBaseEcdsaSubjectId: BaseEcdsaSubjectId = registrationWalletSubjectId;
void invalidBaseEcdsaSubjectId;

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
  rpId: key.rpId,
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

const ecdsaKeyFacts: EcdsaKeyFacts = walletKey.keyFacts;
void ecdsaKeyFacts;

const ecdsaWalletSignerRecord: EcdsaWalletSignerRecord = {
  kind: 'ecdsa_wallet_signer_record',
  walletKey,
  authBinding: buildPasskeyEcdsaAuthBinding({ rpId: key.rpId }),
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
  subjectId: 'wallet-subject-alice',
};
void invalidPublicFactsWithSubject;

const invalidPublicFactsWithSessionId: VerifiedEcdsaPublicFacts = {
  ...publicFacts,
  // @ts-expect-error public facts reject volatile threshold session ids.
  thresholdSessionId: lane.thresholdSessionId,
};
void invalidPublicFactsWithSessionId;

const invalidPublicFactsWithTarget: VerifiedEcdsaPublicFacts = {
  ...publicFacts,
  // @ts-expect-error public facts reject concrete signing targets.
  chainTarget: lane.chainTarget,
};
void invalidPublicFactsWithTarget;

const invalidPublicFactsWithAuthMethod: VerifiedEcdsaPublicFacts = {
  ...publicFacts,
  // @ts-expect-error public facts reject auth-method binding.
  authMethod: lane.authMethod,
};
void invalidPublicFactsWithAuthMethod;

const invalidPublicFactsWithRawPublicKey: VerifiedEcdsaPublicFacts = {
  ...publicFacts,
  // @ts-expect-error public facts require a boundary-verified compressed ECDSA public key.
  publicKeyB64u: 'raw-public-key',
};
void invalidPublicFactsWithRawPublicKey;

const durablePublicFactsRecord: DurableEvmFamilyEcdsaPublicFactsRecord = {
  ecdsaRestore: {
    keyHandle,
    thresholdEcdsaPublicKeyB64u: publicKeyB64u,
    participantIds: key.participantIds,
    ethereumAddress: key.thresholdOwnerAddress,
  },
};
void durablePublicFactsRecord;

const invalidDurablePublicFactsRecordWithSigningRoot: DurableEvmFamilyEcdsaPublicFactsRecord = {
  ...durablePublicFactsRecord,
  // @ts-expect-error durable public facts reject signing-root identity.
  signingRootId: key.signingRootId,
};
void invalidDurablePublicFactsRecordWithSigningRoot;

const invalidDurablePublicFactsRecordWithThresholdKeyId: DurableEvmFamilyEcdsaPublicFactsRecord = {
  ecdsaRestore: {
    ...durablePublicFactsRecord.ecdsaRestore,
    // @ts-expect-error durable public facts reject threshold-key identity.
    ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
  },
};
void invalidDurablePublicFactsRecordWithThresholdKeyId;

const passkeyBinding = buildPasskeyEcdsaAuthBinding({ rpId: 'localhost' });
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

const jwtTransportAuth = buildThresholdEcdsaSessionTransportAuth({
  thresholdSessionKind: 'jwt',
  thresholdSessionAuthToken: 'threshold-auth-token',
});
void jwtTransportAuth;

const knownReadySessionPolicy = buildKnownReadyThresholdEcdsaSessionPolicy({
  remainingUses: 1,
  expiresAtMs: 1_900_000_000_000,
});
void knownReadySessionPolicy;

// @ts-expect-error known ready threshold-session policy requires remainingUses.
const invalidKnownReadySessionPolicyMissingUses: ReadyThresholdEcdsaSessionPolicy = {
  kind: 'known_threshold_ecdsa_session_policy',
  expiresAtMs: 1_900_000_000_000,
};
void invalidKnownReadySessionPolicyMissingUses;

const invalidReadySessionWithAuth: ReadyThresholdEcdsaSession = {
  kind: 'ready_threshold_ecdsa_session',
  walletSigningSessionId: lane.walletSigningSessionId,
  thresholdSessionId: lane.thresholdSessionId,
  policy: knownReadySessionPolicy,
  // @ts-expect-error ready threshold sessions carry auth in signer transport.
  thresholdSessionAuthToken: 'threshold-auth-token',
};
void invalidReadySessionWithAuth;

// @ts-expect-error jwt threshold-session transport auth requires a token.
const invalidJwtTransportAuth: ThresholdEcdsaSessionTransportAuth = {
  kind: 'jwt_threshold_session_auth',
};
void invalidJwtTransportAuth;

// @ts-expect-error cookie threshold-session transport auth rejects token fields.
const invalidCookieTransportAuth: ThresholdEcdsaSessionTransportAuth = {
  kind: 'cookie_threshold_session_auth',
  thresholdSessionAuthToken: jwtTransportAuth.thresholdSessionAuthToken,
};
void invalidCookieTransportAuth;

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
  subjectId: 'wallet-subject-alice',
};
void invalidResolvedKeyWithSubjectId;

const readyMaterialRecordOnly: ReadyEvmFamilyEcdsaMaterial = {
  kind: 'ready_evm_family_ecdsa_material',
  key,
  lane,
  record: {} as ThresholdEcdsaSessionRecord,
  signingKeyContext: {
    ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
    signingRootId: key.signingRootId,
    signingRootVersion: key.signingRootVersion,
    participantIds: key.participantIds,
  },
  cachedExportArtifact: null,
};
void readyMaterialRecordOnly;

const invalidReadyMaterialWithKeyRef = {
  ...readyMaterialRecordOnly,
  // @ts-expect-error ready material derives key refs at signer/export boundaries.
  keyRef: {} as ThresholdEcdsaSecp256k1KeyRef,
} satisfies ReadyEvmFamilyEcdsaMaterial;
void invalidReadyMaterialWithKeyRef;

// @ts-expect-error ready material requires a record.
const readyMaterialMissingRecord: ReadyEvmFamilyEcdsaMaterial = {
  kind: 'ready_evm_family_ecdsa_material',
  key,
  lane,
  signingKeyContext: {
    ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
    signingRootId: key.signingRootId,
    signingRootVersion: key.signingRootVersion,
    participantIds: key.participantIds,
  },
  cachedExportArtifact: null,
};
void readyMaterialMissingRecord;

// @ts-expect-error ready material owns cached export artifact provenance.
const readyMaterialMissingCachedExportArtifact: ReadyEvmFamilyEcdsaMaterial = {
  kind: 'ready_evm_family_ecdsa_material',
  key,
  lane,
  record: {} as ThresholdEcdsaSessionRecord,
  signingKeyContext: {
    ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
    signingRootId: key.signingRootId,
    signingRootVersion: key.signingRootVersion,
    participantIds: key.participantIds,
  },
};
void readyMaterialMissingCachedExportArtifact;

// @ts-expect-error ready material owns signing-key routing context.
const readyMaterialMissingSigningKeyContext: ReadyEvmFamilyEcdsaMaterial = {
  kind: 'ready_evm_family_ecdsa_material',
  key,
  lane,
  record: {} as ThresholdEcdsaSessionRecord,
  cachedExportArtifact: null,
};
void readyMaterialMissingSigningKeyContext;

declare const readyMaterial: ReadyEvmFamilyEcdsaMaterial;

const invalidReadyMaterialWithSubjectId = {
  ...readyMaterial,
  // @ts-expect-error ready material derives subject from key/lane identity.
  subjectId: 'wallet-subject-alice',
} satisfies ReadyEvmFamilyEcdsaMaterial;
void invalidReadyMaterialWithSubjectId;

declare const signerSession: ReadyEcdsaSignerSession;
void signerSession;

const invalidSignerSessionWithKeyRef: ReadyEcdsaSignerSession = {
  ...signerSession,
  // @ts-expect-error signer sessions reject broad key refs.
  keyRef: {} as ThresholdEcdsaSecp256k1KeyRef,
};
void invalidSignerSessionWithKeyRef;

const invalidSignerSessionWithRawToken: ReadyEcdsaSignerSession = {
  ...signerSession,
  // @ts-expect-error signer sessions carry threshold auth inside transport.auth.
  thresholdSessionAuthToken: 'threshold-auth-token',
};
void invalidSignerSessionWithRawToken;

const invalidSignerSessionWithInlineShare: ReadyEcdsaSignerSession = {
  ...signerSession,
  // @ts-expect-error signer sessions carry client share inside clientShare.
  clientAdditiveShare32B64u: 'client-share',
};
void invalidSignerSessionWithInlineShare;

// @ts-expect-error signer sessions require transport material.
const signerSessionMissingTransport: ReadyEcdsaSignerSession = {
  kind: 'ready_ecdsa_signer_session',
  publicFacts,
  chainTarget: evmTarget,
  session: signerSession.session,
  clientShare: signerSession.clientShare,
};
void signerSessionMissingTransport;

// @ts-expect-error signer sessions require client-share material.
const signerSessionMissingClientShare: ReadyEcdsaSignerSession = {
  kind: 'ready_ecdsa_signer_session',
  publicFacts,
  chainTarget: evmTarget,
  session: signerSession.session,
  transport: signerSession.transport,
};
void signerSessionMissingClientShare;

const invalidSignerSessionWithExportArtifact: ReadyEcdsaSignerSession = {
  ...signerSession,
  // @ts-expect-error signing-only material rejects export artifacts.
  exportArtifact: {},
};
void invalidSignerSessionWithExportArtifact;

const invalidSignerSessionWithSubjectId: ReadyEcdsaSignerSession = {
  ...signerSession,
  // @ts-expect-error signer sessions derive subject from the shared key identity.
  subjectId: 'wallet-subject-alice',
};
void invalidSignerSessionWithSubjectId;

export {};

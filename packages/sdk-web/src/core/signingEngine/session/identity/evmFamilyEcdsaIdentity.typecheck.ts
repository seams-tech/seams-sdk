import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type {
  ThresholdEcdsaBackendBinding,
  ThresholdEcdsaHssRoleLocalClientState,
  ThresholdEcdsaSecp256k1KeyRef,
} from '../../interfaces/signing';
import type { EcdsaRoleLocalReadyRecord } from '@/core/platform/types';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaWalletKey,
  buildEvmFamilyEcdsaSessionLane,
  buildEvmFamilyEcdsaSessionLanePolicy,
  buildEmailOtpEcdsaAuthBinding,
  buildEcdsaWalletSessionTransportAuth,
  buildPasskeyEcdsaAuthBinding,
  buildKnownReadyThresholdEcdsaSessionPolicy,
  buildResolvedEvmFamilyEcdsaKey,
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
  type EcdsaWalletSessionTransportAuth,
  type PasskeyEcdsaAuthBinding,
  type ReadyEcdsaSignerSession,
  type ReadyRouterAbEcdsaHssNormalSigning,
  type ReadyThresholdEcdsaSignerTransport,
  type ReadyThresholdEcdsaSession,
  type ReadyThresholdEcdsaSessionPolicy,
  type ReadyEvmFamilyEcdsaMaterial,
  type ResolvedEvmFamilyEcdsaKey,
  type ThresholdEcdsaPublicKeyB64u,
  type VerifiedEcdsaPublicFacts,
  type WalletSessionJwtTransportAuth,
} from './evmFamilyEcdsaIdentity';
import { walletIdFromWalletProfile } from '../../interfaces/ecdsaChainTarget';
import type { RouterAbEcdsaHssNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaHss';

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
  signingGrantId: 'signing-grant-1',
  walletSessionAuth: {
    kind: 'wallet_session_jwt',
    walletSessionJwt: 'wallet-session-jwt',
  },
  remainingUses: 1,
  expiresAtMs: 1_900_000_000_000,
});

const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
  chainTarget: evmTarget,
  thresholdSessionId: 'threshold-session-1',
  signingGrantId: 'signing-grant-1',
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
  subjectId: 'wallet-alice',
};
void invalidKeyWithSubjectId;

const baseEcdsaSubjectId = deriveBaseEcdsaSubjectIdFromWalletId(key.walletId);
const validBaseEcdsaSubjectId: BaseEcdsaSubjectId = baseEcdsaSubjectId;
void validBaseEcdsaSubjectId;

const registrationWalletId = walletIdFromWalletProfile({ walletId: key.walletId });
// @ts-expect-error protocol-local ECDSA HSS subject identity requires its narrow builder.
const invalidBaseEcdsaSubjectId: BaseEcdsaSubjectId = registrationWalletId;
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
  signingGrantId: lane.signingGrantId,
  walletSessionAuth: lane.walletSessionAuth,
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
  subjectId: 'wallet-alice',
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

const walletSessionJwtTransportAuth = buildEcdsaWalletSessionTransportAuth({
  kind: 'wallet_session_jwt',
  walletSessionJwt: 'wallet-session-jwt',
});
void walletSessionJwtTransportAuth;
const validWalletSessionJwtTransportAuth: WalletSessionJwtTransportAuth =
  walletSessionJwtTransportAuth;
void validWalletSessionJwtTransportAuth;

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
  signingGrantId: lane.signingGrantId,
  thresholdSessionId: lane.thresholdSessionId,
  policy: knownReadySessionPolicy,
  // @ts-expect-error ready threshold sessions carry auth in Router A/B signer credentials.
  walletSessionAuth: walletSessionJwtTransportAuth,
};
void invalidReadySessionWithAuth;

// @ts-expect-error Wallet Session JWT auth requires a token.
const invalidWalletSessionJwtTransportAuth: EcdsaWalletSessionTransportAuth = {
  kind: 'wallet_session_jwt',
};
void invalidWalletSessionJwtTransportAuth;

const invalidCookieTransportAuth: EcdsaWalletSessionTransportAuth = {
  // @ts-expect-error ECDSA Wallet Session transport auth is bearer-JWT only.
  kind: 'browser_cookie',
  walletSessionJwt: walletSessionJwtTransportAuth.walletSessionJwt,
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
  subjectId: 'wallet-alice',
};
void invalidResolvedKeyWithSubjectId;

const readyMaterialRecordOnly: ReadyEvmFamilyEcdsaMaterial = {
  kind: 'ready_evm_family_ecdsa_material',
  key,
  lane,
  record: {} as ThresholdEcdsaSessionRecord,
  signingKeyContext: {
    ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
    participantIds: key.participantIds,
  },
  cachedExportArtifact: null,
};
void readyMaterialRecordOnly;

const invalidReadyMaterialSigningKeyContextWithSigningRoot = {
  ...readyMaterialRecordOnly,
  signingKeyContext: {
    ...readyMaterialRecordOnly.signingKeyContext,
    // @ts-expect-error ready signing-key context derives signing root from material key.
    signingRootId: key.signingRootId,
  },
} satisfies ReadyEvmFamilyEcdsaMaterial;
void invalidReadyMaterialSigningKeyContextWithSigningRoot;

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
  subjectId: 'wallet-alice',
} satisfies ReadyEvmFamilyEcdsaMaterial;
void invalidReadyMaterialWithSubjectId;

declare const signerSession: ReadyEcdsaSignerSession;
void signerSession;
declare const routerAbEcdsaHssNormalSigningState: RouterAbEcdsaHssNormalSigningStateV1;

const invalidSignerSessionWithKeyRef: ReadyEcdsaSignerSession = {
  ...signerSession,
  // @ts-expect-error signer sessions reject broad key refs.
  keyRef: {} as ThresholdEcdsaSecp256k1KeyRef,
};
void invalidSignerSessionWithKeyRef;

const invalidSignerSessionWithRawToken: ReadyEcdsaSignerSession = {
  ...signerSession,
  // @ts-expect-error Router A/B signer sessions carry bearer auth inside the Router A/B credential.
  walletSessionJwt: 'wallet-session-jwt',
};
void invalidSignerSessionWithRawToken;

// @ts-expect-error Router A/B ECDSA-HSS ready signer sessions require parsed normal-signing state.
const signerSessionMissingRouterAbState: ReadyEcdsaSignerSession = {
  kind: 'ready_ecdsa_signer_session',
  publicFacts,
  chainTarget: evmTarget,
  session: signerSession.session,
  transport: signerSession.transport,
  clientShare: signerSession.clientShare,
};
void signerSessionMissingRouterAbState;

const invalidReadyTransportWithCookieAuth: ReadyThresholdEcdsaSignerTransport = {
  ...signerSession.transport,
  // @ts-expect-error ready transport does not carry auth; Router A/B credential owns it.
  auth: { kind: 'browser_cookie' },
};
void invalidReadyTransportWithCookieAuth;

const invalidReadyTransportWithRawClientVerifier: ReadyThresholdEcdsaSignerTransport = {
  ...signerSession.transport,
  // @ts-expect-error ready transport carries ECDSA verifier material through signingMaterial.
  clientVerifyingShareB64u: 'raw-client-verifier',
};
void invalidReadyTransportWithRawClientVerifier;

const invalidReadyTransportWithLooseThresholdKeyId: ReadyThresholdEcdsaSignerTransport = {
  ...signerSession.transport,
  // @ts-expect-error ready transport derives threshold key identity from signingMaterial.
  ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
};
void invalidReadyTransportWithLooseThresholdKeyId;

const invalidReadyTransportWithLooseSigningRoot: ReadyThresholdEcdsaSignerTransport = {
  ...signerSession.transport,
  // @ts-expect-error ready transport derives signing-root identity from signingMaterial.
  signingRootId: key.signingRootId,
};
void invalidReadyTransportWithLooseSigningRoot;

const ecdsaSigningMaterialThresholdKeyId: string =
  signerSession.transport.signingMaterial.ecdsaThresholdKeyId;
const ecdsaSigningMaterialSigningRootId: string =
  signerSession.transport.signingMaterial.signingRootId;
const ecdsaSigningMaterialSigningRootVersion: string =
  signerSession.transport.signingMaterial.signingRootVersion;
void ecdsaSigningMaterialThresholdKeyId;
void ecdsaSigningMaterialSigningRootId;
void ecdsaSigningMaterialSigningRootVersion;

const invalidSigningMaterialWithKeyHandle = {
  ...signerSession.transport.signingMaterial,
  // @ts-expect-error parsed Router A/B signing-material refs reject loose key handles.
  keyHandle,
} satisfies ReadyThresholdEcdsaSignerTransport['signingMaterial'];
void invalidSigningMaterialWithKeyHandle;

const invalidRouterAbReadyWithCookieCredential: ReadyRouterAbEcdsaHssNormalSigning = {
  kind: 'router_ab_ecdsa_hss_normal_signing_ready_v1',
  state: routerAbEcdsaHssNormalSigningState,
  // @ts-expect-error Router A/B ECDSA-HSS normal signing credentials are bearer JWTs.
  credential: { kind: 'cookie' },
  walletSessionSessionId: 'wallet-session-1',
};
void invalidRouterAbReadyWithCookieCredential;

const invalidSignerSessionWithRawRouterAbState = {
  ...signerSession,
  // @ts-expect-error broad spreads cannot replace ready Router A/B state with raw boundary state.
  routerAbEcdsaHssNormalSigning: routerAbEcdsaHssNormalSigningState,
} satisfies ReadyEcdsaSignerSession;
void invalidSignerSessionWithRawRouterAbState;

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

declare const roleLocalReadyRecord: EcdsaRoleLocalReadyRecord;

type OldRoleLocalReadyStateBlobShare = {
  kind: 'role_local_ready_state_blob';
  stateBlob: EcdsaRoleLocalReadyRecord['stateBlob'];
  ecdsaRoleLocalReadyRecord: EcdsaRoleLocalReadyRecord;
};

const oldRoleLocalReadyStateBlobShare = {
  kind: 'role_local_ready_state_blob',
  stateBlob: roleLocalReadyRecord.stateBlob,
  ecdsaRoleLocalReadyRecord: roleLocalReadyRecord,
} satisfies OldRoleLocalReadyStateBlobShare;

// @ts-expect-error ready signer sessions require worker-owned role-local material handles.
const invalidRawRoleLocalBlobClientShare: ReadyEcdsaSignerSession['clientShare'] =
  oldRoleLocalReadyStateBlobShare;
void invalidRawRoleLocalBlobClientShare;

const validOpaqueRoleLocalClientState = {
  kind: 'role_local_ready',
  artifactKind: 'ecdsa-hss-role-local-client-state',
  stateBlob: roleLocalReadyRecord.stateBlob,
  publicFacts: roleLocalReadyRecord.publicFacts,
} satisfies ThresholdEcdsaHssRoleLocalClientState;
void validOpaqueRoleLocalClientState;

const invalidMetadataBackendBindingWithMaterial = {
  materialKind: 'metadata_only',
  relayerKeyId: 'relayer-key',
  clientVerifyingShareB64u: 'client-verifying-share',
  stateBlob: roleLocalReadyRecord.stateBlob,
};
// @ts-expect-error metadata-only backend bindings reject signing material.
void (invalidMetadataBackendBindingWithMaterial satisfies ThresholdEcdsaBackendBinding);

const invalidSignerSessionWithSubjectId: ReadyEcdsaSignerSession = {
  ...signerSession,
  // @ts-expect-error signer sessions derive subject from the shared key identity.
  subjectId: 'wallet-alice',
};
void invalidSignerSessionWithSubjectId;

export {};

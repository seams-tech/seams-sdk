import type {
  EvmFamilyKeyFingerprint,
  ReadyEcdsaSignerSession,
  VerifiedEcdsaPublicFacts,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type {
  AuthFactorIdentity,
  EmailOtpWalletAuthAuthority,
  PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type {
  EcdsaExportLane,
  FreshEmailOtpEcdsaExportMaterialNeedsChallenge,
  FreshEmailOtpEcdsaExportMaterialRouteAuthReady,
  ReadyEcdsaExportLane,
  ReadyThresholdEcdsaExportMaterial,
} from './ecdsaExportMaterial';

declare const signerSession: ReadyEcdsaSignerSession;
declare const publicFacts: VerifiedEcdsaPublicFacts;
declare const record: ThresholdEcdsaSessionRecord;
declare const keyRef: unknown;
declare const evmFamilyKeyFingerprint: EvmFamilyKeyFingerprint;
declare const runtimePolicyScope: ThresholdRuntimePolicyScope;
declare const committedLane: EcdsaExportLane<EmailOtpWalletAuthAuthority>;
declare const readyCommittedLane: ReadyEcdsaExportLane<EmailOtpWalletAuthAuthority>;
declare const readyPasskeyCommittedLane: ReadyEcdsaExportLane<PasskeyWalletAuthAuthority>;

// @ts-expect-error post-finalize ECDSA export lanes require wallet-bound authority, not pure factor identity.
type InvalidFactorBackedEcdsaExportLane = EcdsaExportLane<AuthFactorIdentity>;
void ({} as InvalidFactorBackedEcdsaExportLane);

const exportMaterial: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  authMethod: 'passkey',
  signerSession,
  publicFacts,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
  committedLane: readyPasskeyCommittedLane,
};
void exportMaterial;

// @ts-expect-error ready passkey export material requires the committed lane.
const passkeyExportMaterialWithoutCommittedLane: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  authMethod: 'passkey',
  signerSession,
  publicFacts,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
};
void passkeyExportMaterialWithoutCommittedLane;

// @ts-expect-error ready export material requires signer-session material.
const exportMaterialMissingSignerSession: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  authMethod: 'passkey',
  publicFacts,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
  committedLane: readyPasskeyCommittedLane,
};
void exportMaterialMissingSignerSession;

// @ts-expect-error ready export material requires verified public facts.
const exportMaterialMissingPublicFacts: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  authMethod: 'passkey',
  signerSession,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
  committedLane: readyPasskeyCommittedLane,
};
void exportMaterialMissingPublicFacts;

const exportMaterialWithThresholdKeyId: ReadyThresholdEcdsaExportMaterial = {
  ...exportMaterial,
  // @ts-expect-error ready export material carries keyHandle through public facts.
  ecdsaThresholdKeyId: 'ehss-key-1',
};
void exportMaterialWithThresholdKeyId;

const exportMaterialWithBroadReadyMaterial: ReadyThresholdEcdsaExportMaterial = {
  ...exportMaterial,
  // @ts-expect-error export material rejects broad ready signing material.
  readyMaterial: {},
};
void exportMaterialWithBroadReadyMaterial;

const emailOtpExportMaterial: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  authMethod: 'email_otp',
  signerSession,
  publicFacts,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
  committedLane: readyCommittedLane,
};
void emailOtpExportMaterial;

// @ts-expect-error ready Email OTP export material requires the committed lane.
const emailOtpExportMaterialWithoutCommittedLane: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  authMethod: 'email_otp',
  signerSession,
  publicFacts,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
};
void emailOtpExportMaterialWithoutCommittedLane;

const readyExportMaterialWithLooseRecord: ReadyThresholdEcdsaExportMaterial = {
  ...exportMaterial,
  // @ts-expect-error ready export material carries session records through committed lanes.
  record,
};
void readyExportMaterialWithLooseRecord;

const exportMaterialWithBroadKeyRef: ReadyThresholdEcdsaExportMaterial = {
  ...exportMaterial,
  // @ts-expect-error export material exposes signerSession instead of broad key refs.
  keyRef,
};
void exportMaterialWithBroadKeyRef;

const freshNeedsChallengeMaterial: FreshEmailOtpEcdsaExportMaterialNeedsChallenge = {
  kind: 'fresh_email_otp_needs_challenge',
  providerIdentityMode: 'explicit_provider_user',
  providerUserId: 'google:alice',
  chainTarget: record.chainTarget,
  publicFacts,
  emailHashHex: 'email-hash',
  runtimePolicyScope,
};
void freshNeedsChallengeMaterial;

// @ts-expect-error fresh Email OTP export material requires runtimePolicyScope.
const freshNeedsChallengeMissingRuntimeScope: FreshEmailOtpEcdsaExportMaterialNeedsChallenge = {
  kind: 'fresh_email_otp_needs_challenge',
  providerIdentityMode: 'wallet_session_subject',
  chainTarget: record.chainTarget,
  publicFacts,
  emailHashHex: 'email-hash',
};
void freshNeedsChallengeMissingRuntimeScope;

// @ts-expect-error wallet-session subject branch rejects explicit provider identity.
const freshNeedsChallengeWalletWithProviderUser: FreshEmailOtpEcdsaExportMaterialNeedsChallenge = {
  kind: 'fresh_email_otp_needs_challenge',
  providerIdentityMode: 'wallet_session_subject',
  chainTarget: record.chainTarget,
  publicFacts,
  emailHashHex: 'email-hash',
  runtimePolicyScope,
  providerUserId: 'google:alice',
};
void freshNeedsChallengeWalletWithProviderUser;

const freshRouteAuthReadyMaterial: FreshEmailOtpEcdsaExportMaterialRouteAuthReady = {
  kind: 'fresh_email_otp_route_auth_ready',
  chainTarget: record.chainTarget,
  publicFacts,
  runtimePolicyScope,
  committedLane,
};
void freshRouteAuthReadyMaterial;

// @ts-expect-error route-auth-ready fresh material requires the committed lane.
const freshRouteAuthReadyWithoutCommittedLane: FreshEmailOtpEcdsaExportMaterialRouteAuthReady = {
  kind: 'fresh_email_otp_route_auth_ready',
  chainTarget: record.chainTarget,
  publicFacts,
  runtimePolicyScope,
};
void freshRouteAuthReadyWithoutCommittedLane;

const freshRouteAuthReadyWithLooseRecord: FreshEmailOtpEcdsaExportMaterialRouteAuthReady = {
  ...freshRouteAuthReadyMaterial,
  // @ts-expect-error route-auth-ready fresh material rejects loose session records.
  record,
};
void freshRouteAuthReadyWithLooseRecord;

export {};

import type {
  EvmFamilyKeyFingerprint,
  ReadyEcdsaSignerSession,
  VerifiedEcdsaPublicFacts,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type {
  FreshEmailOtpEcdsaExportMaterialNeedsChallenge,
  FreshEmailOtpEcdsaExportMaterialRouteAuthReady,
  ReadyThresholdEcdsaExportMaterial,
} from './ecdsaExportMaterial';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';

declare const signerSession: ReadyEcdsaSignerSession;
declare const publicFacts: VerifiedEcdsaPublicFacts;
declare const record: ThresholdEcdsaSessionRecord;
declare const keyRef: unknown;
declare const evmFamilyKeyFingerprint: EvmFamilyKeyFingerprint;
declare const runtimePolicyScope: ThresholdRuntimePolicyScope;
declare const authLane: EmailOtpAuthLane;

const exportMaterial: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  signerSession,
  publicFacts,
  record,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
};
void exportMaterial;

// @ts-expect-error ready export material requires signer-session material.
const exportMaterialMissingSignerSession: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  publicFacts,
  record,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
};
void exportMaterialMissingSignerSession;

// @ts-expect-error ready export material requires verified public facts.
const exportMaterialMissingPublicFacts: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  signerSession,
  record,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
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

const exportMaterialWithBroadKeyRef: ReadyThresholdEcdsaExportMaterial = {
  ...exportMaterial,
  // @ts-expect-error export material exposes signerSession instead of broad key refs.
  keyRef,
};
void exportMaterialWithBroadKeyRef;

const freshNeedsChallengeMaterial: FreshEmailOtpEcdsaExportMaterialNeedsChallenge = {
  kind: 'fresh_email_otp_needs_challenge',
  authSubjectMode: 'explicit_auth_subject',
  authSubjectId: 'google:alice',
  chainTarget: record.chainTarget,
  publicFacts,
  runtimePolicyScope,
};
void freshNeedsChallengeMaterial;

// @ts-expect-error fresh Email OTP export material requires runtimePolicyScope.
const freshNeedsChallengeMissingRuntimeScope: FreshEmailOtpEcdsaExportMaterialNeedsChallenge = {
  kind: 'fresh_email_otp_needs_challenge',
  authSubjectMode: 'wallet_session_subject',
  chainTarget: record.chainTarget,
  publicFacts,
};
void freshNeedsChallengeMissingRuntimeScope;

// @ts-expect-error wallet-session subject branch rejects explicit auth subjects.
const freshNeedsChallengeWalletWithAuthSubject: FreshEmailOtpEcdsaExportMaterialNeedsChallenge = {
  kind: 'fresh_email_otp_needs_challenge',
  authSubjectMode: 'wallet_session_subject',
  chainTarget: record.chainTarget,
  publicFacts,
  runtimePolicyScope,
  authSubjectId: 'google:alice',
};
void freshNeedsChallengeWalletWithAuthSubject;

const freshRouteAuthReadyMaterial: FreshEmailOtpEcdsaExportMaterialRouteAuthReady = {
  kind: 'fresh_email_otp_route_auth_ready',
  chainTarget: record.chainTarget,
  publicFacts,
  runtimePolicyScope,
  record,
  authLane,
};
void freshRouteAuthReadyMaterial;

// @ts-expect-error route-auth-ready fresh material requires the route auth lane.
const freshRouteAuthReadyWithoutAuthLane: FreshEmailOtpEcdsaExportMaterialRouteAuthReady = {
  kind: 'fresh_email_otp_route_auth_ready',
  chainTarget: record.chainTarget,
  publicFacts,
  runtimePolicyScope,
  record,
};
void freshRouteAuthReadyWithoutAuthLane;

export {};

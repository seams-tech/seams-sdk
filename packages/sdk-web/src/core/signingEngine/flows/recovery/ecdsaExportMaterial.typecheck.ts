import type {
  EvmFamilyKeyFingerprint,
  ReadyEcdsaSignerSession,
  VerifiedEcdsaPublicFacts,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type {
  PersistedEcdsaRoleLocalMaterial,
  ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { ExactEcdsaSigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';
import type {
  EcdsaExportOperationAuthorization,
  EmailOtpEcdsaExportAuthLane,
  EmailOtpEcdsaExportSessionRecord,
  EmailOtpEcdsaPublicReauthExportAuthority,
  ExactEcdsaExportSession,
  FreshEmailOtpEcdsaExportMaterial,
  FreshPasskeyEcdsaExportMaterial,
  PasskeyEcdsaExportBootstrapContext,
  ReadyThresholdEcdsaExportMaterial,
} from './ecdsaExportMaterial';

declare const signerSession: ReadyEcdsaSignerSession;
declare const publicFacts: VerifiedEcdsaPublicFacts;
declare const record: ThresholdEcdsaSessionRecord;
declare const emailOtpRecord: EmailOtpEcdsaExportSessionRecord;
declare const existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
declare const keyRef: unknown;
declare const evmFamilyKeyFingerprint: EvmFamilyKeyFingerprint;
declare const runtimePolicyScope: ThresholdRuntimePolicyScope;
declare const laneIdentity: ExactEcdsaSigningLaneIdentity;
declare const authLane: EmailOtpEcdsaExportAuthLane;
declare const publicReauthAuthority: EmailOtpEcdsaPublicReauthExportAuthority;
declare const currentExactExportSession: Extract<
  ExactEcdsaExportSession,
  { state: 'ready' | 'restorable' | 'deferred' }
>;
declare const passkeyBootstrap: PasskeyEcdsaExportBootstrapContext;

const reusableSessionAuthorization: EcdsaExportOperationAuthorization = {
  kind: 'reusable_wallet_session',
  walletSessionId: 'wallet-session-1',
};
void reusableSessionAuthorization;

const stepUpAuthorization: EcdsaExportOperationAuthorization = {
  kind: 'operation_step_up',
  grantId: 'grant-1',
};
void stepUpAuthorization;

// @ts-expect-error one export authorization branch cannot carry both identities.
const mixedAuthorization: EcdsaExportOperationAuthorization = {
  kind: 'reusable_wallet_session',
  walletSessionId: 'wallet-session-1',
  grantId: 'grant-1',
};
void mixedAuthorization;

const exportSessionWithSigningGrantId: ExactEcdsaExportSession = {
  ...currentExactExportSession,
  // @ts-expect-error export sessions carry no signing-grant identity.
  signingGrantId: 'grant-1',
};
void exportSessionWithSigningGrantId;

const exportSessionWithThresholdSessionId: ExactEcdsaExportSession = {
  ...currentExactExportSession,
  // @ts-expect-error export sessions carry no threshold-session identity.
  thresholdSessionId: 'threshold-session-1',
};
void exportSessionWithThresholdSessionId;

const exportMaterial: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  authMethod: 'passkey',
  signerSession,
  publicFacts,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
  laneIdentity,
  record,
};
void exportMaterial;

// @ts-expect-error ready export material requires the exact lane identity.
const exportMaterialWithoutLaneIdentity: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  authMethod: 'passkey',
  signerSession,
  publicFacts,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
  record,
};
void exportMaterialWithoutLaneIdentity;

// @ts-expect-error ready export material requires signer-session material.
const exportMaterialMissingSignerSession: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  authMethod: 'passkey',
  publicFacts,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
  laneIdentity,
  record,
};
void exportMaterialMissingSignerSession;

// @ts-expect-error ready export material requires verified public facts.
const exportMaterialMissingPublicFacts: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  authMethod: 'passkey',
  signerSession,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
  laneIdentity,
  record,
};
void exportMaterialMissingPublicFacts;

// @ts-expect-error passkey export material carries no Email OTP auth lane.
const passkeyExportMaterialWithAuthLane: ReadyThresholdEcdsaExportMaterial = {
  ...exportMaterial,
  authLane,
};
void passkeyExportMaterialWithAuthLane;

const exportMaterialWithThresholdKeyId: ReadyThresholdEcdsaExportMaterial = {
  ...exportMaterial,
  // @ts-expect-error ready export material carries keyHandle through public facts.
  ecdsaThresholdKeyId: 'ederivation-key-1',
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
  laneIdentity,
  record,
  authLane,
};
void emailOtpExportMaterial;

// @ts-expect-error ready Email OTP export material requires its route auth lane.
const emailOtpExportMaterialWithoutAuthLane: ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material',
  authMethod: 'email_otp',
  signerSession,
  publicFacts,
  cachedExportArtifact: null,
  evmFamilyKeyFingerprint,
  laneIdentity,
  record,
};
void emailOtpExportMaterialWithoutAuthLane;

const exportMaterialWithBroadKeyRef: ReadyThresholdEcdsaExportMaterial = {
  ...exportMaterial,
  // @ts-expect-error export material exposes signerSession instead of broad key refs.
  keyRef,
};
void exportMaterialWithBroadKeyRef;

const walletSessionAuthorizedMaterial: FreshEmailOtpEcdsaExportMaterial = {
  kind: 'fresh_email_otp_route_auth_ready',
  chainTarget: record.chainTarget,
  publicFacts,
  runtimePolicyScope,
  authorization: {
    kind: 'wallet_session_authorized',
    record: emailOtpRecord,
    authLane,
    operationAuthorization: reusableSessionAuthorization,
  },
};
void walletSessionAuthorizedMaterial;

const publicReauthRouteAuthReadyMaterial: FreshEmailOtpEcdsaExportMaterial = {
  kind: 'fresh_email_otp_route_auth_ready',
  chainTarget: record.chainTarget,
  publicFacts,
  runtimePolicyScope,
  authorization: { kind: 'public_reauth_authority_backed', publicReauthAuthority },
};
void publicReauthRouteAuthReadyMaterial;

const invalidMixedPublicReauthAuthority: FreshEmailOtpEcdsaExportMaterial = {
  ...walletSessionAuthorizedMaterial,
  // @ts-expect-error one export authorization branch cannot carry public reauth authority.
  authorization: {
    kind: 'wallet_session_authorized',
    record: emailOtpRecord,
    authLane,
    operationAuthorization: reusableSessionAuthorization,
    publicReauthAuthority,
  },
};
void invalidMixedPublicReauthAuthority;

// @ts-expect-error retired export sessions require an exact durable public reauth authority.
const retiredExportSessionWithoutAuthority: ExactEcdsaExportSession = {
  ...currentExactExportSession,
  state: 'exhausted',
  source: 'durable_sealed_record',
};
void retiredExportSessionWithoutAuthority;

// @ts-expect-error route-auth-ready fresh material requires one exact authority branch.
const freshRouteAuthReadyWithoutAuthority: FreshEmailOtpEcdsaExportMaterial = {
  kind: 'fresh_email_otp_route_auth_ready',
  chainTarget: record.chainTarget,
  publicFacts,
  runtimePolicyScope,
};
void freshRouteAuthReadyWithoutAuthority;

const freshRouteAuthReadyWithLooseRecord: FreshEmailOtpEcdsaExportMaterial = {
  ...walletSessionAuthorizedMaterial,
  // @ts-expect-error route-auth-ready fresh material keeps its record inside the authorization branch.
  record,
};
void freshRouteAuthReadyWithLooseRecord;

const freshPasskeyExportMaterial: FreshPasskeyEcdsaExportMaterial = {
  kind: 'fresh_passkey_needs_authorization',
  chainTarget: record.chainTarget,
  publicFacts,
  runtimePolicyScope,
  publicCapability: record.ecdsaRoleLocalPublicFacts.publicCapability,
  existingRoleLocalMaterial,
  bootstrap: passkeyBootstrap,
};
void freshPasskeyExportMaterial;

// @ts-expect-error fresh passkey export requires normalized bootstrap metadata.
const freshPasskeyExportWithoutBootstrap: FreshPasskeyEcdsaExportMaterial = {
  kind: 'fresh_passkey_needs_authorization',
  chainTarget: record.chainTarget,
  publicFacts,
  runtimePolicyScope,
};
void freshPasskeyExportWithoutBootstrap;

const freshPasskeyExportWithRuntimeRecord: FreshPasskeyEcdsaExportMaterial = {
  ...freshPasskeyExportMaterial,
  // @ts-expect-error fresh passkey export does not carry mutable runtime records.
  record,
};
void freshPasskeyExportWithRuntimeRecord;

export {};

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
  FreshEmailOtpEcdsaExportMaterial,
  FreshPasskeyEcdsaExportMaterial,
  PasskeyEcdsaExportBootstrapContext,
  ReadyEcdsaExportLane,
  ReadyThresholdEcdsaExportMaterial,
} from './ecdsaExportMaterial';
import type { RecordBackedEcdsaCommittedLane } from '../signEvmFamily/ecdsaSelection';
import type { EmailOtpEcdsaSigningSessionAuthority } from '../../session/emailOtp/ecdsaSigningSessionAuthority';

declare const signerSession: ReadyEcdsaSignerSession;
declare const publicFacts: VerifiedEcdsaPublicFacts;
declare const record: ThresholdEcdsaSessionRecord;
declare const keyRef: unknown;
declare const evmFamilyKeyFingerprint: EvmFamilyKeyFingerprint;
declare const runtimePolicyScope: ThresholdRuntimePolicyScope;
declare const committedLane: EcdsaExportLane<EmailOtpWalletAuthAuthority>;
declare const broadCommittedLane: RecordBackedEcdsaCommittedLane<EmailOtpWalletAuthAuthority>;
declare const readyCommittedLane: ReadyEcdsaExportLane<EmailOtpWalletAuthAuthority>;
declare const readyPasskeyCommittedLane: ReadyEcdsaExportLane<PasskeyWalletAuthAuthority>;
declare const signingSessionAuthority: EmailOtpEcdsaSigningSessionAuthority;
declare const passkeyBootstrap: PasskeyEcdsaExportBootstrapContext;

// @ts-expect-error post-finalize ECDSA export lanes require wallet-bound authority, not pure factor identity.
type InvalidFactorBackedEcdsaExportLane = EcdsaExportLane<AuthFactorIdentity>;
void ({} as InvalidFactorBackedEcdsaExportLane);

// @ts-expect-error Email OTP ECDSA export lanes require runtime-policy-scoped records.
const broadEmailOtpCommittedLaneAsExportLane: EcdsaExportLane<EmailOtpWalletAuthAuthority> =
  broadCommittedLane;
void broadEmailOtpCommittedLaneAsExportLane;

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

const freshRouteAuthReadyMaterial: FreshEmailOtpEcdsaExportMaterial = {
  kind: 'fresh_email_otp_route_auth_ready',
  chainTarget: record.chainTarget,
  publicFacts,
  runtimePolicyScope,
  authorization: { kind: 'record_backed', committedLane },
};
void freshRouteAuthReadyMaterial;

const durableRouteAuthReadyMaterial: FreshEmailOtpEcdsaExportMaterial = {
  kind: 'fresh_email_otp_route_auth_ready',
  chainTarget: record.chainTarget,
  publicFacts,
  runtimePolicyScope,
  authorization: { kind: 'durable_authority_backed', signingSessionAuthority },
};
void durableRouteAuthReadyMaterial;

// @ts-expect-error route-auth-ready fresh material requires one exact authority branch.
const freshRouteAuthReadyWithoutAuthority: FreshEmailOtpEcdsaExportMaterial = {
  kind: 'fresh_email_otp_route_auth_ready',
  chainTarget: record.chainTarget,
  publicFacts,
  runtimePolicyScope,
};
void freshRouteAuthReadyWithoutAuthority;

const freshRouteAuthReadyWithLooseRecord: FreshEmailOtpEcdsaExportMaterial = {
  ...freshRouteAuthReadyMaterial,
  // @ts-expect-error route-auth-ready fresh material rejects loose session records.
  record,
};
void freshRouteAuthReadyWithLooseRecord;

const freshPasskeyExportMaterial: FreshPasskeyEcdsaExportMaterial = {
  kind: 'fresh_passkey_needs_authorization',
  chainTarget: record.chainTarget,
  publicFacts,
  runtimePolicyScope,
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

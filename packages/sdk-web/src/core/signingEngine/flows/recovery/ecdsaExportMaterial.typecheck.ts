import type { VerifiedEcdsaPublicFacts } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { PersistedEcdsaRoleLocalMaterial } from '../../session/material/ecdsaRoleLocalMaterialResolver';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { RouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { ThresholdEcdsaChainTarget } from '../../interfaces/ecdsaChainTarget';
import type { EmailOtpEcdsaSigningSessionAuthority } from '../../session/emailOtp/ecdsaSigningSessionAuthority';
import type {
  EcdsaExportOperationAuthorization,
  EmailOtpEcdsaPublicReauthExportAuthority,
  ExactEcdsaExportSession,
  FreshEmailOtpEcdsaExportMaterial,
  FreshPasskeyEcdsaExportMaterial,
} from './ecdsaExportMaterial';

declare const chainTarget: ThresholdEcdsaChainTarget;
declare const publicFacts: VerifiedEcdsaPublicFacts;
declare const runtimePolicyScope: ThresholdRuntimePolicyScope;
declare const signingSessionAuthority: EmailOtpEcdsaSigningSessionAuthority;
declare const publicReauthAuthority: EmailOtpEcdsaPublicReauthExportAuthority;
declare const publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
declare const existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
declare const relayerUrl: string;
declare const currentExactExportSession: Extract<
  ExactEcdsaExportSession,
  { state: 'ready' | 'restorable' | 'deferred' }
>;
declare const obsoleteRecord: unknown;

const reusableSessionAuthorization: EcdsaExportOperationAuthorization = {
  kind: 'reusable_wallet_session',
  walletSessionId: 'wallet-session-1',
};

// @ts-expect-error one export authorization branch cannot carry both identities.
const mixedAuthorization: EcdsaExportOperationAuthorization = {
  kind: 'reusable_wallet_session',
  walletSessionId: 'wallet-session-1',
  grantId: 'grant-1',
};
void mixedAuthorization;

const exportSessionWithThresholdSessionId: ExactEcdsaExportSession = {
  ...currentExactExportSession,
  // @ts-expect-error export sessions carry no threshold-session identity.
  thresholdSessionId: 'threshold-session-1',
};
void exportSessionWithThresholdSessionId;

const walletSessionAuthorizedMaterial: FreshEmailOtpEcdsaExportMaterial = {
  kind: 'fresh_email_otp_route_auth_ready',
  chainTarget,
  publicFacts,
  runtimePolicyScope,
  authorization: {
    kind: 'wallet_session_authorized',
    signingSessionAuthority,
    operationAuthorization: reusableSessionAuthorization,
  },
};

const invalidMixedPublicReauthAuthority: FreshEmailOtpEcdsaExportMaterial = {
  ...walletSessionAuthorizedMaterial,
  // @ts-expect-error one export authorization branch cannot carry public reauth authority.
  authorization: {
    kind: 'wallet_session_authorized',
    signingSessionAuthority,
    operationAuthorization: reusableSessionAuthorization,
    publicReauthAuthority,
  },
};
void invalidMixedPublicReauthAuthority;

// @ts-expect-error route-auth-ready fresh material requires one exact authority branch.
const freshRouteAuthReadyWithoutAuthority: FreshEmailOtpEcdsaExportMaterial = {
  kind: 'fresh_email_otp_route_auth_ready',
  chainTarget,
  publicFacts,
  runtimePolicyScope,
};
void freshRouteAuthReadyWithoutAuthority;

const freshRouteAuthReadyWithLooseRecord: FreshEmailOtpEcdsaExportMaterial = {
  ...walletSessionAuthorizedMaterial,
  // @ts-expect-error canonical export material carries no composite session record.
  record: obsoleteRecord,
};
void freshRouteAuthReadyWithLooseRecord;

const publicReauthMaterial: FreshEmailOtpEcdsaExportMaterial = {
  kind: 'fresh_email_otp_route_auth_ready',
  chainTarget,
  publicFacts,
  runtimePolicyScope,
  authorization: { kind: 'public_reauth_authority_backed', publicReauthAuthority },
};
void publicReauthMaterial;

const freshPasskeyExportMaterial: FreshPasskeyEcdsaExportMaterial = {
  kind: 'fresh_passkey_needs_authorization',
  chainTarget,
  publicFacts,
  runtimePolicyScope,
  publicCapability,
  existingRoleLocalMaterial,
  relayerUrl,
};

// @ts-expect-error fresh passkey export requires exact relayer transport.
const freshPasskeyExportWithoutRelayer: FreshPasskeyEcdsaExportMaterial = {
  kind: 'fresh_passkey_needs_authorization',
  chainTarget,
  publicFacts,
  runtimePolicyScope,
  publicCapability,
  existingRoleLocalMaterial,
};
void freshPasskeyExportWithoutRelayer;

const freshPasskeyExportWithRuntimeRecord: FreshPasskeyEcdsaExportMaterial = {
  ...freshPasskeyExportMaterial,
  // @ts-expect-error fresh passkey export does not carry mutable runtime records.
  record: obsoleteRecord,
};
void freshPasskeyExportWithRuntimeRecord;

export {};

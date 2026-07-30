import type { VerifiedEcdsaPublicFacts } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { PersistedEcdsaRoleLocalMaterial } from '../../session/material/ecdsaRoleLocalMaterialResolver';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { RouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { ThresholdEcdsaChainTarget } from '../../interfaces/ecdsaChainTarget';
import type { EmailOtpEcdsaSigningSessionAuthority } from '../../session/emailOtp/ecdsaSigningSessionAuthority';
import type {
  ExactEcdsaExportSession,
  FreshEmailOtpEcdsaExportMaterial,
  FreshPasskeyEcdsaExportMaterial,
} from './ecdsaExportMaterial';

declare const chainTarget: ThresholdEcdsaChainTarget;
declare const publicFacts: VerifiedEcdsaPublicFacts;
declare const runtimePolicyScope: ThresholdRuntimePolicyScope;
declare const signingSessionAuthority: EmailOtpEcdsaSigningSessionAuthority;
declare const publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
declare const existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
declare const relayerUrl: string;
declare const currentExactExportSession: Extract<
  ExactEcdsaExportSession,
  { state: 'ready' | 'restorable' | 'deferred' }
>;
declare const obsoleteRecord: unknown;

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
  },
};

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

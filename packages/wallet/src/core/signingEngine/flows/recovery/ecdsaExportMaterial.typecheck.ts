import type { VerifiedEcdsaPublicFacts } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { PersistedEcdsaRoleLocalMaterial } from '../../session/material/ecdsaRoleLocalMaterialResolver';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { RouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbEcdsaDerivationNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { ThresholdEcdsaChainTarget } from '../../interfaces/ecdsaChainTarget';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type {
  ExactEcdsaExportLane,
  FreshEmailOtpEcdsaExportMaterial,
  FreshPasskeyEcdsaExportMaterial,
} from './ecdsaExportMaterial';

declare const chainTarget: ThresholdEcdsaChainTarget;
declare const publicFacts: VerifiedEcdsaPublicFacts;
declare const runtimePolicyScope: ThresholdRuntimePolicyScope;
declare const persistedMaterial: PersistedEcdsaRoleLocalMaterial;
declare const authority: EmailOtpWalletAuthAuthority;
declare const publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
declare const existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
declare const relayerUrl: string;
declare const normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
declare const relayerKeyId: string;
declare const participantIds: readonly [number, number];
declare const currentExactExportLane: ExactEcdsaExportLane;
declare const obsoleteRecord: unknown;

const exportLaneWithThresholdSessionId: ExactEcdsaExportLane = {
  ...currentExactExportLane,
  // @ts-expect-error export lanes carry no threshold-session identity.
  thresholdSessionId: 'threshold-session-1',
};
void exportLaneWithThresholdSessionId;

const walletSessionAuthorizedMaterial: FreshEmailOtpEcdsaExportMaterial = {
  kind: 'fresh_email_otp_route_auth_ready',
  source: 'canonical_capability',
  chainTarget,
  publicFacts,
  runtimePolicyScope,
  persistedMaterial,
  normalSigning,
  relayerKeyId,
  participantIds,
  relayerUrl,
  authorization: {
    kind: 'fresh_operation_authorization_required',
    authority,
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
  source: 'canonical_capability',
  chainTarget,
  publicFacts,
  runtimePolicyScope,
  publicCapability,
  existingRoleLocalMaterial,
  normalSigning,
  relayerKeyId,
  participantIds,
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
  normalSigning,
  relayerKeyId,
  participantIds,
};
void freshPasskeyExportWithoutRelayer;

const freshPasskeyExportWithRuntimeRecord: FreshPasskeyEcdsaExportMaterial = {
  ...freshPasskeyExportMaterial,
  // @ts-expect-error fresh passkey export does not carry mutable runtime records.
  record: obsoleteRecord,
};
void freshPasskeyExportWithRuntimeRecord;

export {};

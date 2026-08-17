import type { AccountId } from '@/core/types/accountIds';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { ThresholdEcdsaDerivationRouteAuth } from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { SigningSessionStatus } from '@/core/types/seams';
import { SIGNER_AUTH_METHODS, type SignerAuthMethod } from '@shared/utils/signerDomain';
import type { EcdsaSessionProvisionPlan } from './ecdsaProvisionPlan';
import type { ActiveEcdsaCapabilityManifest } from '../material/ecdsaCapabilityManifest';
import type { ExactEcdsaSealedRuntime } from '../material/ecdsaSealedRuntime';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../material/ecdsaSigningCapability';
import type { EcdsaSealTransportAuthMaterial } from '../persistence/sealedSessionTransportAuth';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  SelectedEcdsaLane,
  ThresholdEcdsaSessionStoreSource,
  ThresholdEd25519SessionStoreSource,
} from '../identity/laneIdentity';
import { laneCandidateStateFromRuntimePolicy } from '../identity/laneIdentity';
import { signingLaneAuthMethod } from '../identity/signingLaneAuthBinding';
import type { EmailOtpEcdsaSigningSessionAuthority } from '../emailOtp/ecdsaSigningSessionAuthority';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type {
  EmailOtpEd25519SessionPolicyAuthority,
  Ed25519SessionPolicyAuthority,
  PasskeyEd25519SessionPolicyAuthority,
  ThresholdRuntimePolicyScope,
} from '../../threshold/sessionPolicy';
import type { Ed25519WalletSessionMintAuthorization } from '../../threshold/ed25519/walletSession';
import type { RouterAbEd25519NormalSigningState } from '../../threshold/ed25519/routerAbNormalSigningState';
import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import type { SigningOperationIntent } from '../operationState/types';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EvmFamilyEcdsaKeyIdentity } from '../identity/evmFamilyEcdsaIdentity';
import type {
  ExactEcdsaSigningLaneIdentity,
  ExactEd25519SigningLaneIdentity,
} from '../identity/exactSigningLaneIdentity';
import {
  walletSessionTokenForCurve,
  type ActiveWalletSessionAuthorizationProjection,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { ExactEd25519SealedSessionRuntime } from './ed25519SealedSessionRuntime';
import type { MpcMaterialActivationRef, ThresholdEd25519SessionId } from '@shared/utils/domainIds';

function authMethodForThresholdEcdsaSessionSource(
  source: ThresholdEcdsaSessionStoreSource,
): SignerAuthMethod {
  switch (source) {
    case SIGNER_AUTH_METHODS.emailOtp:
      return SIGNER_AUTH_METHODS.emailOtp;
    case 'login':
    case 'registration':
    case 'manual-bootstrap':
      return SIGNER_AUTH_METHODS.passkey;
    default:
      return assertNeverThresholdEcdsaSessionSource(source);
  }
}

function assertNeverThresholdEcdsaSessionSource(value: never): never {
  throw new Error(`Unsupported threshold ECDSA session source: ${String(value)}`);
}

export type WarmSessionCapability = 'ed25519' | 'ecdsa';
export type WarmSessionPrfClaimState = 'missing' | 'warm' | 'expired' | 'exhausted' | 'unavailable';

export type WarmSessionMaterialWriteDiagnosticBucket =
  | 'worker_ready'
  | 'worker_put'
  | 'sealed_record_persist'
  | 'sealed_record_resolve_transport'
  | 'sealed_record_existing_read'
  | 'sealed_record_policy_read'
  | 'sealed_record_apply_server_seal'
  | 'sealed_record_apply_runtime_setup'
  | 'sealed_record_apply_client_seal'
  | 'sealed_record_apply_server_route'
  | 'sealed_record_apply_client_unseal'
  | 'sealed_record_apply_policy_update'
  | 'sealed_record_register'
  | 'sealed_record_verify_read';

export type WarmSessionMaterialWriteDiagnostics = {
  recordDuration(bucket: WarmSessionMaterialWriteDiagnosticBucket, durationMs: number): void;
};

type WarmSessionPrfClaimBase = {
  thresholdSessionId: string;
};

export type WarmSessionWarmPrfClaim = WarmSessionPrfClaimBase & {
  state: 'warm';
  expiresAtMs: number;
  remainingUses: number;
  code?: never;
};

export type WarmSessionUnavailablePrfClaim = WarmSessionPrfClaimBase & {
  state: 'unavailable';
  code: string;
  expiresAtMs?: never;
  remainingUses?: never;
};

export type WarmSessionMissingPrfClaim = WarmSessionPrfClaimBase & {
  state: 'missing';
  expiresAtMs?: never;
  remainingUses?: never;
  code?: never;
};

export type WarmSessionExpiredPrfClaim = WarmSessionPrfClaimBase & {
  state: 'expired';
  expiresAtMs?: never;
  remainingUses?: never;
  code?: never;
};

export type WarmSessionExhaustedPrfClaim = WarmSessionPrfClaimBase & {
  state: 'exhausted';
  expiresAtMs?: never;
  remainingUses?: never;
  code?: never;
};

export type WarmSessionPrfClaim =
  | WarmSessionWarmPrfClaim
  | WarmSessionUnavailablePrfClaim
  | WarmSessionMissingPrfClaim
  | WarmSessionExpiredPrfClaim
  | WarmSessionExhaustedPrfClaim;

type WarmSessionEd25519CapabilityStateValue =
  | 'missing'
  | 'ready'
  | 'authorization_required'
  | 'invalid'
  | 'prf_missing'
  | 'prf_unavailable';

type WarmSessionEd25519PresentCapabilityStateValue = Exclude<
  WarmSessionEd25519CapabilityStateValue,
  'missing'
>;
type WarmSessionEcdsaPresentCapabilityStateValue =
  | 'ready'
  | 'authorization_required'
  | 'auth_missing'
  | 'material_pending'
  | 'prf_missing'
  | 'prf_unavailable';

/** Correlation failures that are not absence. A wallet with a manifest and a
 * sealed record that disagree is a different situation from a wallet with no
 * material, and collapsing the two would hide a real store fault. */
export type WarmSessionEcdsaInvalidReason =
  | 'binding_mismatch'
  | 'exact_record_conflict'
  | 'corrupt';

type WarmSessionMissingEd25519CapabilityState = {
  capability: 'ed25519';
  runtime: null;
  auth: null;
  prfClaim: null;
  invalidReason?: never;
  state: 'missing';
};

export type WarmSessionEd25519InvalidReason = 'exact_record_conflict' | 'corrupt';

type WarmSessionInvalidEd25519CapabilityState = {
  capability: 'ed25519';
  runtime: null;
  auth: null;
  prfClaim: null;
  invalidReason: WarmSessionEd25519InvalidReason;
  state: 'invalid';
};

type WarmSessionEd25519AuthorizationRequiredState = {
  capability: 'ed25519';
  runtime: ExactEd25519SealedSessionRuntime;
  auth: null;
  prfClaim: WarmSessionPrfClaim | null;
  invalidReason?: never;
  state: 'authorization_required';
};

type WarmSessionEd25519AuthorizedState = {
  capability: 'ed25519';
  runtime: ExactEd25519SealedSessionRuntime;
  auth: ActiveWalletSessionAuthorizationProjection;
  prfClaim: WarmSessionPrfClaim | null;
  invalidReason?: never;
  state: Exclude<
    WarmSessionEd25519PresentCapabilityStateValue,
    'authorization_required' | 'invalid'
  >;
};

export type WarmSessionEd25519CapabilityState =
  | WarmSessionMissingEd25519CapabilityState
  | WarmSessionInvalidEd25519CapabilityState
  | WarmSessionEd25519AuthorizationRequiredState
  | WarmSessionEd25519AuthorizedState;

type WarmSessionMissingEcdsaCapabilityState = {
  capability: 'ecdsa';
  manifest: null;
  runtime: null;
  key: null;
  lane: null;
  auth: null;
  prfClaim: null;
  invalidReason?: never;
  emailOtpAuthContext?: never;
  state: 'missing';
};

/** Material exists on both sides but they do not agree. Carried explicitly so
 * callers can tell a store fault from an absent capability. */
type WarmSessionInvalidEcdsaCapabilityState = {
  capability: 'ecdsa';
  manifest: null;
  runtime: null;
  key: null;
  lane: null;
  auth: null;
  prfClaim: null;
  invalidReason: WarmSessionEcdsaInvalidReason;
  emailOtpAuthContext?: never;
  state: 'invalid';
};

// The manifest selects the exact capability and public facts; the sealed
// runtime supplies session-scoped state. Neither carries authorization, which
// stays an independent second proof.
type WarmSessionEmailOtpEcdsaCapabilityFields = {
  capability: 'ecdsa';
  manifest: ActiveEcdsaCapabilityManifest;
  runtime: ExactEcdsaSealedRuntime;
  key: EvmFamilyEcdsaKeyIdentity;
  lane: SelectedEcdsaLane;
  prfClaim: WarmSessionPrfClaim | null;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
};

type WarmSessionNonEmailOtpEcdsaCapabilityFields = {
  capability: 'ecdsa';
  manifest: ActiveEcdsaCapabilityManifest;
  runtime: ExactEcdsaSealedRuntime;
  key: EvmFamilyEcdsaKeyIdentity;
  lane: SelectedEcdsaLane;
  prfClaim: WarmSessionPrfClaim | null;
  emailOtpAuthContext?: never;
};

type WarmSessionEcdsaCapabilityFields =
  | WarmSessionEmailOtpEcdsaCapabilityFields
  | WarmSessionNonEmailOtpEcdsaCapabilityFields;

type WarmSessionEcdsaAuthMissingState = WarmSessionEcdsaCapabilityFields & {
  auth: null;
  invalidReason?: never;
  state: 'auth_missing';
};

// Durable ECDSA capability material exists and its material activation remains
// valid, but no active reusable Wallet Session authorizes signing. A
// SelectedEcdsaLane embeds that authorization, so no lane can exist here:
// operation planning must request step-up while material hydration
// independently resolves live or sealed material. Distinct from
// `auth_missing`, which reports missing or unusable transport auth for an
// authorization that otherwise exists.
type WarmSessionEcdsaAuthorizationRequiredState = {
  capability: 'ecdsa';
  manifest: ActiveEcdsaCapabilityManifest;
  runtime: ExactEcdsaSealedRuntime;
  key: EvmFamilyEcdsaKeyIdentity;
  lane: null;
  auth: null;
  prfClaim: WarmSessionPrfClaim | null;
  invalidReason?: never;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext | null;
  state: 'authorization_required';
};

type WarmSessionEcdsaPrfReadyState = WarmSessionEcdsaCapabilityFields & {
  auth: ActiveEvmFamilyWalletSessionAuthorization;
  prfClaim: WarmSessionWarmPrfClaim;
  invalidReason?: never;
  state: 'ready' | 'material_pending';
};

type WarmSessionEcdsaPrfBlockedState = WarmSessionEcdsaCapabilityFields & {
  auth: ActiveEvmFamilyWalletSessionAuthorization;
  invalidReason?: never;
  state: Exclude<
    WarmSessionEcdsaPresentCapabilityStateValue,
    'authorization_required' | 'auth_missing' | 'ready' | 'material_pending'
  >;
};

export type WarmSessionEcdsaCapabilityState =
  | WarmSessionMissingEcdsaCapabilityState
  | WarmSessionInvalidEcdsaCapabilityState
  | WarmSessionEcdsaAuthorizationRequiredState
  | WarmSessionEcdsaAuthMissingState
  | WarmSessionEcdsaPrfReadyState
  | WarmSessionEcdsaPrfBlockedState;

export type WarmSessionEnvelope = {
  walletId: WalletId;
  capabilities: {
    ed25519: WarmSessionEd25519CapabilityState;
    ecdsa: {
      evm: WarmSessionEcdsaCapabilityState;
      tempo: WarmSessionEcdsaCapabilityState;
    };
  };
  updatedAtMs: number;
};

// Presence is the state discriminant, not a nullable field: ECDSA no longer
// has a record to be null, and 'invalid' is present-but-unusable rather than
// absent.
type WarmSessionPresentCapabilityState = Exclude<
  WarmSessionEd25519CapabilityState | WarmSessionEcdsaCapabilityState,
  { state: 'missing' | 'invalid' }
>;

function expectedPresentCapabilityState(args: {
  capability: WarmSessionPresentCapabilityState;
  hasWalletSessionToken: boolean;
  emailOtpSingleUseConsumed: boolean;
}): WarmSessionEd25519CapabilityState['state'] | WarmSessionEcdsaCapabilityState['state'] {
  const { capability } = args;
  if (!capability.auth || !args.hasWalletSessionToken) {
    return capability.capability === 'ed25519' ? 'authorization_required' : 'auth_missing';
  }
  if (args.emailOtpSingleUseConsumed) return 'prf_missing';
  const prfClaim = capability.prfClaim;
  if (capability.capability === 'ed25519') {
    const runtimeState = laneCandidateStateFromRuntimePolicy({
      remainingUses: capability.runtime.remainingUses,
      expiresAtMs: capability.runtime.expiresAtMs,
    });
    if (runtimeState === 'expired' || runtimeState === 'exhausted') {
      return 'authorization_required';
    }
    if (prfClaim?.state === 'unavailable') return 'prf_unavailable';
    if (prfClaim?.state !== 'warm') return 'prf_missing';
    return 'ready';
  }
  // Allowance and expiry are classified by the shared Refactor 92 rule before
  // any worker or PRF state is considered: a warm claim over an expired or
  // exhausted session is not ready, and expiry must not be reported as
  // exhaustion. Both are authorization states, so they surface as
  // authorization_required -- the material itself is untouched.
  const runtimeState = laneCandidateStateFromRuntimePolicy({
    remainingUses: capability.runtime.remainingUses,
    expiresAtMs: capability.runtime.expiresAtMs,
  });
  if (runtimeState === 'expired' || runtimeState === 'exhausted') {
    return 'authorization_required';
  }
  if (!prfClaim) return 'prf_missing';
  if (prfClaim.state === 'unavailable') return 'prf_unavailable';
  if (prfClaim.state !== 'warm') return 'prf_missing';
  return 'ready';
}

function assertEd25519CapabilityStateInvariant(args: {
  walletId: WalletId;
  label: string;
  capability: WarmSessionEd25519CapabilityState;
}): void {
  const { capability } = args;
  const runtime = capability.runtime;
  const auth = capability.auth;
  const prfClaim = capability.prfClaim;
  const thresholdSessionId = String(runtime?.thresholdSessionId || '').trim();

  if (!runtime) {
    if (capability.state !== 'missing' && capability.state !== 'invalid') {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: missing runtime must be missing or invalid`,
      );
    }
    if (auth) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: missing runtime cannot have auth`,
      );
    }
    if (prfClaim) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: missing runtime cannot have warm-session status`,
      );
    }
    return;
  }

  if (String(runtime.walletId) !== String(args.walletId)) {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: runtime wallet does not match envelope wallet`,
    );
  }
  if (!thresholdSessionId) {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: runtime is missing thresholdSessionId`,
    );
  }

  if (auth) {
    if (String(auth.walletId) !== String(runtime.walletId)) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: authorization wallet does not match runtime`,
      );
    }
    if (auth.authMethod !== runtime.factor.kind) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: authorization factor does not match runtime`,
      );
    }
  }

  if (prfClaim) {
    if (String(prfClaim.thresholdSessionId || '').trim() !== thresholdSessionId) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: warm-session status thresholdSessionId does not match record thresholdSessionId`,
      );
    }
    switch (prfClaim.state) {
      case 'warm':
        if (prfClaim.remainingUses <= 0 || prfClaim.expiresAtMs <= 0) {
          throw new Error(
            `[WarmSessionStore] invalid ${args.label} capability: warm warm-session status requires positive remainingUses and expiresAtMs`,
          );
        }
        break;
      case 'unavailable':
        if (!String(prfClaim.code || '').trim()) {
          throw new Error(
            `[WarmSessionStore] invalid ${args.label} capability: unavailable warm-session status requires a code`,
          );
        }
        break;
      case 'missing':
      case 'expired':
      case 'exhausted':
        break;
      default:
        prfClaim satisfies never;
        throw new Error('[WarmSessionStore] unsupported warm-session claim state');
    }
  }

  const hasWalletSessionToken = Boolean(auth && walletSessionTokenForCurve(auth, 'ed25519'));
  const expectedState = expectedPresentCapabilityState({
    capability,
    hasWalletSessionToken,
    emailOtpSingleUseConsumed: false,
  });
  if (capability.state !== expectedState) {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: state=${capability.state} does not match derived state=${expectedState}`,
    );
  }
}

function assertEcdsaCapabilityStateInvariant(args: {
  walletId: WalletId;
  label: string;
  capability: Extract<WarmSessionEcdsaCapabilityState, { manifest: ActiveEcdsaCapabilityManifest }>;
}): void {
  const { capability } = args;
  const runtime = capability.runtime;
  const publicFacts = capability.manifest.durableMaterial.roleLocalPublicFacts;

  if (String(runtime.walletId) !== String(args.walletId)) {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: runtime wallet does not match envelope wallet`,
    );
  }
  if (String(capability.key.walletId) !== String(args.walletId)) {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: key wallet does not match envelope wallet`,
    );
  }
  if (
    String(capability.key.thresholdOwnerAddress).toLowerCase() !==
    String(publicFacts.ethereumAddress).toLowerCase()
  ) {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: key owner address does not match manifest public facts`,
    );
  }
  // Authorization is the independent second proof. Without it there is no lane;
  // with it the lane must name the same material the manifest and runtime do.
  if (capability.state === 'authorization_required') {
    if (capability.lane) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: authorization_required cannot carry a lane`,
      );
    }
    return;
  }
  if (!capability.lane) {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: authorized ECDSA capability requires a lane`,
    );
  }
  if (
    !thresholdEcdsaChainTargetsEqual(
      capability.lane.identity.signer.chainTarget,
      runtime.chainTarget,
    )
  ) {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: lane chain target does not match runtime chain target`,
    );
  }
  if (
    String(capability.lane.materialActivation.activationId) !==
    String(runtime.materialActivation.activationId)
  ) {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: lane material activation does not match runtime`,
    );
  }
  if (signingLaneAuthMethod(capability.lane.auth) !== runtime.authBinding.kind) {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: lane authMethod does not match sealed auth binding`,
    );
  }
  if (capability.emailOtpAuthContext && runtime.authBinding.kind !== 'email_otp') {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: non-email_otp binding cannot carry email-otp auth context`,
    );
  }
}

function assertCapabilityStateInvariant(args: {
  walletId: WalletId;
  label: string;
  capability: WarmSessionEd25519CapabilityState | WarmSessionEcdsaCapabilityState;
}): void {
  const { capability } = args;
  if (capability.state === 'missing') return;
  if (capability.capability === 'ecdsa') {
    // 'invalid' is present-but-unusable: it carries a typed correlation reason
    // and no material to check.
    if (capability.state === 'invalid') return;
    assertEcdsaCapabilityStateInvariant({
      walletId: args.walletId,
      label: args.label,
      capability,
    });
    return;
  }
  assertEd25519CapabilityStateInvariant(
    args as {
      walletId: WalletId;
      label: string;
      capability: WarmSessionEd25519CapabilityState;
    },
  );
}

export function assertWarmSessionEnvelopeInvariant(
  envelope: WarmSessionEnvelope,
): WarmSessionEnvelope {
  assertCapabilityStateInvariant({
    walletId: envelope.walletId,
    label: 'ed25519',
    capability: envelope.capabilities.ed25519,
  });
  assertCapabilityStateInvariant({
    walletId: envelope.walletId,
    label: 'ecdsa.evm',
    capability: envelope.capabilities.ecdsa.evm,
  });
  assertCapabilityStateInvariant({
    walletId: envelope.walletId,
    label: 'ecdsa.tempo',
    capability: envelope.capabilities.ecdsa.tempo,
  });
  return envelope;
}
type ProvisionWarmEd25519CapabilityBaseArgs = {
  relayerKeyId: string;
  auth?: Ed25519WalletSessionMintAuthorization;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  runtimeScopeBootstrap?: {
    projectEnvironmentId: string;
    publishableKey: string;
  };
  participantIds: readonly number[];
  sessionKind: 'opaque';
  relayerUrl?: string;
  ttlMs?: number;
  remainingUses?: number;
  onWalletSessionAuthorityReady?: (
    authority: MintedEd25519WalletSessionAuthority,
  ) => void | Promise<void>;
  beforeProvision?: () => void | Promise<void>;
  assertNotCancelled?: () => void;
};

type ProvisionWarmEd25519PasskeyCapabilityArgs = ProvisionWarmEd25519CapabilityBaseArgs & {
  source: Exclude<ThresholdEd25519SessionStoreSource, 'email_otp'>;
  authority: PasskeyEd25519SessionPolicyAuthority;
  materialActivation: MpcMaterialActivationRef;
  emailOtpAuthContext?: never;
};

type ProvisionWarmEd25519EmailOtpCapabilityArgs = ProvisionWarmEd25519CapabilityBaseArgs & {
  source: 'email_otp';
  authority: EmailOtpEd25519SessionPolicyAuthority;
  materialActivation?: never;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
};

type ProvisionWarmEd25519CapabilityCommonArgs =
  | ProvisionWarmEd25519PasskeyCapabilityArgs
  | ProvisionWarmEd25519EmailOtpCapabilityArgs;

export type FreshWarmEd25519CapabilityProvisionArgs = ProvisionWarmEd25519CapabilityCommonArgs & {
  kind: 'fresh_ed25519_provisioning';
  walletId: string;
  nearAccountId: AccountId | string;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  laneIdentity?: never;
  thresholdSessionId?: never;
};

export type ExactWarmEd25519CapabilityProvisionArgs = ProvisionWarmEd25519CapabilityCommonArgs & {
  kind: 'exact_ed25519_provisioning';
  laneIdentity: ExactEd25519SigningLaneIdentity;
  existingWalletSessionToken: string;
  walletId?: never;
  nearAccountId?: never;
  nearEd25519SigningKeyId?: never;
  signerSlot?: never;
  thresholdSessionId?: never;
};

export type ProvisionWarmEd25519CapabilityArgs =
  | FreshWarmEd25519CapabilityProvisionArgs
  | ExactWarmEd25519CapabilityProvisionArgs;

export type MintedEd25519WalletSessionAuthority = {
  kind: 'minted_ed25519_wallet_session_authority';
  thresholdSessionId: ThresholdEd25519SessionId;
  walletSessionId: WalletSessionId;
  authorizationId: WalletSessionAuthorizationId;
  quotaId: MpcWalletSigningQuotaId;
  expiresAtMs: number;
  remainingUses: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  walletSessionToken: string;
};

export type ProvisionWarmEd25519CapabilitySuccessResult = {
  ok: true;
  thresholdSessionId: ThresholdEd25519SessionId;
  walletSessionId: WalletSessionId;
  authorizationId: WalletSessionAuthorizationId;
  quotaId: MpcWalletSigningQuotaId;
  expiresAtMs: number;
  remainingUses: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  walletSessionToken: string;
};

export type ProvisionWarmEd25519CapabilityFailureResult = {
  ok: false;
  code: string;
  message: string;
};

export type ProvisionWarmEd25519CapabilityResult =
  | ProvisionWarmEd25519CapabilitySuccessResult
  | ProvisionWarmEd25519CapabilityFailureResult;

type EnsureWarmEcdsaProvisionPlanReadyCommonArgs = {
  walletId: WalletId;
  subjectId?: never;
  chainTarget: ThresholdEcdsaChainTarget;
  keyRef?: never;
  source: ThresholdEcdsaSessionStoreSource;
  runtimeScopeBootstrap?: {
    projectEnvironmentId: string;
    publishableKey: string;
  };
  usesNeeded?: number;
  sessionBudgetUses: number;
  operationIntent?: SigningOperationIntent;
  beforeReconnect?: () => void | Promise<void>;
  assertNotCancelled?: () => void;
};

export type EnsureWarmEcdsaProvisionPlanReadyArgs =
  | (EnsureWarmEcdsaProvisionPlanReadyCommonArgs & {
      plan: Extract<
        EcdsaSessionProvisionPlan,
        {
          kind: 'passkey_ecdsa_session_provision';
        }
      >;
      capability: WarmSessionEcdsaCapabilityState;
    })
  | (EnsureWarmEcdsaProvisionPlanReadyCommonArgs & {
      plan: Extract<EcdsaSessionProvisionPlan, { kind: 'email_otp_ecdsa_session_provision' }>;
      capability: WarmSessionEcdsaCapabilityState;
    });

export type WarmSessionCapabilityReader = {
  getWarmSession: (walletId: WalletId) => Promise<WarmSessionEnvelope>;
  getEcdsaCapabilityForLane: (args: {
    lane: ExactEcdsaSigningLaneIdentity;
    authorization: ActiveEvmFamilyWalletSessionAuthorization;
  }) => Promise<WarmSessionEcdsaCapabilityState | null>;
  // Lane-qualified, and async because canonical resolution reads persistence.
  // There is deliberately no threshold-session-id entry point: that id indexes
  // runtime state and must never select material.
  resolveEcdsaSealTransportForLane: (args: {
    lane: ExactEcdsaSigningLaneIdentity;
    authorization: ActiveEvmFamilyWalletSessionAuthorization;
  }) => Promise<EcdsaSealTransportAuthMaterial | null>;
};

export type ThresholdWarmSessionStatusReader = {
  getEd25519SigningSessionStatus: (args: {
    runtime: ExactEd25519SealedSessionRuntime;
    authorization: ActiveWalletSessionAuthorizationProjection | null;
    nowMs: number;
  }) => Promise<SigningSessionStatus>;
};

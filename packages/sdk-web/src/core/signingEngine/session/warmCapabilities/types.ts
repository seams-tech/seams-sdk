import type { AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaHssRouteAuth } from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { SigningSessionStatus } from '@/core/types/seams';
import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type { EcdsaSessionProvisionPlan } from './ecdsaProvisionPlan';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
  ThresholdSessionSealTransportAuthMaterial,
} from '../persistence/records';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  SelectedEcdsaLane,
  ThresholdEcdsaSessionStoreSource,
  ThresholdEd25519SessionStoreSource,
} from '../identity/laneIdentity';
import {
  emailOtpAuthContextConsumedAtMs,
  emailOtpAuthContextRetention,
} from '../identity/laneIdentity';
import { signingLaneAuthMethod } from '../identity/signingLaneAuthBinding';
import type { EmailOtpEcdsaSigningSessionAuthority } from '../emailOtp/ecdsaSigningSessionAuthority';
import type { EmailOtpEd25519SigningSessionAuthority } from '../emailOtp/ed25519SigningSessionAuthority';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type {
  EmailOtpEd25519SessionPolicyAuthority,
  Ed25519SessionPolicyAuthority,
  PasskeyEd25519SessionPolicyAuthority,
  ThresholdRuntimePolicyScope,
  ThresholdSessionKind,
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
  classifyRouterAbEcdsaHssPersistedSigningRecord,
  classifyRouterAbEd25519PersistedSigningRecord,
} from '../routerAbSigningWalletSession';

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
  sessionId: string;
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

export type WarmSessionEd25519AuthMaterialWithToken = {
  capability: 'ed25519';
  record: ThresholdEd25519SessionRecord;
  walletSessionJwt: string;
  walletSessionJwtSource: 'ed25519_record';
};

export type WarmSessionEd25519AuthMaterialWithoutToken = {
  capability: 'ed25519';
  record: ThresholdEd25519SessionRecord;
  walletSessionJwt?: never;
  walletSessionJwtSource: 'none';
};

export type WarmSessionEd25519AuthMaterial =
  | WarmSessionEd25519AuthMaterialWithToken
  | WarmSessionEd25519AuthMaterialWithoutToken;

export type WarmSessionEcdsaAuthMaterialWithToken = {
  capability: 'ecdsa';
  state: 'ready';
  record: ThresholdEcdsaSessionRecord;
  walletSessionJwt: string;
  walletSessionJwtSource: 'ecdsa_record';
  unavailableReason?: never;
};

export type WarmSessionEcdsaAuthMaterialWithoutToken = {
  capability: 'ecdsa';
  state: 'unavailable';
  record: ThresholdEcdsaSessionRecord;
  walletSessionJwt?: never;
  walletSessionJwtSource: 'none';
  unavailableReason: 'cookie_session' | 'missing_session_identity' | 'missing_wallet_session_jwt';
};

export type WarmSessionEcdsaAuthMaterial =
  | WarmSessionEcdsaAuthMaterialWithToken
  | WarmSessionEcdsaAuthMaterialWithoutToken;

type WarmSessionCapabilityStateValue =
  | 'missing'
  | 'ready'
  | 'auth_missing'
  | 'invalid'
  | 'material_pending'
  | 'prf_missing'
  | 'prf_unavailable';

type WarmSessionEd25519PresentCapabilityStateValue = Exclude<
  WarmSessionCapabilityStateValue,
  'missing'
>;
type WarmSessionEcdsaPresentCapabilityStateValue = Exclude<
  WarmSessionCapabilityStateValue,
  'missing' | 'invalid'
>;

type WarmSessionMissingEd25519CapabilityState = {
  capability: 'ed25519';
  record: null;
  auth: null;
  prfClaim: null;
  emailOtpAuthContext?: never;
  state: 'missing';
};

type WarmSessionEmailOtpEd25519CapabilityFields = {
  capability: 'ed25519';
  record: ThresholdEd25519SessionRecord;
  prfClaim: WarmSessionPrfClaim | null;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
};

type WarmSessionNonEmailOtpEd25519CapabilityFields = {
  capability: 'ed25519';
  record: ThresholdEd25519SessionRecord;
  prfClaim: WarmSessionPrfClaim | null;
  emailOtpAuthContext?: never;
};

type WarmSessionEd25519CapabilityFields =
  | WarmSessionEmailOtpEd25519CapabilityFields
  | WarmSessionNonEmailOtpEd25519CapabilityFields;

type WarmSessionEd25519AuthMissingState = WarmSessionEd25519CapabilityFields & {
  auth: WarmSessionEd25519AuthMaterialWithoutToken | null;
  state: 'auth_missing';
};

type WarmSessionEd25519AuthenticatedState = WarmSessionEd25519CapabilityFields & {
  auth: WarmSessionEd25519AuthMaterialWithToken;
  state: Exclude<WarmSessionEd25519PresentCapabilityStateValue, 'auth_missing'>;
};

export type WarmSessionEd25519CapabilityState =
  | WarmSessionMissingEd25519CapabilityState
  | WarmSessionEd25519AuthMissingState
  | WarmSessionEd25519AuthenticatedState;

type WarmSessionMissingEcdsaCapabilityState = {
  capability: 'ecdsa';
  record: null;
  key: null;
  lane: null;
  auth: null;
  prfClaim: null;
  emailOtpAuthContext?: never;
  state: 'missing';
};

type WarmSessionEmailOtpEcdsaCapabilityFields = {
  capability: 'ecdsa';
  record: ThresholdEcdsaSessionRecord;
  key: EvmFamilyEcdsaKeyIdentity;
  lane: SelectedEcdsaLane;
  prfClaim: WarmSessionPrfClaim | null;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
};

type WarmSessionNonEmailOtpEcdsaCapabilityFields = {
  capability: 'ecdsa';
  record: ThresholdEcdsaSessionRecord;
  key: EvmFamilyEcdsaKeyIdentity;
  lane: SelectedEcdsaLane;
  prfClaim: WarmSessionPrfClaim | null;
  emailOtpAuthContext?: never;
};

type WarmSessionEcdsaCapabilityFields =
  | WarmSessionEmailOtpEcdsaCapabilityFields
  | WarmSessionNonEmailOtpEcdsaCapabilityFields;

type WarmSessionEcdsaAuthMissingState = WarmSessionEcdsaCapabilityFields & {
  auth: WarmSessionEcdsaAuthMaterialWithoutToken | null;
  state: 'auth_missing';
};

type WarmSessionEcdsaPrfReadyState = WarmSessionEcdsaCapabilityFields & {
  auth: WarmSessionEcdsaAuthMaterialWithToken;
  prfClaim: WarmSessionWarmPrfClaim;
  state: 'ready' | 'material_pending';
};

type WarmSessionEcdsaPrfBlockedState = WarmSessionEcdsaCapabilityFields & {
  auth: WarmSessionEcdsaAuthMaterialWithToken;
  state: Exclude<
    WarmSessionEcdsaPresentCapabilityStateValue,
    'auth_missing' | 'ready' | 'material_pending'
  >;
};

export type WarmSessionEcdsaCapabilityState =
  | WarmSessionMissingEcdsaCapabilityState
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

function assertCapabilityStateInvariant(args: {
  walletId: WalletId;
  label: string;
  capability: WarmSessionEd25519CapabilityState | WarmSessionEcdsaCapabilityState;
}): void {
  const { capability } = args;
  const record = capability.record;
  const auth = capability.auth;
  const prfClaim = capability.prfClaim;
  const emailOtpAuthContext =
    'emailOtpAuthContext' in capability ? capability.emailOtpAuthContext : null;
  const sessionId = String(record?.thresholdSessionId || '').trim();

  if (!record) {
    if (capability.state !== 'missing') {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: missing record must have state=missing`,
      );
    }
    if (auth) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: missing record cannot have auth`,
      );
    }
    if (prfClaim) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: missing record cannot have warm-session status`,
      );
    }
    if (emailOtpAuthContext) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: missing record cannot have email-otp auth context`,
      );
    }
    if (capability.capability === 'ecdsa') {
      if (capability.key || capability.lane) {
        throw new Error(
          `[WarmSessionStore] invalid ${args.label} capability: missing ECDSA record cannot carry key/lane identity`,
        );
      }
    }
    return;
  }

  if (capability.capability === 'ecdsa') {
    if (!capability.key || !capability.lane) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: ECDSA record requires key/lane identity`,
      );
    }
    if (String(capability.record.walletId) !== String(args.walletId)) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: record wallet does not match envelope wallet`,
      );
    }
    if (String(capability.key.walletId) !== String(args.walletId)) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: key wallet does not match envelope wallet`,
      );
    }
    if (
      String(capability.key.thresholdOwnerAddress).toLowerCase() !==
      String(capability.record.ethereumAddress).toLowerCase()
    ) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: key owner address does not match record owner address`,
      );
    }
    if (
      !thresholdEcdsaChainTargetsEqual(
        capability.lane.identity.signer.chainTarget,
        capability.record.chainTarget,
      )
    ) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: lane chain target does not match record chain target`,
      );
    }
    if (
      String(capability.lane.thresholdSessionId) !== String(capability.record.thresholdSessionId)
    ) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: lane thresholdSessionId does not match record`,
      );
    }
    if (
      String(capability.lane.signingGrantId) !==
      String(capability.record.signingGrantId)
    ) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: lane signingGrantId does not match record`,
      );
    }
    const expectedAuthMethod = capability.record.source === 'email_otp' ? 'email_otp' : 'passkey';
    if (signingLaneAuthMethod(capability.lane.auth) !== expectedAuthMethod) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: lane authMethod does not match record source`,
      );
    }
  } else if (String(capability.record.walletId) !== String(args.walletId)) {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: record wallet does not match envelope wallet`,
    );
  }
  if (!sessionId) {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: record is missing thresholdSessionId`,
    );
  }

  if (auth) {
    if (auth.record !== record) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: auth.record must reference the capability record`,
      );
    }
    if (auth.capability !== capability.capability) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: auth capability does not match capability state`,
      );
    }
  }

  if (prfClaim) {
    if (String(prfClaim.sessionId || '').trim() !== sessionId) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: warm-session status sessionId does not match record sessionId`,
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

  if (record.source === 'email_otp' && !emailOtpAuthContext) {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: email_otp record requires explicit email-otp auth context`,
    );
  }
  if (record.source !== 'email_otp' && emailOtpAuthContext) {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: non-email_otp record cannot carry email-otp auth context`,
    );
  }

  const hasWalletSessionJwt = Boolean(String(auth?.walletSessionJwt || '').trim());
  const emailOtpSingleUseConsumed =
    record.source === 'email_otp' &&
    emailOtpAuthContext &&
    emailOtpAuthContextRetention(emailOtpAuthContext) === 'single_use' &&
    Number(emailOtpAuthContextConsumedAtMs(emailOtpAuthContext)) > 0;
  const expectedState = (() => {
    if (!auth || !hasWalletSessionJwt) return 'auth_missing';
    if (emailOtpSingleUseConsumed) return 'prf_missing';
    if (capability.capability === 'ed25519') {
      const persistedState = classifyRouterAbEd25519PersistedSigningRecord(capability.record);
      if (persistedState.kind === 'runtime_validated') return 'ready';
      if (
        persistedState.kind === 'non_signing' ||
        persistedState.reason === 'missing_wallet_session_jwt'
      ) {
        return 'auth_missing';
      }
      if (persistedState.kind === 'restore_available') return 'material_pending';
      if (persistedState.kind === 'invalid') return 'invalid';
      if (record.source !== 'email_otp') {
        if (!prfClaim || prfClaim.state === 'missing' || prfClaim.state === 'warm') {
          return 'material_pending';
        }
        return prfClaim.state === 'unavailable' ? 'prf_unavailable' : 'prf_missing';
      }
      if (!prfClaim) return 'prf_missing';
      if (prfClaim.state === 'warm') return 'material_pending';
      if (prfClaim.state === 'unavailable') return 'prf_unavailable';
      return 'prf_missing';
    }
    if (!prfClaim) return 'prf_missing';
    if (prfClaim.state === 'unavailable') return 'prf_unavailable';
    if (prfClaim.state !== 'warm') return 'prf_missing';
    const persistedState = classifyRouterAbEcdsaHssPersistedSigningRecord(capability.record);
    if (persistedState.kind === 'runtime_validated') return 'ready';
    if (
      persistedState.kind === 'non_signing' ||
      persistedState.reason === 'missing_wallet_session_jwt'
    ) {
      return 'auth_missing';
    }
    if (persistedState.kind === 'restore_available') return 'material_pending';
    if (prfClaim.state === 'warm') return 'material_pending';
    return 'prf_missing';
  })();
  if (capability.state !== expectedState) {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: state=${capability.state} does not match derived state=${expectedState}`,
    );
  }
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
  walletId: string;
  nearAccountId: AccountId | string;
  nearEd25519SigningKeyId: string;
  relayerKeyId: string;
  auth?: Ed25519WalletSessionMintAuthorization;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  runtimeScopeBootstrap?: {
    projectEnvironmentId: string;
    publishableKey: string;
  };
  participantIds: readonly number[];
  sessionKind: 'jwt';
  signerSlot: number;
  relayerUrl?: string;
  ttlMs?: number;
  remainingUses?: number;
  beforeProvision?: () => void | Promise<void>;
  assertNotCancelled?: () => void;
};

type ProvisionWarmEd25519PasskeyCapabilityArgs = ProvisionWarmEd25519CapabilityBaseArgs & {
  source: Exclude<ThresholdEd25519SessionStoreSource, 'email_otp'>;
  authority: PasskeyEd25519SessionPolicyAuthority;
  emailOtpAuthContext?: never;
};

type ProvisionWarmEd25519EmailOtpCapabilityArgs = ProvisionWarmEd25519CapabilityBaseArgs & {
  source: 'email_otp';
  authority: EmailOtpEd25519SessionPolicyAuthority;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
};

type ProvisionWarmEd25519CapabilityCommonArgs =
  | ProvisionWarmEd25519PasskeyCapabilityArgs
  | ProvisionWarmEd25519EmailOtpCapabilityArgs;

export type FreshWarmEd25519CapabilityProvisionArgs = ProvisionWarmEd25519CapabilityCommonArgs & {
  kind: 'fresh_ed25519_provisioning';
  sessionId?: never;
  signingGrantId?: never;
};

export type ExactWarmEd25519CapabilityProvisionArgs = ProvisionWarmEd25519CapabilityCommonArgs & {
  kind: 'exact_ed25519_provisioning';
  sessionId: string;
  signingGrantId: string;
};

export type ProvisionWarmEd25519CapabilityArgs =
  | FreshWarmEd25519CapabilityProvisionArgs
  | ExactWarmEd25519CapabilityProvisionArgs;

export type ProvisionWarmEd25519CapabilitySuccessResult = {
  ok: true;
  sessionId: string;
  signingGrantId: string;
  expiresAtMs: number;
  remainingUses: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  jwt: string;
  ecdsaHssPasskeyPrfFirstB64u?: string;
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
          kind:
            | 'wallet_session_ecdsa_reconnect'
            | 'passkey_ecdsa_session_provision';
        }
      >;
      record: ThresholdEcdsaSessionRecord;
    })
  | (EnsureWarmEcdsaProvisionPlanReadyCommonArgs & {
      plan: Extract<
        EcdsaSessionProvisionPlan,
        { kind: 'email_otp_ecdsa_session_provision' }
      >;
      record: ThresholdEcdsaSessionRecord | null;
    });

export type EnsureWarmEcdsaCapabilityReadyResult = {
  record: ThresholdEcdsaSessionRecord;
  keyRef?: never;
  warmSession: WarmSessionEnvelope;
  capability: WarmSessionEcdsaCapabilityState;
  reconnected: boolean;
};

export type ApplyWarmEcdsaPostSignPolicyArgs = {
  lane: ExactEcdsaSigningLaneIdentity;
  selectedRecord: ThresholdEcdsaSessionRecord;
  walletId?: never;
  chainTarget?: never;
  thresholdSessionId?: never;
};

export type AssertWarmEcdsaOperationAllowedArgs = {
  lane: ExactEcdsaSigningLaneIdentity;
  operationLabel: string;
  source: ThresholdEcdsaSessionStoreSource;
  sensitivePolicy?: SensitiveOperationPolicy;
  walletId?: never;
  chainTarget?: never;
  thresholdSessionId?: never;
};

type ClaimWarmSessionPrfArgsBase = {
  thresholdSessionId: string;
  errorContext: string;
  uses?: number;
  consume?: boolean;
};

export type ThresholdOnlyWarmSessionPrfClaimArgs = ClaimWarmSessionPrfArgsBase & {
  kind: 'threshold_only_claim';
  walletId?: never;
  authMethod?: never;
  signingGrantId?: never;
  curve?: never;
  chain?: never;
  chainTarget?: never;
};

export type WalletScopedEd25519WarmSessionPrfClaimArgs = ClaimWarmSessionPrfArgsBase & {
  kind: 'wallet_scoped_ed25519_claim';
  walletId: string;
  authMethod: 'passkey' | 'email_otp';
  signingGrantId: string;
  curve: 'ed25519';
  chain: 'near';
  chainTarget?: never;
};

export type WalletScopedEcdsaWarmSessionPrfClaimArgs = ClaimWarmSessionPrfArgsBase & {
  kind: 'wallet_scoped_ecdsa_claim';
  walletId: string;
  authMethod: 'passkey';
  signingGrantId: string;
  curve: 'ecdsa';
  chain: 'near';
  chainTarget: ThresholdEcdsaChainTarget;
};

export type ClaimWarmSessionPrfArgs =
  | ThresholdOnlyWarmSessionPrfClaimArgs
  | WalletScopedEd25519WarmSessionPrfClaimArgs
  | WalletScopedEcdsaWarmSessionPrfClaimArgs;

export type WarmEcdsaRecordBackedSigningSessionStatus = SigningSessionStatus & {
  key: EvmFamilyEcdsaKeyIdentity;
  lane: SelectedEcdsaLane;
  chainTarget: ThresholdEcdsaChainTarget;
  source: ThresholdEcdsaSessionStoreSource;
  signingGrantId: string;
};

export type WarmEcdsaMissingSigningSessionStatus = SigningSessionStatus & {
  status: 'not_found';
  chainTarget: ThresholdEcdsaChainTarget;
  source?: never;
  signingGrantId?: never;
};

export type WarmEcdsaSigningSessionStatus =
  | WarmEcdsaRecordBackedSigningSessionStatus
  | WarmEcdsaMissingSigningSessionStatus;

export type WarmSessionEcdsaCapabilityRef = {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
};

export type GetWarmEcdsaSigningSessionStatusArgs = Omit<
  WarmSessionEcdsaCapabilityRef,
  'thresholdSessionId'
> & {
  thresholdSessionId: string;
};

export type WarmSessionCapabilityReader = {
  getWarmSession: (walletId: WalletId) => Promise<WarmSessionEnvelope>;
  resolveEd25519RecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => WarmSessionEd25519CapabilityState['record'];
  resolveEcdsaRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => WarmSessionEcdsaCapabilityState['record'];
  resolveEd25519AuthByThresholdSessionId: (
    thresholdSessionId: string,
  ) => WarmSessionEd25519AuthMaterial | null;
  resolveEcdsaAuthByThresholdSessionId: (
    thresholdSessionId: string,
  ) => WarmSessionEcdsaAuthMaterial | null;
  resolveEmailOtpEd25519SigningSessionAuthority: (args: {
    lane: ExactEd25519SigningLaneIdentity;
  }) => EmailOtpEd25519SigningSessionAuthority | null;
  resolveEmailOtpEcdsaSigningSessionAuthority: (args: {
    lane: ExactEcdsaSigningLaneIdentity;
  }) => EmailOtpEcdsaSigningSessionAuthority | null;
  getEd25519CapabilityByThresholdSessionId: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionEd25519CapabilityState | null>;
  getEcdsaCapabilityByThresholdSessionId: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionEcdsaCapabilityState | null>;
  getEcdsaCapabilityForLane: (
    lane: ExactEcdsaSigningLaneIdentity,
  ) => Promise<WarmSessionEcdsaCapabilityState | null>;
  resolveEcdsaSealTransportByThresholdSessionId: (args: {
    lane: ExactEcdsaSigningLaneIdentity;
  }) => ThresholdSessionSealTransportAuthMaterial | null;
};

export type ThresholdWarmSessionStatusReader = {
  getEd25519SigningSessionStatus: (
    nearAccountId: AccountId,
  ) => Promise<SigningSessionStatus | null>;
  getEd25519SigningSessionStatusForSession: (args: {
    nearAccountId: AccountId;
    thresholdSessionId: string;
  }) => Promise<SigningSessionStatus | null>;
  getEcdsaSigningSessionStatus: (
    args: GetWarmEcdsaSigningSessionStatusArgs,
  ) => Promise<WarmEcdsaSigningSessionStatus | null>;
  listEcdsaSigningSessionStatuses: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
  }) => Promise<WarmEcdsaRecordBackedSigningSessionStatus[]>;
  assertEcdsaSigningSessionReady: (
    args: Omit<WarmSessionEcdsaCapabilityRef, 'thresholdSessionId'> & {
      thresholdSessionId: unknown;
      usesNeeded?: number;
    },
  ) => Promise<Extract<WarmSessionStatusResult, { ok: true }>>;
};

export type WarmSessionProvisioner = {
  provisionEd25519Capability: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  ensureEcdsaCapabilityReady: (
    args: EnsureWarmEcdsaProvisionPlanReadyArgs,
  ) => Promise<EnsureWarmEcdsaCapabilityReadyResult>;
  claimWarmSessionPrfFirstMaterial: (args: ClaimWarmSessionPrfArgs) => Promise<string>;
  ensureEcdsaPrfSealPersistedByThresholdSessionId: (args: {
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdSessionId: string;
    required?: boolean;
    errorContext?: string;
  }) => Promise<void>;
};

export type WarmSessionPostSignPolicy = {
  applyEcdsaPostSignPolicy: (args: ApplyWarmEcdsaPostSignPolicyArgs) => Promise<void>;
  assertEcdsaOperationAllowed: (args: AssertWarmEcdsaOperationAllowedArgs) => Promise<void>;
};

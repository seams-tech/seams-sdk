import type { AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaHssRouteAuth } from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { SigningSessionStatus } from '@/core/types/seams';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from './ecdsaBootstrapPersistence';
import type { EcdsaSessionProvisionPlan } from './ecdsaProvisionPlan';
import type {
  ThresholdEcdsaSessionAuthTokenSource,
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
  ThresholdSessionSealTransportAuthMaterial,
} from '../persistence/records';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
  ThresholdEd25519SessionStoreSource,
} from '../identity/laneIdentity';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type {
  ThresholdEcdsaSessionBootstrapResult,
} from '../../threshold/ecdsa/activation';
import type {
  ThresholdRuntimePolicyScope,
  ThresholdSessionKind,
} from '../../threshold/sessionPolicy';
import type { WarmSessionStatusResult } from '../../uiConfirm/types';
import type { SigningOperationIntent } from '../operationState/types';
import type { ThresholdEcdsaChainTarget, WalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type WarmSessionCapability = 'ed25519' | 'ecdsa';
export type WarmSessionPrfClaimState = 'missing' | 'warm' | 'expired' | 'exhausted' | 'unavailable';

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
  thresholdSessionAuthToken: string;
  thresholdSessionAuthTokenSource: 'ed25519';
};

export type WarmSessionEd25519AuthMaterialWithoutToken = {
  capability: 'ed25519';
  record: ThresholdEd25519SessionRecord;
  thresholdSessionAuthToken?: never;
  thresholdSessionAuthTokenSource: 'none';
};

export type WarmSessionEd25519AuthMaterial =
  | WarmSessionEd25519AuthMaterialWithToken
  | WarmSessionEd25519AuthMaterialWithoutToken;

export type WarmSessionEcdsaAuthMaterialWithToken = {
  capability: 'ecdsa';
  record: ThresholdEcdsaSessionRecord;
  thresholdSessionAuthToken: string;
  thresholdSessionAuthTokenSource: 'ecdsa';
};

export type WarmSessionEcdsaAuthMaterialWithoutToken = {
  capability: 'ecdsa';
  record: ThresholdEcdsaSessionRecord;
  thresholdSessionAuthToken?: never;
  thresholdSessionAuthTokenSource: 'none';
};

export type WarmSessionEcdsaAuthMaterial =
  | WarmSessionEcdsaAuthMaterialWithToken
  | WarmSessionEcdsaAuthMaterialWithoutToken;

type WarmSessionCapabilityStateValue =
  | 'missing'
  | 'ready'
  | 'auth_missing'
  | 'prf_missing'
  | 'prf_unavailable';

type WarmSessionPresentCapabilityStateValue = Exclude<WarmSessionCapabilityStateValue, 'missing'>;

type WarmSessionMissingEd25519CapabilityState = {
  capability: 'ed25519';
  record: null;
  auth: null;
  prfClaim: null;
  emailOtpAuthContext?: never;
  state: 'missing';
};

type WarmSessionEmailOtpEd25519CapabilityState = {
  capability: 'ed25519';
  record: ThresholdEd25519SessionRecord;
  auth: WarmSessionEd25519AuthMaterial | null;
  prfClaim: WarmSessionPrfClaim | null;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  state: WarmSessionPresentCapabilityStateValue;
};

type WarmSessionNonEmailOtpEd25519CapabilityState = {
  capability: 'ed25519';
  record: ThresholdEd25519SessionRecord;
  auth: WarmSessionEd25519AuthMaterial | null;
  prfClaim: WarmSessionPrfClaim | null;
  emailOtpAuthContext?: never;
  state: WarmSessionPresentCapabilityStateValue;
};

export type WarmSessionEd25519CapabilityState =
  | WarmSessionMissingEd25519CapabilityState
  | WarmSessionEmailOtpEd25519CapabilityState
  | WarmSessionNonEmailOtpEd25519CapabilityState;

type WarmSessionMissingEcdsaCapabilityState = {
  capability: 'ecdsa';
  record: null;
  auth: null;
  prfClaim: null;
  emailOtpAuthContext?: never;
  state: 'missing';
};

type WarmSessionEmailOtpEcdsaCapabilityState = {
  capability: 'ecdsa';
  record: ThresholdEcdsaSessionRecord;
  auth: WarmSessionEcdsaAuthMaterial | null;
  prfClaim: WarmSessionPrfClaim | null;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  state: WarmSessionPresentCapabilityStateValue;
};

type WarmSessionNonEmailOtpEcdsaCapabilityState = {
  capability: 'ecdsa';
  record: ThresholdEcdsaSessionRecord;
  auth: WarmSessionEcdsaAuthMaterial | null;
  prfClaim: WarmSessionPrfClaim | null;
  emailOtpAuthContext?: never;
  state: WarmSessionPresentCapabilityStateValue;
};

export type WarmSessionEcdsaCapabilityState =
  | WarmSessionMissingEcdsaCapabilityState
  | WarmSessionEmailOtpEcdsaCapabilityState
  | WarmSessionNonEmailOtpEcdsaCapabilityState;

export type WarmSessionEnvelope = {
  walletId: AccountId;
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
  walletId: AccountId;
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
    return;
  }

  if (capability.capability === 'ecdsa') {
    if (String(capability.record.walletId) !== String(args.walletId)) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: record wallet does not match envelope wallet`,
      );
    }
  } else if (String(capability.record.nearAccountId) !== String(args.walletId)) {
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

  const requiresAuthToken = record.thresholdSessionKind === 'jwt';
  const hasAuthToken = Boolean(String(auth?.thresholdSessionAuthToken || '').trim());
  const emailOtpSingleUseConsumed =
    record.source === 'email_otp' &&
    emailOtpAuthContext?.retention === 'single_use' &&
    Number(emailOtpAuthContext.consumedAtMs) > 0;
  const emailOtpHasWorkerOwnedClientBase =
    record.source === 'email_otp' &&
    !emailOtpSingleUseConsumed &&
    Boolean(String((record as { xClientBaseB64u?: unknown }).xClientBaseB64u || '').trim());
  const expectedState =
    !auth || (requiresAuthToken && !hasAuthToken)
      ? 'auth_missing'
      : emailOtpSingleUseConsumed
        ? 'prf_missing'
        : emailOtpHasWorkerOwnedClientBase
          ? 'ready'
          : !prfClaim
            ? 'prf_missing'
            : prfClaim.state === 'unavailable'
              ? 'prf_unavailable'
              : prfClaim.state !== 'warm'
                ? 'prf_missing'
                : 'ready';
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
type ProvisionWarmEd25519CapabilityCommonArgs = {
  nearAccountId: AccountId | string;
  relayerKeyId: string;
  appSessionJwt?: string;
  useAppSessionCookie?: boolean;
  localPrfCredential?: WebAuthnAuthenticationCredential;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  participantIds: readonly number[];
  sessionKind: ThresholdSessionKind;
  relayerUrl?: string;
  ttlMs?: number;
  remainingUses?: number;
  source: ThresholdEd25519SessionStoreSource;
  beforeProvision?: () => void | Promise<void>;
  assertNotCancelled?: () => void;
};

export type FreshWarmEd25519CapabilityProvisionArgs =
  ProvisionWarmEd25519CapabilityCommonArgs & {
    kind: 'fresh_ed25519_provisioning';
    sessionId?: never;
    walletSigningSessionId?: never;
  };

export type ExactWarmEd25519CapabilityProvisionArgs =
  ProvisionWarmEd25519CapabilityCommonArgs & {
    kind: 'exact_ed25519_provisioning';
    sessionId: string;
    walletSigningSessionId: string;
  };

export type ProvisionWarmEd25519CapabilityArgs =
  | FreshWarmEd25519CapabilityProvisionArgs
  | ExactWarmEd25519CapabilityProvisionArgs;

export type ProvisionWarmEd25519CapabilitySuccessResult = {
  ok: true;
  sessionId: string;
  walletSigningSessionId: string;
  expiresAtMs: number;
  remainingUses: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  jwt: string;
  ecdsaHssClientRootShare32B64u?: string;
};

export type ProvisionWarmEd25519CapabilityFailureResult = {
  ok: false;
  code: string;
  message: string;
};

export type ProvisionWarmEd25519CapabilityResult =
  | ProvisionWarmEd25519CapabilitySuccessResult
  | ProvisionWarmEd25519CapabilityFailureResult;

export type EnsureWarmEcdsaProvisionPlanReadyArgs = {
  walletId: AccountId | string;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  plan: EcdsaSessionProvisionPlan;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
  source: ThresholdEcdsaSessionStoreSource;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  usesNeeded?: number;
  sessionBudgetUses: number;
  operationIntent?: SigningOperationIntent;
  beforeReconnect?: () => void | Promise<void>;
  assertNotCancelled?: () => void;
};

export type EnsureWarmEcdsaCapabilityReadyResult = {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  warmSession: WarmSessionEnvelope;
  capability: WarmSessionEcdsaCapabilityState;
  reconnected: boolean;
};

export type ApplyWarmEcdsaPostSignPolicyArgs = {
  walletId: AccountId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  selectedRecord: ThresholdEcdsaSessionRecord;
};

export type AssertWarmEcdsaOperationAllowedArgs = {
  walletId: AccountId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  operationLabel: string;
  thresholdSessionId: string;
  source: ThresholdEcdsaSessionStoreSource;
  sensitivePolicy?: SensitiveOperationPolicy;
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
  walletSigningSessionId?: never;
  curve?: never;
  chain?: never;
  chainTarget?: never;
};

export type WalletScopedEd25519WarmSessionPrfClaimArgs = ClaimWarmSessionPrfArgsBase & {
  kind: 'wallet_scoped_ed25519_claim';
  walletId: string;
  authMethod: 'passkey';
  walletSigningSessionId: string;
  curve: 'ed25519';
  chain: 'near';
  chainTarget?: never;
};

export type WalletScopedEcdsaWarmSessionPrfClaimArgs = ClaimWarmSessionPrfArgsBase & {
  kind: 'wallet_scoped_ecdsa_claim';
  walletId: string;
  authMethod: 'passkey';
  walletSigningSessionId: string;
  curve: 'ecdsa';
  chain: 'near';
  chainTarget: ThresholdEcdsaChainTarget;
};

export type ClaimWarmSessionPrfArgs =
  | ThresholdOnlyWarmSessionPrfClaimArgs
  | WalletScopedEd25519WarmSessionPrfClaimArgs
  | WalletScopedEcdsaWarmSessionPrfClaimArgs;

export type WarmEcdsaRecordBackedSigningSessionStatus = SigningSessionStatus & {
  chainTarget: ThresholdEcdsaChainTarget;
  source: ThresholdEcdsaSessionStoreSource;
  walletSigningSessionId: string;
};

export type WarmEcdsaMissingSigningSessionStatus = SigningSessionStatus & {
  status: 'not_found';
  chainTarget: ThresholdEcdsaChainTarget;
  source?: never;
  walletSigningSessionId?: never;
};

export type WarmEcdsaSigningSessionStatus =
  | WarmEcdsaRecordBackedSigningSessionStatus
  | WarmEcdsaMissingSigningSessionStatus;

export type WarmSessionEcdsaCapabilityRef = {
  walletId: AccountId | string;
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
  getWarmSession: (walletId: AccountId | string) => Promise<WarmSessionEnvelope>;
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
  resolveEmailOtpSigningSessionAuthLane: (args: {
    thresholdSessionId: string;
    curve: 'ed25519' | 'ecdsa';
  }) => EmailOtpAuthLane | null;
  getEd25519CapabilityByThresholdSessionId: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionEd25519CapabilityState | null>;
  getEcdsaCapabilityByThresholdSessionId: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionEcdsaCapabilityState | null>;
  resolveEcdsaSealTransportByThresholdSessionId: (
    args: {
      thresholdSessionId: string;
      chainTarget: ThresholdEcdsaChainTarget;
    },
  ) => ThresholdSessionSealTransportAuthMaterial | null;
};

export type ThresholdWarmSessionStatusReader = {
  getEd25519SigningSessionStatus: (
    nearAccountId: AccountId | string,
  ) => Promise<SigningSessionStatus | null>;
  getEd25519SigningSessionStatusForSession: (args: {
    nearAccountId: AccountId | string;
    thresholdSessionId: string;
  }) => Promise<SigningSessionStatus | null>;
  getEcdsaSigningSessionStatus: (
    args: GetWarmEcdsaSigningSessionStatusArgs,
  ) => Promise<WarmEcdsaSigningSessionStatus | null>;
  listEcdsaSigningSessionStatuses: (args: {
    walletId: AccountId | string;
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
  claimPrfFirstByThresholdSessionId: (args: ClaimWarmSessionPrfArgs) => Promise<string>;
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

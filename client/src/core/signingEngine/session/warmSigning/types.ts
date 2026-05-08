import type { AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaHssRouteAuth } from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { SigningSessionStatus } from '@/core/types/seams';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from './ecdsaBootstrapPersistence';
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
import type { SigningOperationIntent } from '../signingSession/types';
import type { ThresholdEcdsaChainTarget, WalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type WarmSessionCapability = 'ed25519' | 'ecdsa';
export type WarmSessionPrfClaimState = 'missing' | 'warm' | 'expired' | 'exhausted' | 'unavailable';

export type WarmSessionPrfClaim = {
  state: WarmSessionPrfClaimState;
  sessionId: string;
  expiresAtMs?: number;
  remainingUses?: number;
  code?: string;
};

export type WarmSessionEd25519AuthMaterial = {
  capability: 'ed25519';
  record: ThresholdEd25519SessionRecord;
  thresholdSessionAuthToken?: string;
  thresholdSessionAuthTokenSource: 'ed25519' | 'none';
};

export type WarmSessionEcdsaAuthMaterial = {
  capability: 'ecdsa';
  record: ThresholdEcdsaSessionRecord;
  thresholdSessionAuthToken?: string;
  thresholdSessionAuthTokenSource: Exclude<ThresholdEcdsaSessionAuthTokenSource, 'ed25519'>;
};

export type WarmSessionEd25519CapabilityState = {
  capability: 'ed25519';
  record: ThresholdEd25519SessionRecord | null;
  auth: WarmSessionEd25519AuthMaterial | null;
  prfClaim: WarmSessionPrfClaim | null;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext | null;
  state: 'missing' | 'ready' | 'auth_missing' | 'prf_missing' | 'prf_unavailable';
};

export type WarmSessionEcdsaCapabilityState = {
  capability: 'ecdsa';
  record: ThresholdEcdsaSessionRecord | null;
  auth: WarmSessionEcdsaAuthMaterial | null;
  prfClaim: WarmSessionPrfClaim | null;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext | null;
  state: 'missing' | 'ready' | 'auth_missing' | 'prf_missing' | 'prf_unavailable';
};

export type WarmSessionEnvelope = {
  accountId: AccountId;
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
  accountId: AccountId;
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

  if (String(record.nearAccountId) !== String(args.accountId)) {
    throw new Error(
      `[WarmSessionStore] invalid ${args.label} capability: record account does not match envelope account`,
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
    if (
      prfClaim.state === 'warm' &&
      (typeof prfClaim.remainingUses !== 'number' ||
        prfClaim.remainingUses <= 0 ||
        typeof prfClaim.expiresAtMs !== 'number' ||
        prfClaim.expiresAtMs <= 0)
    ) {
      throw new Error(
        `[WarmSessionStore] invalid ${args.label} capability: warm warm-session status requires positive remainingUses and expiresAtMs`,
      );
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
    accountId: envelope.accountId,
    label: 'ed25519',
    capability: envelope.capabilities.ed25519,
  });
  assertCapabilityStateInvariant({
    accountId: envelope.accountId,
    label: 'ecdsa.evm',
    capability: envelope.capabilities.ecdsa.evm,
  });
  assertCapabilityStateInvariant({
    accountId: envelope.accountId,
    label: 'ecdsa.tempo',
    capability: envelope.capabilities.ecdsa.tempo,
  });
  return envelope;
}
export type ProvisionWarmEd25519CapabilityArgs = {
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
  participantIds?: number[];
  sessionKind?: ThresholdSessionKind;
  relayerUrl?: string;
  ttlMs?: number;
  remainingUses?: number;
  sessionId?: string;
  walletSigningSessionId?: string;
  source?: ThresholdEd25519SessionStoreSource;
  beforeProvision?: () => void | Promise<void>;
  assertNotCancelled?: () => void;
};

export type ProvisionWarmEd25519CapabilityResult = {
  ok: boolean;
  sessionId?: string;
  walletSigningSessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  jwt?: string;
  ecdsaHssClientRootShare32B64u?: string;
  code?: string;
  message?: string;
};

export type EnsureWarmEcdsaCapabilityReadyArgs = {
  nearAccountId: AccountId | string;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
  source?: ThresholdEcdsaSessionStoreSource;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  usesNeeded?: number;
  sessionBudgetUses: number;
  operationIntent?: SigningOperationIntent;
  sessionId?: string;
  walletSigningSessionId?: string;
  clientRootShare32B64u?: string;
  webauthnAuthentication?: WebAuthnAuthenticationCredential;
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
  nearAccountId: AccountId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId?: string;
  source?: ThresholdEcdsaSessionStoreSource;
  selectedRecord: ThresholdEcdsaSessionRecord;
};

export type AssertWarmEcdsaOperationAllowedArgs = {
  nearAccountId: AccountId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  operationLabel: string;
  thresholdSessionId?: string;
  source?: ThresholdEcdsaSessionStoreSource;
  sensitivePolicy?: SensitiveOperationPolicy;
};

export type ResolveWarmEcdsaBootstrapRequestArgs = {
  nearAccountId: AccountId | string;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  relayerUrl?: string;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  walletSigningSessionId?: string;
  thresholdSessionAuth?: ThresholdEcdsaHssRouteAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
  webauthnAuthentication?: WebAuthnAuthenticationCredential;
  operationIntent?: SigningOperationIntent;
};

export type WarmEcdsaBootstrapRequest = {
  nearAccountId: AccountId;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  relayerUrl?: string;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  walletSigningSessionId?: string;
  thresholdSessionAuth?: ThresholdEcdsaHssRouteAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
  webauthnAuthentication?: WebAuthnAuthenticationCredential;
  operationIntent?: SigningOperationIntent;
};

export type ProvisionWarmEcdsaCapabilityArgs = ResolveWarmEcdsaBootstrapRequestArgs & {
  source?: ThresholdEcdsaSessionStoreSource;
  ttlMs?: number;
  remainingUses?: number;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  beforeProvision?: () => void | Promise<void>;
  assertNotCancelled?: () => void;
};

export type ClaimWarmSessionPrfArgs = {
  thresholdSessionId: string;
  errorContext: string;
  uses?: number;
  consume?: boolean;
  walletId?: string;
  authMethod?: 'passkey' | 'email_otp';
  curve?: 'ed25519' | 'ecdsa';
  chain?: 'near';
  chainTarget?: ThresholdEcdsaChainTarget;
  walletSigningSessionId?: string;
};

export type WarmEcdsaSigningSessionStatus = SigningSessionStatus & {
  chainTarget: ThresholdEcdsaChainTarget;
  source?: ThresholdEcdsaSessionStoreSource;
  walletSigningSessionId?: string;
};

export type WarmSessionEcdsaCapabilityRef = {
  nearAccountId: AccountId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId?: string;
};

export type GetWarmEcdsaSigningSessionStatusArgs = Omit<
  WarmSessionEcdsaCapabilityRef,
  'thresholdSessionId'
> & {
  thresholdSessionId: string;
};

export type WarmSessionCapabilityReader = {
  getWarmSession: (nearAccountId: AccountId | string) => Promise<WarmSessionEnvelope>;
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
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
  }) => Promise<WarmEcdsaSigningSessionStatus[]>;
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
  resolveEcdsaBootstrapRequest: (
    args: ResolveWarmEcdsaBootstrapRequestArgs,
  ) => Promise<WarmEcdsaBootstrapRequest>;
  provisionEcdsaCapability: (
    args: ProvisionWarmEcdsaCapabilityArgs,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  tryReuseReadyEcdsaBootstrap: (args: {
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => Promise<ThresholdEcdsaSessionBootstrapResult | null>;
  ensureEcdsaCapabilityReady: (
    args: EnsureWarmEcdsaCapabilityReadyArgs,
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

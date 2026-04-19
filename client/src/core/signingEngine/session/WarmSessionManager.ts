import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type {
  SigningSessionRetention,
  SigningSessionStatus,
  WalletAuthMethod,
} from '@/core/types/tatchi';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { WarmSessionStatusResult } from '../touchConfirm';
import type {
  WarmSessionSealPersister,
  WarmSessionMaterialClaimer,
  WarmSessionStatusBatchReader,
  WarmSessionStatusReader,
} from '../touchConfirm';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEd25519SessionStoreSource,
  ThresholdEd25519SessionRecord,
  ThresholdEcdsaSessionStoreSource,
  ThresholdEcdsaSessionRecord,
  ThresholdSessionSealTransportAuthMaterial,
} from '../api/thresholdLifecycle/thresholdSessionStore';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../interfaces/signing';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../orchestration/thresholdActivation';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from '../api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence';
import type { ThresholdRuntimePolicyScope } from '../threshold/session/sessionPolicy';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import {
  SENSITIVE_OPERATION_POLICIES,
  type SensitiveOperationPolicy,
} from '@shared/utils/signerDomain';
import { WalletAuthPolicyError } from '../auth';
import {
  readWarmSessionCapabilityRecordsForAccount,
  readWarmSessionEd25519RecordByThresholdSessionId,
  readWarmSessionEcdsaRecordByThresholdSessionId,
} from './warmSessionStore';
import type { Ed25519SessionKind } from '../threshold/session/ed25519SessionTypes';
import { assertWarmSessionEnvelopeInvariant } from './warmSessionTypes';
import type {
  WarmSessionEd25519AuthMaterial,
  WarmSessionEcdsaAuthMaterial,
  WarmSessionEcdsaCapabilityState,
  WarmSessionEd25519CapabilityState,
  WarmSessionEnvelope,
  WarmSessionPrfClaim,
} from './warmSessionTypes';
import {
  buildReusableEcdsaBootstrapResult,
  getMatchingReadyEcdsaCapability,
  getPrimaryAndSecondaryEcdsaCapabilities,
  normalizeParticipantIds,
  toOptionalNonEmptyString,
  type WarmSessionEcdsaCapabilityRef,
} from './warmSessionEcdsaProvisioning';
import {
  deriveEcdsaCapabilityState,
  deriveEd25519CapabilityState,
  formatMissingWarmPrfMaterialError,
  formatWarmSessionClaimUnavailableError,
  reportWarmSessionAvailabilityFailure,
  readWarmSessionClaim,
  readWarmSessionClaims,
  resolveEcdsaAuthMaterial,
  resolveEcdsaSealTransport,
  resolveEd25519AuthMaterial,
  toSigningSessionStatus,
} from './warmSessionReadModel';
import {
  emitWarmSessionTransition,
  summarizeWarmSessionTransition,
  type WarmSessionTransitionEvent,
} from './warmSessionTransitions';
import { claimWarmSessionPrfFirst, ensureEcdsaPrfSealPersisted } from './warmSessionRuntime';
export type {
  WarmSessionTransitionCapabilitySnapshot,
  WarmSessionTransitionEvent,
  WarmSessionTransitionSnapshot,
} from './warmSessionTransitions';
export type { WarmSessionEcdsaCapabilityRef } from './warmSessionEcdsaProvisioning';

export type WarmSessionManagerDeps = {
  touchConfirm?: Partial<
    Pick<
      WarmSessionStatusReader &
        WarmSessionStatusBatchReader &
        WarmSessionMaterialClaimer &
        WarmSessionSealPersister & {
          clearWarmSessionMaterial(args: { sessionId: string }): Promise<void>;
        },
      | 'getWarmSessionStatus'
      | 'getWarmSessionStatuses'
      | 'claimWarmSessionMaterial'
      | 'sealAndPersistWarmSessionMaterial'
      | 'clearWarmSessionMaterial'
    >
  >;
  clearThresholdEcdsaSessionRecordForLane?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => void;
  markThresholdEcdsaEmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => void;
  clearThresholdEcdsaSigningArtifactsForLane?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => void | Promise<void>;
  getThresholdEcdsaSessionRecordForSigning?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => WarmSessionEcdsaPolicyRecordHint | null;
  signingSessionSeal?: {
    keyVersion?: string;
    shamirPrimeB64u?: string;
  };
  getThresholdEcdsaKeyRefForSigning?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => ThresholdEcdsaSecp256k1KeyRef;
  provisionThresholdEcdsaSession?: (
    args: ProvisionWarmEcdsaCapabilityArgs,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  bootstrapThresholdEcdsaSession?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  provisionThresholdEd25519Session?: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  onTransition?: (event: WarmSessionTransitionEvent) => void | Promise<void>;
};

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
  sessionKind?: Ed25519SessionKind;
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
  jwt?: string;
  ecdsaHssClientRootShare32B64u?: string;
  code?: string;
  message?: string;
};

export type EnsureWarmEcdsaCapabilityReadyArgs = {
  nearAccountId: AccountId | string;
  chain: ThresholdEcdsaActivationChain;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  usesNeeded?: number;
  beforeReconnect?: () => void | Promise<void>;
  assertNotCancelled?: () => void;
};

export type EnsureWarmEcdsaCapabilityReadyResult = {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  warmSession: WarmSessionEnvelope;
  capability: WarmSessionEcdsaCapabilityState;
  reconnected: boolean;
};

export type ResolveWarmEcdsaBootstrapRequestArgs = {
  nearAccountId: AccountId | string;
  chain: ThresholdEcdsaActivationChain;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  relayerUrl?: string;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  thresholdRouteAuth?: AppOrThresholdSessionAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
};

export type WarmEcdsaBootstrapRequest = {
  nearAccountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  relayerUrl?: string;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  thresholdRouteAuth?: AppOrThresholdSessionAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
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
};

export type WarmSessionEd25519SigningAuthPlan = {
  sessionId: string;
  kind: 'warmSession' | 'passkeyReauth' | 'emailOtpReauth';
  warmSessionReady: boolean;
  accountId: string;
  method: WalletAuthMethod;
  retention?: SigningSessionRetention | null;
  expiresAtMs: number;
  remainingUses: number;
};

type WarmSessionEcdsaPolicyRecordHint = {
  source: ThresholdEcdsaSessionStoreSource;
  thresholdSessionId: string;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext | null;
};

export const THRESHOLD_SESSION_MISSING_ERROR =
  '[chains] Missing threshold signingSessionId; reconnect threshold session before signing';

function cloneOptionalFixed32Bytes(value: Uint8Array | undefined): Uint8Array | undefined {
  if (!(value instanceof Uint8Array)) return undefined;
  if (value.length !== 32) {
    throw new Error('clientRootShare32 must be 32 bytes');
  }
  return value;
}
export const THRESHOLD_SESSION_EXHAUSTED_ERROR =
  '[chains] threshold signingSession is exhausted; reconnect threshold session before signing';
export const THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR =
  '[chains] threshold signingSession auth is unavailable; reconnect threshold session before signing';
export const THRESHOLD_SESSION_STATUS_UNAVAILABLE_ERROR =
  '[chains] threshold signingSession status is unavailable; retry after refreshing the signer runtime';

export function formatThresholdSigningSessionStatusError(code: string): string {
  return `[chains] threshold signingSession is ${code}; reconnect threshold session before signing`;
}

export function formatThresholdSigningSessionAvailabilityError(code?: string): string {
  const suffix = typeof code === 'string' && code.trim() ? ` (${code.trim()})` : '';
  return `${THRESHOLD_SESSION_STATUS_UNAVAILABLE_ERROR}${suffix}`;
}

export function requireThresholdSigningSessionId(sessionIdRaw: unknown): string {
  const sessionId = String(sessionIdRaw || '').trim();
  if (!sessionId) {
    throw new Error(THRESHOLD_SESSION_MISSING_ERROR);
  }
  return sessionId;
}

function normalizeUsesNeeded(usesNeededRaw: unknown): number {
  const usesNeeded = Math.floor(Number(usesNeededRaw) || 0);
  return usesNeeded > 0 ? usesNeeded : 1;
}

function assertPersistedWarmSessionRecord(args: {
  label: 'Ed25519' | 'ECDSA';
  nearAccountId: AccountId;
  expectedSessionId: string;
  persistedSessionIdRaw: unknown;
}): void {
  const persistedSessionId = String(args.persistedSessionIdRaw || '').trim();
  if (persistedSessionId === args.expectedSessionId) {
    return;
  }
  throw new Error(
    `[WarmSessionManager] provisioned ${args.label} capability was not persisted for ${args.nearAccountId} (expected sessionId=${args.expectedSessionId}, found=${persistedSessionId || 'missing'})`,
  );
}

export type WarmSessionManager = {
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
  getEd25519CapabilityByThresholdSessionId: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionEd25519CapabilityState | null>;
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
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => Promise<ThresholdEcdsaSessionBootstrapResult | null>;
  ensureEcdsaCapabilityReady: (
    args: EnsureWarmEcdsaCapabilityReadyArgs,
  ) => Promise<EnsureWarmEcdsaCapabilityReadyResult>;
  assertEcdsaSigningSessionReady: (
    args: WarmSessionEcdsaCapabilityRef & {
      thresholdSessionId: unknown;
      usesNeeded?: number;
    },
  ) => Promise<Extract<WarmSessionStatusResult, { ok: true }>>;
  resolveEd25519SigningAuthPlan: (args: {
    nearAccountId: AccountId | string;
    usesNeeded?: number;
    operationLabel?: string;
  }) => Promise<WarmSessionEd25519SigningAuthPlan>;
  getEd25519SigningSessionStatus: (
    nearAccountId: AccountId | string,
  ) => Promise<SigningSessionStatus | null>;
  getEcdsaSigningSessionStatus: (
    args: WarmSessionEcdsaCapabilityRef,
  ) => Promise<SigningSessionStatus | null>;
  claimPrfFirstByThresholdSessionId: (args: ClaimWarmSessionPrfArgs) => Promise<string>;
  ensureEcdsaPrfSealPersistedByThresholdSessionId: (args: {
    chain: ThresholdEcdsaActivationChain;
    thresholdSessionId: string;
    required?: boolean;
    errorContext?: string;
  }) => Promise<void>;
  applyEcdsaPostSignPolicy: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    thresholdSessionId?: string;
  }) => Promise<void>;
  assertEcdsaOperationAllowed: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    operationLabel: string;
    thresholdSessionId?: string;
    sensitivePolicy?: SensitiveOperationPolicy;
  }) => Promise<void>;
  resolveEcdsaSealTransportByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdSessionSealTransportAuthMaterial | null;
};

export function createWarmSessionManager(deps: WarmSessionManagerDeps = {}): WarmSessionManager {
  const reconnectInFlightByCapability = new Map<
    string,
    Promise<EnsureWarmEcdsaCapabilityReadyResult>
  >();
  const sealPersistInFlightBySessionId = new Map<string, Promise<void>>();

  function buildEcdsaCapabilityInflightKey(args: {
    nearAccountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    usesNeeded?: number;
    keyRef: ThresholdEcdsaSecp256k1KeyRef | null;
  }): string {
    const keyId = String(args.keyRef?.ecdsaThresholdKeyId || '').trim() || 'auto';
    const sessionId = String(args.keyRef?.thresholdSessionId || '').trim() || 'auto';
    return [
      String(args.nearAccountId),
      args.chain,
      String(normalizeUsesNeeded(args.usesNeeded)),
      keyId,
      sessionId,
    ].join('::');
  }

  async function clearEcdsaWarmCapabilityBestEffort(args: {
    nearAccountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    thresholdSessionId?: string;
  }): Promise<void> {
    const thresholdSessionId = String(args.thresholdSessionId || '').trim();
    if (typeof deps.clearThresholdEcdsaSigningArtifactsForLane === 'function') {
      await Promise.resolve(
        deps.clearThresholdEcdsaSigningArtifactsForLane({
          nearAccountId: args.nearAccountId,
          chain: args.chain,
        }),
      ).catch(() => undefined);
    }
    deps.clearThresholdEcdsaSessionRecordForLane?.({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
    });
    if (thresholdSessionId && typeof deps.touchConfirm?.clearWarmSessionMaterial === 'function') {
      await deps.touchConfirm
        .clearWarmSessionMaterial({ sessionId: thresholdSessionId })
        .catch(() => undefined);
    }
  }

  async function clearEcdsaEphemeralMaterialBestEffort(args: {
    nearAccountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    thresholdSessionId?: string;
  }): Promise<void> {
    const thresholdSessionId = String(args.thresholdSessionId || '').trim();
    if (typeof deps.clearThresholdEcdsaSigningArtifactsForLane === 'function') {
      await Promise.resolve(
        deps.clearThresholdEcdsaSigningArtifactsForLane({
          nearAccountId: args.nearAccountId,
          chain: args.chain,
        }),
      ).catch(() => undefined);
    }
    if (thresholdSessionId && typeof deps.touchConfirm?.clearWarmSessionMaterial === 'function') {
      await deps.touchConfirm
        .clearWarmSessionMaterial({ sessionId: thresholdSessionId })
        .catch(() => undefined);
    }
  }

  function shouldInvalidateEmailOtpCapability(args: {
    record: WarmSessionEcdsaPolicyRecordHint | null;
    prfClaim: WarmSessionEcdsaCapabilityState['prfClaim'];
  }): boolean {
    if (args.record?.source !== 'email_otp') return false;
    const state = args.prfClaim?.state;
    if (
      args.record.emailOtpAuthContext?.retention === 'single_use' &&
      (state === 'missing' || state === 'expired' || state === 'exhausted')
    ) {
      return false;
    }
    return state === 'missing' || state === 'expired' || state === 'exhausted';
  }

  function resolveWalletSigningSessionId(
    record: ThresholdEd25519SessionRecord | ThresholdEcdsaSessionRecord | null,
  ): string {
    return String(record?.walletSigningSessionId || record?.thresholdSessionId || '').trim();
  }

  function toScopedClaim(args: {
    source: WarmSessionPrfClaim;
    sessionId: string;
    remainingUses?: number;
    expiresAtMs?: number;
  }): WarmSessionPrfClaim {
    if (args.source.state !== 'warm') {
      return {
        ...args.source,
        sessionId: args.sessionId,
      };
    }
    return {
      state: 'warm',
      sessionId: args.sessionId,
      remainingUses: args.remainingUses ?? args.source.remainingUses,
      expiresAtMs: args.expiresAtMs ?? args.source.expiresAtMs,
    };
  }

  function applyWalletSigningSessionBudget(args: {
    records: Array<{
      record: ThresholdEd25519SessionRecord | ThresholdEcdsaSessionRecord | null;
      claim: WarmSessionPrfClaim | null;
    }>;
  }): Map<string, WarmSessionPrfClaim | null> {
    const byWalletSessionId = new Map<
      string,
      Array<{
        thresholdSessionId: string;
        claim: WarmSessionPrfClaim | null;
      }>
    >();

    for (const entry of args.records) {
      const thresholdSessionId = String(entry.record?.thresholdSessionId || '').trim();
      const walletSigningSessionId = resolveWalletSigningSessionId(entry.record);
      if (!thresholdSessionId || !walletSigningSessionId) continue;
      const group = byWalletSessionId.get(walletSigningSessionId) || [];
      group.push({ thresholdSessionId, claim: entry.claim });
      byWalletSessionId.set(walletSigningSessionId, group);
    }

    const scoped = new Map<string, WarmSessionPrfClaim | null>();
    for (const group of byWalletSessionId.values()) {
      const terminal =
        group.find((entry) => entry.claim?.state === 'expired')?.claim ||
        group.find((entry) => entry.claim?.state === 'exhausted')?.claim ||
        null;
      const warmClaims = group
        .map((entry) => entry.claim)
        .filter((claim): claim is WarmSessionPrfClaim & { state: 'warm' } => claim?.state === 'warm');
      const walletRemainingUses = warmClaims.length
        ? Math.min(...warmClaims.map((claim) => Math.floor(Number(claim.remainingUses) || 0)))
        : undefined;
      const walletExpiresAtMs = warmClaims.length
        ? Math.min(...warmClaims.map((claim) => Math.floor(Number(claim.expiresAtMs) || 0)))
        : undefined;

      for (const entry of group) {
        if (terminal) {
          scoped.set(
            entry.thresholdSessionId,
            toScopedClaim({
              source: terminal,
              sessionId: entry.thresholdSessionId,
            }),
          );
          continue;
        }
        if (entry.claim?.state === 'warm') {
          scoped.set(
            entry.thresholdSessionId,
            toScopedClaim({
              source: entry.claim,
              sessionId: entry.thresholdSessionId,
              remainingUses: walletRemainingUses,
              expiresAtMs: walletExpiresAtMs,
            }),
          );
          continue;
        }
        scoped.set(entry.thresholdSessionId, entry.claim);
      }
    }
    return scoped;
  }

  async function readWalletScopedClaimsForRecords(
    records: ReturnType<typeof readWarmSessionCapabilityRecordsForAccount>,
  ): Promise<{
    ed25519Claim: WarmSessionPrfClaim | null;
    evmClaim: WarmSessionPrfClaim | null;
    tempoClaim: WarmSessionPrfClaim | null;
  }> {
    const claimsBySessionId = await readWarmSessionClaims({
      touchConfirm: deps.touchConfirm,
      sessionIds: [
        records.ed25519?.thresholdSessionId || '',
        records.ecdsa.evm?.thresholdSessionId || '',
        records.ecdsa.tempo?.thresholdSessionId || '',
      ],
    });
    const rawEd25519Claim =
      claimsBySessionId.get(String(records.ed25519?.thresholdSessionId || '').trim()) || null;
    const rawEvmClaim =
      claimsBySessionId.get(String(records.ecdsa.evm?.thresholdSessionId || '').trim()) || null;
    const rawTempoClaim =
      claimsBySessionId.get(String(records.ecdsa.tempo?.thresholdSessionId || '').trim()) || null;
    const walletScopedClaims = applyWalletSigningSessionBudget({
      records: [
        { record: records.ed25519, claim: rawEd25519Claim },
        { record: records.ecdsa.evm, claim: rawEvmClaim },
        { record: records.ecdsa.tempo, claim: rawTempoClaim },
      ],
    });
    return {
      ed25519Claim:
        walletScopedClaims.get(String(records.ed25519?.thresholdSessionId || '').trim()) || null,
      evmClaim:
        walletScopedClaims.get(String(records.ecdsa.evm?.thresholdSessionId || '').trim()) || null,
      tempoClaim:
        walletScopedClaims.get(String(records.ecdsa.tempo?.thresholdSessionId || '').trim()) ||
        null,
    };
  }

  function formatEmailOtpSensitiveOperationError(args: {
    operationLabel: string;
    mode: 'passkey' | 'per_operation';
  }): Error {
    if (args.mode === 'per_operation') {
      return new WalletAuthPolicyError({
        code: 'fresh_email_otp_required',
        policy: 'sensitive_operation_requires_fresh_email_otp',
        operationLabel: args.operationLabel,
        message: `[SigningEngine] ${args.operationLabel} requires fresh Email OTP verification with per_operation policy`,
      });
    }
    return new WalletAuthPolicyError({
      code: 'passkey_step_up_required',
      policy: 'sensitive_operation_requires_passkey',
      operationLabel: args.operationLabel,
      message: `[SigningEngine] ${args.operationLabel} requires fresh passkey authentication after Email OTP login`,
    });
  }

  function resolveCurrentEcdsaRecord(args: {
    nearAccountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
  }): WarmSessionEcdsaPolicyRecordHint | null {
    if (typeof deps.getThresholdEcdsaSessionRecordForSigning === 'function') {
      try {
        const record = deps.getThresholdEcdsaSessionRecordForSigning(args);
        if (record) return record;
      } catch {}
    }
    return readWarmSessionCapabilityRecordsForAccount(args.nearAccountId).ecdsa[args.chain];
  }

  return {
    async getWarmSession(nearAccountId: AccountId | string): Promise<WarmSessionEnvelope> {
      const accountId = toAccountId(nearAccountId);
      const records = readWarmSessionCapabilityRecordsForAccount(accountId);

      const ed25519Auth = resolveEd25519AuthMaterial(records.ed25519);
      const evmAuth = resolveEcdsaAuthMaterial(records.ecdsa.evm);
      const tempoAuth = resolveEcdsaAuthMaterial(records.ecdsa.tempo);

      const { ed25519Claim, evmClaim, tempoClaim } =
        await readWalletScopedClaimsForRecords(records);
      const invalidateEvmCapability = shouldInvalidateEmailOtpCapability({
        record: records.ecdsa.evm,
        prfClaim: evmClaim,
      });
      const invalidateTempoCapability = shouldInvalidateEmailOtpCapability({
        record: records.ecdsa.tempo,
        prfClaim: tempoClaim,
      });

      if (invalidateEvmCapability || invalidateTempoCapability) {
        await Promise.all([
          invalidateEvmCapability
            ? clearEcdsaWarmCapabilityBestEffort({
                nearAccountId: accountId,
                chain: 'evm',
                thresholdSessionId: records.ecdsa.evm?.thresholdSessionId,
              })
            : Promise.resolve(),
          invalidateTempoCapability
            ? clearEcdsaWarmCapabilityBestEffort({
                nearAccountId: accountId,
                chain: 'tempo',
                thresholdSessionId: records.ecdsa.tempo?.thresholdSessionId,
              })
            : Promise.resolve(),
        ]);
      }

      return assertWarmSessionEnvelopeInvariant({
        accountId,
        capabilities: {
          ed25519: {
            capability: 'ed25519',
            record: records.ed25519,
            auth: ed25519Auth,
            prfClaim: ed25519Claim,
            state: deriveEd25519CapabilityState({
              record: records.ed25519,
              auth: ed25519Auth,
              prfClaim: ed25519Claim,
              emailOtpAuthContext: records.ed25519?.emailOtpAuthContext || null,
            }),
            ...(records.ed25519?.emailOtpAuthContext
              ? { emailOtpAuthContext: records.ed25519.emailOtpAuthContext }
              : {}),
          },
          ecdsa: {
            evm: {
              capability: 'ecdsa',
              chain: 'evm',
              record: invalidateEvmCapability ? null : records.ecdsa.evm,
              auth: invalidateEvmCapability ? null : evmAuth,
              prfClaim: invalidateEvmCapability ? null : evmClaim,
              ...(invalidateEvmCapability
                ? {}
                : records.ecdsa.evm?.emailOtpAuthContext
                  ? { emailOtpAuthContext: records.ecdsa.evm.emailOtpAuthContext }
                  : {}),
              state: deriveEcdsaCapabilityState({
                record: invalidateEvmCapability ? null : records.ecdsa.evm,
                auth: invalidateEvmCapability ? null : evmAuth,
                prfClaim: invalidateEvmCapability ? null : evmClaim,
                emailOtpAuthContext: invalidateEvmCapability
                  ? null
                  : records.ecdsa.evm?.emailOtpAuthContext || null,
              }),
            },
            tempo: {
              capability: 'ecdsa',
              chain: 'tempo',
              record: invalidateTempoCapability ? null : records.ecdsa.tempo,
              auth: invalidateTempoCapability ? null : tempoAuth,
              prfClaim: invalidateTempoCapability ? null : tempoClaim,
              ...(invalidateTempoCapability
                ? {}
                : records.ecdsa.tempo?.emailOtpAuthContext
                  ? { emailOtpAuthContext: records.ecdsa.tempo.emailOtpAuthContext }
                  : {}),
              state: deriveEcdsaCapabilityState({
                record: invalidateTempoCapability ? null : records.ecdsa.tempo,
                auth: invalidateTempoCapability ? null : tempoAuth,
                prfClaim: invalidateTempoCapability ? null : tempoClaim,
                emailOtpAuthContext: invalidateTempoCapability
                  ? null
                  : records.ecdsa.tempo?.emailOtpAuthContext || null,
              }),
            },
          },
        },
        updatedAtMs: Date.now(),
      });
    },

    resolveEd25519RecordByThresholdSessionId(
      thresholdSessionId: string,
    ): WarmSessionEd25519CapabilityState['record'] {
      return readWarmSessionEd25519RecordByThresholdSessionId(thresholdSessionId);
    },

    resolveEcdsaRecordByThresholdSessionId(
      thresholdSessionId: string,
    ): WarmSessionEcdsaCapabilityState['record'] {
      return readWarmSessionEcdsaRecordByThresholdSessionId(thresholdSessionId);
    },

    resolveEd25519AuthByThresholdSessionId(
      thresholdSessionId: string,
    ): WarmSessionEd25519AuthMaterial | null {
      return resolveEd25519AuthMaterial(
        readWarmSessionEd25519RecordByThresholdSessionId(thresholdSessionId),
      );
    },

    resolveEcdsaAuthByThresholdSessionId(
      thresholdSessionId: string,
    ): WarmSessionEcdsaAuthMaterial | null {
      const record = readWarmSessionEcdsaRecordByThresholdSessionId(thresholdSessionId);
      return record ? resolveEcdsaAuthMaterial(record) : null;
    },

    async getEd25519CapabilityByThresholdSessionId(
      thresholdSessionId: string,
    ): Promise<WarmSessionEd25519CapabilityState | null> {
      const record = readWarmSessionEd25519RecordByThresholdSessionId(thresholdSessionId);
      if (!record) return null;
      const auth = resolveEd25519AuthMaterial(record);
      const prfClaim = await readWarmSessionClaim(deps.touchConfirm, record.thresholdSessionId);
      return {
        capability: 'ed25519',
        record,
        auth,
        prfClaim,
        state: deriveEd25519CapabilityState({
          record,
          auth,
          prfClaim,
          emailOtpAuthContext: record.emailOtpAuthContext || null,
        }),
        ...(record.emailOtpAuthContext ? { emailOtpAuthContext: record.emailOtpAuthContext } : {}),
      };
    },

    async provisionEd25519Capability(
      args: ProvisionWarmEd25519CapabilityArgs,
    ): Promise<ProvisionWarmEd25519CapabilityResult> {
      const nearAccountId = toAccountId(args.nearAccountId);
      if (typeof deps.provisionThresholdEd25519Session !== 'function') {
        throw new Error(
          '[WarmSessionManager] provisionThresholdEd25519Session is required to provision Ed25519 capability',
        );
      }
      const beforeWarmSession = await this.getWarmSession(nearAccountId);
      await args.beforeProvision?.();
      args.assertNotCancelled?.();
      const provisioned = await deps.provisionThresholdEd25519Session(args);
      args.assertNotCancelled?.();

      if (!provisioned.ok) {
        return provisioned;
      }

      const expectedSessionId = toOptionalNonEmptyString(provisioned.sessionId);
      if (!expectedSessionId) {
        throw new Error(
          `[WarmSessionManager] provisioned Ed25519 capability is missing sessionId for ${nearAccountId}`,
        );
      }

      const afterWarmSession = await this.getWarmSession(nearAccountId);
      assertPersistedWarmSessionRecord({
        label: 'Ed25519',
        nearAccountId,
        expectedSessionId,
        persistedSessionIdRaw: afterWarmSession.capabilities.ed25519.record?.thresholdSessionId,
      });
      emitWarmSessionTransition({
        onTransition: deps.onTransition,
        event: {
          type: 'ed25519_capability_provisioned',
          accountId: nearAccountId,
          thresholdSessionId: expectedSessionId,
          before: summarizeWarmSessionTransition(beforeWarmSession),
          after: summarizeWarmSessionTransition(afterWarmSession),
        },
      });
      return provisioned;
    },

    async resolveEcdsaBootstrapRequest(
      args: ResolveWarmEcdsaBootstrapRequestArgs,
    ): Promise<WarmEcdsaBootstrapRequest> {
      const nearAccountId = toAccountId(args.nearAccountId);
      const warmSession = await this.getWarmSession(nearAccountId);
      const { primary: primaryCapability, secondary: secondaryCapability } =
        getPrimaryAndSecondaryEcdsaCapabilities({
          warmSession,
          chain: args.chain,
        });
      const primaryWarmCapability =
        primaryCapability.prfClaim?.state === 'warm' ? primaryCapability : null;
      const reusableWarmCapability = primaryWarmCapability;

      const explicitParticipantIds = normalizeParticipantIds(args.participantIds);
      const explicitRelayerUrl = toOptionalNonEmptyString(args.relayerUrl);
      const explicitThresholdRouteAuth = args.thresholdRouteAuth;
      const explicitSessionId = toOptionalNonEmptyString(args.sessionId);
      const explicitThresholdKeyId = toOptionalNonEmptyString(args.ecdsaThresholdKeyId);
      const explicitClientRootShare32 = cloneOptionalFixed32Bytes(args.clientRootShare32);
      const explicitClientRootShare32B64u = toOptionalNonEmptyString(args.clientRootShare32B64u);
      const explicitRuntimeScopeBootstrap =
        args.runtimeScopeBootstrap &&
        String(args.runtimeScopeBootstrap.environmentId || '').trim() &&
        String(args.runtimeScopeBootstrap.publishableKey || '').trim()
          ? {
              environmentId: String(args.runtimeScopeBootstrap.environmentId || '').trim(),
              publishableKey: String(args.runtimeScopeBootstrap.publishableKey || '').trim(),
            }
          : null;
      const preferredMetadataCapability = primaryCapability.record
        ? primaryCapability
        : secondaryCapability.record
          ? secondaryCapability
          : null;
      const preferredParticipantIds =
        normalizeParticipantIds(primaryCapability.record?.participantIds) ||
        normalizeParticipantIds(secondaryCapability.record?.participantIds);
      const preferredSessionKind =
        primaryCapability.record?.thresholdSessionKind ||
        secondaryCapability.record?.thresholdSessionKind ||
        'jwt';

      return {
        nearAccountId,
        chain: args.chain,
        ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
        ...(explicitRelayerUrl
          ? { relayerUrl: explicitRelayerUrl }
          : toOptionalNonEmptyString(preferredMetadataCapability?.record?.relayerUrl)
            ? {
                relayerUrl: String(
                  toOptionalNonEmptyString(preferredMetadataCapability?.record?.relayerUrl) || '',
                ).trim(),
              }
            : {}),
        ...(explicitThresholdKeyId
          ? { ecdsaThresholdKeyId: explicitThresholdKeyId }
          : toOptionalNonEmptyString(primaryCapability.record?.ecdsaThresholdKeyId)
            ? {
                ecdsaThresholdKeyId: String(
                  toOptionalNonEmptyString(primaryCapability.record?.ecdsaThresholdKeyId) || '',
                ).trim(),
              }
            : toOptionalNonEmptyString(secondaryCapability.record?.ecdsaThresholdKeyId)
              ? {
                  ecdsaThresholdKeyId: String(
                    toOptionalNonEmptyString(secondaryCapability.record?.ecdsaThresholdKeyId) || '',
                  ).trim(),
                }
              : {}),
        ...(explicitParticipantIds
          ? { participantIds: explicitParticipantIds }
          : preferredParticipantIds
            ? {
                participantIds: preferredParticipantIds,
              }
            : {}),
        sessionKind: args.sessionKind || preferredSessionKind,
        ...(explicitSessionId
          ? { sessionId: explicitSessionId }
          : toOptionalNonEmptyString(reusableWarmCapability?.record?.thresholdSessionId)
            ? {
                sessionId: String(
                  toOptionalNonEmptyString(reusableWarmCapability?.record?.thresholdSessionId) ||
                    '',
                ).trim(),
              }
            : {}),
        ...(explicitThresholdRouteAuth
          ? { thresholdRouteAuth: explicitThresholdRouteAuth }
          : toOptionalNonEmptyString(reusableWarmCapability?.auth?.thresholdSessionJwt)
            ? {
                thresholdRouteAuth: {
                  kind: 'threshold_session',
                  jwt: String(
                    toOptionalNonEmptyString(reusableWarmCapability?.auth?.thresholdSessionJwt) ||
                      '',
                  ).trim(),
                },
              }
            : {}),
        ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
        ...(explicitRuntimeScopeBootstrap
          ? { runtimeScopeBootstrap: explicitRuntimeScopeBootstrap }
          : {}),
        ...(explicitClientRootShare32 ? { clientRootShare32: explicitClientRootShare32 } : {}),
        ...(explicitClientRootShare32B64u
          ? { clientRootShare32B64u: explicitClientRootShare32B64u }
          : {}),
      };
    },

    async provisionEcdsaCapability(
      args: ProvisionWarmEcdsaCapabilityArgs,
    ): Promise<ThresholdEcdsaSessionBootstrapResult> {
      const nearAccountId = toAccountId(args.nearAccountId);
      const beforeWarmSession = await this.getWarmSession(nearAccountId);
      const hasThresholdRouteAuth = Boolean(args.thresholdRouteAuth);
      const normalizedClientRootShare32 =
        args.clientRootShare32 instanceof Uint8Array ? args.clientRootShare32 : undefined;
      const normalizedClientRootShare32B64u = toOptionalNonEmptyString(args.clientRootShare32B64u);
      const normalizedSessionId = toOptionalNonEmptyString(args.sessionId);

      if (
        !hasThresholdRouteAuth &&
        !normalizedClientRootShare32 &&
        !normalizedClientRootShare32B64u &&
        !normalizedSessionId
      ) {
        const reusableBootstrap = await this.tryReuseReadyEcdsaBootstrap({
          nearAccountId,
          chain: args.chain,
          source: args.source,
        });
        if (reusableBootstrap) {
          return reusableBootstrap;
        }
      }

      const resolvedBootstrapRequest = await this.resolveEcdsaBootstrapRequest({
        nearAccountId,
        chain: args.chain,
        relayerUrl: args.relayerUrl,
        ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
        participantIds: args.participantIds,
        sessionKind: args.sessionKind,
        sessionId: args.sessionId,
        thresholdRouteAuth: args.thresholdRouteAuth,
        runtimePolicyScope: args.runtimePolicyScope,
        runtimeScopeBootstrap: args.runtimeScopeBootstrap,
        clientRootShare32: args.clientRootShare32,
        clientRootShare32B64u: args.clientRootShare32B64u,
      });
      if (
        !resolvedBootstrapRequest.clientRootShare32 &&
        !resolvedBootstrapRequest.clientRootShare32B64u &&
        resolvedBootstrapRequest.thresholdRouteAuth &&
        resolvedBootstrapRequest.sessionId
      ) {
        resolvedBootstrapRequest.clientRootShare32B64u =
          await this.claimPrfFirstByThresholdSessionId({
            thresholdSessionId: resolvedBootstrapRequest.sessionId,
            errorContext: 'threshold-ecdsa authorization bootstrap',
            uses: 1,
          });
      }

      await args.beforeProvision?.();
      args.assertNotCancelled?.();

      if (typeof deps.provisionThresholdEcdsaSession === 'function') {
        const provisioned = await deps.provisionThresholdEcdsaSession({
          ...args,
          ...resolvedBootstrapRequest,
        });
        args.assertNotCancelled?.();

        const expectedSessionId = toOptionalNonEmptyString(
          provisioned.thresholdEcdsaKeyRef?.thresholdSessionId,
        );
        if (!expectedSessionId) {
          throw new Error(
            `[WarmSessionManager] provisioned ECDSA capability is missing thresholdSessionId for ${nearAccountId}`,
          );
        }

        const afterWarmSession = await this.getWarmSession(nearAccountId);
        assertPersistedWarmSessionRecord({
          label: 'ECDSA',
          nearAccountId,
          expectedSessionId,
          persistedSessionIdRaw:
            afterWarmSession.capabilities.ecdsa[args.chain].record?.thresholdSessionId,
        });
        emitWarmSessionTransition({
          onTransition: deps.onTransition,
          event: {
            type: 'ecdsa_capability_provisioned',
            accountId: nearAccountId,
            chain: args.chain,
            thresholdSessionId: expectedSessionId,
            before: summarizeWarmSessionTransition(beforeWarmSession),
            after: summarizeWarmSessionTransition(afterWarmSession),
          },
        });
        return provisioned;
      }

      if (typeof deps.bootstrapThresholdEcdsaSession === 'function') {
        const provisioned = await deps.bootstrapThresholdEcdsaSession({
          nearAccountId,
          chain: args.chain,
        });
        args.assertNotCancelled?.();

        const expectedSessionId = toOptionalNonEmptyString(
          provisioned.thresholdEcdsaKeyRef?.thresholdSessionId,
        );
        if (!expectedSessionId) {
          throw new Error(
            `[WarmSessionManager] provisioned ECDSA capability is missing thresholdSessionId for ${nearAccountId}`,
          );
        }

        const afterWarmSession = await this.getWarmSession(nearAccountId);
        assertPersistedWarmSessionRecord({
          label: 'ECDSA',
          nearAccountId,
          expectedSessionId,
          persistedSessionIdRaw:
            afterWarmSession.capabilities.ecdsa[args.chain].record?.thresholdSessionId,
        });
        emitWarmSessionTransition({
          onTransition: deps.onTransition,
          event: {
            type: 'ecdsa_capability_provisioned',
            accountId: nearAccountId,
            chain: args.chain,
            thresholdSessionId: expectedSessionId,
            before: summarizeWarmSessionTransition(beforeWarmSession),
            after: summarizeWarmSessionTransition(afterWarmSession),
          },
        });
        return provisioned;
      }

      throw new Error(
        '[WarmSessionManager] provisionThresholdEcdsaSession is required to provision ECDSA capability',
      );
    },

    async tryReuseReadyEcdsaBootstrap(args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      source?: ThresholdEcdsaSessionStoreSource;
    }): Promise<ThresholdEcdsaSessionBootstrapResult | null> {
      if (typeof deps.getThresholdEcdsaKeyRefForSigning !== 'function') return null;
      const nearAccountId = toAccountId(args.nearAccountId);
      let keyRef: ThresholdEcdsaSecp256k1KeyRef | null = null;
      try {
        keyRef = deps.getThresholdEcdsaKeyRefForSigning({
          nearAccountId,
          chain: args.chain,
        });
      } catch {
        keyRef = null;
      }
      const warmSession = await this.getWarmSession(nearAccountId);
      const capability = getMatchingReadyEcdsaCapability({
        warmSession,
        chain: args.chain,
        keyRef,
        usesNeeded: 1,
      });
      if (!keyRef || !capability) return null;
      return (
        buildReusableEcdsaBootstrapResult({
          keyRef,
          capability,
          source: args.source || 'manual-bootstrap',
        }) || null
      );
    },

    async ensureEcdsaCapabilityReady(
      args: EnsureWarmEcdsaCapabilityReadyArgs,
    ): Promise<EnsureWarmEcdsaCapabilityReadyResult> {
      const nearAccountId = toAccountId(args.nearAccountId);
      const resolveKeyRef = (): ThresholdEcdsaSecp256k1KeyRef | null => {
        if (args.keyRef) return args.keyRef;
        if (typeof deps.getThresholdEcdsaKeyRefForSigning !== 'function') return null;
        try {
          return deps.getThresholdEcdsaKeyRefForSigning({
            nearAccountId,
            chain: args.chain,
          });
        } catch {
          return null;
        }
      };

      let keyRef = resolveKeyRef();
      let warmSession = await this.getWarmSession(nearAccountId);
      let capability = getMatchingReadyEcdsaCapability({
        warmSession,
        chain: args.chain,
        keyRef,
        usesNeeded: args.usesNeeded,
      });
      if (keyRef && capability) {
        return {
          keyRef,
          warmSession,
          capability,
          reconnected: false,
        };
      }

      if (typeof deps.bootstrapThresholdEcdsaSession !== 'function') {
        if (typeof deps.provisionThresholdEcdsaSession !== 'function') {
          throw new Error(
            '[WarmSessionManager] provisionThresholdEcdsaSession is required to reconnect ECDSA capability',
          );
        }
      }
      if (typeof deps.getThresholdEcdsaKeyRefForSigning !== 'function') {
        throw new Error(
          '[WarmSessionManager] getThresholdEcdsaKeyRefForSigning is required to resolve ECDSA capability',
        );
      }

      const reconnectRecord = resolveCurrentEcdsaRecord({
        nearAccountId,
        chain: args.chain,
      });
      const secondaryRecord = getPrimaryAndSecondaryEcdsaCapabilities({
        warmSession,
        chain: args.chain,
      }).secondary.record;
      const secondaryEmailOtpRecord =
        secondaryRecord?.source === 'email_otp' ? secondaryRecord : null;
      if (
        reconnectRecord?.source === 'email_otp' &&
        reconnectRecord.emailOtpAuthContext?.retention === 'single_use'
      ) {
        throw formatEmailOtpSensitiveOperationError({
          operationLabel: `${args.chain} signing`,
          mode: 'per_operation',
        });
      }
      if (
        !reconnectRecord &&
        secondaryEmailOtpRecord?.emailOtpAuthContext?.retention === 'single_use' &&
        Number(secondaryEmailOtpRecord.emailOtpAuthContext.consumedAtMs) > 0
      ) {
        throw formatEmailOtpSensitiveOperationError({
          operationLabel: `${args.chain} signing`,
          mode: 'per_operation',
        });
      }
      const inheritedEmailOtpRecord =
        reconnectRecord?.source === 'email_otp' ? reconnectRecord : secondaryEmailOtpRecord;

      const inflightKey = buildEcdsaCapabilityInflightKey({
        nearAccountId,
        chain: args.chain,
        usesNeeded: args.usesNeeded,
        keyRef,
      });
      let reconnectPromise = reconnectInFlightByCapability.get(inflightKey);
      if (!reconnectPromise) {
        reconnectPromise = (async (): Promise<EnsureWarmEcdsaCapabilityReadyResult> => {
          const provisioned = await this.provisionEcdsaCapability({
            nearAccountId,
            chain: args.chain,
            source: inheritedEmailOtpRecord ? 'email_otp' : 'manual-bootstrap',
            ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
            ...(args.runtimeScopeBootstrap
              ? { runtimeScopeBootstrap: args.runtimeScopeBootstrap }
              : {}),
            ...(inheritedEmailOtpRecord?.emailOtpAuthContext
              ? { emailOtpAuthContext: inheritedEmailOtpRecord.emailOtpAuthContext }
              : {}),
            beforeProvision: args.beforeReconnect,
            assertNotCancelled: args.assertNotCancelled,
          });
          args.assertNotCancelled?.();

          const refreshedKeyRef = provisioned.thresholdEcdsaKeyRef;
          const refreshedWarmSession = await this.getWarmSession(nearAccountId);
          const refreshedCapability = getMatchingReadyEcdsaCapability({
            warmSession: refreshedWarmSession,
            chain: args.chain,
            keyRef: refreshedKeyRef,
            usesNeeded: args.usesNeeded,
          });
          if (!refreshedKeyRef || !refreshedCapability) {
            throw new Error(
              '[WarmSessionManager] threshold ECDSA warm capability is not ready after reconnect',
            );
          }

          emitWarmSessionTransition({
            onTransition: deps.onTransition,
            event: {
              type: 'ecdsa_capability_reconnected',
              accountId: nearAccountId,
              chain: args.chain,
              thresholdSessionId: String(refreshedKeyRef.thresholdSessionId || '').trim(),
              before: summarizeWarmSessionTransition(warmSession),
              after: summarizeWarmSessionTransition(refreshedWarmSession),
            },
          });

          return {
            keyRef: refreshedKeyRef,
            warmSession: refreshedWarmSession,
            capability: refreshedCapability,
            reconnected: true,
          };
        })();
        reconnectInFlightByCapability.set(inflightKey, reconnectPromise);
        void reconnectPromise.then(
          () => {
            if (reconnectInFlightByCapability.get(inflightKey) === reconnectPromise) {
              reconnectInFlightByCapability.delete(inflightKey);
            }
          },
          () => {
            if (reconnectInFlightByCapability.get(inflightKey) === reconnectPromise) {
              reconnectInFlightByCapability.delete(inflightKey);
            }
          },
        );
      }

      const reconnectedCapability = await reconnectPromise;
      args.assertNotCancelled?.();
      return reconnectedCapability;
    },

    async assertEcdsaSigningSessionReady(args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      thresholdSessionId: unknown;
      usesNeeded?: number;
    }): Promise<Extract<WarmSessionStatusResult, { ok: true }>> {
      const thresholdSessionId = requireThresholdSigningSessionId(args.thresholdSessionId);
      const status = await this.getEcdsaSigningSessionStatus({
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        thresholdSessionId,
      });
      if (!status || status.status === 'not_found') {
        throw new Error(formatThresholdSigningSessionStatusError('not_found'));
      }
      if (status.status === 'unavailable') {
        throw new Error(formatThresholdSigningSessionAvailabilityError(status.statusCode));
      }
      if (status.status === 'expired') {
        throw new Error(formatThresholdSigningSessionStatusError('expired'));
      }
      if (status.status === 'exhausted') {
        throw new Error(THRESHOLD_SESSION_EXHAUSTED_ERROR);
      }

      const remainingUses = Math.floor(Number(status.remainingUses) || 0);
      if (remainingUses < normalizeUsesNeeded(args.usesNeeded)) {
        throw new Error(THRESHOLD_SESSION_EXHAUSTED_ERROR);
      }

      return {
        ok: true,
        remainingUses,
        expiresAtMs: Number(status.expiresAtMs) || Date.now(),
      };
    },

    async resolveEd25519SigningAuthPlan(args: {
      nearAccountId: AccountId | string;
      usesNeeded?: number;
      operationLabel?: string;
    }): Promise<WarmSessionEd25519SigningAuthPlan> {
      const accountId = String(args.nearAccountId || '').trim();
      const warmSession = await this.getWarmSession(args.nearAccountId);
      const capability = warmSession.capabilities.ed25519;
      const isEmailOtpSession = capability.record?.source === 'email_otp';
      const method: WalletAuthMethod = isEmailOtpSession ? 'email_otp' : 'passkey';
      const retention: SigningSessionRetention | null = isEmailOtpSession
        ? (capability.emailOtpAuthContext?.retention ?? 'session')
        : 'session';
      const resolveExpiresAtMs = (): number =>
        Math.floor(
          Number(capability.prfClaim?.expiresAtMs ?? capability.record?.expiresAtMs) || Date.now(),
        );
      const resolveRemainingUses = (): number =>
        Math.max(
          0,
          Math.floor(
            Number(capability.prfClaim?.remainingUses ?? capability.record?.remainingUses) || 0,
          ),
        );
      const buildPlan = (input: {
        kind: WarmSessionEd25519SigningAuthPlan['kind'];
        warmSessionReady: boolean;
        remainingUses?: number;
      }): WarmSessionEd25519SigningAuthPlan => ({
        sessionId,
        kind: input.kind,
        warmSessionReady: input.warmSessionReady,
        accountId,
        method,
        retention,
        expiresAtMs: resolveExpiresAtMs(),
        remainingUses: input.remainingUses ?? resolveRemainingUses(),
      });
      const requireEmailOtpReauth = (): WarmSessionEd25519SigningAuthPlan =>
        buildPlan({
          kind: 'emailOtpReauth',
          warmSessionReady: false,
          remainingUses: 0,
        });
      const sessionId = String(capability.record?.thresholdSessionId || '').trim();
      if (!sessionId) {
        throw new Error(THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR);
      }
      if (capability.state === 'auth_missing') {
        if (isEmailOtpSession) return requireEmailOtpReauth();
        throw new Error(THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR);
      }
      if (capability.state === 'prf_unavailable') {
        if (isEmailOtpSession) return requireEmailOtpReauth();
        throw new Error(formatThresholdSigningSessionAvailabilityError(capability.prfClaim?.code));
      }
      if (capability.state === 'ready') {
        const remainingUses = Math.floor(
          Number(
            capability.prfClaim?.state === 'warm'
              ? capability.prfClaim.remainingUses
              : capability.record?.remainingUses,
          ) || 0,
        );
        if (isEmailOtpSession && capability.prfClaim?.state !== 'warm') {
          return requireEmailOtpReauth();
        }
        if (remainingUses < normalizeUsesNeeded(args.usesNeeded)) {
          if (isEmailOtpSession) return requireEmailOtpReauth();
          throw new Error(THRESHOLD_SESSION_EXHAUSTED_ERROR);
        }
        return buildPlan({
          kind: 'warmSession',
          warmSessionReady: true,
          remainingUses,
        });
      }

      const status = await this.getEd25519SigningSessionStatus(args.nearAccountId);
      if (status?.status === 'unavailable') {
        if (isEmailOtpSession) return requireEmailOtpReauth();
        throw new Error(formatThresholdSigningSessionAvailabilityError(status.statusCode));
      }
      if (status?.status === 'expired') {
        if (isEmailOtpSession) return requireEmailOtpReauth();
        throw new Error(formatThresholdSigningSessionStatusError('expired'));
      }
      if (status?.status === 'exhausted') {
        if (isEmailOtpSession) return requireEmailOtpReauth();
        throw new Error(THRESHOLD_SESSION_EXHAUSTED_ERROR);
      }
      if (status?.status === 'active') {
        if (isEmailOtpSession) return requireEmailOtpReauth();
        return buildPlan({
          kind: 'passkeyReauth',
          warmSessionReady: false,
        });
      }
      if (capability.state === 'missing') {
        if (isEmailOtpSession) return requireEmailOtpReauth();
        throw new Error(THRESHOLD_SESSION_MISSING_ERROR);
      }

      if (isEmailOtpSession) return requireEmailOtpReauth();

      if (args.operationLabel) {
        console.warn(
          `[SigningEngine][near] ${args.operationLabel} warm session cache is unavailable; falling back to WebAuthn`,
          {
            nearAccountId: args.nearAccountId,
            sessionId,
            code: status?.status || 'not_found',
          },
        );
      }

      return buildPlan({
        kind: 'passkeyReauth',
        warmSessionReady: false,
      });
    },

    async getEd25519SigningSessionStatus(
      nearAccountId: AccountId | string,
    ): Promise<SigningSessionStatus | null> {
      const records = readWarmSessionCapabilityRecordsForAccount(toAccountId(nearAccountId));
      const record = records.ed25519;
      const normalizedThresholdSessionId = String(record?.thresholdSessionId || '').trim();
      if (!normalizedThresholdSessionId) return null;
      const { ed25519Claim } = await readWalletScopedClaimsForRecords(records);
      return toSigningSessionStatus({
        sessionId: normalizedThresholdSessionId,
        claim: ed25519Claim,
        authMethod: record?.source === 'email_otp' ? 'email_otp' : 'passkey',
        retention: record?.emailOtpAuthContext?.retention || null,
      });
    },

    async getEcdsaSigningSessionStatus(args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      thresholdSessionId?: string;
    }): Promise<SigningSessionStatus | null> {
      const accountId = toAccountId(args.nearAccountId);
      const expectedThresholdSessionId = String(args.thresholdSessionId || '').trim();
      const records = readWarmSessionCapabilityRecordsForAccount(accountId);
      const record = resolveCurrentEcdsaRecord({
        nearAccountId: accountId,
        chain: args.chain,
      }) || records.ecdsa[args.chain];
      const normalizedThresholdSessionId = String(record?.thresholdSessionId || '').trim();
      if (!normalizedThresholdSessionId) return null;
      if (
        expectedThresholdSessionId &&
        expectedThresholdSessionId !== normalizedThresholdSessionId
      ) {
        return {
          sessionId: expectedThresholdSessionId,
          status: 'not_found',
        };
      }
      const claims = await readWalletScopedClaimsForRecords(records);
      const storedRecord = records.ecdsa[args.chain];
      const claim =
        String(storedRecord?.thresholdSessionId || '').trim() !== normalizedThresholdSessionId
          ? await readWarmSessionClaim(deps.touchConfirm, normalizedThresholdSessionId)
          : args.chain === 'evm'
          ? claims.evmClaim
          : claims.tempoClaim;
      if (shouldInvalidateEmailOtpCapability({ record, prfClaim: claim })) {
        await clearEcdsaWarmCapabilityBestEffort({
          nearAccountId: accountId,
          chain: args.chain,
          thresholdSessionId: normalizedThresholdSessionId,
        });
      }
      return toSigningSessionStatus({
        sessionId: normalizedThresholdSessionId,
        claim,
        authMethod: record?.source === 'email_otp' ? 'email_otp' : 'passkey',
        retention: record?.emailOtpAuthContext?.retention || null,
      });
    },

    async claimPrfFirstByThresholdSessionId(args: ClaimWarmSessionPrfArgs): Promise<string> {
      return await claimWarmSessionPrfFirst({
        touchConfirm: deps.touchConfirm,
        thresholdSessionId: args.thresholdSessionId,
        errorContext: args.errorContext,
        uses: args.uses,
      });
    },

    async ensureEcdsaPrfSealPersistedByThresholdSessionId(args: {
      chain: ThresholdEcdsaActivationChain;
      thresholdSessionId: string;
      required?: boolean;
      errorContext?: string;
    }): Promise<void> {
      await ensureEcdsaPrfSealPersisted({
        touchConfirm: deps.touchConfirm,
        thresholdSessionId: args.thresholdSessionId,
        required: args.required,
        errorContext: args.errorContext,
        sealPersistInFlightBySessionId,
        resolveSealTransport: (thresholdSessionId) =>
          this.resolveEcdsaSealTransportByThresholdSessionId(thresholdSessionId),
      });
    },

    async applyEcdsaPostSignPolicy(args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      thresholdSessionId?: string;
    }): Promise<void> {
      const accountId = toAccountId(args.nearAccountId);
      const record = resolveCurrentEcdsaRecord({
        nearAccountId: accountId,
        chain: args.chain,
      });
      const warmSession = await this.getWarmSession(accountId);
      const secondaryRecord = getPrimaryAndSecondaryEcdsaCapabilities({
        warmSession,
        chain: args.chain,
      }).secondary.record;
      const effectiveEmailOtpRecord =
        record?.source === 'email_otp'
          ? record
          : secondaryRecord?.source === 'email_otp'
            ? secondaryRecord
            : null;
      const effectiveEmailOtpRecordChain: ThresholdEcdsaActivationChain | null =
        record?.source === 'email_otp'
          ? args.chain
          : secondaryRecord?.source === 'email_otp'
            ? args.chain === 'tempo'
              ? 'evm'
              : 'tempo'
            : null;
      if (!effectiveEmailOtpRecord) return;
      if (args.thresholdSessionId && record?.source === 'email_otp') {
        const expectedThresholdSessionId = String(args.thresholdSessionId || '').trim();
        const actualThresholdSessionId = String(record.thresholdSessionId || '').trim();
        if (
          expectedThresholdSessionId &&
          actualThresholdSessionId &&
          expectedThresholdSessionId !== actualThresholdSessionId
        ) {
          return;
        }
      }
      if (effectiveEmailOtpRecord.emailOtpAuthContext?.retention !== 'single_use') return;
      deps.markThresholdEcdsaEmailOtpSessionConsumedForAccount?.({
        nearAccountId: accountId,
        chain: args.chain,
      });
      await clearEcdsaEphemeralMaterialBestEffort({
        nearAccountId: accountId,
        chain: args.chain,
        thresholdSessionId: String(
          record?.thresholdSessionId || args.thresholdSessionId || '',
        ).trim(),
      });
      if (
        effectiveEmailOtpRecordChain !== args.chain ||
        String(effectiveEmailOtpRecord.thresholdSessionId || '').trim() !==
          String(record?.thresholdSessionId || args.thresholdSessionId || '').trim()
      ) {
        await clearEcdsaEphemeralMaterialBestEffort({
          nearAccountId: accountId,
          chain: effectiveEmailOtpRecordChain || args.chain,
          thresholdSessionId: effectiveEmailOtpRecord.thresholdSessionId,
        });
      }
    },

    async assertEcdsaOperationAllowed(args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      operationLabel: string;
      thresholdSessionId?: string;
      sensitivePolicy?: SensitiveOperationPolicy;
    }): Promise<void> {
      const accountId = toAccountId(args.nearAccountId);
      const record = resolveCurrentEcdsaRecord({
        nearAccountId: accountId,
        chain: args.chain,
      });
      const secondaryRecord = getPrimaryAndSecondaryEcdsaCapabilities({
        warmSession: await this.getWarmSession(accountId),
        chain: args.chain,
      }).secondary.record;
      const effectiveRecord =
        record?.source === 'email_otp'
          ? record
          : secondaryRecord?.source === 'email_otp'
            ? secondaryRecord
            : null;
      if (!effectiveRecord) return;
      const thresholdSessionId = String(args.thresholdSessionId || '').trim();
      const actualThresholdSessionId = String(effectiveRecord.thresholdSessionId || '').trim();
      if (
        thresholdSessionId &&
        actualThresholdSessionId &&
        thresholdSessionId !== actualThresholdSessionId
      ) {
        return;
      }
      if (
        effectiveRecord.emailOtpAuthContext?.retention === 'single_use' &&
        Number(effectiveRecord.emailOtpAuthContext.consumedAtMs) > 0
      ) {
        throw formatEmailOtpSensitiveOperationError({
          operationLabel: args.operationLabel,
          mode: 'per_operation',
        });
      }
      const sensitivePolicy =
        args.sensitivePolicy || SENSITIVE_OPERATION_POLICIES.inheritSessionPolicy;
      if (sensitivePolicy === SENSITIVE_OPERATION_POLICIES.inheritSessionPolicy) return;
      if (sensitivePolicy === SENSITIVE_OPERATION_POLICIES.requireFreshSameMethod) {
        if (effectiveRecord.emailOtpAuthContext?.retention === 'single_use') return;
        throw formatEmailOtpSensitiveOperationError({
          operationLabel: args.operationLabel,
          mode: 'per_operation',
        });
      }
      if (
        sensitivePolicy === SENSITIVE_OPERATION_POLICIES.requirePasskey ||
        sensitivePolicy === SENSITIVE_OPERATION_POLICIES.denyEmailOtp
      ) {
        throw formatEmailOtpSensitiveOperationError({
          operationLabel: args.operationLabel,
          mode: 'passkey',
        });
      }
    },

    resolveEcdsaSealTransportByThresholdSessionId(
      thresholdSessionId: string,
    ): ThresholdSessionSealTransportAuthMaterial | null {
      const record = readWarmSessionEcdsaRecordByThresholdSessionId(thresholdSessionId);
      if (!record) return null;
      const auth = resolveEcdsaAuthMaterial(record);
      return resolveEcdsaSealTransport({
        record,
        auth,
        keyVersion: String(
          record.signingSessionSealKeyVersion || deps.signingSessionSeal?.keyVersion || '',
        ).trim(),
        shamirPrimeB64u: String(
          record.signingSessionSealShamirPrimeB64u ||
            deps.signingSessionSeal?.shamirPrimeB64u ||
            '',
        ).trim(),
      });
    },
  };
}

export function resolveExplicitEcdsaWarmSessionAuthByThresholdSessionId(
  thresholdSessionId: string,
): WarmSessionEcdsaAuthMaterial | null {
  return createWarmSessionManager().resolveEcdsaAuthByThresholdSessionId(thresholdSessionId);
}

export function resolveEcdsaWarmSessionSealTransportByThresholdSessionId(
  thresholdSessionId: string,
): ThresholdSessionSealTransportAuthMaterial | null {
  return createWarmSessionManager().resolveEcdsaSealTransportByThresholdSessionId(
    thresholdSessionId,
  );
}

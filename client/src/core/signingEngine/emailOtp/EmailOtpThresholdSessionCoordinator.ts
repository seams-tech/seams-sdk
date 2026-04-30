import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthPolicy, SeamsConfigsReadonly } from '@/core/types/seams';
import type { TouchIdPrompt } from '@/core/signingEngine/signers/webauthn/prompt/touchIdPrompt';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager';
import type {
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from '@/core/signingEngine/touchConfirm/types';
import type {
  ThresholdEd25519SessionRecord,
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  upsertStoredThresholdEd25519SessionRecord,
} from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '@/core/signingEngine/orchestration/thresholdActivation';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmSigning/types';
import {
  createSigningSessionRestoreCache,
  restorePersistedSessionsForAccountCommand,
  restorePersistedSessionForSigningCommand,
  type RestorePersistedSessionsForAccountInput,
  type RestorePersistedSessionsForAccountResult,
  type RestorePersistedSessionForSigningInput,
  type RestorePersistedSessionForSigningResult,
  type RestorePersistedSessionPurpose,
  type RestoreSealedRecordForAccountResult,
} from '@/core/signingEngine/session/restoreCoordinator';
import {
  readSigningSessionSnapshot,
  warmStatusToSigningSessionSnapshotRuntimeClaim,
  type ReadSigningSessionSnapshotInput,
  type SigningSessionSnapshot,
  type SigningSessionSnapshotRuntimeClaim,
  type SigningSessionSnapshotRuntimeEd25519Record,
  type SigningSessionSnapshotRuntimeEcdsaRecord,
} from '@/core/signingEngine/session/snapshotReader';
import { resolveEmailOtpEcdsaWorkerSessionId } from '@/core/signingEngine/session/signingSession/readiness';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/session/sessionPolicy';
import {
  buildEd25519SessionPolicy,
  generateWalletSigningSessionId,
  normalizeThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/session/sessionPolicy';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpWorkerProgressEvent } from '@/core/signingEngine/workerManager/workerTypes';
import { type WalletAuthCurve } from '@/core/signingEngine/auth';
import {
  SigningAuthPlanKind,
  UserConfirmationType,
  type UserConfirmDecision,
  type UserConfirmRequest,
} from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import {
  deriveThresholdEd25519HssClientInputsWasm,
  prepareThresholdEd25519HssClientRequestWasm,
} from '@/core/signingEngine/signers/wasm/hssClientSignerWasm';
import { runThresholdEd25519HssCeremonyWithSession as runThresholdEd25519HssCeremonyWithSessionValue } from '@/core/signingEngine/api/thresholdLifecycle/thresholdEd25519Lifecycle';
import {
  THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
} from '@/core/signingEngine/orchestration/near/shared/ensureThresholdEd25519HssClientBase';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import {
  decodeJwtPayloadRecord,
  isAppSessionJwt,
  isSessionJwtUnexpired,
} from '@shared/utils/sessionTokens';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  type WalletEmailOtpExportOperation,
  type WalletEmailOtpChannel,
  type WalletEmailOtpLoginOperation,
  type WalletEmailOtpTransactionSignOperation,
} from '@shared/utils/emailOtpDomain';
import {
  THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  normalizeThresholdEd25519ParticipantIds,
} from '@shared/threshold/participants';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from '@/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence';
import type { EmailOtpEnrollmentResult } from '@/core/SeamsPasskey/emailOtp';
import {
  acquireSigningSessionRestoreLease,
  deleteExactSealedSession,
  listExactSealedSessionsForAccount,
  listResolvedIdentitiesForAccount,
  publishResolvedIdentity,
  releaseSigningSessionRestoreLease,
  readExactSealedSession,
  updateExactSealedSessionPolicy,
  writeExactSealedSession,
  type SigningSessionSealedRecordFilter,
  type SigningSessionRestoreLeaseHandle,
  type SigningSessionSealedStoreRecord,
} from '@/core/signingEngine/session/sealedSessionStore';
import {
  authLaneAppSessionJwt,
  authLaneToRouteAuth,
  buildEmailOtpRoutePlan,
  resolveEmailOtpAuthLane,
  routeFamilyForAuthLane,
  type EmailOtpAuthLane,
  type EmailOtpRoutePlan,
} from './authLane';

type EmailOtpSigningSessionChallengeOperation =
  | WalletEmailOtpTransactionSignOperation
  | WalletEmailOtpExportOperation;

const EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE =
  'Email OTP signing-session authority is unavailable; unlock wallet again';

export type EmailOtpBootstrapRecovery = {
  challengeId: string;
  enrollmentSealKeyVersion: string;
  unlockChallengeId: string;
  unlockChallengeB64u: string;
  clientUnlockPublicKeyB64u: string;
  unlockSignatureB64u: string;
  thresholdEd25519PrfFirstB64u?: string;
};

export type EmailOtpThresholdEcdsaLoginResult = {
  recovery: EmailOtpBootstrapRecovery;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
  ed25519Provisioning?: EmailOtpThresholdEd25519ProvisioningResult;
};

export type EmailOtpThresholdEcdsaEnrollmentResult = {
  enrollment: EmailOtpEnrollmentResult;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
};

export type EmailOtpThresholdEcdsaRehydrateResult = {
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
  remainingUses: number;
  expiresAtMs: number;
  ed25519RestoreSeedB64u?: string;
};

export type EmailOtpThresholdEd25519ProvisioningResult = {
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  sessionId: string;
  expiresAtMs: number;
  remainingUses: number;
  participantIds: number[];
  jwt: string;
  xClientBaseB64u?: string;
};

type ManagedRegistrationBootstrapGrant = {
  token: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
};

type RegistrationTransport =
  | { mode: 'managed'; relayerUrl: string; environmentId: string; publishableKey: string }
  | { mode: 'backend_proxy'; bootstrapUrl: string; relayerUrl: string };

function createExportUiRequestId(prefix: string): string {
  const randomPart =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${randomPart}`;
}

export type ProvisionEmailOtpThresholdEd25519CapabilityArgs = {
  nearAccountId: AccountId | string;
  relayUrl: string;
  rpId: string;
  prfFirstB64u: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  appSessionJwt?: string;
  routeAuth?: AppOrThresholdSessionAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  registrationAttemptId?: string;
  participantIds?: number[];
  ttlMs?: number;
  remainingUses?: number;
  walletSigningSessionId?: string;
  ecdsaThresholdSessionId?: string;
};

export type LoginEmailOtpEcdsaCapabilityArgs = {
  nearAccountId: AccountId | string;
  chain?: ThresholdEcdsaActivationChain;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  emailOtpAuthReason?: 'login' | 'sign';
  relayUrl?: string;
  challengeId?: string;
  otpCode: string;
  operation?: WalletEmailOtpLoginOperation;
  shamirPrimeB64u?: string;
  appSessionJwt?: string;
  routeAuth?: AppOrThresholdSessionAuth;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  ed25519ParticipantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  walletSigningSessionId?: string;
  routePlan?: EmailOtpRoutePlan;
  ttlMs?: number;
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
  ed25519ProvisioningMode?: 'schedule' | 'await' | 'skip';
  authSubjectId?: string;
  includeEcdsaExportArtifact?: boolean;
};

export type EnrollAndLoginEmailOtpEcdsaCapabilityArgs = {
  nearAccountId: AccountId | string;
  chain?: ThresholdEcdsaActivationChain;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  otpCode: string;
  relayUrl?: string;
  challengeId?: string;
  shamirPrimeB64u?: string;
  appSessionJwt?: string;
  routeAuth?: AppOrThresholdSessionAuth;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  walletSigningSessionId?: string;
  routePlan?: EmailOtpRoutePlan;
  ttlMs?: number;
  remainingUses?: number;
  clientSecret32?: Uint8Array;
  otpChannel?: WalletEmailOtpChannel;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  registrationAttemptId?: string;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
};

export type EmailOtpThresholdSessionCoordinatorDeps = {
  configs: SeamsConfigsReadonly;
  signerWorkerManager: SignerWorkerManager;
  touchIdPrompt: TouchIdPrompt;
  requestUserConfirmation: (request: UserConfirmRequest) => Promise<UserConfirmDecision>;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  refreshAppSessionJwt?: (args: { relayUrl: string }) => Promise<string>;
  commitWorkerProvisionedThresholdEcdsaSessions: (args: {
    nearAccountId: AccountId | string;
    primaryChain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: 'email_otp';
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }>;
  getThresholdEcdsaKeyRefForLookup: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source: ThresholdEcdsaSessionStoreSource;
  }) => ThresholdEcdsaSecp256k1KeyRef | Promise<ThresholdEcdsaSecp256k1KeyRef>;
  getThresholdEcdsaSessionRecordByThresholdSessionId?: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  persistEmailOtpThresholdEd25519LocalMetadata: (args: {
    nearAccountId: AccountId;
    rpId: string;
    relayerUrl: string;
    publicKey: string;
    relayerKeyId: string;
    keyVersion: string;
    participantIds: number[];
  }) => Promise<void>;
  persistWarmSessionEd25519Capability: (args: {
    nearAccountId: AccountId;
    rpId: string;
    relayerUrl: string;
    relayerKeyId: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    participantIds: number[];
    sessionKind: 'jwt' | 'cookie';
    sessionId: string;
    walletSigningSessionId?: string;
    expiresAtMs: number;
    remainingUses: number;
    jwt: string;
    xClientBaseB64u?: string;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    source: 'email_otp';
  }) => unknown | Promise<unknown>;
  hydrateSigningSession: (args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: {
      curve?: 'ed25519' | 'ecdsa';
      relayerUrl?: string;
      thresholdSessionJwt?: string;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };
  }) => Promise<void>;
  writeExactSealedSession?: typeof writeExactSealedSession;
  readExactSealedSession?: typeof readExactSealedSession;
  listExactSealedSessionsForAccount?: typeof listExactSealedSessionsForAccount;
  acquireSigningSessionRestoreLease?: typeof acquireSigningSessionRestoreLease;
  releaseSigningSessionRestoreLease?: (
    lease: SigningSessionRestoreLeaseHandle | null | undefined,
  ) => Promise<void>;
};

export class EmailOtpThresholdSessionCoordinator {
  private appSessionJwtByAccount: Map<string, string> = new Map();
  private ed25519WarmupByAccount: Map<string, Promise<EmailOtpThresholdEd25519ProvisioningResult>> =
    new Map();
  private sealedRefreshDiagnosticLogAtMsByKey: Map<string, number> = new Map();
  private ecdsaAccountSealedRestoreInFlightByKey: Map<string, Promise<void>> = new Map();
  private ecdsaAccountSealedRestoreCompletedKeys: Set<string> = new Set();
  private ecdsaSigningRestoreCache = createSigningSessionRestoreCache();

  constructor(private readonly deps: EmailOtpThresholdSessionCoordinatorDeps) {}

  private clearEcdsaRestoreCaches(): void {
    this.ecdsaSigningRestoreCache.clear();
    this.ecdsaAccountSealedRestoreCompletedKeys.clear();
    this.ecdsaAccountSealedRestoreInFlightByKey.clear();
  }

  private shouldLogSealedRefreshDiagnostic(key: string, nowMs = Date.now()): boolean {
    const normalizedKey = String(key || '').trim();
    if (!normalizedKey) return false;
    const lastLoggedAtMs = this.sealedRefreshDiagnosticLogAtMsByKey.get(normalizedKey) || 0;
    if (nowMs - lastLoggedAtMs < 60_000) return false;
    this.sealedRefreshDiagnosticLogAtMsByKey.set(normalizedKey, nowMs);
    return true;
  }

  private resolveEmailOtpEcdsaSealedRecordFilter(
    sessionId: string,
    explicitChain?: ThresholdEcdsaActivationChain,
  ): SigningSessionSealedRecordFilter | null {
    const chain =
      explicitChain || getStoredThresholdEcdsaSessionRecordByThresholdSessionId(sessionId)?.chain;
    if (chain !== 'tempo' && chain !== 'evm') return null;
    return { authMethod: 'email_otp', curve: 'ecdsa', chain };
  }

  private async cleanupSigningSession(args: {
    sessionId: string;
    chain?: ThresholdEcdsaActivationChain;
    reason: 'explicit_clear' | 'expired' | 'exhausted' | 'invalid_persisted_record';
  }): Promise<void> {
    const sessionId = String(args.sessionId || '').trim();
    if (!sessionId) return;
    const filter = this.resolveEmailOtpEcdsaSealedRecordFilter(sessionId, args.chain);
    if (filter) {
      // Expiry/exhaustion deletes the durable refresh seal, not the active-tab
      // lane identity. The next signing command still needs that identity to
      // select the exact lane and prompt OTP reauth.
      const preserveResolvedIdentity = args.reason === 'expired' || args.reason === 'exhausted';
      await deleteExactSealedSession(sessionId, filter, {
        deleteResolvedIdentity: !preserveResolvedIdentity,
      }).catch(() => undefined);
    }
    this.clearEcdsaRestoreCaches();
  }

  private async recordSessionPolicyResult(args: {
    sessionId: string;
    result: WarmSessionStatusResult | WarmSessionClaimResult;
  }): Promise<void> {
    const sessionId = String(args.sessionId || '').trim();
    if (!sessionId) return;
    const result = args.result;
    if (result.ok) {
      if (result.remainingUses <= 0 || Date.now() >= result.expiresAtMs) {
        await this.cleanupSigningSession({
          sessionId,
          reason: result.remainingUses <= 0 ? 'exhausted' : 'expired',
        });
        return;
      }
      const filter = this.resolveEmailOtpEcdsaSealedRecordFilter(sessionId);
      if (filter) {
        await updateExactSealedSessionPolicy({
          thresholdSessionId: sessionId,
          filter,
          expiresAtMs: result.expiresAtMs,
          remainingUses: result.remainingUses,
          updatedAtMs: Date.now(),
        }).catch(() => undefined);
      }
      this.clearEcdsaRestoreCaches();
      return;
    }
    if (result.code === 'expired' || result.code === 'exhausted') {
      await this.cleanupSigningSession({
        sessionId,
        reason: result.code,
      });
    }
  }

  private async recordSessionMaterialClaimed(
    sessionId: string,
    result: WarmSessionClaimResult,
  ): Promise<void> {
    await this.recordSessionPolicyResult({ sessionId, result });
  }

  private async recordSessionUseConsumed(
    sessionId: string,
    result: WarmSessionStatusResult,
  ): Promise<void> {
    await this.recordSessionPolicyResult({ sessionId, result });
  }

  private async recordSessionMaterialRestored(
    sessionId: string,
    result: WarmSessionStatusResult,
  ): Promise<void> {
    await this.recordSessionPolicyResult({ sessionId, result });
  }

  private async registerSigningSession(
    record: Parameters<typeof writeExactSealedSession>[0],
  ): Promise<void> {
    const writer = this.deps.writeExactSealedSession || writeExactSealedSession;
    await writer(record);
    this.clearEcdsaRestoreCaches();
  }

  private async tryRestoreEcdsaWarmSessionStatusFromSealedRecord(
    sessionId: string,
  ): Promise<WarmSessionStatusResult | null> {
    if (this.deps.configs.signing.sessionPersistenceMode !== 'sealed_refresh_v1') return null;
    const requestedSessionId = String(sessionId || '').trim();
    if (!requestedSessionId) return null;
    const reader = this.deps.readExactSealedSession || readExactSealedSession;
    const readEcdsaSealedRecord = async (
      thresholdSessionId: string,
    ): Promise<SigningSessionSealedStoreRecord | null> => {
      for (const chain of ['tempo', 'evm'] as const) {
        const record = await reader(thresholdSessionId, {
          authMethod: 'email_otp',
          curve: 'ecdsa',
          chain,
        }).catch((error) => {
          console.warn('[EmailOtpSession] sealed refresh ECDSA read failed', {
            thresholdSessionId,
            chain,
            error: error instanceof Error ? error.message : String(error || 'unknown error'),
          });
          return null;
        });
        if (record) return record;
      }
      return null;
    };
    const readEd25519CompanionSealedRecord = async (
      thresholdSessionId: string,
    ): Promise<SigningSessionSealedStoreRecord | null> =>
      await reader(thresholdSessionId, {
        authMethod: 'email_otp',
        curve: 'ed25519',
      }).catch((error) => {
        console.warn('[EmailOtpSession] sealed refresh Ed25519 companion read failed', {
          thresholdSessionId,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
        return null;
      });

    let thresholdSessionId = requestedSessionId;
    let sealedRecord: SigningSessionSealedStoreRecord | null = null;
    const requestedEd25519Record =
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(requestedSessionId);
    if (requestedEd25519Record?.source === 'email_otp') {
      const companionRecord = await readEd25519CompanionSealedRecord(requestedSessionId);
      const companionEcdsaSessionId = String(
        companionRecord?.thresholdSessionIds.ecdsa || '',
      ).trim();
      if (companionEcdsaSessionId) {
        thresholdSessionId = companionEcdsaSessionId;
        sealedRecord = await readEcdsaSealedRecord(companionEcdsaSessionId);
      }
    }
    if (!sealedRecord) {
      sealedRecord = await readEcdsaSealedRecord(requestedSessionId);
    }
    if (!sealedRecord) {
      const companionRecord = await readEd25519CompanionSealedRecord(requestedSessionId);
      const companionEcdsaSessionId = String(
        companionRecord?.thresholdSessionIds.ecdsa || '',
      ).trim();
      if (companionEcdsaSessionId && companionEcdsaSessionId !== requestedSessionId) {
        thresholdSessionId = companionEcdsaSessionId;
        sealedRecord = await readEcdsaSealedRecord(companionEcdsaSessionId);
      }
    }
    if (!sealedRecord) return null;
    if (sealedRecord.remainingUses <= 0 || Date.now() >= sealedRecord.expiresAtMs) {
      console.debug('[EmailOtpSession] sealed refresh restore deferred by durable policy hint', {
        thresholdSessionId,
        remainingUses: sealedRecord.remainingUses,
        expiresAtMs: sealedRecord.expiresAtMs,
      });
      return null;
    }
    if (
      sealedRecord.authMethod !== 'email_otp' ||
      sealedRecord.secretKind !== 'signing_session_secret32' ||
      sealedRecord.thresholdSessionIds.ecdsa !== thresholdSessionId
    ) {
      console.warn('[EmailOtpSession] sealed refresh restore deferred by store metadata mismatch', {
        thresholdSessionId,
        authMethod: sealedRecord.authMethod,
        secretKind: sealedRecord.secretKind,
        ecdsaThresholdSessionId: sealedRecord.thresholdSessionIds.ecdsa,
      });
      return null;
    }
    const ecdsaRecord =
      this.deps.getThresholdEcdsaSessionRecordByThresholdSessionId?.(thresholdSessionId) ||
      getStoredThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId);
    if (
      (!ecdsaRecord && !sealedRecord.ecdsaRestore) ||
      (ecdsaRecord && ecdsaRecord.source !== 'email_otp') ||
      (ecdsaRecord && ecdsaRecord.emailOtpAuthContext?.retention !== 'session')
    ) {
      const diagnosticKey = `missing-ecdsa-record:${thresholdSessionId}`;
      if (this.shouldLogSealedRefreshDiagnostic(diagnosticKey)) {
        console.debug('[EmailOtpSession] sealed refresh restore waiting for ECDSA record', {
          thresholdSessionId,
          source: ecdsaRecord?.source,
          retention: ecdsaRecord?.emailOtpAuthContext?.retention,
        });
      }
      return null;
    }
    const sealedEd25519SessionId = String(sealedRecord.thresholdSessionIds.ed25519 || '').trim();
    const ed25519Record = sealedEd25519SessionId
      ? getStoredThresholdEd25519SessionRecordByThresholdSessionId(sealedEd25519SessionId)
      : null;
    if (
      sealedEd25519SessionId &&
      (!ed25519Record ||
        ed25519Record.source !== 'email_otp' ||
        ed25519Record.emailOtpAuthContext?.retention !== 'session' ||
        ed25519Record.walletSigningSessionId !== sealedRecord.walletSigningSessionId)
    ) {
      const diagnosticKey = `missing-ed25519-companion:${thresholdSessionId}:${sealedEd25519SessionId}`;
      if (this.shouldLogSealedRefreshDiagnostic(diagnosticKey)) {
        console.debug(
          '[EmailOtpSession] sealed refresh restoring ECDSA without Ed25519 companion',
          {
            thresholdSessionId,
            sealedEd25519SessionId,
            ed25519Source: ed25519Record?.source,
            ed25519Retention: ed25519Record?.emailOtpAuthContext?.retention,
            ed25519WalletSigningSessionId: ed25519Record?.walletSigningSessionId,
            walletSigningSessionId: sealedRecord.walletSigningSessionId,
          },
        );
      }
    }

    const acquireLease =
      this.deps.acquireSigningSessionRestoreLease || acquireSigningSessionRestoreLease;
    const releaseLease =
      this.deps.releaseSigningSessionRestoreLease || releaseSigningSessionRestoreLease;
    const lease = await acquireLease({
      thresholdSessionId,
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chain: sealedRecord.ecdsaRestore?.chain as 'tempo' | 'evm',
    }).catch(() => null);
    if (!lease) {
      const diagnosticKey = `lease-unavailable:${thresholdSessionId}`;
      if (this.shouldLogSealedRefreshDiagnostic(diagnosticKey)) {
        console.debug('[EmailOtpSession] sealed refresh restore deferred; lease unavailable', {
          thresholdSessionId,
        });
      }
      return null;
    }
    try {
      console.debug('[EmailOtpSession] sealed refresh restore started', {
        thresholdSessionId,
        walletSigningSessionId: sealedRecord.walletSigningSessionId,
      });
      const restored = await this.restoreEcdsaSigningSessionMaterialFromSealedRecord({
        sealedRecord,
        ecdsaRecord,
        ...(ed25519Record ? { ed25519Record } : {}),
      }).catch((error) => {
        console.warn('[EmailOtpSession] sealed refresh restore failed', {
          thresholdSessionId,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
        return null;
      });
      if (!restored) {
        return null;
      }
      console.debug('[EmailOtpSession] sealed refresh restore succeeded', {
        thresholdSessionId,
        remainingUses: restored.remainingUses,
        expiresAtMs: restored.expiresAtMs,
      });
      const result: WarmSessionStatusResult = {
        ok: true,
        remainingUses: restored.remainingUses,
        expiresAtMs: restored.expiresAtMs,
      };
      const chain = sealedRecord.ecdsaRestore?.chain;
      const walletId = String(sealedRecord.walletId || sealedRecord.userId || '').trim();
      if (walletId && (chain === 'tempo' || chain === 'evm')) {
        publishResolvedIdentity({
          walletId,
          authMethod: 'email_otp',
          curve: 'ecdsa',
          chain,
          walletSigningSessionId: sealedRecord.walletSigningSessionId,
          thresholdSessionId,
        });
      }
      await this.recordSessionMaterialRestored(thresholdSessionId, result);
      return result;
    } finally {
      await releaseLease(lease).catch(() => undefined);
    }
  }

  private shouldAttemptEcdsaSealedRestoreForSessionId(sessionIdRaw: string): boolean {
    const sessionId = String(sessionIdRaw || '').trim();
    if (!sessionId) return false;
    const ecdsaRecord =
      this.deps.getThresholdEcdsaSessionRecordByThresholdSessionId?.(sessionId) ||
      getStoredThresholdEcdsaSessionRecordByThresholdSessionId(sessionId);
    if (ecdsaRecord?.source === 'email_otp') return true;
    const ed25519Record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(sessionId);
    // Ed25519 status reads should not probe the ECDSA sealed store. Account-scoped
    // restore is responsible for ECDSA recovery before ECDSA lane selection.
    if (ed25519Record?.source === 'email_otp') return false;
    return true;
  }

  async restorePersistedSessionsForAccount(
    args: RestorePersistedSessionsForAccountInput,
  ): Promise<RestorePersistedSessionsForAccountResult> {
    if (this.deps.configs.signing.sessionPersistenceMode !== 'sealed_refresh_v1') {
      return { listed: 0, attempted: 0, restored: 0, deferred: 0, skipped: 0, truncated: 0 };
    }
    const accountId = String(toAccountId(args.walletId) || '').trim();
    if (!accountId) {
      return { listed: 0, attempted: 0, restored: 0, deferred: 0, skipped: 0, truncated: 0 };
    }
    const listRecords =
      this.deps.listExactSealedSessionsForAccount || listExactSealedSessionsForAccount;

    const result = await restorePersistedSessionsForAccountCommand(
      {
        ...args,
        walletId: accountId,
      },
      {
        listExactSealedSessionsForAccount: ({ walletId: recordAccountId, ...filter }) =>
          listRecords({
            accountId: recordAccountId,
            filter,
          }),
        restoreSealedRecordForAccount: (restoreArgs) =>
          this.restoreEmailOtpSealedRecordForAccount(restoreArgs),
        cache: this.ecdsaSigningRestoreCache,
        onListError: ({ accountId: failedAccountId, error }) => {
          console.warn('[EmailOtpSession] account-scoped sealed ECDSA restore list failed', {
            accountId: failedAccountId,
            error: error instanceof Error ? error.message : String(error || 'unknown error'),
          });
        },
      },
    );
    if (!result.listed) {
      const diagnosticKey = `account-sealed-ecdsa-empty:${accountId}`;
      if (this.shouldLogSealedRefreshDiagnostic(diagnosticKey)) {
        console.debug('[EmailOtpSession] no durable sealed ECDSA records for account restore', {
          accountId,
        });
      }
    }
    return result;
  }

  async restorePersistedSessionForSigning(
    args: RestorePersistedSessionForSigningInput,
  ): Promise<RestorePersistedSessionForSigningResult> {
    if (this.deps.configs.signing.sessionPersistenceMode !== 'sealed_refresh_v1') {
      return { attempted: 0, restored: 0, deferred: 0 };
    }
    const accountId = String(toAccountId(args.walletId) || '').trim();
    if (!accountId) return { attempted: 0, restored: 0, deferred: 0 };
    const listRecords =
      this.deps.listExactSealedSessionsForAccount || listExactSealedSessionsForAccount;

    return await restorePersistedSessionForSigningCommand(
      {
        ...args,
        walletId: accountId,
      },
      {
        listExactSealedSessionsForAccount: ({ walletId: recordAccountId, ...filter }) => {
          if (filter.curve === 'ecdsa' && filter.chain !== 'tempo' && filter.chain !== 'evm') {
            return Promise.resolve([]);
          }
          return listRecords({
            accountId: recordAccountId,
            filter:
              filter.curve === 'ecdsa'
                ? { authMethod: filter.authMethod, curve: 'ecdsa', chain: filter.chain }
                : { authMethod: filter.authMethod, curve: 'ed25519' },
          });
        },
        restoreSealedRecordForAccount: (restoreArgs) =>
          this.restoreEmailOtpSealedRecordForAccount(restoreArgs),
        cache: this.ecdsaSigningRestoreCache,
        onListError: ({ accountId: failedAccountId, chain, reason, error }) => {
          console.warn('[EmailOtpSession] signing-intent sealed ECDSA restore list failed', {
            accountId: failedAccountId,
            chain,
            reason,
            error: error instanceof Error ? error.message : String(error || 'unknown error'),
          });
        },
      },
    );
  }

  async readPersistedSessionSnapshot(
    args: ReadSigningSessionSnapshotInput,
  ): Promise<SigningSessionSnapshot> {
    const accountId = String(toAccountId(args.walletId) || '').trim();
    const listRecords =
      this.deps.configs.signing.sessionPersistenceMode === 'sealed_refresh_v1'
        ? this.deps.listExactSealedSessionsForAccount || listExactSealedSessionsForAccount
        : async () => [];

    return await readSigningSessionSnapshot(
      {
        ...args,
        walletId: accountId,
      },
      {
        listSealedRecordsForAccount: async ({ accountId: recordAccountId, filter }) => {
          const listByAuthMethod = async (authMethod: 'email_otp' | 'passkey') => {
            if (filter.curve === 'ecdsa') {
              return await listRecords({
                accountId: recordAccountId,
                filter: { authMethod, curve: 'ecdsa', chain: filter.chain },
              });
            }
            return await listRecords({
              accountId: recordAccountId,
              filter: { authMethod, curve: 'ed25519' },
            });
          };
          if (filter.authMethod) {
            return await listByAuthMethod(filter.authMethod);
          }
          const [emailOtpRecords, passkeyRecords] = await Promise.all([
            listByAuthMethod('email_otp'),
            listByAuthMethod('passkey'),
          ]);
          return [...emailOtpRecords, ...passkeyRecords];
        },
        listRuntimeEcdsaRecordsForAccount: async ({ accountId: recordAccountId }) => {
          const runtimeRecords: SigningSessionSnapshotRuntimeEcdsaRecord[] = [];
          const seen = new Set<string>();
          for (const chain of ['tempo', 'evm'] as const) {
            for (const identity of listResolvedIdentitiesForAccount({
              walletId: recordAccountId,
              authMethod: 'email_otp',
              curve: 'ecdsa',
              chain,
            })) {
              const thresholdSessionId = String(identity.thresholdSessionId || '').trim();
              if (!thresholdSessionId || seen.has(thresholdSessionId)) continue;
              seen.add(thresholdSessionId);
              runtimeRecords.push({
                authMethod: 'email_otp',
                curve: 'ecdsa',
                chain,
                thresholdSessionId,
                walletSigningSessionId: identity.walletSigningSessionId,
              });
            }
          }
          return runtimeRecords;
        },
        listRuntimeEd25519RecordsForAccount: async ({ accountId: recordAccountId }) => {
          const records: SigningSessionSnapshotRuntimeEd25519Record[] = [];
          const seen = new Set<string>();
          const pushRecord = (record: SigningSessionSnapshotRuntimeEd25519Record) => {
            const thresholdSessionId = String(record.thresholdSessionId || '').trim();
            if (!thresholdSessionId || seen.has(thresholdSessionId)) return;
            seen.add(thresholdSessionId);
            records.push(record);
          };
          const identities = listResolvedIdentitiesForAccount({
            walletId: recordAccountId,
            curve: 'ed25519',
          });
          for (const identity of identities) {
            pushRecord({
              authMethod: identity.authMethod,
              curve: 'ed25519',
              chain: 'near',
              thresholdSessionId: identity.thresholdSessionId,
              walletSigningSessionId: identity.walletSigningSessionId,
            });
          }
          return records;
        },
        readRuntimeClaimsForSessions: async (sessionIds) => {
          const claims = new Map<string, SigningSessionSnapshotRuntimeClaim | null>();
          await Promise.all(
            sessionIds.map(async (sessionId) => {
              const ecdsaRecord =
                getStoredThresholdEcdsaSessionRecordByThresholdSessionId(sessionId);
              const statusSessionId =
                ecdsaRecord?.source === 'email_otp'
                  ? resolveEmailOtpEcdsaWorkerSessionId(ecdsaRecord)
                  : sessionId;
              const status = await this.readWarmSessionStatusOnly(statusSessionId);
              claims.set(
                sessionId,
                warmStatusToSigningSessionSnapshotRuntimeClaim({ sessionId, status }),
              );
            }),
          );
          return claims;
        },
      },
    );
  }

  private async restoreEmailOtpSealedRecordForAccount(args: {
    accountId: string;
    record: SigningSessionSealedStoreRecord;
    purpose: RestorePersistedSessionPurpose;
  }): Promise<RestoreSealedRecordForAccountResult> {
    if (args.purpose.authMethod !== 'email_otp') return 'deferred';
    if (args.purpose.curve === 'ed25519') {
      return await this.restoreEd25519SealedRecordForAccount(args);
    }
    return await this.restoreEcdsaSealedRecordForAccount(args);
  }

  private async restoreEcdsaSealedRecordForAccount(args: {
    accountId: string;
    record: SigningSessionSealedStoreRecord;
    purpose: RestorePersistedSessionPurpose;
  }): Promise<RestoreSealedRecordForAccountResult> {
    if (args.purpose.curve !== 'ecdsa') return 'deferred';
    const thresholdSessionId = String(args.purpose.thresholdSessionId || '').trim();
    if (!thresholdSessionId) return 'deferred';
    if (args.record.authMethod !== args.purpose.authMethod) return 'deferred';
    if (args.record.thresholdSessionIds.ecdsa !== thresholdSessionId) return 'deferred';
    if (args.record.ecdsaRestore?.chain !== args.purpose.chain) return 'deferred';
    if (args.record.walletSigningSessionId !== args.purpose.walletSigningSessionId) {
      return 'deferred';
    }
    const restoreKey = [
      args.accountId,
      args.purpose.authMethod,
      args.purpose.curve,
      args.purpose.chain,
      args.purpose.walletSigningSessionId,
      thresholdSessionId,
    ].join(':');
    if (this.ecdsaAccountSealedRestoreCompletedKeys.has(restoreKey)) return 'ready';
    const existing =
      this.deps.getThresholdEcdsaSessionRecordByThresholdSessionId?.(thresholdSessionId) ||
      getStoredThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId);
    if (existing?.source === 'email_otp') {
      const workerStatus = await this.readWarmSessionStatusFromWorker(thresholdSessionId).catch(
        () => null,
      );
      if (workerStatus?.ok) {
        this.ecdsaAccountSealedRestoreCompletedKeys.add(restoreKey);
        return 'ready';
      }
    }
    const inFlight = this.ecdsaAccountSealedRestoreInFlightByKey.get(restoreKey);
    if (inFlight) {
      await inFlight;
      return this.ecdsaAccountSealedRestoreCompletedKeys.has(restoreKey) ? 'ready' : 'deferred';
    }
    let restoreResult: 'restored' | 'deferred' = 'deferred';
    const task = (async () => {
      const sealedEd25519SessionId = String(args.record.thresholdSessionIds.ed25519 || '').trim();
      const ed25519Record = sealedEd25519SessionId
        ? getStoredThresholdEd25519SessionRecordByThresholdSessionId(sealedEd25519SessionId)
        : null;
      if (
        sealedEd25519SessionId &&
        (!ed25519Record ||
          ed25519Record.source !== 'email_otp' ||
          ed25519Record.emailOtpAuthContext?.retention !== 'session' ||
          ed25519Record.walletSigningSessionId !== args.purpose.walletSigningSessionId)
      ) {
        const diagnosticKey = `exact-purpose-missing-ed25519-companion:${thresholdSessionId}:${sealedEd25519SessionId}`;
        if (this.shouldLogSealedRefreshDiagnostic(diagnosticKey)) {
          console.debug(
            '[EmailOtpSession] exact-purpose ECDSA restore proceeding without Ed25519 companion',
            {
              thresholdSessionId,
              sealedEd25519SessionId,
              walletSigningSessionId: args.purpose.walletSigningSessionId,
            },
          );
        }
      }
      const restored = await this.restoreEcdsaSigningSessionMaterialFromSealedRecord({
        sealedRecord: args.record,
        ecdsaRecord: existing,
        ...(ed25519Record ? { ed25519Record } : {}),
      });
      if (restored) {
        await this.recordSessionMaterialRestored(thresholdSessionId, {
          ok: true,
          remainingUses: restored.remainingUses,
          expiresAtMs: restored.expiresAtMs,
        });
        this.ecdsaAccountSealedRestoreCompletedKeys.add(restoreKey);
        restoreResult = 'restored';
      }
    })()
      .catch((error) => {
        console.warn('[EmailOtpSession] account-scoped sealed ECDSA restore failed', {
          accountId: args.accountId,
          thresholdSessionId,
          walletSigningSessionId: args.purpose.walletSigningSessionId,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      })
      .finally(() => {
        this.ecdsaAccountSealedRestoreInFlightByKey.delete(restoreKey);
      });
    this.ecdsaAccountSealedRestoreInFlightByKey.set(restoreKey, task);
    await task;
    return restoreResult;
  }

  private buildEd25519RecordFromSealedRestoreMetadata(args: {
    accountId: string;
    record: SigningSessionSealedStoreRecord;
    purpose: RestorePersistedSessionPurpose;
  }): ThresholdEd25519SessionRecord | null {
    if (args.purpose.curve !== 'ed25519') return null;
    const existing = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
      args.purpose.thresholdSessionId,
    );
    if (
      existing?.source === 'email_otp' &&
      existing.emailOtpAuthContext?.retention === 'session' &&
      existing.walletSigningSessionId === args.purpose.walletSigningSessionId
    ) {
      return existing;
    }
    const metadata = args.record.ed25519Restore;
    if (!metadata) return null;
    const relayerUrl = String(args.record.relayerUrl || '').trim();
    const signingRootId = String(args.record.signingRootId || '').trim();
    if (!relayerUrl || !signingRootId) return null;
    const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(metadata.runtimePolicyScope);
    return upsertStoredThresholdEd25519SessionRecord({
      nearAccountId: args.accountId,
      rpId: metadata.rpId,
      relayerUrl,
      relayerKeyId: metadata.relayerKeyId,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      ...(metadata.xClientBaseB64u ? { xClientBaseB64u: metadata.xClientBaseB64u } : {}),
      participantIds: metadata.participantIds,
      thresholdSessionKind: metadata.sessionKind,
      thresholdSessionId: args.purpose.thresholdSessionId,
      walletSigningSessionId: args.purpose.walletSigningSessionId,
      ...(metadata.thresholdSessionJwt
        ? { thresholdSessionJwt: metadata.thresholdSessionJwt }
        : {}),
      expiresAtMs: args.record.expiresAtMs,
      remainingUses: args.record.remainingUses,
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      source: 'email_otp',
    });
  }

  private async restoreEd25519SealedRecordForAccount(args: {
    accountId: string;
    record: SigningSessionSealedStoreRecord;
    purpose: RestorePersistedSessionPurpose;
  }): Promise<RestoreSealedRecordForAccountResult> {
    if (args.purpose.curve !== 'ed25519') return 'deferred';
    const ecdsaThresholdSessionId = String(args.record.thresholdSessionIds.ecdsa || '').trim();
    if (!ecdsaThresholdSessionId) return 'deferred';
    const ed25519Record = this.buildEd25519RecordFromSealedRestoreMetadata(args);
    if (!ed25519Record) return 'deferred';
    const existingStatus = await this.readWarmSessionStatusFromWorker(
      args.purpose.thresholdSessionId,
    ).catch(() => null);
    if (existingStatus?.ok) return 'ready';
    const ecdsaRecord =
      this.deps.getThresholdEcdsaSessionRecordByThresholdSessionId?.(ecdsaThresholdSessionId) ||
      getStoredThresholdEcdsaSessionRecordByThresholdSessionId(ecdsaThresholdSessionId);
    const restored = await this.restoreEcdsaSigningSessionMaterialFromSealedRecord({
      sealedRecord: args.record,
      ecdsaRecord,
      ed25519Record,
    }).catch((error) => {
      console.warn('[EmailOtpSession] exact-purpose Ed25519 sealed restore failed', {
        accountId: args.accountId,
        thresholdSessionId: args.purpose.thresholdSessionId,
        ecdsaThresholdSessionId,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
      });
      return null;
    });
    if (!restored?.ed25519RestoreSeedB64u) return 'deferred';
    await this.recordSessionMaterialRestored(ecdsaThresholdSessionId, {
      ok: true,
      remainingUses: restored.remainingUses,
      expiresAtMs: restored.expiresAtMs,
    });
    await this.recordSessionMaterialRestored(args.purpose.thresholdSessionId, {
      ok: true,
      remainingUses: restored.remainingUses,
      expiresAtMs: restored.expiresAtMs,
    });
    const status = await this.readWarmSessionStatusFromWorker(
      args.purpose.thresholdSessionId,
    ).catch(() => null);
    return status?.ok ? 'restored' : 'deferred';
  }

  private async readWarmSessionStatusFromWorker(
    sessionId: string,
  ): Promise<WarmSessionStatusResult> {
    return await this.deps.signerWorkerManager.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'getEmailOtpWarmSessionStatus',
        timeoutMs: 5_000,
        payload: { sessionId },
      },
    });
  }

  async readWarmSessionStatusOnly(sessionId: string): Promise<WarmSessionStatusResult> {
    const normalizedSessionId = String(sessionId || '').trim();
    if (!normalizedSessionId) {
      return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
    }
    return await this.readWarmSessionStatusFromWorker(normalizedSessionId).catch((error) => ({
      ok: false as const,
      code: 'worker_error',
      message: error instanceof Error ? error.message : String(error || 'Email OTP worker error'),
    }));
  }

  private async claimWarmSessionMaterialFromWorker(args: {
    sessionId: string;
    uses?: number;
    consume?: boolean;
  }): Promise<WarmSessionClaimResult> {
    return await this.deps.signerWorkerManager.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'claimEmailOtpWarmSessionMaterial',
        timeoutMs: 5_000,
        payload: {
          sessionId: args.sessionId,
          ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
          ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
        },
      },
    });
  }

  private async consumeWarmSessionUsesFromWorker(args: {
    sessionId: string;
    uses?: number;
  }): Promise<WarmSessionStatusResult> {
    return await this.deps.signerWorkerManager.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'consumeEmailOtpWarmSessionUses',
        timeoutMs: 5_000,
        payload: {
          sessionId: args.sessionId,
          ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
        },
      },
    });
  }

  async claimWarmSessionMaterial(args: {
    sessionId: string;
    uses?: number;
    consume?: boolean;
    curve?: 'ed25519' | 'ecdsa';
    chain?: 'near' | 'tempo' | 'evm';
  }): Promise<WarmSessionClaimResult> {
    const normalizedSessionId = String(args.sessionId || '').trim();
    if (!normalizedSessionId) {
      return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
    }
    try {
      const result = await this.claimWarmSessionMaterialFromWorker({
        sessionId: normalizedSessionId,
        ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
        ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
      });
      if (
        !result.ok &&
        result.code === 'not_found' &&
        this.shouldAttemptEcdsaSealedRestoreForSessionId(normalizedSessionId)
      ) {
        const restored =
          await this.tryRestoreEcdsaWarmSessionStatusFromSealedRecord(normalizedSessionId);
        if (restored?.ok) {
          const retry = await this.claimWarmSessionMaterialFromWorker({
            sessionId: normalizedSessionId,
            ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
            ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
          });
          await this.recordSessionMaterialClaimed(normalizedSessionId, retry);
          return retry;
        }
        if (restored) {
          await this.recordSessionMaterialRestored(normalizedSessionId, restored);
        }
        return result;
      }
      await this.recordSessionMaterialClaimed(normalizedSessionId, result);
      return result;
    } catch (error) {
      return {
        ok: false,
        code: 'worker_error',
        message: error instanceof Error ? error.message : String(error || 'Email OTP worker error'),
      };
    }
  }

  async consumeWarmSessionUses(args: {
    sessionId: string;
    uses?: number;
    curve?: 'ed25519' | 'ecdsa';
    chain?: 'near' | 'tempo' | 'evm';
  }): Promise<WarmSessionStatusResult> {
    const normalizedSessionId = String(args.sessionId || '').trim();
    if (!normalizedSessionId) {
      return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
    }
    try {
      const result = await this.consumeWarmSessionUsesFromWorker({
        sessionId: normalizedSessionId,
        ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
      });
      if (
        !result.ok &&
        result.code === 'not_found' &&
        this.shouldAttemptEcdsaSealedRestoreForSessionId(normalizedSessionId)
      ) {
        const restored =
          await this.tryRestoreEcdsaWarmSessionStatusFromSealedRecord(normalizedSessionId);
        if (restored?.ok) {
          const retry = await this.consumeWarmSessionUsesFromWorker({
            sessionId: normalizedSessionId,
            ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
          });
          await this.recordSessionUseConsumed(normalizedSessionId, retry);
          return retry;
        }
        if (restored) {
          await this.recordSessionMaterialRestored(normalizedSessionId, restored);
        }
        return result;
      }
      await this.recordSessionUseConsumed(normalizedSessionId, result);
      return result;
    } catch (error) {
      return {
        ok: false,
        code: 'worker_error',
        message: error instanceof Error ? error.message : String(error || 'Email OTP worker error'),
      };
    }
  }

  async clearWarmSessionMaterial(sessionId: string): Promise<void> {
    const normalizedSessionId = String(sessionId || '').trim();
    if (!normalizedSessionId) return;
    await this.deps.signerWorkerManager
      .requestWorkerOperation({
        kind: 'emailOtp',
        request: {
          type: 'clearEmailOtpWarmSessionMaterial',
          timeoutMs: 5_000,
          payload: { sessionId: normalizedSessionId },
        },
      })
      .catch(() => undefined);
    await this.cleanupSigningSession({
      sessionId: normalizedSessionId,
      reason: 'explicit_clear',
    });
  }

  rememberAppSessionJwt(args: { nearAccountId: AccountId | string; appSessionJwt?: string }): void {
    const jwt = String(args.appSessionJwt || '').trim();
    if (!jwt) return;
    if (!isAppSessionJwt(jwt)) return;
    const accountId = String(args.nearAccountId || '').trim();
    if (!accountId) return;
    if (!(this.appSessionJwtByAccount instanceof Map)) {
      this.appSessionJwtByAccount = new Map();
    }
    this.appSessionJwtByAccount.set(accountId, jwt);
  }

  async resolveAppSessionJwt(args: {
    nearAccountId: AccountId | string;
    relayUrl: string;
  }): Promise<string> {
    const accountId = String(args.nearAccountId || '').trim();
    if (!(this.appSessionJwtByAccount instanceof Map)) {
      this.appSessionJwtByAccount = new Map();
    }
    const cached = accountId ? String(this.appSessionJwtByAccount.get(accountId) || '').trim() : '';
    if (cached && isAppSessionJwt(cached) && isSessionJwtUnexpired(cached, { skewMs: 30_000 })) {
      return cached;
    }
    const refreshCandidate =
      cached && isAppSessionJwt(cached) && isSessionJwtUnexpired(cached) ? cached : '';
    if (accountId) this.appSessionJwtByAccount.delete(accountId);
    const refreshed = this.deps.refreshAppSessionJwt
      ? await this.deps.refreshAppSessionJwt({ relayUrl: args.relayUrl })
      : await this.refreshAppSessionJwt({
          relayUrl: args.relayUrl,
          ...(refreshCandidate ? { appSessionJwt: refreshCandidate } : {}),
        });
    if (accountId && refreshed) {
      this.rememberAppSessionJwt({ nearAccountId: accountId, appSessionJwt: refreshed });
    }
    return refreshed;
  }

  private async refreshAppSessionJwt(args: {
    relayUrl: string;
    appSessionJwt?: string;
  }): Promise<string> {
    const relayUrl = String(args.relayUrl || '').trim();
    if (!relayUrl) {
      throw new Error('Missing relayer url for Email OTP export session refresh');
    }
    const appSessionJwt = String(args.appSessionJwt || '').trim();
    const response = await fetch(joinNormalizedUrl(relayUrl, '/session/refresh'), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(appSessionJwt ? { Authorization: `Bearer ${appSessionJwt}` } : {}),
      },
      credentials: 'include',
      body: JSON.stringify({ session_kind: 'jwt' }),
    });
    const json = (await response.json().catch(() => null)) as Record<string, unknown> | null;
    if (!response.ok || !json || json.ok === false) {
      const message =
        (typeof json?.message === 'string' && json.message.trim()) ||
        `Email OTP export session refresh failed (HTTP ${response.status})`;
      throw new Error(message);
    }
    const jwt = typeof json.jwt === 'string' ? json.jwt.trim() : '';
    if (!jwt) {
      throw new Error('Email OTP export session refresh did not return a JWT');
    }
    return jwt;
  }

  private buildRoutePlan(args: {
    freshRouteFamily: 'login' | 'registration';
    routeAuth?: AppOrThresholdSessionAuth;
    appSessionJwt?: string;
    sessionKind?: 'jwt' | 'cookie';
    thresholdSessionId?: string;
    walletSigningSessionId?: string;
    curve?: 'ed25519' | 'ecdsa';
    chain?: ThresholdEcdsaActivationChain;
    operation?: WalletEmailOtpLoginOperation;
  }): EmailOtpRoutePlan {
    const authLane = resolveEmailOtpAuthLane({
      sessionKind: args.sessionKind,
      appSessionJwt: args.appSessionJwt,
      routeAuth: args.routeAuth,
      thresholdSessionId: args.thresholdSessionId,
      walletSigningSessionId: args.walletSigningSessionId,
      curve: args.curve,
      chain: args.chain,
    });
    if (!authLane) {
      throw new Error(`Email OTP ${args.freshRouteFamily} requires route auth`);
    }
    return buildEmailOtpRoutePlan({
      routeFamily: routeFamilyForAuthLane({
        authLane,
        freshRouteFamily: args.freshRouteFamily,
      }),
      authLane,
      operation: args.operation,
    });
  }

  private buildSigningSessionRoutePlan(args: {
    authLane?: EmailOtpAuthLane;
    routeAuth?: AppOrThresholdSessionAuth;
    thresholdSessionId?: string;
    walletSigningSessionId?: string;
    curve?: 'ed25519' | 'ecdsa';
    chain?: ThresholdEcdsaActivationChain;
    operation: EmailOtpSigningSessionChallengeOperation;
  }): EmailOtpRoutePlan {
    const authLane =
      args.authLane?.kind === 'signing_session'
        ? args.authLane
        : resolveEmailOtpAuthLane({
            routeAuth: args.routeAuth,
            thresholdSessionId: args.thresholdSessionId,
            walletSigningSessionId: args.walletSigningSessionId,
            curve: args.curve,
            chain: args.chain,
          });
    if (authLane?.kind !== 'signing_session') {
      throw new Error(EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE);
    }
    return buildEmailOtpRoutePlan({
      routeFamily: 'signing_session',
      authLane,
      operation: args.operation,
    });
  }

  private routeAuthFromPlan(routePlan: EmailOtpRoutePlan): AppOrThresholdSessionAuth | undefined {
    return authLaneToRouteAuth(routePlan.authLane);
  }

  private appSessionJwtFromLane(authLane?: EmailOtpAuthLane): string {
    return authLaneAppSessionJwt(authLane);
  }

  private appSessionSubjectFromLane(authLane?: EmailOtpAuthLane): string {
    const jwt = this.appSessionJwtFromLane(authLane);
    if (!jwt) return '';
    const payload = decodeJwtPayloadRecord(jwt);
    const sub = typeof payload?.sub === 'string' ? payload.sub.trim() : '';
    return sub || '';
  }

  private thresholdRouteAuthFromEcdsaBootstrap(
    bootstrap: ThresholdEcdsaSessionBootstrapResult | undefined,
  ): AppOrThresholdSessionAuth | undefined {
    const jwt = String(bootstrap?.session?.jwt || '').trim();
    return jwt ? { kind: 'threshold_session', jwt } : undefined;
  }

  private walletSigningSessionIdFromEcdsaBootstrap(
    bootstrap: ThresholdEcdsaSessionBootstrapResult | undefined,
    defaultWalletSigningSessionId?: string,
  ): string {
    return (
      String(bootstrap?.session?.walletSigningSessionId || '').trim() ||
      String(bootstrap?.thresholdEcdsaKeyRef?.walletSigningSessionId || '').trim() ||
      String(defaultWalletSigningSessionId || '').trim()
    );
  }

  private thresholdSessionIdFromEcdsaBootstrap(
    bootstrap: ThresholdEcdsaSessionBootstrapResult | undefined,
  ): string {
    return (
      String(bootstrap?.session?.sessionId || '').trim() ||
      String(bootstrap?.thresholdEcdsaKeyRef?.thresholdSessionId || '').trim()
    );
  }

  isEd25519WarmupPending(args: { nearAccountId: AccountId | string }): boolean {
    const accountId = this.normalizeWarmupAccountId(args.nearAccountId);
    return Boolean(accountId && this.getEd25519WarmupMap().has(accountId));
  }

  async waitForPendingEd25519Warmup(args: { nearAccountId: AccountId | string }): Promise<boolean> {
    const accountId = this.normalizeWarmupAccountId(args.nearAccountId);
    if (!accountId) return false;
    const pending = this.getEd25519WarmupMap().get(accountId);
    if (!pending) return false;
    await pending;
    return true;
  }

  scheduleEd25519CapabilityProvisioning(
    args: ProvisionEmailOtpThresholdEd25519CapabilityArgs,
  ): void {
    const accountId = this.normalizeWarmupAccountId(args.nearAccountId);
    if (!accountId) return;
    const warmupMap = this.getEd25519WarmupMap();
    if (warmupMap.has(accountId)) return;
    const pending = this.provisionEd25519Capability(args);
    warmupMap.set(accountId, pending);
    void pending
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error || 'unknown error');
        console.warn('[email-otp] background threshold-ed25519 warm-up failed', {
          nearAccountId: accountId,
          message,
        });
      })
      .finally(() => {
        const currentWarmupMap = this.getEd25519WarmupMap();
        if (currentWarmupMap.get(accountId) === pending) {
          currentWarmupMap.delete(accountId);
        }
      });
  }

  private async requestEmailOtpChallengeWithRoutePlan(args: {
    nearAccountId: AccountId | string;
    routePlan: EmailOtpRoutePlan;
  }): Promise<{ challengeId: string; emailHint?: string; appSessionJwt?: string }> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const relayUrl = this.requireRelayUrl();
    const workerCtx = this.deps.getSignerWorkerContext();
    if (!workerCtx) {
      throw new Error('Email OTP signing requires the dedicated emailOtp worker');
    }
    const response = await workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'requestEmailOtpChallenge',
        timeoutMs: 30_000,
        payload: {
          relayUrl,
          walletId: String(nearAccountId),
          routePlan: args.routePlan,
          otpChannel: EMAIL_OTP_CHANNEL,
        },
      },
    });
    const challengeId = String(response.challengeId || '').trim();
    if (!challengeId) {
      throw new Error('Email OTP signing challenge response did not include challengeId');
    }
    return {
      challengeId,
      ...(String(response.emailHint || '').trim()
        ? { emailHint: String(response.emailHint || '').trim() }
        : {}),
      ...(this.appSessionJwtFromLane(args.routePlan.authLane)
        ? { appSessionJwt: this.appSessionJwtFromLane(args.routePlan.authLane) }
        : {}),
    };
  }

  async requestTransactionSigningChallenge(args: {
    nearAccountId: AccountId | string;
    chain: 'near' | ThresholdEcdsaActivationChain;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  }): Promise<{ challengeId: string; emailHint?: string }> {
    const providedAuthLane = args.authLane;
    const providedRouteAuth = providedAuthLane
      ? authLaneToRouteAuth(providedAuthLane)
      : args.routeAuth;
    const routePlan =
      !providedAuthLane && !providedRouteAuth
        ? this.buildRoutePlan({
            freshRouteFamily: 'login',
            appSessionJwt: await this.resolveAppSessionJwt({
              nearAccountId: args.nearAccountId,
              relayUrl: this.requireRelayUrl(),
            }),
            sessionKind: 'jwt',
            curve: args.chain === 'near' ? 'ed25519' : 'ecdsa',
            ...(args.chain !== 'near' ? { chain: args.chain } : {}),
            operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
          })
        : this.buildSigningSessionRoutePlan({
            authLane: providedAuthLane,
            routeAuth: providedRouteAuth,
            curve: args.chain === 'near' ? 'ed25519' : 'ecdsa',
            ...(args.chain !== 'near' ? { chain: args.chain } : {}),
            operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
          });
    return this.requestEmailOtpChallengeWithRoutePlan({
      nearAccountId: args.nearAccountId,
      routePlan,
    });
  }

  private async requestExportChallenge(args: {
    nearAccountId: AccountId | string;
    chain: 'near' | ThresholdEcdsaActivationChain;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  }): Promise<{ challengeId: string; emailHint?: string }> {
    const providedAuthLane = args.authLane;
    const providedRouteAuth = providedAuthLane
      ? authLaneToRouteAuth(providedAuthLane)
      : args.routeAuth;
    const routePlan =
      !providedAuthLane && !providedRouteAuth && args.chain !== 'near'
        ? this.buildRoutePlan({
            freshRouteFamily: 'login',
            appSessionJwt: await this.resolveAppSessionJwt({
              nearAccountId: args.nearAccountId,
              relayUrl: this.requireRelayUrl(),
            }),
            sessionKind: 'jwt',
            curve: 'ecdsa',
            chain: args.chain,
            operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
          })
        : this.buildSigningSessionRoutePlan({
            authLane: providedAuthLane,
            routeAuth: providedRouteAuth,
            curve: args.chain === 'near' ? 'ed25519' : 'ecdsa',
            ...(args.chain !== 'near' ? { chain: args.chain } : {}),
            operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
          });
    return this.requestEmailOtpChallengeWithRoutePlan({
      nearAccountId: args.nearAccountId,
      routePlan,
    });
  }

  async requestExportAuthorization(args: {
    nearAccountId: AccountId | string;
    chain: 'near' | ThresholdEcdsaActivationChain;
    publicKey: string;
    curve: WalletAuthCurve;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  }): Promise<{ challengeId: string; otpCode: string }> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const requestExportChallenge = async () => {
      const challenge = await this.requestExportChallenge({
        nearAccountId,
        chain: args.chain,
        ...(args.routeAuth ? { routeAuth: args.routeAuth } : {}),
        ...(args.authLane ? { authLane: args.authLane } : {}),
      });
      const challengeId = String(challenge.challengeId || '').trim();
      if (!challengeId) {
        throw new Error('Email OTP export challenge response did not include challengeId');
      }
      return {
        challengeId,
        emailHint: String(challenge.emailHint || '').trim(),
      };
    };
    const firstChallenge = await requestExportChallenge();
    let challenge = {
      challengeId: firstChallenge.challengeId,
      ...(firstChallenge.emailHint ? { emailHint: firstChallenge.emailHint } : {}),
    };
    const decision = await this.deps.requestUserConfirmation({
      requestId: createExportUiRequestId(`export-${args.curve}-email-otp-auth`),
      type: UserConfirmationType.SIGN_INTENT_DIGEST,
      summary: {
        operation: 'Export Private Key',
        accountId: nearAccountId,
        publicKey: args.publicKey,
        warning:
          'Enter the email code to export this key. Anyone with the private key can fully control the account.',
      },
      payload: {
        nearAccountId,
        publicKey: args.publicKey,
        challengeB64u: challenge.challengeId,
        signingAuthPlan: {
          kind: SigningAuthPlanKind.EmailOtpReauth,
          method: 'email_otp',
          emailOtpPrompt: {
            challengeId: challenge.challengeId,
            ...(challenge.emailHint ? { emailHint: challenge.emailHint } : {}),
            title: 'Enter email code to export',
            body: 'This one-time code authorizes private key export only.',
            helperText: 'Enter the 6-digit code sent to your email',
            onResend: async () => {
              challenge = await requestExportChallenge();
              return challenge;
            },
          },
        },
        emailOtpPrompt: {
          challengeId: challenge.challengeId,
          ...(challenge.emailHint ? { emailHint: challenge.emailHint } : {}),
          title: 'Enter email code to export',
          body: 'This one-time code authorizes private key export only.',
          helperText: 'Enter the 6-digit code sent to your email',
          onResend: async () => {
            challenge = await requestExportChallenge();
            return challenge;
          },
        },
      },
      intentDigest: `export-keys:${nearAccountId}:${args.chain}:${args.curve}:email-otp`,
    });
    if (!decision.confirmed) {
      throw new Error(decision.error || 'User cancelled Email OTP export request');
    }
    const otpCode = String(decision.otpCode || '')
      .replace(/\D/g, '')
      .slice(0, 6);
    if (otpCode.length !== 6) {
      throw new Error('Email OTP export requires a 6-digit code');
    }
    const responseChallengeId = String(
      decision.emailOtpChallengeId || challenge.challengeId,
    ).trim();
    return {
      challengeId: responseChallengeId,
      otpCode,
    };
  }

  async recoverEd25519ExportPrfFirst(args: {
    nearAccountId: AccountId | string;
    challengeId: string;
    otpCode: string;
    record: ThresholdEd25519SessionRecord;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  }): Promise<{ prfFirstB64u: string }> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const relayUrl = String(args.record.relayerUrl || this.requireRelayUrl()).trim();
    const shamirPrimeB64u = String(this.requireShamirPrimeB64u()).trim();
    const workerCtx = this.deps.getSignerWorkerContext();
    if (!workerCtx) {
      throw new Error('Email OTP Ed25519 export requires the dedicated emailOtp worker');
    }
    const providedAuthLane = args.authLane;
    const providedRouteAuth = providedAuthLane
      ? authLaneToRouteAuth(providedAuthLane)
      : args.routeAuth;
    const routePlan = this.buildSigningSessionRoutePlan({
      authLane: providedAuthLane,
      routeAuth: providedRouteAuth,
      thresholdSessionId: args.record.thresholdSessionId,
      walletSigningSessionId: args.record.walletSigningSessionId,
      curve: 'ed25519',
      operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
    });
    const workerResult = await workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'recoverEmailOtpEd25519ExportPrfFirst',
        timeoutMs: 60_000,
        payload: {
          relayUrl,
          walletId: String(nearAccountId),
          userId: String(args.record.emailOtpAuthContext?.authSubjectId || nearAccountId),
          challengeId: args.challengeId,
          otpCode: args.otpCode,
          shamirPrimeB64u,
          routePlan,
          otpChannel: EMAIL_OTP_CHANNEL,
          ...(args.record.runtimePolicyScope
            ? { runtimePolicyScope: args.record.runtimePolicyScope }
            : {}),
        },
      },
    });
    const prfFirstB64u = String(workerResult.thresholdEd25519PrfFirstB64u || '').trim();
    if (!prfFirstB64u) {
      throw new Error('Email OTP Ed25519 export did not recover client seed material');
    }
    return { prfFirstB64u };
  }

  async exportEcdsaKeyWithAuthorization(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    challengeId: string;
    otpCode: string;
    record: ThresholdEcdsaSessionRecord;
    rpId: string;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  }): Promise<{ publicKeyHex: string; privateKeyHex: string; ethereumAddress: string }> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const relayUrl = String(args.record.relayerUrl || this.requireRelayUrl()).trim();
    const shamirPrimeB64u = String(this.requireShamirPrimeB64u()).trim();
    const ecdsaThresholdKeyId = String(args.record.ecdsaThresholdKeyId || '').trim();
    if (!ecdsaThresholdKeyId) {
      throw new Error('Email OTP ECDSA export requires ecdsaThresholdKeyId');
    }
    const thresholdSessionJwt = String(args.record.thresholdSessionJwt || '').trim();
    const sessionKind = args.record.thresholdSessionKind || 'jwt';
    if (!thresholdSessionJwt && sessionKind !== 'cookie') {
      throw new Error('Email OTP ECDSA export requires threshold session route auth');
    }
    const workerCtx = this.deps.getSignerWorkerContext();
    if (!workerCtx) {
      throw new Error('Email OTP ECDSA export requires the dedicated emailOtp worker');
    }
    const providedAuthLane = args.authLane;
    const providedRouteAuth = providedAuthLane
      ? authLaneToRouteAuth(providedAuthLane)
      : args.routeAuth;
    const routePlan = this.buildSigningSessionRoutePlan({
      authLane: providedAuthLane,
      routeAuth: providedRouteAuth,
      thresholdSessionId: args.record.thresholdSessionId,
      walletSigningSessionId: args.record.walletSigningSessionId,
      curve: 'ecdsa',
      chain: args.chain,
      operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
    });
    return await workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization',
        timeoutMs: 60_000,
        payload: {
          relayUrl,
          walletId: String(nearAccountId),
          userId: String(args.record.emailOtpAuthContext?.authSubjectId || nearAccountId),
          challengeId: args.challengeId,
          otpCode: args.otpCode,
          shamirPrimeB64u,
          routePlan,
          rpId: args.rpId,
          thresholdSessionJwt,
          sessionKind,
          ecdsaThresholdKeyId,
          chain: args.chain,
          ...(args.record.runtimePolicyScope
            ? { runtimePolicyScope: args.record.runtimePolicyScope }
            : {}),
        },
      },
    });
  }

  async bootstrapAndExportEcdsaKeyWithAuthorization(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    challengeId: string;
    otpCode: string;
    ecdsaThresholdKeyId: string;
    participantIds?: number[];
  }): Promise<{ publicKeyHex: string; privateKeyHex: string; ethereumAddress: string }> {
    const relayUrl = this.requireRelayUrl();
    const operation = WALLET_EMAIL_OTP_EXPORT_OPERATION;
    const appSessionJwt = await this.resolveAppSessionJwt({
      nearAccountId: args.nearAccountId,
      relayUrl,
    });
    const routePlan = this.buildRoutePlan({
      freshRouteFamily: 'login',
      appSessionJwt,
      sessionKind: 'jwt',
      curve: 'ecdsa',
      chain: args.chain,
      operation,
    });
    const result = await this.loginWithEcdsaCapabilityInternal({
      nearAccountId: args.nearAccountId,
      relayUrl,
      chain: args.chain,
      emailOtpAuthPolicy: 'per_operation',
      emailOtpAuthReason: 'sign',
      challengeId: args.challengeId,
      otpCode: args.otpCode,
      operation,
      routePlan,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      ...(Array.isArray(args.participantIds) && args.participantIds.length > 0
        ? { participantIds: args.participantIds }
        : {}),
      remainingUses: 1,
      includeEcdsaExportArtifact: true,
    });
    const artifact = result.bootstrap.thresholdEcdsaKeyRef.ecdsaHssExportArtifact;
    if (!artifact) {
      throw new Error('Email OTP ECDSA export did not return an export artifact');
    }
    return artifact;
  }

  async loginWithEcdsaCapabilityForSigning(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    challengeId: string;
    otpCode: string;
    record?: ThresholdEcdsaSessionRecord;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  }): Promise<ThresholdEcdsaSecp256k1KeyRef> {
    const record = args.record;
    const operation = WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION;
    const emailOtpAuthPolicy: EmailOtpAuthPolicy = 'per_operation';
    const remainingUses = 1;
    if (!record) {
      const relayUrl = this.requireRelayUrl();
      const appSessionJwt = await this.resolveAppSessionJwt({
        nearAccountId: args.nearAccountId,
        relayUrl,
      });
      const routePlan = this.buildRoutePlan({
        freshRouteFamily: 'login',
        appSessionJwt,
        sessionKind: 'jwt',
        curve: 'ecdsa',
        chain: args.chain,
        operation,
      });
      await this.loginWithEcdsaCapabilityInternal({
        nearAccountId: args.nearAccountId,
        relayUrl,
        chain: args.chain,
        emailOtpAuthPolicy,
        emailOtpAuthReason: 'sign',
        challengeId: args.challengeId,
        otpCode: args.otpCode,
        operation,
        routePlan,
        remainingUses,
      });
      return this.deps.getThresholdEcdsaKeyRefForLookup({
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        source: 'email_otp',
      });
    }
    const explicitAuthLane = args.authLane;
    const explicitRouteAuth = explicitAuthLane
      ? authLaneToRouteAuth(explicitAuthLane)
      : args.routeAuth;
    const routePlan = this.buildSigningSessionRoutePlan({
      authLane: explicitAuthLane,
      routeAuth: explicitRouteAuth,
      thresholdSessionId: record.thresholdSessionId,
      walletSigningSessionId: record.walletSigningSessionId,
      curve: 'ecdsa',
      chain: args.chain,
      operation,
    });
    await this.loginWithEcdsaCapabilityInternal({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      emailOtpAuthPolicy,
      emailOtpAuthReason: 'sign',
      challengeId: args.challengeId,
      otpCode: args.otpCode,
      operation,
      ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
      participantIds: record.participantIds,
      sessionKind: record.thresholdSessionKind,
      routePlan,
      authSubjectId: record.emailOtpAuthContext?.authSubjectId,
      remainingUses,
      ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    });
    return this.deps.getThresholdEcdsaKeyRefForLookup({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      source: 'email_otp',
    });
  }

  async loginWithEcdsaCapabilityInternal(
    args: LoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpThresholdEcdsaLoginResult> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const chain: ThresholdEcdsaActivationChain = args.chain || 'tempo';
    const emailOtpAuthPolicy: EmailOtpAuthPolicy =
      args.emailOtpAuthPolicy || this.deps.configs.signing.emailOtp.authPolicy;
    const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext = {
      policy: emailOtpAuthPolicy,
      retention: emailOtpAuthPolicy === 'per_operation' ? 'single_use' : 'session',
      reason: args.emailOtpAuthReason || 'login',
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
    };
    const relayUrl = String(args.relayUrl || this.requireRelayUrl()).trim();
    const shamirPrimeB64u = String(args.shamirPrimeB64u || this.requireShamirPrimeB64u()).trim();
    const remainingUses =
      typeof args.remainingUses === 'number'
        ? args.remainingUses
        : emailOtpAuthPolicy === 'per_operation'
          ? 1
          : undefined;
    const workerCtx = this.deps.getSignerWorkerContext();
    const sessionKind = args.sessionKind || 'jwt';
    const walletSigningSessionId =
      String(args.walletSigningSessionId || '').trim() || generateWalletSigningSessionId();
    const rpId = this.requireRpId('Email OTP login');
    const routePlan =
      args.routePlan ||
      this.buildRoutePlan({
        freshRouteFamily: 'login',
        routeAuth: args.routeAuth,
        appSessionJwt: args.appSessionJwt,
        sessionKind,
        thresholdSessionId: args.sessionId,
        walletSigningSessionId,
        curve: 'ecdsa',
        chain,
        operation: args.operation,
      });
    const routeAuth = this.routeAuthFromPlan(routePlan);

    if (!workerCtx) {
      throw new Error('Email OTP login requires the dedicated emailOtp worker');
    }
    const appSessionJwt = this.appSessionJwtFromLane(routePlan.authLane);
    if (appSessionJwt) this.rememberAppSessionJwt({ nearAccountId, appSessionJwt });
    const authSubjectId = this.appSessionSubjectFromLane(routePlan.authLane);
    const workerResult = await workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'loginWithEmailOtpAndBootstrapEcdsaSession',
        timeoutMs: 60_000,
        payload: {
          relayUrl,
          walletId: String(nearAccountId),
          userId: String(args.authSubjectId || nearAccountId),
          ...(args.challengeId ? { challengeId: args.challengeId } : {}),
          otpCode: args.otpCode,
          shamirPrimeB64u,
          routePlan,
          otpChannel: EMAIL_OTP_CHANNEL,
          rpId,
          chain,
          ...(args.ecdsaThresholdKeyId ? { ecdsaThresholdKeyId: args.ecdsaThresholdKeyId } : {}),
          ...(Array.isArray(args.participantIds) && args.participantIds.length > 0
            ? { participantIds: args.participantIds }
            : {}),
          sessionKind,
          ...(args.sessionId ? { sessionId: args.sessionId } : {}),
          walletSigningSessionId,
          ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
          ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
          ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
          ...(args.includeEcdsaExportArtifact ? { includeEcdsaExportArtifact: true } : {}),
        },
        onEvent: args.onProgress,
      },
    });
    const resolvedEmailOtpAuthContext = {
      ...emailOtpAuthContext,
      ...(authSubjectId ? { authSubjectId } : {}),
    };
    const { bootstrap, warmCapability } =
      await this.deps.commitWorkerProvisionedThresholdEcdsaSessions({
        nearAccountId,
        primaryChain: chain,
        bootstrap: workerResult.bootstrap,
        source: 'email_otp',
        emailOtpAuthContext: resolvedEmailOtpAuthContext,
        ...(args.smartAccount ? { smartAccount: args.smartAccount } : {}),
      });
    await this.persistEmailOtpEcdsaSigningSessionSealForUnlock({
      nearAccountId,
      chain,
      bootstrap,
      emailOtpAuthContext: resolvedEmailOtpAuthContext,
      relayerUrl: relayUrl,
      shamirPrimeB64u,
    });
    const thresholdEd25519PrfFirstB64u = String(
      workerResult.recovery?.thresholdEd25519PrfFirstB64u || '',
    ).trim();
    let ed25519Provisioning: EmailOtpThresholdEd25519ProvisioningResult | undefined;
    if (thresholdEd25519PrfFirstB64u) {
      const freshThresholdRouteAuth = this.thresholdRouteAuthFromEcdsaBootstrap(bootstrap);
      const ed25519ProvisioningArgs: ProvisionEmailOtpThresholdEd25519CapabilityArgs = {
        nearAccountId,
        relayUrl,
        rpId,
        prfFirstB64u: thresholdEd25519PrfFirstB64u,
        emailOtpAuthContext,
        ...(appSessionJwt ? { appSessionJwt } : {}),
        ...(freshThresholdRouteAuth || routeAuth
          ? { routeAuth: freshThresholdRouteAuth || routeAuth }
          : {}),
        ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
        ...(Array.isArray(args.ed25519ParticipantIds)
          ? { participantIds: args.ed25519ParticipantIds }
          : Array.isArray(args.participantIds)
            ? { participantIds: args.participantIds }
            : {}),
        ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
        ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
        walletSigningSessionId: this.walletSigningSessionIdFromEcdsaBootstrap(
          bootstrap,
          walletSigningSessionId,
        ),
        ecdsaThresholdSessionId: this.thresholdSessionIdFromEcdsaBootstrap(bootstrap),
      };
      const shouldAwaitEd25519Provisioning =
        args.ed25519ProvisioningMode === 'await' ||
        (!args.ed25519ProvisioningMode && resolvedEmailOtpAuthContext.retention === 'session');
      if (shouldAwaitEd25519Provisioning) {
        // Session-mode OTP unlock should not report completion until both signing
        // lanes are durable; otherwise a quick refresh can strand the wallet.
        ed25519Provisioning = await this.provisionEd25519Capability(ed25519ProvisioningArgs);
      } else if (args.ed25519ProvisioningMode !== 'skip') {
        this.scheduleEd25519CapabilityProvisioning(ed25519ProvisioningArgs);
      }
    }
    return {
      recovery: workerResult.recovery,
      bootstrap,
      warmCapability,
      ...(ed25519Provisioning ? { ed25519Provisioning } : {}),
    };
  }

  async enrollAndLoginWithEcdsaCapabilityInternal(
    args: EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpThresholdEcdsaEnrollmentResult> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const chain: ThresholdEcdsaActivationChain = args.chain || 'tempo';
    const emailOtpAuthPolicy: EmailOtpAuthPolicy =
      args.emailOtpAuthPolicy || this.deps.configs.signing.emailOtp.authPolicy;
    const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext = {
      policy: emailOtpAuthPolicy,
      retention: emailOtpAuthPolicy === 'per_operation' ? 'single_use' : 'session',
      reason: 'login',
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
    };
    const relayUrl = String(args.relayUrl || this.requireRelayUrl()).trim();
    const shamirPrimeB64u = String(args.shamirPrimeB64u || this.requireShamirPrimeB64u()).trim();
    const sessionKind = args.sessionKind || 'jwt';
    const walletSigningSessionId =
      String(args.walletSigningSessionId || '').trim() || generateWalletSigningSessionId();
    const routePlan =
      args.routePlan ||
      this.buildRoutePlan({
        freshRouteFamily: 'registration',
        routeAuth: args.routeAuth,
        appSessionJwt: args.appSessionJwt,
        sessionKind,
        walletSigningSessionId,
        curve: 'ecdsa',
        chain,
      });
    const routeAuth = this.routeAuthFromPlan(routePlan);
    const workerCtx = this.deps.getSignerWorkerContext();
    if (!workerCtx) {
      throw new Error('Email OTP enrollment login requires the dedicated emailOtp worker');
    }
    const rpId = this.requireRpId('Email OTP enrollment login');
    const appSessionJwt = this.appSessionJwtFromLane(routePlan.authLane);
    if (appSessionJwt) this.rememberAppSessionJwt({ nearAccountId, appSessionJwt });
    const authSubjectId = this.appSessionSubjectFromLane(routePlan.authLane);
    const remainingUses =
      typeof args.remainingUses === 'number'
        ? args.remainingUses
        : emailOtpAuthPolicy === 'per_operation'
          ? 1
          : undefined;
    const workerClientSecret32 = args.clientSecret32 ? Uint8Array.from(args.clientSecret32) : null;
    try {
      const workerResult = await workerCtx.requestWorkerOperation({
        kind: 'emailOtp',
        request: {
          type: 'enrollEmailOtpWalletAndBootstrapEcdsaSession',
          timeoutMs: 60_000,
          payload: {
            relayUrl,
            walletId: String(nearAccountId),
            userId: String(nearAccountId),
            ...(args.challengeId ? { challengeId: args.challengeId } : {}),
            otpCode: args.otpCode,
            shamirPrimeB64u,
            routePlan,
            otpChannel: EMAIL_OTP_CHANNEL,
            ...(workerClientSecret32
              ? { clientSecret32: workerClientSecret32.buffer.slice(0) }
              : {}),
            rpId,
            ...(args.ecdsaThresholdKeyId ? { ecdsaThresholdKeyId: args.ecdsaThresholdKeyId } : {}),
            ...(Array.isArray(args.participantIds) && args.participantIds.length > 0
              ? { participantIds: args.participantIds }
              : {}),
            sessionKind,
            ...(args.sessionId ? { sessionId: args.sessionId } : {}),
            walletSigningSessionId,
            ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
            ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
            ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
          },
          onEvent: args.onProgress,
        },
      });
      const resolvedEmailOtpAuthContext = {
        ...emailOtpAuthContext,
        ...(authSubjectId ? { authSubjectId } : {}),
      };
      const { bootstrap, warmCapability } =
        await this.deps.commitWorkerProvisionedThresholdEcdsaSessions({
          nearAccountId,
          primaryChain: chain,
          bootstrap: workerResult.bootstrap,
          source: 'email_otp',
          emailOtpAuthContext: resolvedEmailOtpAuthContext,
          ...(args.smartAccount ? { smartAccount: args.smartAccount } : {}),
        });
      await this.persistEmailOtpEcdsaSigningSessionSealForUnlock({
        nearAccountId,
        chain,
        bootstrap,
        emailOtpAuthContext: resolvedEmailOtpAuthContext,
        relayerUrl: relayUrl,
        shamirPrimeB64u,
      });
      const thresholdEd25519PrfFirstB64u = String(
        workerResult.enrollment?.thresholdEd25519PrfFirstB64u || '',
      ).trim();
      if (thresholdEd25519PrfFirstB64u) {
        const freshThresholdRouteAuth = this.thresholdRouteAuthFromEcdsaBootstrap(bootstrap);
        await this.provisionEd25519Capability({
          nearAccountId,
          relayUrl,
          rpId,
          prfFirstB64u: thresholdEd25519PrfFirstB64u,
          emailOtpAuthContext,
          ...(appSessionJwt ? { appSessionJwt } : {}),
          ...(freshThresholdRouteAuth || routeAuth
            ? { routeAuth: freshThresholdRouteAuth || routeAuth }
            : {}),
          ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
          ...(args.registrationAttemptId
            ? { registrationAttemptId: args.registrationAttemptId }
            : {}),
          ...(Array.isArray(args.participantIds) ? { participantIds: args.participantIds } : {}),
          ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
          ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
          walletSigningSessionId: this.walletSigningSessionIdFromEcdsaBootstrap(
            bootstrap,
            walletSigningSessionId,
          ),
          ecdsaThresholdSessionId: this.thresholdSessionIdFromEcdsaBootstrap(bootstrap),
        });
      }
      return {
        enrollment: workerResult.enrollment,
        bootstrap,
        warmCapability,
      };
    } finally {
      workerClientSecret32?.fill(0);
    }
  }

  private async persistEmailOtpEcdsaSigningSessionSealForUnlock(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    relayerUrl: string;
    shamirPrimeB64u: string;
  }): Promise<void> {
    if (this.deps.configs.signing.sessionPersistenceMode !== 'sealed_refresh_v1') return;
    if (args.emailOtpAuthContext.retention !== 'session') return;

    const workerCtx = this.deps.getSignerWorkerContext();
    if (!workerCtx) {
      throw new Error('Email OTP sealed refresh requires the dedicated emailOtp worker');
    }

    const keyRef = args.bootstrap.thresholdEcdsaKeyRef;
    const session = args.bootstrap.session;
    const thresholdSessionId = String(session?.sessionId || keyRef.thresholdSessionId || '').trim();
    const walletSigningSessionId = String(
      session?.walletSigningSessionId || keyRef.walletSigningSessionId || '',
    ).trim();
    const relayerUrl = String(args.relayerUrl || keyRef.relayerUrl || '').trim();
    const shamirPrimeB64u = String(
      args.shamirPrimeB64u || this.deps.configs.signing.sessionSeal?.shamirPrimeB64u || '',
    ).trim();
    if (!thresholdSessionId || !walletSigningSessionId || !relayerUrl || !shamirPrimeB64u) {
      throw new Error('Email OTP sealed refresh is missing threshold-session persistence metadata');
    }

    const thresholdSessionJwt = String(session?.jwt || keyRef.thresholdSessionJwt || '').trim();
    const keyVersion = String(this.deps.configs.signing.sessionSeal?.keyVersion || '').trim();
    const sessionKind = keyRef.thresholdSessionKind || (thresholdSessionJwt ? 'jwt' : 'cookie');
    const ecdsaThresholdKeyId = String(keyRef.ecdsaThresholdKeyId || '').trim();
    const relayerKeyId = String(keyRef.backendBinding?.relayerKeyId || '').trim();
    const participantIds = Array.isArray(keyRef.participantIds)
      ? keyRef.participantIds
          .map((participantId) => Math.floor(Number(participantId)))
          .filter((participantId) => Number.isFinite(participantId) && participantId > 0)
      : [];
    if (
      !ecdsaThresholdKeyId ||
      !relayerKeyId ||
      !participantIds.length ||
      (sessionKind === 'jwt' && !thresholdSessionJwt)
    ) {
      throw new Error('Email OTP sealed refresh is missing ECDSA restore metadata');
    }
    const sealed = await workerCtx
      .requestWorkerOperation({
        kind: 'emailOtp',
        request: {
          type: 'sealEmailOtpWarmSessionMaterial',
          timeoutMs: 30_000,
          payload: {
            sessionId: thresholdSessionId,
            transport: {
              relayerUrl,
              ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
              ...(keyVersion ? { keyVersion } : {}),
              shamirPrimeB64u,
            },
          },
        },
      })
      .catch((error) => {
        const message = error instanceof Error ? error.message : String(error || 'unknown error');
        throw new Error(`Email OTP sealed refresh seal failed: ${message}`);
      });

    if (!sealed?.ok) {
      const message = String(sealed?.message || sealed?.code || 'unknown error').trim();
      throw new Error(`Email OTP sealed refresh seal failed: ${message}`);
    }
    const sealedSecretB64u = String(sealed.sealedSecretB64u || '').trim();
    const expiresAtMs = Math.floor(Number(sealed.expiresAtMs) || Number(session?.expiresAtMs) || 0);
    const remainingUses = Math.floor(
      Number(sealed.remainingUses) || Number(session?.remainingUses) || 0,
    );
    if (!sealedSecretB64u || expiresAtMs <= 0 || remainingUses < 0) {
      throw new Error('Email OTP sealed refresh seal returned invalid persistence metadata');
    }

    await this.registerSigningSession({
      thresholdSessionId,
      sealedSecretB64u,
      curve: 'ecdsa',
      authMethod: 'email_otp',
      walletSigningSessionId,
      thresholdSessionIds: { ecdsa: thresholdSessionId },
      walletId: String(args.nearAccountId || '').trim(),
      userId: String(keyRef.userId || args.nearAccountId || '').trim(),
      signingRootId: String(keyRef.signingRootId || '').trim(),
      ...(String(keyRef.signingRootVersion || '').trim()
        ? { signingRootVersion: String(keyRef.signingRootVersion || '').trim() }
        : {}),
      relayerUrl,
      ...(String(sealed.keyVersion || keyVersion).trim()
        ? { keyVersion: String(sealed.keyVersion || keyVersion).trim() }
        : {}),
      shamirPrimeB64u,
      ecdsaRestore: {
        chain: args.chain,
        ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
        sessionKind,
        ecdsaThresholdKeyId,
        relayerKeyId,
        participantIds,
      },
      expiresAtMs,
      remainingUses,
      updatedAtMs: Date.now(),
    });
    const reader = this.deps.readExactSealedSession || readExactSealedSession;
    const persisted = await reader(thresholdSessionId, {
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chain: args.chain,
    }).catch((error) => {
      const message = error instanceof Error ? error.message : String(error || 'unknown error');
      throw new Error(`Email OTP sealed refresh read-back failed: ${message}`);
    });
    if (!persisted) {
      throw new Error('Email OTP sealed refresh record was not durably persisted');
    }
    if (
      persisted.authMethod !== 'email_otp' ||
      persisted.secretKind !== 'signing_session_secret32' ||
      persisted.thresholdSessionIds.ecdsa !== thresholdSessionId ||
      persisted.walletSigningSessionId !== walletSigningSessionId ||
      persisted.sealedSecretB64u !== sealedSecretB64u
    ) {
      throw new Error('Email OTP sealed refresh read-back record does not match unlock session');
    }
  }

  private async attachEd25519SessionToEmailOtpSigningSessionSealBestEffort(args: {
    ecdsaThresholdSessionId?: string;
    ed25519ThresholdSessionId: string;
  }): Promise<void> {
    if (this.deps.configs.signing.sessionPersistenceMode !== 'sealed_refresh_v1') return;
    const ecdsaThresholdSessionId = String(args.ecdsaThresholdSessionId || '').trim();
    const ed25519ThresholdSessionId = String(args.ed25519ThresholdSessionId || '').trim();
    if (!ecdsaThresholdSessionId || !ed25519ThresholdSessionId) return;
    const reader = this.deps.readExactSealedSession || readExactSealedSession;
    let existing: SigningSessionSealedStoreRecord | null = null;
    for (const chain of ['tempo', 'evm'] as const) {
      existing = await reader(ecdsaThresholdSessionId, {
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chain,
      }).catch(() => null);
      if (existing) break;
    }
    if (!existing || existing.authMethod !== 'email_otp') return;
    const ed25519Record =
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(ed25519ThresholdSessionId);
    if (
      !ed25519Record ||
      ed25519Record.source !== 'email_otp' ||
      ed25519Record.emailOtpAuthContext?.retention !== 'session' ||
      ed25519Record.walletSigningSessionId !== existing.walletSigningSessionId
    ) {
      return;
    }
    await this.registerSigningSession({
      thresholdSessionId: ecdsaThresholdSessionId,
      sealedSecretB64u: existing.sealedSecretB64u,
      curve: existing.curve || 'ecdsa',
      authMethod: existing.authMethod,
      walletSigningSessionId: existing.walletSigningSessionId,
      thresholdSessionIds: {
        ...existing.thresholdSessionIds,
        ed25519: ed25519ThresholdSessionId,
      },
      walletId: existing.walletId,
      userId: existing.userId,
      signingRootId: existing.signingRootId,
      signingRootVersion: existing.signingRootVersion,
      relayerUrl: existing.relayerUrl,
      keyVersion: existing.keyVersion,
      shamirPrimeB64u: existing.shamirPrimeB64u,
      ecdsaRestore: existing.ecdsaRestore,
      ed25519Restore: {
        rpId: ed25519Record.rpId,
        relayerKeyId: ed25519Record.relayerKeyId,
        participantIds: ed25519Record.participantIds,
        ...(ed25519Record.thresholdSessionJwt
          ? { thresholdSessionJwt: ed25519Record.thresholdSessionJwt }
          : {}),
        sessionKind: ed25519Record.thresholdSessionKind || 'jwt',
        ...(ed25519Record.runtimePolicyScope
          ? { runtimePolicyScope: ed25519Record.runtimePolicyScope }
          : {}),
        ...(ed25519Record.xClientBaseB64u
          ? { xClientBaseB64u: ed25519Record.xClientBaseB64u }
          : {}),
      },
      issuedAtMs: existing.issuedAtMs,
      expiresAtMs: existing.expiresAtMs,
      remainingUses: existing.remainingUses,
      updatedAtMs: Date.now(),
    });
  }

  private async restoreEcdsaSigningSessionMaterialFromSealedRecord(args: {
    sealedRecord: SigningSessionSealedStoreRecord;
    ecdsaRecord?: ThresholdEcdsaSessionRecord | null;
    ed25519Record?: ThresholdEd25519SessionRecord | null;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }): Promise<EmailOtpThresholdEcdsaRehydrateResult | null> {
    const sealedRecord = args.sealedRecord;
    const ecdsaRecord = args.ecdsaRecord || null;
    const ecdsaRestore = sealedRecord.ecdsaRestore;
    if (sealedRecord.authMethod !== 'email_otp') return null;
    if (sealedRecord.secretKind !== 'signing_session_secret32') return null;
    // Sealed refresh restore is lane-exact. Accepting an Ed25519 seal here could
    // pair the restored ECDSA lane with the wrong wallet session and later fail
    // as an unauthorized Email OTP bootstrap.
    if (sealedRecord.curve !== 'ecdsa') {
      throw new Error('Email OTP sealed refresh curve mismatch');
    }
    if (ecdsaRecord && ecdsaRecord.source !== 'email_otp') return null;
    const emailOtpAuthContext =
      ecdsaRecord?.emailOtpAuthContext ||
      ({
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      } satisfies ThresholdEcdsaEmailOtpAuthContext);
    if (emailOtpAuthContext.retention !== 'session') return null;

    const workerCtx = this.deps.getSignerWorkerContext();
    if (!workerCtx) {
      throw new Error('Email OTP sealed refresh requires the dedicated emailOtp worker');
    }

    const thresholdSessionId = String(
      ecdsaRecord?.thresholdSessionId || sealedRecord.thresholdSessionIds.ecdsa || '',
    ).trim();
    const walletSigningSessionId = String(
      ecdsaRecord?.walletSigningSessionId || sealedRecord.walletSigningSessionId || '',
    ).trim();
    const relayerUrl = String(ecdsaRecord?.relayerUrl || sealedRecord.relayerUrl || '').trim();
    const shamirPrimeB64u = String(
      ecdsaRecord?.signingSessionSealShamirPrimeB64u ||
        sealedRecord.shamirPrimeB64u ||
        this.deps.configs.signing.sessionSeal?.shamirPrimeB64u ||
        '',
    ).trim();
    const thresholdSessionJwt = String(
      ecdsaRecord?.thresholdSessionJwt || ecdsaRestore?.thresholdSessionJwt || '',
    ).trim();
    const keyVersion = String(
      sealedRecord.keyVersion ||
        ecdsaRecord?.signingSessionSealKeyVersion ||
        this.deps.configs.signing.sessionSeal?.keyVersion ||
        '',
    ).trim();
    if (!thresholdSessionId || !walletSigningSessionId || !relayerUrl || !shamirPrimeB64u) {
      throw new Error('Email OTP sealed refresh is missing threshold-session restore metadata');
    }
    if (sealedRecord.thresholdSessionIds.ecdsa !== thresholdSessionId) {
      throw new Error('Email OTP sealed refresh threshold-session id mismatch');
    }
    if (sealedRecord.walletSigningSessionId !== walletSigningSessionId) {
      throw new Error('Email OTP sealed refresh wallet signing-session id mismatch');
    }
    if (
      sealedRecord.signingRootId &&
      ecdsaRecord?.signingRootId &&
      sealedRecord.signingRootId !== ecdsaRecord.signingRootId
    ) {
      throw new Error('Email OTP sealed refresh signing-root id mismatch');
    }
    if (
      sealedRecord.signingRootVersion &&
      ecdsaRecord?.signingRootVersion &&
      sealedRecord.signingRootVersion !== ecdsaRecord.signingRootVersion
    ) {
      throw new Error('Email OTP sealed refresh signing-root version mismatch');
    }
    const restoreChain = ecdsaRecord?.chain || ecdsaRestore?.chain;
    const restoreSigningRootId = ecdsaRecord?.signingRootId || sealedRecord.signingRootId;
    const restoreEcdsaThresholdKeyId =
      ecdsaRecord?.ecdsaThresholdKeyId || ecdsaRestore?.ecdsaThresholdKeyId;
    const restoreRelayerKeyId = ecdsaRecord?.relayerKeyId || ecdsaRestore?.relayerKeyId;
    const restoreParticipantIds = ecdsaRecord?.participantIds || ecdsaRestore?.participantIds;
    const restoreSessionKind =
      ecdsaRecord?.thresholdSessionKind || ecdsaRestore?.sessionKind || 'jwt';
    const restoreRuntimePolicyScope =
      ecdsaRecord?.runtimePolicyScope ||
      normalizeThresholdRuntimePolicyScope(ecdsaRestore?.runtimePolicyScope);
    if (
      !restoreChain ||
      !restoreSigningRootId ||
      !restoreEcdsaThresholdKeyId ||
      !restoreRelayerKeyId ||
      !restoreParticipantIds?.length ||
      (restoreSessionKind === 'jwt' && !thresholdSessionJwt)
    ) {
      throw new Error('Email OTP sealed refresh is missing durable ECDSA restore metadata');
    }
    const ed25519Record =
      args.ed25519Record &&
      args.ed25519Record.source === 'email_otp' &&
      args.ed25519Record.emailOtpAuthContext?.retention === 'session' &&
      sealedRecord.thresholdSessionIds.ed25519 === args.ed25519Record.thresholdSessionId &&
      args.ed25519Record.walletSigningSessionId === walletSigningSessionId
        ? args.ed25519Record
        : null;

    const restored = await workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
        timeoutMs: 60_000,
        payload: {
          sealedSecretB64u: sealedRecord.sealedSecretB64u,
          remainingUses: sealedRecord.remainingUses,
          expiresAtMs: sealedRecord.expiresAtMs,
          transport: {
            relayerUrl,
            ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
            ...(keyVersion ? { keyVersion } : {}),
            shamirPrimeB64u,
          },
          restore: {
            sessionId: thresholdSessionId,
            walletId: sealedRecord.walletId || String(ecdsaRecord?.nearAccountId || ''),
            userId:
              sealedRecord.userId ||
              String(ecdsaRecord?.nearAccountId || sealedRecord.walletId || ''),
            rpId: this.requireRpId('Email OTP sealed refresh'),
            chain: restoreChain,
            walletSigningSessionId,
            signingRootId: restoreSigningRootId,
            ...(ecdsaRecord?.signingRootVersion || sealedRecord.signingRootVersion
              ? {
                  signingRootVersion:
                    ecdsaRecord?.signingRootVersion || sealedRecord.signingRootVersion,
                }
              : {}),
            ecdsaThresholdKeyId: restoreEcdsaThresholdKeyId,
            relayerKeyId: restoreRelayerKeyId,
            participantIds: restoreParticipantIds,
            sessionKind: restoreSessionKind,
            ...(restoreRuntimePolicyScope ? { runtimePolicyScope: restoreRuntimePolicyScope } : {}),
            // The same sealed signing-session secret can rehydrate the Ed25519
            // companion only when we carry its exact lane identity into the
            // worker. Without this, ECDSA reload works while NEAR Ed25519
            // falls through as missing after page refresh.
            ...(ed25519Record
              ? {
                  ed25519: {
                    sessionId: ed25519Record.thresholdSessionId,
                    relayerKeyId: ed25519Record.relayerKeyId,
                    participantIds: ed25519Record.participantIds,
                  },
                }
              : {}),
          },
        },
      },
    });
    if (!restored.ok) {
      throw new Error(restored.message || restored.code || 'Email OTP sealed refresh failed');
    }

    const { bootstrap, warmCapability } =
      await this.deps.commitWorkerProvisionedThresholdEcdsaSessions({
        nearAccountId:
          ecdsaRecord?.nearAccountId || sealedRecord.walletId || sealedRecord.userId || '',
        primaryChain: restoreChain,
        bootstrap: restored.bootstrap,
        source: 'email_otp',
        emailOtpAuthContext,
        ...(args.smartAccount ? { smartAccount: args.smartAccount } : {}),
      });
    if (ed25519Record) {
      upsertStoredThresholdEd25519SessionRecord({
        nearAccountId: ed25519Record.nearAccountId,
        rpId: ed25519Record.rpId,
        relayerUrl: ed25519Record.relayerUrl,
        relayerKeyId: ed25519Record.relayerKeyId,
        participantIds: ed25519Record.participantIds,
        ...(ed25519Record.runtimePolicyScope
          ? { runtimePolicyScope: ed25519Record.runtimePolicyScope }
          : {}),
        ...(ed25519Record.xClientBaseB64u
          ? { xClientBaseB64u: ed25519Record.xClientBaseB64u }
          : {}),
        thresholdSessionKind: ed25519Record.thresholdSessionKind,
        thresholdSessionId: ed25519Record.thresholdSessionId,
        ...(ed25519Record.walletSigningSessionId
          ? { walletSigningSessionId: ed25519Record.walletSigningSessionId }
          : {}),
        thresholdSessionJwt: ed25519Record.thresholdSessionJwt,
        expiresAtMs: restored.expiresAtMs,
        remainingUses: restored.remainingUses,
        ...(ed25519Record.emailOtpAuthContext
          ? { emailOtpAuthContext: ed25519Record.emailOtpAuthContext }
          : {}),
        updatedAtMs: Date.now(),
        source: ed25519Record.source,
      });
      if (restored.ed25519RestoreSeedB64u) {
        await this.deps.hydrateSigningSession({
          sessionId: ed25519Record.thresholdSessionId,
          prfFirstB64u: restored.ed25519RestoreSeedB64u,
          expiresAtMs: restored.expiresAtMs,
          remainingUses: restored.remainingUses,
          transport: {
            curve: 'ed25519',
            relayerUrl: ed25519Record.relayerUrl,
            ...(ed25519Record.thresholdSessionJwt
              ? { thresholdSessionJwt: ed25519Record.thresholdSessionJwt }
              : {}),
          },
        });
      }
    }
    return {
      bootstrap,
      warmCapability,
      remainingUses: restored.remainingUses,
      expiresAtMs: restored.expiresAtMs,
      ...(restored.ed25519RestoreSeedB64u
        ? { ed25519RestoreSeedB64u: restored.ed25519RestoreSeedB64u }
        : {}),
    };
  }

  async loginWithEd25519CapabilityForSigning(args: {
    nearAccountId: AccountId | string;
    challengeId: string;
    otpCode: string;
    record: ThresholdEd25519SessionRecord;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
    remainingUses?: number;
  }): Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const relayUrl = String(args.record.relayerUrl || this.requireRelayUrl()).trim();
    const providedAuthLane = args.authLane;
    const providedRouteAuth = providedAuthLane
      ? authLaneToRouteAuth(providedAuthLane)
      : args.routeAuth;
    const operation = WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION;
    const routePlan =
      providedAuthLane || providedRouteAuth
        ? this.buildSigningSessionRoutePlan({
            authLane: providedAuthLane,
            routeAuth: providedRouteAuth,
            thresholdSessionId: args.record.thresholdSessionId,
            walletSigningSessionId: args.record.walletSigningSessionId,
            curve: 'ed25519',
            operation,
          })
        : this.buildRoutePlan({
            freshRouteFamily: 'login',
            appSessionJwt: await this.resolveAppSessionJwt({
              nearAccountId,
              relayUrl,
            }),
            sessionKind: 'jwt',
            curve: 'ed25519',
            operation,
          });
    const defaultRemainingUses = Math.max(1, Math.floor(Number(args.remainingUses) || 1));
    let ecdsaChain: ThresholdEcdsaActivationChain | null = null;
    let ecdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef | null = null;
    for (const candidateChain of ['tempo', 'evm'] as const) {
      try {
        const candidate = await this.deps.getThresholdEcdsaKeyRefForLookup({
          nearAccountId,
          chain: candidateChain,
          source: 'email_otp',
        });
        ecdsaChain = candidateChain;
        ecdsaKeyRef = candidate;
        break;
      } catch {}
    }
    ecdsaChain = ecdsaChain || 'tempo';
    const ecdsaLogin = await this.loginWithEcdsaCapabilityInternal({
      nearAccountId,
      relayUrl,
      chain: ecdsaChain,
      emailOtpAuthPolicy: 'per_operation',
      emailOtpAuthReason: 'sign',
      challengeId: args.challengeId,
      otpCode: args.otpCode,
      operation,
      ...(ecdsaKeyRef?.ecdsaThresholdKeyId
        ? { ecdsaThresholdKeyId: ecdsaKeyRef.ecdsaThresholdKeyId }
        : {}),
      participantIds: ecdsaKeyRef?.participantIds || args.record.participantIds,
      ed25519ParticipantIds: args.record.participantIds,
      sessionKind: args.record.thresholdSessionKind,
      routePlan,
      ...(args.record.runtimePolicyScope
        ? { runtimePolicyScope: args.record.runtimePolicyScope }
        : {}),
      remainingUses: defaultRemainingUses,
      ed25519ProvisioningMode: 'await',
    });
    const provisioned = ecdsaLogin.ed25519Provisioning;
    if (!provisioned?.sessionId) {
      throw new Error('Email OTP Ed25519 signing did not provision an Ed25519 signing session');
    }
    const refreshedRecord = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
      provisioned.sessionId,
    );
    return {
      sessionId: provisioned.sessionId,
      ...(refreshedRecord ? { record: refreshedRecord } : {}),
    };
  }

  async provisionEd25519Capability(
    args: ProvisionEmailOtpThresholdEd25519CapabilityArgs,
  ): Promise<EmailOtpThresholdEd25519ProvisioningResult> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const relayerUrl = String(args.relayUrl || '').trim();
    const rpId = String(args.rpId || '').trim();
    const prfFirstB64u = String(args.prfFirstB64u || '').trim();
    if (!relayerUrl)
      throw new Error('Email OTP threshold-ed25519 provisioning requires relayerUrl');
    if (!rpId) throw new Error('Email OTP threshold-ed25519 provisioning requires rpId');
    if (!prfFirstB64u) {
      throw new Error('Email OTP threshold-ed25519 provisioning requires client seed material');
    }

    const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds) || [
      ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
    ];
    const keyVersion = 'threshold-ed25519-hss-v1';
    const registrationTransport = resolveRegistrationTransportFromConfig({
      configs: this.deps.configs,
      relayerUrl,
    });

    let runtimePolicyScope = args.runtimePolicyScope;
    let managedGrantForNextRegistrationRequest: ManagedRegistrationBootstrapGrant | null = null;
    if (!runtimePolicyScope && registrationTransport.mode === 'managed') {
      managedGrantForNextRegistrationRequest = await requestManagedRegistrationBootstrapGrant({
        relayerUrl: registrationTransport.relayerUrl,
        environmentId: registrationTransport.environmentId,
        publishableKey: registrationTransport.publishableKey,
        nearAccountId: String(nearAccountId),
        rpId,
      });
      runtimePolicyScope = managedGrantForNextRegistrationRequest.runtimePolicyScope;
    }
    const orgId = String(runtimePolicyScope?.orgId || '').trim();
    const signingRootId = runtimePolicyScope
      ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope).signingRootId
      : '';
    if (!orgId || !signingRootId) {
      throw new Error(
        'Email OTP threshold-ed25519 provisioning requires canonical signing-root scope',
      );
    }

    const workerCtx = this.deps.getSignerWorkerContext();
    if (!workerCtx) {
      throw new Error(
        'Email OTP threshold-ed25519 provisioning requires the dedicated emailOtp worker',
      );
    }
    const context = {
      signingRootId,
      nearAccountId: String(nearAccountId),
      keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
      keyVersion,
      participantIds,
      derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
    };
    const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
      sessionId: `email-otp-ed25519-registration:${String(nearAccountId)}`,
      ...context,
      prfFirstB64u,
      workerCtx,
    });

    const registrationHeaders = async (): Promise<Record<string, string>> => {
      if (registrationTransport.mode !== 'managed') return {};
      if (managedGrantForNextRegistrationRequest) {
        const grant = managedGrantForNextRegistrationRequest;
        managedGrantForNextRegistrationRequest = null;
        return { Authorization: `Bearer ${grant.token}` };
      }
      const grant = await requestManagedRegistrationBootstrapGrant({
        relayerUrl: registrationTransport.relayerUrl,
        environmentId: registrationTransport.environmentId,
        publishableKey: registrationTransport.publishableKey,
        nearAccountId: String(nearAccountId),
        rpId,
      });
      return { Authorization: `Bearer ${grant.token}` };
    };
    const registrationUrl = (path: string): string => {
      if (registrationTransport.mode === 'managed') {
        return joinUrlPath(registrationTransport.relayerUrl, path);
      }
      return (
        replaceUrlPathSuffix(registrationTransport.bootstrapUrl, '/registration/bootstrap', path) ||
        joinUrlPath(registrationTransport.bootstrapUrl || registrationTransport.relayerUrl, path)
      );
    };

    const prepared = await postJsonExpectOk({
      url: registrationUrl('/registration/threshold-ed25519/hss/prepare'),
      headers: await registrationHeaders(),
      operation: 'Email OTP threshold-ed25519 registration prepare',
      body: {
        new_account_id: String(nearAccountId),
        rp_id: rpId,
        context,
      },
    });
    const ceremonyHandle = String(prepared.ceremonyHandle || '').trim();
    const preparedSession = prepared.preparedSession as {
      contextBindingB64u?: string;
      evaluatorDriverStateB64u?: string;
    };
    const clientOtOfferMessageB64u = String(prepared.clientOtOfferMessageB64u || '').trim();
    if (!ceremonyHandle || !preparedSession || !clientOtOfferMessageB64u) {
      throw new Error('Email OTP threshold-ed25519 registration prepare returned incomplete data');
    }
    const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
      evaluatorDriverStateB64u: String(preparedSession.evaluatorDriverStateB64u || '').trim(),
      clientOtOfferMessageB64u,
      clientInputs,
      workerCtx,
    });
    await postJsonExpectOk({
      url: registrationUrl('/registration/threshold-ed25519/hss/respond'),
      headers: await registrationHeaders(),
      operation: 'Email OTP threshold-ed25519 registration respond',
      body: {
        new_account_id: String(nearAccountId),
        rp_id: rpId,
        ceremonyHandle,
        clientRequest,
      },
    });
    const finalized = await postJsonExpectOk({
      url: registrationUrl('/registration/threshold-ed25519/hss/finalize'),
      headers: await registrationHeaders(),
      operation: 'Email OTP threshold-ed25519 registration finalize',
      body: {
        new_account_id: String(nearAccountId),
        rp_id: rpId,
        ceremonyHandle,
        account_provisioning: { mode: 'create_if_missing' },
        ...(args.registrationAttemptId
          ? { google_email_otp_registration_attempt_id: args.registrationAttemptId }
          : {}),
      },
    });
    const publicKey = String(finalized.publicKey || '').trim();
    const relayerKeyId = String(finalized.relayerKeyId || '').trim();
    if (!publicKey || !relayerKeyId) {
      throw new Error('Email OTP threshold-ed25519 registration finalize returned incomplete data');
    }
    const accountProvisioning = finalized.accountProvisioning as
      | { mode?: unknown; status?: unknown }
      | undefined;
    if (
      String(accountProvisioning?.mode || '').trim() !== 'create_if_missing' ||
      !['created', 'already_ready'].includes(String(accountProvisioning?.status || '').trim())
    ) {
      throw new Error(
        'Email OTP threshold-ed25519 registration did not provision the finalized public key on-chain',
      );
    }

    await this.deps.persistEmailOtpThresholdEd25519LocalMetadata({
      nearAccountId,
      rpId,
      relayerUrl,
      publicKey,
      relayerKeyId,
      keyVersion,
      participantIds,
    });

    const { policy } = await buildEd25519SessionPolicy({
      nearAccountId,
      rpId,
      relayerKeyId,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      participantIds,
      walletSigningSessionId: args.walletSigningSessionId,
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
    });
    const minted = await postJsonExpectOk({
      url: joinUrlPath(relayerUrl, '/threshold-ed25519/session'),
      headers:
        args.routeAuth?.jwt || args.appSessionJwt
          ? { Authorization: `Bearer ${args.routeAuth?.jwt || args.appSessionJwt}` }
          : {},
      credentials: 'include',
      operation: 'Email OTP threshold-ed25519 session mint',
      body: {
        sessionKind: 'jwt',
        relayerKeyId,
        sessionPolicy: policy,
      },
    });
    const sessionId = String(minted.sessionId || policy.sessionId || '').trim();
    const jwt = String(minted.jwt || '').trim();
    const expiresAtMs = Number.isFinite(Number(minted.expiresAtMs))
      ? Math.floor(Number(minted.expiresAtMs))
      : minted.expiresAt
        ? Date.parse(String(minted.expiresAt))
        : Date.now() + policy.ttlMs;
    const remainingUses = Number.isFinite(Number(minted.remainingUses))
      ? Math.floor(Number(minted.remainingUses))
      : policy.remainingUses;
    const sessionScope =
      normalizeThresholdRuntimePolicyScope(minted.runtimePolicyScope) || runtimePolicyScope;
    if (!sessionId || !jwt || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
      throw new Error('Email OTP threshold-ed25519 session mint returned incomplete data');
    }

    await this.deps.persistWarmSessionEd25519Capability({
      nearAccountId,
      rpId,
      relayerUrl,
      relayerKeyId,
      ...(sessionScope ? { runtimePolicyScope: sessionScope } : {}),
      participantIds,
      sessionKind: 'jwt',
      sessionId,
      ...(policy.walletSigningSessionId
        ? { walletSigningSessionId: policy.walletSigningSessionId }
        : {}),
      expiresAtMs,
      remainingUses,
      jwt,
      emailOtpAuthContext: args.emailOtpAuthContext,
      source: 'email_otp',
    });
    await this.deps.hydrateSigningSession({
      sessionId,
      prfFirstB64u,
      expiresAtMs,
      remainingUses,
      transport: {
        curve: 'ed25519',
        relayerUrl,
        thresholdSessionJwt: jwt,
      },
    });
    await this.attachEd25519SessionToEmailOtpSigningSessionSealBestEffort({
      ecdsaThresholdSessionId: args.ecdsaThresholdSessionId,
      ed25519ThresholdSessionId: sessionId,
    });

    const completed = await runThresholdEd25519HssCeremonyWithSessionValue({
      relayerUrl,
      thresholdSessionJwt: jwt,
      relayerKeyId,
      operation: 'warm_session_reconstruction',
      context: {
        ...context,
        signingRootId: sessionScope
          ? signingRootScopeFromRuntimePolicyScope(sessionScope).signingRootId
          : signingRootId,
      },
      clientInputs,
      workerCtx,
    });
    if (!completed.success || !completed.clientOutput?.xClientBaseB64u) {
      throw new Error(
        completed.error || 'Email OTP threshold-ed25519 client-base reconstruction failed',
      );
    }
    await this.deps.persistWarmSessionEd25519Capability({
      nearAccountId,
      rpId,
      relayerUrl,
      relayerKeyId,
      ...(sessionScope ? { runtimePolicyScope: sessionScope } : {}),
      participantIds,
      sessionKind: 'jwt',
      sessionId,
      ...(policy.walletSigningSessionId
        ? { walletSigningSessionId: policy.walletSigningSessionId }
        : {}),
      expiresAtMs,
      remainingUses,
      jwt,
      xClientBaseB64u: completed.clientOutput.xClientBaseB64u,
      emailOtpAuthContext: args.emailOtpAuthContext,
      source: 'email_otp',
    });
    await this.attachEd25519SessionToEmailOtpSigningSessionSealBestEffort({
      ecdsaThresholdSessionId: args.ecdsaThresholdSessionId,
      ed25519ThresholdSessionId: sessionId,
    });

    return {
      publicKey,
      relayerKeyId,
      keyVersion,
      sessionId,
      expiresAtMs,
      remainingUses,
      participantIds,
      jwt,
      xClientBaseB64u: completed.clientOutput.xClientBaseB64u,
    };
  }

  private normalizeWarmupAccountId(nearAccountId: AccountId | string): string {
    return String(nearAccountId || '').trim();
  }

  private getEd25519WarmupMap(): Map<string, Promise<EmailOtpThresholdEd25519ProvisioningResult>> {
    if (!(this.ed25519WarmupByAccount instanceof Map)) {
      this.ed25519WarmupByAccount = new Map();
    }
    return this.ed25519WarmupByAccount;
  }

  private requireRelayUrl(): string {
    const relayUrl = String(this.deps.configs.network.relayer?.url || '').trim();
    if (!relayUrl) {
      throw new Error('Missing relayer url (configs.network.relayer.url)');
    }
    return relayUrl;
  }

  private requireShamirPrimeB64u(): string {
    const shamirPrimeB64u = String(
      this.deps.configs.signing.sessionSeal?.shamirPrimeB64u || '',
    ).trim();
    if (!shamirPrimeB64u) {
      throw new Error('Missing shamir prime for Email OTP runtime');
    }
    return shamirPrimeB64u;
  }

  private requireRpId(operation: string): string {
    const rpId =
      typeof (this.deps.touchIdPrompt as { getRpId?: unknown } | undefined)?.getRpId === 'function'
        ? String(this.deps.touchIdPrompt.getRpId() || '').trim()
        : '';
    if (!rpId) {
      throw new Error(`${operation} requires an RP ID for ECDSA bootstrap`);
    }
    return rpId;
  }
}

function joinUrlPath(baseUrl: string, path: string): string {
  const base = String(baseUrl || '')
    .trim()
    .replace(/\/+$/, '');
  const suffix = String(path || '').trim();
  if (!base) return '';
  return `${base}${suffix.startsWith('/') ? suffix : `/${suffix}`}`;
}

function replaceUrlPathSuffix(url: string, fromPath: string, toPath: string): string {
  const raw = String(url || '').trim();
  if (!raw) return '';
  try {
    const parsed = new URL(raw);
    if (parsed.pathname === fromPath || parsed.pathname === `${fromPath}/`) {
      parsed.pathname = toPath;
      return parsed.toString();
    }
  } catch {}
  if (raw.endsWith(fromPath)) return `${raw.slice(0, raw.length - fromPath.length)}${toPath}`;
  if (raw.endsWith(`${fromPath}/`)) {
    return `${raw.slice(0, raw.length - fromPath.length - 1)}${toPath}`;
  }
  return '';
}

function resolveRegistrationTransportFromConfig(args: {
  configs: SeamsConfigsReadonly;
  relayerUrl: string;
}): RegistrationTransport {
  const registration = args.configs.registration;
  if (registration.mode === 'managed') {
    return {
      mode: 'managed',
      relayerUrl: String(args.relayerUrl || args.configs.network.relayer.url || '').trim(),
      environmentId: String(registration.environmentId || '').trim(),
      publishableKey: String(registration.publishableKey || '').trim(),
    };
  }
  return {
    mode: 'backend_proxy',
    bootstrapUrl: String(registration.bootstrapUrl || '').trim(),
    relayerUrl: String(args.relayerUrl || args.configs.network.relayer.url || '').trim(),
  };
}

async function readJsonObjectResponse(response: Response): Promise<Record<string, unknown>> {
  const parsed = await response.json().catch(() => ({}));
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
    ? (parsed as Record<string, unknown>)
    : {};
}

async function postJsonExpectOk(args: {
  url: string;
  headers?: Record<string, string>;
  body: unknown;
  credentials?: RequestCredentials;
  operation: string;
}): Promise<Record<string, unknown>> {
  const response = await fetch(args.url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(args.headers || {}) },
    credentials: args.credentials || 'omit',
    body: JSON.stringify(args.body),
  });
  const data = await readJsonObjectResponse(response);
  if (!response.ok || data.ok === false) {
    throw new Error(
      String(data.message || data.code || `${args.operation} failed with HTTP ${response.status}`),
    );
  }
  return data;
}

async function requestManagedRegistrationBootstrapGrant(args: {
  relayerUrl: string;
  environmentId: string;
  publishableKey: string;
  nearAccountId: string;
  rpId: string;
}): Promise<ManagedRegistrationBootstrapGrant> {
  const data = await postJsonExpectOk({
    url: joinUrlPath(args.relayerUrl, '/v1/registration/bootstrap-grants'),
    headers: { Authorization: `Bearer ${args.publishableKey}` },
    operation: 'Managed registration bootstrap grant',
    body: {
      environmentId: args.environmentId,
      newAccountId: args.nearAccountId,
      rpId: args.rpId,
      flow: 'registration_v1',
    },
  });
  const grant =
    data.grant && typeof data.grant === 'object' && !Array.isArray(data.grant)
      ? (data.grant as Record<string, unknown>)
      : {};
  const token = String(grant.token || '').trim();
  const orgId = String(grant.orgId || '').trim();
  const projectId = String(grant.projectId || '').trim();
  const envId = String(grant.envId || '').trim();
  const signingRootVersion = String(grant.signingRootVersion || '').trim();
  if (!token || !orgId || !projectId || !envId || !signingRootVersion) {
    throw new Error('Managed registration grant response missing token or runtime scope');
  }
  return {
    token,
    runtimePolicyScope: {
      orgId,
      projectId,
      envId,
      signingRootVersion,
    },
  };
}

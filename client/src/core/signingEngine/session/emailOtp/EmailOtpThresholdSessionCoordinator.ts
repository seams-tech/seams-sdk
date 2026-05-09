import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import { chainFamilyFromNetwork } from '@/core/config/chains';
import type { EmailOtpAuthPolicy, SeamsConfigsReadonly } from '@/core/types/seams';
import type { TouchIdPrompt } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type {
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from '@/core/signingEngine/uiConfirm/types';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  listStoredThresholdEd25519SessionRecordsForAccount,
  listThresholdEcdsaRuntimeLanesForSubject,
  upsertStoredThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  thresholdEcdsaChainTargetFromConfig,
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmCapabilities/types';
import {
  createSigningSessionRestoreAttemptRegistry,
  createSigningSessionRestoreCache,
  restorePersistedSessionsForAccountCommand,
  restorePersistedSessionForSigningCommand,
} from '@/core/signingEngine/session/sealedRecovery/restoreCoordinator';
import type {
  RestorePersistedEcdsaSessionPurpose,
  RestorePersistedEd25519SessionPurpose,
  RestorePersistedSessionsForAccountInput,
  RestorePersistedSessionsForAccountResult,
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionForSigningResult,
  RestorePersistedSessionPurpose,
  RestoreSealedRecordForAccountResult,
  SigningSessionRestoreAttemptRegistry,
} from '@/core/signingEngine/session/sealedRecovery/types';
import {
  ecdsaAvailableLaneIdentityKey,
  ed25519AvailableLaneIdentityKey,
  readAvailableSigningLanes,
  warmStatusToAvailableSigningLanesRuntimeClaim,
  type ReadAvailableSigningLanesInput,
  type AvailableSigningLanes,
  type AvailableSigningLanesRuntimeClaim,
  type AvailableSigningLanesRuntimeEd25519Record,
  type AvailableSigningLanesRuntimeEcdsaRecord,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import { resolveEmailOtpEcdsaWorkerSessionId } from '@/core/signingEngine/session/availability/readiness';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import { generateWalletSigningSessionId } from '@/core/signingEngine/threshold/sessionPolicy';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpWorkerProgressEvent } from '@/core/signingEngine/workerManager/workerTypes';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  type WalletEmailOtpExportOperation,
  type WalletEmailOtpChannel,
  type WalletEmailOtpLoginOperation,
  type WalletEmailOtpTransactionSignOperation,
} from '@shared/utils/emailOtpDomain';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';
import type { EmailOtpEnrollmentResult } from '@/core/SeamsPasskey/emailOtp';
import {
  acquireSigningSessionRestoreLease,
  deleteExactSealedSession,
  listExactSealedSessionsForAccount,
  publishResolvedIdentity,
  releaseSigningSessionRestoreLease,
  readExactSealedSession,
  updateExactSealedSessionPolicy,
  writeExactSealedSession,
  type WriteExactSealedSessionBaseInput,
  type SigningSessionSealedRecordFilter,
  type SigningSessionRestoreLeaseHandle,
  type SigningSessionSealedStoreRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';

type EmailOtpEcdsaRouteChain = ThresholdEcdsaChainTarget['kind'];
type EmailOtpRouteChain = 'near' | EmailOtpEcdsaRouteChain;
import {
  authLaneToRouteAuth,
  type EmailOtpAuthLane,
  type EmailOtpRoutePlan,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpBootstrapRecovery } from '../../stepUpConfirmation/otpPrompt/bootstrapRecovery';
import {
  requestClaimEmailOtpWarmSessionMaterial,
  requestClearEmailOtpWarmSessionMaterial,
  requestConsumeEmailOtpWarmSessionUses,
  requestGetEmailOtpWarmSessionStatus,
  requestSealEmailOtpWarmSessionMaterial,
} from './workerRequests';
import {
  restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord,
  type EmailOtpThresholdEcdsaRehydrateResult,
} from './ecdsaRecovery';
import {
  buildEmailOtpEd25519RecordFromSealedRestoreMetadata,
  restoreEmailOtpEd25519SealedRecordForAccount,
  type EmailOtpEd25519RestorePurpose,
} from './ed25519Recovery';
import {
  attachEd25519SessionToEmailOtpSigningSessionSealBestEffort,
  selectEmailOtpEcdsaRecordForEd25519Signing,
} from './companionSessions';
import {
  claimEmailOtpWarmSessionMaterial,
  clearEmailOtpWarmSessionMaterial,
  consumeEmailOtpWarmSessionUses,
  readEmailOtpWarmSessionStatusOnly,
} from './status';
import {
  exportEcdsaKeyWithAuthorization,
  exportEcdsaKeyWithFreshEmailOtpLane,
  recoverEd25519ExportPrfFirst,
  requestExportChallenge,
  requestTransactionSigningChallenge,
  type EmailOtpEcdsaExportArtifact,
  type EmailOtpSigningSessionChallengeOperation,
} from './exportRecovery';
import {
  EmailOtpAppSessionJwtCache,
  appSessionJwtFromEmailOtpAuthLane,
  appSessionSubjectFromEmailOtpAuthLane,
} from './appSessionJwtCache';
import {
  provisionEmailOtpEd25519Capability,
  type EmailOtpThresholdEd25519ProvisioningResult,
  type ProvisionEmailOtpThresholdEd25519CapabilityArgs,
} from './provisioning';
import {
  buildEmailOtpSigningSessionRoutePlan,
  buildFreshEmailOtpRoutePlan,
  ecdsaBootstrapWithWalletSigningSessionId,
  routeAuthFromEmailOtpRoutePlan,
  thresholdSessionAuthFromEcdsaBootstrap,
  thresholdSessionIdFromEcdsaBootstrap,
  walletSigningSessionIdFromEcdsaBootstrap,
} from './routePlan';

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

export type LoginEmailOtpEcdsaCapabilityArgs = {
  nearAccountId: AccountId | string;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
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
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
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
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  refreshAppSessionJwt?: (args: { relayUrl: string }) => Promise<string>;
  commitEvmFamilyThresholdEcdsaSessions: (args: {
    nearAccountId: AccountId | string;
    primaryChain: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: 'email_otp';
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }>;
  listThresholdEcdsaSessionRecordsForSubject: (args: {
    subjectId: WalletSubjectId;
  }) => ThresholdEcdsaSessionRecord[];
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
      thresholdSessionAuthToken?: string;
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

function isEmailOtpEd25519RestorePurpose(
  purpose: RestorePersistedSessionPurpose,
): purpose is EmailOtpEd25519RestorePurpose {
  return purpose.authMethod === 'email_otp' && purpose.curve === 'ed25519';
}

export class EmailOtpThresholdSessionCoordinator {
  private readonly appSessionJwtCache: EmailOtpAppSessionJwtCache;
  private ed25519WarmupByAccount: Map<string, Promise<EmailOtpThresholdEd25519ProvisioningResult>> =
    new Map();
  private sealedRefreshDiagnosticLogAtMsByKey: Map<string, number> = new Map();
  private readonly ecdsaSigningRestoreAttempts: SigningSessionRestoreAttemptRegistry =
    createSigningSessionRestoreAttemptRegistry();
  private readonly ecdsaSigningRestoreCache = createSigningSessionRestoreCache();

  constructor(private readonly deps: EmailOtpThresholdSessionCoordinatorDeps) {
    this.appSessionJwtCache = new EmailOtpAppSessionJwtCache({
      refreshAppSessionJwt: deps.refreshAppSessionJwt,
    });
  }

  private clearEcdsaRestoreCaches(): void {
    this.ecdsaSigningRestoreCache.clear();
    this.ecdsaSigningRestoreAttempts.clear();
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
    explicitChainTarget?: ThresholdEcdsaChainTarget,
  ): SigningSessionSealedRecordFilter | null {
    const record = getStoredThresholdEcdsaSessionRecordByThresholdSessionId(sessionId);
    const chainTarget = record?.chainTarget;
    if (
      !chainTarget ||
      (explicitChainTarget && !thresholdEcdsaChainTargetsEqual(chainTarget, explicitChainTarget))
    ) {
      return null;
    }
    return { authMethod: 'email_otp', curve: 'ecdsa', chainTarget };
  }

  private async cleanupSigningSession(args: {
    sessionId: string;
    chainTarget?: ThresholdEcdsaChainTarget;
    reason: 'explicit_clear' | 'expired' | 'exhausted' | 'invalid_persisted_record';
  }): Promise<void> {
    const sessionId = String(args.sessionId || '').trim();
    if (!sessionId) return;
    const filter = this.resolveEmailOtpEcdsaSealedRecordFilter(sessionId, args.chainTarget);
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
    record: WriteExactSealedSessionBaseInput & { curve: 'ed25519' | 'ecdsa' },
  ): Promise<void> {
    const writer = this.deps.writeExactSealedSession || writeExactSealedSession;
    if (record.curve === 'ecdsa') {
      const subjectId = String(record.subjectId || '').trim();
      if (!subjectId) {
        throw new Error('[EmailOtpSession] ECDSA sealed write requires subjectId');
      }
      await writer({ ...record, curve: 'ecdsa', subjectId });
      this.clearEcdsaRestoreCaches();
      return;
    }
    await writer({ ...record, curve: 'ed25519' });
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
      const ecdsaRecord =
        this.deps.getThresholdEcdsaSessionRecordByThresholdSessionId?.(thresholdSessionId) ||
        getStoredThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId);
      if (!ecdsaRecord || ecdsaRecord.source !== 'email_otp') return null;
      const chainTarget = ecdsaRecord.chainTarget;
      if (!chainTarget) return null;
      return await reader(thresholdSessionId, {
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chainTarget,
      }).catch((error) => {
        console.warn('[EmailOtpSession] sealed refresh ECDSA read failed', {
          thresholdSessionId,
          chain: chainTarget.kind,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
        return null;
      });
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
    const sealedEcdsaRestore = sealedRecord.ecdsaRestore;
    if (!sealedEcdsaRestore?.chainTarget) return null;
    const lease = await acquireLease({
      thresholdSessionId,
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chainTarget: sealedEcdsaRestore.chainTarget,
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
      const chainTarget = sealedRecord.ecdsaRestore?.chainTarget;
      const walletId = String(sealedRecord.walletId || sealedRecord.userId || '').trim();
      if (walletId && chainTarget) {
        publishResolvedIdentity({
          walletId,
          authMethod: 'email_otp',
          curve: 'ecdsa',
          chainTarget,
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
          return listRecords({
            accountId: recordAccountId,
            filter:
              filter.curve === 'ecdsa'
                ? {
                    authMethod: filter.authMethod,
                    curve: 'ecdsa',
                    chainTarget: filter.chainTarget,
                  }
                : { authMethod: filter.authMethod, curve: 'ed25519' },
          });
        },
        restoreSealedRecordForAccount: (restoreArgs) =>
          this.restoreEmailOtpSealedRecordForAccount(restoreArgs),
        cache: this.ecdsaSigningRestoreCache,
        onListError: ({ accountId: failedAccountId, target, reason, error }) => {
          console.warn('[EmailOtpSession] signing-intent sealed ECDSA restore list failed', {
            accountId: failedAccountId,
            target,
            reason,
            error: error instanceof Error ? error.message : String(error || 'unknown error'),
          });
        },
      },
    );
  }

  private configuredEcdsaSnapshotChainTargets(): ThresholdEcdsaChainTarget[] {
    const targets: ThresholdEcdsaChainTarget[] = [];
    const seen = new Set<string>();
    for (const chain of this.deps.configs.network.chains) {
      const family = chainFamilyFromNetwork(chain.network);
      if (family !== 'evm' && family !== 'tempo') continue;
      const chainTarget = thresholdEcdsaChainTargetFromConfig(chain);
      const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
      if (seen.has(targetKey)) continue;
      seen.add(targetKey);
      targets.push(chainTarget);
    }
    if (!targets.length) {
      throw new Error('[EmailOtpSession] exact ECDSA snapshot requires configured ECDSA targets');
    }
    return targets;
  }

  private emailOtpEcdsaPublicationChainTargets(args: {
    primaryChain: ThresholdEcdsaChainTarget;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  }): ThresholdEcdsaChainTarget[] {
    const targets: ThresholdEcdsaChainTarget[] = [];
    const seen = new Set<string>();
    const pushTarget = (target: ThresholdEcdsaChainTarget): void => {
      const key = thresholdEcdsaChainTargetKey(target);
      if (seen.has(key)) return;
      seen.add(key);
      targets.push(target);
    };
    pushTarget(args.primaryChain);
    if (
      args.emailOtpAuthContext.retention === 'session' &&
      args.emailOtpAuthContext.reason === 'login'
    ) {
      for (const target of this.configuredEcdsaSnapshotChainTargets()) {
        pushTarget(target);
      }
    }
    return targets;
  }

  private async commitEmailOtpEcdsaPublicationBootstraps(args: {
    nearAccountId: AccountId;
    publicationChainTargets: ThresholdEcdsaChainTarget[];
    bootstraps: ThresholdEcdsaSessionBootstrapResult[];
    walletSigningSessionId: string;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    relayerUrl: string;
    shamirPrimeB64u: string;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }): Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }> {
    if (args.bootstraps.length !== args.publicationChainTargets.length) {
      throw new Error('Email OTP ECDSA publication returned an unexpected lane count');
    }
    let primaryResult:
      | {
          bootstrap: ThresholdEcdsaSessionBootstrapResult;
          warmCapability: WarmSessionEcdsaCapabilityState;
        }
      | null = null;
    for (const [index, rawBootstrap] of args.bootstraps.entries()) {
      const expectedTarget = args.publicationChainTargets[index];
      const actualTarget = rawBootstrap.thresholdEcdsaKeyRef.chainTarget;
      if (!thresholdEcdsaChainTargetsEqual(actualTarget, expectedTarget)) {
        throw new Error(
          `Email OTP ECDSA publication returned ${thresholdEcdsaChainTargetKey(actualTarget)} for ${thresholdEcdsaChainTargetKey(expectedTarget)}`,
        );
      }
      const workerBootstrap = ecdsaBootstrapWithWalletSigningSessionId({
        bootstrap: rawBootstrap,
        walletSigningSessionId: args.walletSigningSessionId,
      });
      const result = await this.deps.commitEvmFamilyThresholdEcdsaSessions({
        nearAccountId: args.nearAccountId,
        primaryChain: expectedTarget,
        bootstrap: workerBootstrap,
        source: 'email_otp',
        emailOtpAuthContext: args.emailOtpAuthContext,
        ...(index === 0 && args.smartAccount ? { smartAccount: args.smartAccount } : {}),
      });
      await this.persistEmailOtpEcdsaSigningSessionSealForUnlock({
        nearAccountId: args.nearAccountId,
        primaryChain: expectedTarget,
        bootstrap: result.bootstrap,
        emailOtpAuthContext: args.emailOtpAuthContext,
        relayerUrl: args.relayerUrl,
        shamirPrimeB64u: args.shamirPrimeB64u,
      });
      if (index === 0) primaryResult = result;
    }
    if (!primaryResult) {
      throw new Error('Email OTP ECDSA publication did not commit a primary lane');
    }
    return primaryResult;
  }

  async readPersistedSessionSnapshot(
    args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
  ): Promise<AvailableSigningLanes> {
    const accountId = String(toAccountId(args.walletId) || '').trim();
    const listRecords =
      this.deps.configs.signing.sessionPersistenceMode === 'sealed_refresh_v1'
        ? this.deps.listExactSealedSessionsForAccount || listExactSealedSessionsForAccount
        : async () => [];

    return await readAvailableSigningLanes(
      {
        ...args,
        walletId: accountId,
        subjectId: args.subjectId,
        ecdsaChainTargets: this.configuredEcdsaSnapshotChainTargets(),
      },
      {
        listSealedRecordsForAccount: async ({ accountId: recordAccountId, filter }) => {
          const listByAuthMethod = async (authMethod: 'email_otp' | 'passkey') => {
            if (filter.curve === 'ecdsa') {
              return await listRecords({
                accountId: recordAccountId,
                filter: {
                  authMethod,
                  curve: 'ecdsa',
                  chainTarget: filter.chainTarget,
                },
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
        listRuntimeEcdsaLanesForSubject: async ({ subjectId }) => {
          const runtimeRecords: AvailableSigningLanesRuntimeEcdsaRecord[] = [];
          const seen = new Set<string>();
          for (const runtimeLane of listThresholdEcdsaRuntimeLanesForSubject(
            { recordsByLane: new Map() },
            { subjectId },
          )) {
            if (runtimeLane.authMethod !== 'email_otp') continue;
            const record: AvailableSigningLanesRuntimeEcdsaRecord = {
              subjectId: runtimeLane.subjectId,
              authMethod: 'email_otp',
              curve: 'ecdsa',
              chainTarget: runtimeLane.chainTarget,
              ecdsaThresholdKeyId: runtimeLane.ecdsaThresholdKeyId,
              signingRootId: runtimeLane.signingRootId,
              signingRootVersion: runtimeLane.signingRootVersion,
              thresholdSessionId: runtimeLane.thresholdSessionId,
              walletSigningSessionId: runtimeLane.walletSigningSessionId,
            };
            const identityKey = ecdsaAvailableLaneIdentityKey(record);
            if (!identityKey || seen.has(identityKey)) continue;
            seen.add(identityKey);
            runtimeRecords.push(record);
          }
          return runtimeRecords;
        },
        listRuntimeEd25519RecordsForAccount: async ({ accountId: recordAccountId }) => {
          const records: AvailableSigningLanesRuntimeEd25519Record[] = [];
          const seen = new Set<string>();
          const pushRecord = (record: AvailableSigningLanesRuntimeEd25519Record) => {
            const identityKey = ed25519AvailableLaneIdentityKey(record);
            if (!identityKey || seen.has(identityKey)) return;
            seen.add(identityKey);
            records.push(record);
          };
          for (const runtimeRecord of listStoredThresholdEd25519SessionRecordsForAccount(
            recordAccountId,
          )) {
            const authMethod =
              runtimeRecord.source === SIGNER_AUTH_METHODS.emailOtp ? 'email_otp' : 'passkey';
            if (args.authMethod && args.authMethod !== authMethod) continue;
            pushRecord({
              authMethod,
              curve: 'ed25519',
              chain: 'near',
              thresholdSessionId: runtimeRecord.thresholdSessionId,
              walletSigningSessionId: runtimeRecord.walletSigningSessionId,
            });
          }
          return records;
        },
        readRuntimeClaimsForSessions: async (sessionIds) => {
          const claims = new Map<string, AvailableSigningLanesRuntimeClaim | null>();
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
                warmStatusToAvailableSigningLanesRuntimeClaim({ sessionId, status }),
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
    if (isEmailOtpEd25519RestorePurpose(args.purpose)) {
      return await this.restoreEd25519SealedRecordForAccount({
        ...args,
        purpose: args.purpose,
      });
    }
    if (args.purpose.curve !== 'ecdsa') return 'deferred';
    return await this.restoreEcdsaSealedRecordForAccount({
      ...args,
      purpose: args.purpose,
    });
  }

  private async restoreEcdsaSealedRecordForAccount(args: {
    accountId: string;
    record: SigningSessionSealedStoreRecord;
    purpose: RestorePersistedEcdsaSessionPurpose;
  }): Promise<RestoreSealedRecordForAccountResult> {
    const thresholdSessionId = String(args.purpose.thresholdSessionId || '').trim();
    if (!thresholdSessionId) return 'deferred';
    if (args.record.authMethod !== args.purpose.authMethod) return 'deferred';
    if (args.record.thresholdSessionIds.ecdsa !== thresholdSessionId) return 'deferred';
    if (
      !args.record.ecdsaRestore?.chainTarget ||
      !thresholdEcdsaChainTargetsEqual(args.record.ecdsaRestore.chainTarget, args.purpose.chainTarget)
    ) {
      return 'deferred';
    }
    if (args.record.walletSigningSessionId !== args.purpose.walletSigningSessionId) {
      return 'deferred';
    }
    const restoreKey = [
      args.accountId,
      args.purpose.authMethod,
      args.purpose.curve,
      thresholdEcdsaChainTargetKey(args.purpose.chainTarget),
      args.purpose.walletSigningSessionId,
      thresholdSessionId,
    ].join(':');
    if (this.ecdsaSigningRestoreAttempts.hasCompleted(restoreKey)) return 'ready';
    const existing =
      this.deps.getThresholdEcdsaSessionRecordByThresholdSessionId?.(thresholdSessionId) ||
      getStoredThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId);
    if (existing?.source === 'email_otp') {
      const workerStatus = await this.readWarmSessionStatusFromWorker(thresholdSessionId).catch(
        () => null,
      );
      if (workerStatus?.ok) {
        this.ecdsaSigningRestoreAttempts.rememberCompleted(restoreKey);
        return 'ready';
      }
    }
    const inFlight = this.ecdsaSigningRestoreAttempts.getInFlight(restoreKey);
    if (inFlight) {
      await inFlight;
      return this.ecdsaSigningRestoreAttempts.hasCompleted(restoreKey) ? 'ready' : 'deferred';
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
        this.ecdsaSigningRestoreAttempts.rememberCompleted(restoreKey);
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
        this.ecdsaSigningRestoreAttempts.clearInFlight(restoreKey);
      });
    this.ecdsaSigningRestoreAttempts.setInFlight(restoreKey, task);
    await task;
    return restoreResult;
  }

  private buildEd25519RecordFromSealedRestoreMetadata(args: {
    accountId: string;
    record: SigningSessionSealedStoreRecord;
    purpose: EmailOtpEd25519RestorePurpose;
  }): ThresholdEd25519SessionRecord | null {
    return buildEmailOtpEd25519RecordFromSealedRestoreMetadata(args);
  }

  private async restoreEd25519SealedRecordForAccount(args: {
    accountId: string;
    record: SigningSessionSealedStoreRecord;
    purpose: EmailOtpEd25519RestorePurpose;
  }): Promise<RestoreSealedRecordForAccountResult> {
    return await restoreEmailOtpEd25519SealedRecordForAccount({
      ...args,
      getThresholdEcdsaSessionRecordByThresholdSessionId:
        this.deps.getThresholdEcdsaSessionRecordByThresholdSessionId,
      readWarmSessionStatusFromWorker: (sessionId) =>
        this.readWarmSessionStatusFromWorker(sessionId),
      recordSessionMaterialRestored: (sessionId, status) =>
        this.recordSessionMaterialRestored(sessionId, status),
      restoreEcdsaSigningSessionMaterialFromSealedRecord: (restoreArgs) =>
        this.restoreEcdsaSigningSessionMaterialFromSealedRecord(restoreArgs),
    });
  }

  private async readWarmSessionStatusFromWorker(
    sessionId: string,
  ): Promise<WarmSessionStatusResult> {
    return await requestGetEmailOtpWarmSessionStatus({
      worker: this.deps.signerWorkerManager,
      sessionId,
    });
  }

  async readWarmSessionStatusOnly(sessionId: string): Promise<WarmSessionStatusResult> {
    return await readEmailOtpWarmSessionStatusOnly({
      sessionId,
      readWarmSessionStatusFromWorker: (normalizedSessionId) =>
        this.readWarmSessionStatusFromWorker(normalizedSessionId),
    });
  }

  private async claimWarmSessionMaterialFromWorker(args: {
    sessionId: string;
    uses?: number;
    consume?: boolean;
  }): Promise<WarmSessionClaimResult> {
    return await requestClaimEmailOtpWarmSessionMaterial({
      worker: this.deps.signerWorkerManager,
      sessionId: args.sessionId,
      ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
      ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
    });
  }

  private async consumeWarmSessionUsesFromWorker(args: {
    sessionId: string;
    uses?: number;
  }): Promise<WarmSessionStatusResult> {
    return await requestConsumeEmailOtpWarmSessionUses({
      worker: this.deps.signerWorkerManager,
      sessionId: args.sessionId,
      ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
    });
  }

  async claimWarmSessionMaterial(args: {
    sessionId: string;
    uses?: number;
    consume?: boolean;
    curve?: 'ed25519' | 'ecdsa';
    chain?: 'near';
    chainTarget?: ThresholdEcdsaChainTarget;
  }): Promise<WarmSessionClaimResult> {
    return await claimEmailOtpWarmSessionMaterial({
      sessionId: args.sessionId,
      ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
      ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
      claimWarmSessionMaterialFromWorker: (claimArgs) =>
        this.claimWarmSessionMaterialFromWorker(claimArgs),
      shouldAttemptEcdsaSealedRestoreForSessionId: (sessionId) =>
        this.shouldAttemptEcdsaSealedRestoreForSessionId(sessionId),
      tryRestoreEcdsaWarmSessionStatusFromSealedRecord: (sessionId) =>
        this.tryRestoreEcdsaWarmSessionStatusFromSealedRecord(sessionId),
      recordSessionMaterialClaimed: (sessionId, result) =>
        this.recordSessionMaterialClaimed(sessionId, result),
      recordSessionMaterialRestored: (sessionId, result) =>
        this.recordSessionMaterialRestored(sessionId, result),
    });
  }

  async consumeWarmSessionUses(args: {
    sessionId: string;
    uses?: number;
    curve?: 'ed25519' | 'ecdsa';
    chain?: 'near';
    chainTarget?: ThresholdEcdsaChainTarget;
  }): Promise<WarmSessionStatusResult> {
    return await consumeEmailOtpWarmSessionUses({
      sessionId: args.sessionId,
      ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
      consumeWarmSessionUsesFromWorker: (consumeArgs) =>
        this.consumeWarmSessionUsesFromWorker(consumeArgs),
      shouldAttemptEcdsaSealedRestoreForSessionId: (sessionId) =>
        this.shouldAttemptEcdsaSealedRestoreForSessionId(sessionId),
      tryRestoreEcdsaWarmSessionStatusFromSealedRecord: (sessionId) =>
        this.tryRestoreEcdsaWarmSessionStatusFromSealedRecord(sessionId),
      recordSessionUseConsumed: (sessionId, result) =>
        this.recordSessionUseConsumed(sessionId, result),
      recordSessionMaterialRestored: (sessionId, result) =>
        this.recordSessionMaterialRestored(sessionId, result),
    });
  }

  async clearWarmSessionMaterial(sessionId: string): Promise<void> {
    await clearEmailOtpWarmSessionMaterial({
      sessionId,
      clearWarmSessionMaterialFromWorker: async (normalizedSessionId) => {
        await requestClearEmailOtpWarmSessionMaterial({
          worker: this.deps.signerWorkerManager,
          sessionId: normalizedSessionId,
        });
      },
      cleanupSigningSession: (cleanupArgs) => this.cleanupSigningSession(cleanupArgs),
    });
  }

  rememberAppSessionJwt(args: { nearAccountId: AccountId | string; appSessionJwt?: string }): void {
    this.appSessionJwtCache.remember(args);
  }

  async resolveAppSessionJwt(args: {
    nearAccountId: AccountId | string;
    relayUrl: string;
  }): Promise<string> {
    return await this.appSessionJwtCache.resolve(args);
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

  async requestTransactionSigningChallenge(args: {
    nearAccountId: AccountId | string;
    chain: EmailOtpRouteChain;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  }): Promise<{ challengeId: string; emailHint?: string }> {
    return await requestTransactionSigningChallenge(
      {
        getSignerWorkerContext: this.deps.getSignerWorkerContext,
        requireRelayUrl: () => this.requireRelayUrl(),
        requireShamirPrimeB64u: () => this.requireShamirPrimeB64u(),
        resolveAppSessionJwt: (request) => this.resolveAppSessionJwt(request),
        buildRoutePlan: buildFreshEmailOtpRoutePlan,
        buildSigningSessionRoutePlan: buildEmailOtpSigningSessionRoutePlan,
        appSessionJwtFromLane: appSessionJwtFromEmailOtpAuthLane,
      },
      args,
    );
  }

  async requestExportChallenge(args: {
    nearAccountId: AccountId | string;
    chain: EmailOtpRouteChain;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  }): Promise<{ challengeId: string; emailHint?: string }> {
    return await requestExportChallenge(
      {
        getSignerWorkerContext: this.deps.getSignerWorkerContext,
        requireRelayUrl: () => this.requireRelayUrl(),
        requireShamirPrimeB64u: () => this.requireShamirPrimeB64u(),
        resolveAppSessionJwt: (request) => this.resolveAppSessionJwt(request),
        buildRoutePlan: buildFreshEmailOtpRoutePlan,
        buildSigningSessionRoutePlan: buildEmailOtpSigningSessionRoutePlan,
        appSessionJwtFromLane: appSessionJwtFromEmailOtpAuthLane,
      },
      args,
    );
  }

  async recoverEd25519ExportPrfFirst(args: {
    nearAccountId: AccountId | string;
    challengeId: string;
    otpCode: string;
    record: ThresholdEd25519SessionRecord;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  }): Promise<{ prfFirstB64u: string }> {
    return await recoverEd25519ExportPrfFirst(
      {
        getSignerWorkerContext: this.deps.getSignerWorkerContext,
        requireRelayUrl: () => this.requireRelayUrl(),
        requireShamirPrimeB64u: () => this.requireShamirPrimeB64u(),
        buildSigningSessionRoutePlan: buildEmailOtpSigningSessionRoutePlan,
      },
      args,
    );
  }

  async exportEcdsaKeyWithAuthorization(args: {
    nearAccountId: AccountId | string;
    challengeId: string;
    otpCode: string;
    record: ThresholdEcdsaSessionRecord;
    rpId: string;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  }): Promise<EmailOtpEcdsaExportArtifact> {
    return await exportEcdsaKeyWithAuthorization(
      {
        getSignerWorkerContext: this.deps.getSignerWorkerContext,
        requireRelayUrl: () => this.requireRelayUrl(),
        requireShamirPrimeB64u: () => this.requireShamirPrimeB64u(),
        buildSigningSessionRoutePlan: buildEmailOtpSigningSessionRoutePlan,
      },
      args,
    );
  }

  async exportEcdsaKeyWithFreshEmailOtpLane(args: {
    nearAccountId: AccountId | string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    ecdsaThresholdKeyId: string;
    participantIds: number[];
    authSubjectId?: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  }): Promise<EmailOtpEcdsaExportArtifact> {
    return await exportEcdsaKeyWithFreshEmailOtpLane(
      {
        requireRelayUrl: () => this.requireRelayUrl(),
        resolveAppSessionJwt: (request) => this.resolveAppSessionJwt(request),
        buildRoutePlan: buildFreshEmailOtpRoutePlan,
      },
      {
        ...args,
        loginWithEcdsaCapabilityInternal: (request) => this.loginWithEcdsaCapabilityInternal(request),
      },
    );
  }

  async loginWithEcdsaCapabilityForSigning(args: {
    nearAccountId: AccountId | string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
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
      const routePlan = buildFreshEmailOtpRoutePlan({
        freshRouteFamily: 'login',
        appSessionJwt,
        sessionKind: 'jwt',
        curve: 'ecdsa',
        chainTarget: args.chainTarget,
        operation,
      });
      const result = await this.loginWithEcdsaCapabilityInternal({
        nearAccountId: args.nearAccountId,
        subjectId: args.subjectId,
        relayUrl,
        chainTarget: args.chainTarget,
        emailOtpAuthPolicy,
        emailOtpAuthReason: 'sign',
        challengeId: args.challengeId,
        otpCode: args.otpCode,
        operation,
        routePlan,
        remainingUses,
      });
      return result.bootstrap.thresholdEcdsaKeyRef;
    }
    const explicitAuthLane = args.authLane;
    const explicitRouteAuth = explicitAuthLane
      ? authLaneToRouteAuth(explicitAuthLane)
      : args.routeAuth;
    const routePlan = buildEmailOtpSigningSessionRoutePlan({
      authLane: explicitAuthLane,
      routeAuth: explicitRouteAuth,
      thresholdSessionId: record.thresholdSessionId,
      walletSigningSessionId: record.walletSigningSessionId,
      curve: 'ecdsa',
      chainTarget: record.chainTarget,
      operation,
    });
    const result = await this.loginWithEcdsaCapabilityInternal({
      nearAccountId: args.nearAccountId,
      subjectId: record.subjectId,
      chainTarget: record.chainTarget,
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
    return result.bootstrap.thresholdEcdsaKeyRef;
  }

  async loginWithEcdsaCapabilityInternal(
    args: LoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpThresholdEcdsaLoginResult> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const subjectId = args.subjectId;
    const chainTarget = args.chainTarget;
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
      buildFreshEmailOtpRoutePlan({
        freshRouteFamily: 'login',
        routeAuth: args.routeAuth,
        appSessionJwt: args.appSessionJwt,
        sessionKind,
        thresholdSessionId: args.sessionId,
        walletSigningSessionId,
        curve: 'ecdsa',
        chainTarget,
        operation: args.operation,
      });
    const routeAuth = routeAuthFromEmailOtpRoutePlan(routePlan);

    if (!workerCtx) {
      throw new Error('Email OTP login requires the dedicated emailOtp worker');
    }
    const appSessionJwt = appSessionJwtFromEmailOtpAuthLane(routePlan.authLane);
    if (appSessionJwt) this.rememberAppSessionJwt({ nearAccountId, appSessionJwt });
    const authSubjectId = appSessionSubjectFromEmailOtpAuthLane(routePlan.authLane);
    const publicationChainTargets = this.emailOtpEcdsaPublicationChainTargets({
      primaryChain: chainTarget,
      emailOtpAuthContext,
    });
    const workerResult = await workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'loginWithEmailOtpAndBootstrapEcdsaSession',
        timeoutMs: 60_000,
        payload: {
          relayUrl,
          walletId: String(nearAccountId),
          subjectId,
          userId: String(args.authSubjectId || nearAccountId),
          ...(args.challengeId ? { challengeId: args.challengeId } : {}),
          otpCode: args.otpCode,
          shamirPrimeB64u,
          routePlan,
          otpChannel: EMAIL_OTP_CHANNEL,
          rpId,
          chainTarget,
          publicationChainTargets,
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
    const { bootstrap, warmCapability } = await this.commitEmailOtpEcdsaPublicationBootstraps({
      nearAccountId,
      publicationChainTargets,
      bootstraps: workerResult.bootstraps,
      walletSigningSessionId,
      emailOtpAuthContext: resolvedEmailOtpAuthContext,
      relayerUrl: relayUrl,
      shamirPrimeB64u,
      ...(args.smartAccount ? { smartAccount: args.smartAccount } : {}),
    });
    const thresholdEd25519PrfFirstB64u = String(
      workerResult.recovery?.thresholdEd25519PrfFirstB64u || '',
    ).trim();
    let ed25519Provisioning: EmailOtpThresholdEd25519ProvisioningResult | undefined;
    if (thresholdEd25519PrfFirstB64u) {
      const freshThresholdSessionAuth = thresholdSessionAuthFromEcdsaBootstrap(bootstrap);
      const ed25519ProvisioningArgs: ProvisionEmailOtpThresholdEd25519CapabilityArgs = {
        nearAccountId,
        relayUrl,
        rpId,
        prfFirstB64u: thresholdEd25519PrfFirstB64u,
        emailOtpAuthContext,
        ...(appSessionJwt ? { appSessionJwt } : {}),
        ...(freshThresholdSessionAuth || routeAuth
          ? { routeAuth: freshThresholdSessionAuth || routeAuth }
          : {}),
        ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
        ...(Array.isArray(args.ed25519ParticipantIds)
          ? { participantIds: args.ed25519ParticipantIds }
          : Array.isArray(args.participantIds)
            ? { participantIds: args.participantIds }
            : {}),
        ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
        ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
        walletSigningSessionId: walletSigningSessionIdFromEcdsaBootstrap(
          bootstrap,
          walletSigningSessionId,
        ),
        ecdsaThresholdSessionId: thresholdSessionIdFromEcdsaBootstrap(bootstrap),
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
    const subjectId = args.subjectId;
    const chainTarget = args.chainTarget;
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
      buildFreshEmailOtpRoutePlan({
        freshRouteFamily: 'registration',
        routeAuth: args.routeAuth,
        appSessionJwt: args.appSessionJwt,
        sessionKind,
        walletSigningSessionId,
        curve: 'ecdsa',
        chainTarget,
      });
    const routeAuth = routeAuthFromEmailOtpRoutePlan(routePlan);
    const workerCtx = this.deps.getSignerWorkerContext();
    if (!workerCtx) {
      throw new Error('Email OTP enrollment login requires the dedicated emailOtp worker');
    }
    const rpId = this.requireRpId('Email OTP enrollment login');
    const appSessionJwt = appSessionJwtFromEmailOtpAuthLane(routePlan.authLane);
    if (appSessionJwt) this.rememberAppSessionJwt({ nearAccountId, appSessionJwt });
    const authSubjectId = appSessionSubjectFromEmailOtpAuthLane(routePlan.authLane);
    const remainingUses =
      typeof args.remainingUses === 'number'
        ? args.remainingUses
        : emailOtpAuthPolicy === 'per_operation'
          ? 1
          : undefined;
    const workerClientSecret32 = args.clientSecret32 ? Uint8Array.from(args.clientSecret32) : null;
    try {
      const publicationChainTargets = this.emailOtpEcdsaPublicationChainTargets({
        primaryChain: chainTarget,
        emailOtpAuthContext,
      });
      const workerResult = await workerCtx.requestWorkerOperation({
        kind: 'emailOtp',
        request: {
          type: 'enrollEmailOtpWalletAndBootstrapEcdsaSession',
          timeoutMs: 60_000,
          payload: {
            relayUrl,
            walletId: String(nearAccountId),
            subjectId,
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
            chainTarget,
            publicationChainTargets,
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
      const { bootstrap, warmCapability } = await this.commitEmailOtpEcdsaPublicationBootstraps({
        nearAccountId,
        publicationChainTargets,
        bootstraps: workerResult.bootstraps,
        walletSigningSessionId,
        emailOtpAuthContext: resolvedEmailOtpAuthContext,
        relayerUrl: relayUrl,
        shamirPrimeB64u,
        ...(args.smartAccount ? { smartAccount: args.smartAccount } : {}),
      });
      const thresholdEd25519PrfFirstB64u = String(
        workerResult.enrollment?.thresholdEd25519PrfFirstB64u || '',
      ).trim();
      if (thresholdEd25519PrfFirstB64u) {
        const freshThresholdSessionAuth = thresholdSessionAuthFromEcdsaBootstrap(bootstrap);
        await this.provisionEd25519Capability({
          nearAccountId,
          relayUrl,
          rpId,
          prfFirstB64u: thresholdEd25519PrfFirstB64u,
          emailOtpAuthContext,
          ...(appSessionJwt ? { appSessionJwt } : {}),
          ...(freshThresholdSessionAuth || routeAuth
            ? { routeAuth: freshThresholdSessionAuth || routeAuth }
            : {}),
          ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
          ...(args.registrationAttemptId
            ? { registrationAttemptId: args.registrationAttemptId }
            : {}),
          ...(Array.isArray(args.participantIds) ? { participantIds: args.participantIds } : {}),
          ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
          ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
          walletSigningSessionId: walletSigningSessionIdFromEcdsaBootstrap(
            bootstrap,
            walletSigningSessionId,
          ),
          ecdsaThresholdSessionId: thresholdSessionIdFromEcdsaBootstrap(bootstrap),
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
    primaryChain: ThresholdEcdsaChainTarget;
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

    const thresholdSessionAuthToken = String(session?.jwt || keyRef.thresholdSessionAuthToken || '').trim();
    const keyVersion = String(this.deps.configs.signing.sessionSeal?.keyVersion || '').trim();
    const sessionKind = keyRef.thresholdSessionKind || (thresholdSessionAuthToken ? 'jwt' : 'cookie');
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
      (sessionKind === 'jwt' && !thresholdSessionAuthToken)
    ) {
      throw new Error('Email OTP sealed refresh is missing ECDSA restore metadata');
    }
    const sealed = await requestSealEmailOtpWarmSessionMaterial({
      workerCtx,
      sessionId: thresholdSessionId,
      transport: {
        relayerUrl,
        ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
        ...(keyVersion ? { keyVersion } : {}),
        shamirPrimeB64u,
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

    const sealedRecordBase = {
      thresholdSessionId,
      sealedSecretB64u,
      curve: 'ecdsa' as const,
      authMethod: 'email_otp' as const,
      walletSigningSessionId,
      thresholdSessionIds: { ecdsa: thresholdSessionId },
      subjectId: String(keyRef.subjectId || '').trim(),
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
      expiresAtMs,
      remainingUses,
    };
    const actualChainTarget = keyRef.chainTarget as ThresholdEcdsaChainTarget | undefined;
    if (!actualChainTarget) {
      throw new Error('Email OTP sealed refresh requires exact ECDSA chain target');
    }
    if (!thresholdEcdsaChainTargetsEqual(actualChainTarget, args.primaryChain)) {
      throw new Error(
        `Email OTP sealed refresh chain target drifted from ${thresholdEcdsaChainTargetKey(args.primaryChain)} to ${thresholdEcdsaChainTargetKey(actualChainTarget)}`,
      );
    }
    const updatedAtMs = Date.now();
    await this.registerSigningSession({
      ...sealedRecordBase,
      ecdsaRestore: {
        chainTarget: actualChainTarget,
        ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
        sessionKind,
        ecdsaThresholdKeyId,
        relayerKeyId,
        participantIds,
      },
      updatedAtMs,
    });

    const reader = this.deps.readExactSealedSession || readExactSealedSession;
    const persisted = await reader(thresholdSessionId, {
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chainTarget: actualChainTarget,
    }).catch((error) => {
      const message = error instanceof Error ? error.message : String(error || 'unknown error');
      throw new Error(`Email OTP sealed refresh read-back failed: ${message}`);
    });
    if (!persisted) {
      throw new Error(
        `Email OTP sealed refresh ${thresholdEcdsaChainTargetKey(actualChainTarget)} record was not durably persisted`,
      );
    }
    if (
      persisted.authMethod !== 'email_otp' ||
      persisted.secretKind !== 'signing_session_secret32' ||
      persisted.thresholdSessionIds.ecdsa !== thresholdSessionId ||
      persisted.walletSigningSessionId !== walletSigningSessionId ||
      persisted.sealedSecretB64u !== sealedSecretB64u ||
      !persisted.ecdsaRestore?.chainTarget ||
      !thresholdEcdsaChainTargetsEqual(persisted.ecdsaRestore.chainTarget, actualChainTarget)
    ) {
      throw new Error(
        `Email OTP sealed refresh read-back record does not match ${thresholdEcdsaChainTargetKey(actualChainTarget)} unlock session`,
      );
    }
  }

  private async restoreEcdsaSigningSessionMaterialFromSealedRecord(args: {
    sealedRecord: SigningSessionSealedStoreRecord;
    ecdsaRecord?: ThresholdEcdsaSessionRecord | null;
    ed25519Record?: ThresholdEd25519SessionRecord | null;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }): Promise<EmailOtpThresholdEcdsaRehydrateResult | null> {
    return await restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord({
      configs: this.deps.configs,
      getSignerWorkerContext: this.deps.getSignerWorkerContext,
      commitEvmFamilyThresholdEcdsaSessions: this.deps.commitEvmFamilyThresholdEcdsaSessions,
      hydrateSigningSession: this.deps.hydrateSigningSession,
      requireRpId: (operation) => this.requireRpId(operation),
      ...args,
    });
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
        ? buildEmailOtpSigningSessionRoutePlan({
            authLane: providedAuthLane,
            routeAuth: providedRouteAuth,
            thresholdSessionId: args.record.thresholdSessionId,
            walletSigningSessionId: args.record.walletSigningSessionId,
            curve: 'ed25519',
            operation,
          })
        : buildFreshEmailOtpRoutePlan({
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
    const ecdsaRecord = selectEmailOtpEcdsaRecordForEd25519Signing({
      nearAccountId,
      walletSigningSessionId: args.record.walletSigningSessionId,
      listThresholdEcdsaSessionRecordsForSubject: (subjectArgs) =>
        this.deps.listThresholdEcdsaSessionRecordsForSubject(subjectArgs),
    });
    if (!ecdsaRecord) {
      throw new Error(
        'Email OTP Ed25519 signing requires an exact concrete ECDSA bootstrap lane',
      );
    }
    const ecdsaLogin = await this.loginWithEcdsaCapabilityInternal({
      nearAccountId,
      subjectId: ecdsaRecord.subjectId,
      relayUrl,
      chainTarget: ecdsaRecord.chainTarget,
      emailOtpAuthPolicy: 'per_operation',
      emailOtpAuthReason: 'sign',
      challengeId: args.challengeId,
      otpCode: args.otpCode,
      operation,
      ...(ecdsaRecord?.ecdsaThresholdKeyId
        ? { ecdsaThresholdKeyId: ecdsaRecord.ecdsaThresholdKeyId }
        : {}),
      participantIds: ecdsaRecord?.participantIds || args.record.participantIds,
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
    return await provisionEmailOtpEd25519Capability({
      input: args,
      configs: this.deps.configs,
      getSignerWorkerContext: this.deps.getSignerWorkerContext,
      persistEmailOtpThresholdEd25519LocalMetadata:
        this.deps.persistEmailOtpThresholdEd25519LocalMetadata,
      persistWarmSessionEd25519Capability: this.deps.persistWarmSessionEd25519Capability,
      hydrateSigningSession: this.deps.hydrateSigningSession,
      sessionPersistenceMode: this.deps.configs.signing.sessionPersistenceMode,
      readExactSealedSession: this.deps.readExactSealedSession || readExactSealedSession,
      getThresholdEcdsaSessionRecordByThresholdSessionId:
        this.deps.getThresholdEcdsaSessionRecordByThresholdSessionId,
      registerSigningSession: (record) => this.registerSigningSession(record),
    });
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

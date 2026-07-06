import type { AccountId } from '@/core/types/accountIds';
import type {
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type {
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletResult,
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionForSigningResult,
} from '@/core/signingEngine/session/sealedRecovery/sealedRecovery.types';
import {
  type ReadAvailableSigningLanesInput,
  type AvailableSigningLanes,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  createEmailOtpEcdsaSigningSessionMaterialRestorer,
} from './ecdsaRecovery';
import { EmailOtpAppSessionJwtCache } from './appSessionJwtCache';
import {
  type EmailOtpThresholdEd25519ProvisioningResult,
  type ReconstructEmailOtpEd25519SessionArgs,
} from './provisioning';
import type { EmailOtpWalletSessionCoordinatorDeps } from './ports';
import { readEmailOtpPersistedSessionSnapshot } from './persistedSnapshot';
import {
  type EmailOtpThresholdEcdsaLoginResult,
  type LoginEmailOtpEcdsaCapabilityArgs,
  type LoginEmailOtpEcdsaCapabilityForSigningArgs,
} from './ecdsaLogin';
import {
  type EmailOtpThresholdEcdsaEnrollmentResult,
  type EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaEnrollment';
import { EmailOtpEcdsaLifecycleRuntime } from './ecdsaLifecycleRuntime';
import {
  EmailOtpExportRecoveryRuntime,
  type EmailOtpEd25519ExportArtifact,
  type EmailOtpEcdsaExportArtifact,
  type ExportEd25519SeedWithAuthorizationArgs,
  type ExportEcdsaKeyWithAuthorizationArgs,
  type ExportEcdsaKeyWithFreshEmailOtpLaneArgs,
  type RequestEmailOtpChallengeArgs,
} from './exportRecoveryRuntime';
import {
  EmailOtpEd25519Warmup,
  type Ed25519SigningLane,
  type EmailOtpThresholdEd25519LoginResult,
  type LoginEmailOtpEd25519CapabilityArgs,
} from './ed25519Warmup';
import { EmailOtpRuntimeConfig } from './runtimeConfig';
import { EmailOtpSealedSessionRegistry } from './sealedSessionRegistry';
import { EmailOtpSealedRefreshPolicy } from './sealedRefreshPolicy';
import { EmailOtpSealedRestoreOrchestrator } from './sealedRestoreOrchestrator';
import {
  createEmailOtpWarmSessionWorkerClient,
  EmailOtpWarmSessionRuntime,
} from './warmSessionRuntime';
import {
  createEmailOtpEd25519RecoveryCodeWarmSessionHydration,
} from './recoveryCodeWarmSessionHydration';

export type {
  EmailOtpThresholdEcdsaLoginResult,
  LoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaLogin';
export type {
  EmailOtpThresholdEcdsaEnrollmentResult,
  EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaEnrollment';
export type {
  EmailOtpThresholdEd25519LoginResult,
  LoginEmailOtpEd25519CapabilityArgs,
} from './ed25519Warmup';
export type {
  EmailOtpCoordinatorRuntimePorts,
  EmailOtpEcdsaSessionPorts,
  EmailOtpEd25519SessionPorts,
  EmailOtpEd25519PersistencePorts,
  EmailOtpSealedSessionStorePorts,
  EmailOtpWalletSessionCoordinatorDeps,
} from './ports';

export class EmailOtpWalletSessionRuntime {
  private readonly appSessionJwtCache: EmailOtpAppSessionJwtCache;
  private sealedRefreshDiagnosticLogAtMsByKey: Map<string, number> = new Map();
  private readonly sealedRefreshPolicy: EmailOtpSealedRefreshPolicy;
  private readonly sealedRestoreOrchestrator: EmailOtpSealedRestoreOrchestrator;
  private readonly ed25519Warmup: EmailOtpEd25519Warmup;
  private readonly runtimeConfig: EmailOtpRuntimeConfig;
  private readonly sealedSessionRegistry: EmailOtpSealedSessionRegistry;
  private readonly warmSessionRuntime: EmailOtpWarmSessionRuntime;
  private readonly exportRecoveryRuntime: EmailOtpExportRecoveryRuntime;
  private readonly ecdsaLifecycleRuntime: EmailOtpEcdsaLifecycleRuntime;

  constructor(private readonly deps: EmailOtpWalletSessionCoordinatorDeps) {
    this.appSessionJwtCache = new EmailOtpAppSessionJwtCache({
      refreshAppSessionJwt: deps.refreshAppSessionJwt,
    });
    this.runtimeConfig = new EmailOtpRuntimeConfig({
      configs: deps.configs,
      getRpId: deps.getRpId,
    });
    this.sealedSessionRegistry = new EmailOtpSealedSessionRegistry({
      configs: deps.configs,
      getSignerWorkerContext: deps.getSignerWorkerContext,
      commitEvmFamilyThresholdEcdsaSessions: deps.commitEvmFamilyThresholdEcdsaSessions,
      writeExactSealedSession: deps.writeExactSealedSession,
      readExactSealedSession: deps.readExactSealedSession,
      getThresholdEcdsaSessionRecordByThresholdSessionId:
        deps.getThresholdEcdsaSessionRecordByThresholdSessionId,
      getThresholdEd25519SessionRecordByThresholdSessionId:
        deps.getThresholdEd25519SessionRecordByThresholdSessionId,
      clearEcdsaRestoreCaches: () => this.clearEcdsaRestoreCaches(),
    });
    const recoveryCodeSigningSessionHydration =
      createEmailOtpEd25519RecoveryCodeWarmSessionHydration({
        hydrateSigningSession: deps.hydrateSigningSession,
      });
    this.ecdsaLifecycleRuntime = new EmailOtpEcdsaLifecycleRuntime({
      configs: deps.configs,
      getSignerWorkerContext: deps.getSignerWorkerContext,
      runtimeConfig: this.runtimeConfig,
      rememberAppSessionJwt: (request) => this.rememberAppSessionJwt(request),
      publicationPorts: () => this.sealedSessionRegistry.ecdsaPublicationPorts(),
      reconstructEd25519Session: (request) => this.reconstructEd25519Session(request),
      getThresholdEd25519SessionRecordByThresholdSessionId:
        deps.getThresholdEd25519SessionRecordByThresholdSessionId,
      recoveryCodeSigningSessionHydration,
    });
    this.exportRecoveryRuntime = new EmailOtpExportRecoveryRuntime({
      getSignerWorkerContext: deps.getSignerWorkerContext,
      requireRelayUrl: () => this.runtimeConfig.requireRelayUrl(),
      requireShamirPrimeB64u: () => this.runtimeConfig.requireShamirPrimeB64u(),
      resolveAppSessionJwt: (request) => this.resolveAppSessionJwt(request),
      loginWithEcdsaCapabilityInternal: (request) =>
        this.ecdsaLifecycleRuntime.loginWithEcdsaCapabilityInternal(request),
    });
    const restoreEcdsaSigningSessionMaterialFromSealedRecord =
      createEmailOtpEcdsaSigningSessionMaterialRestorer({
        configs: deps.configs,
        getSignerWorkerContext: deps.getSignerWorkerContext,
        commitEvmFamilyThresholdEcdsaSessions: deps.commitEvmFamilyThresholdEcdsaSessions,
        hydrateSigningSession: deps.hydrateSigningSession,
        requireRpId: (operation) => this.runtimeConfig.requireRpId(operation),
      });
    const warmSessionWorkerClient = createEmailOtpWarmSessionWorkerClient({
      worker: deps.signerWorkerManager,
    });
    this.sealedRefreshPolicy = new EmailOtpSealedRefreshPolicy({
      getThresholdEcdsaSessionRecordByThresholdSessionId:
        deps.getThresholdEcdsaSessionRecordByThresholdSessionId,
      deleteDurableSealedSessionRecord: deps.deleteDurableSealedSessionRecord,
      updateExactSealedSessionPolicy: deps.updateExactSealedSessionPolicy,
      clearEcdsaRestoreCaches: () => this.clearEcdsaRestoreCaches(),
    });
    this.sealedRestoreOrchestrator = new EmailOtpSealedRestoreOrchestrator({
      sessionPersistenceMode: deps.configs.signing.sessionPersistenceMode,
      listExactSealedSessionsForWallet: deps.listExactSealedSessionsForWallet,
      readExactSealedSession: deps.readExactSealedSession,
      acquireSigningSessionRestoreLease: deps.acquireSigningSessionRestoreLease,
      releaseSigningSessionRestoreLease: deps.releaseSigningSessionRestoreLease,
      getThresholdEcdsaSessionRecordByThresholdSessionId:
        deps.getThresholdEcdsaSessionRecordByThresholdSessionId,
      getThresholdEd25519SessionRecordByThresholdSessionId:
        deps.getThresholdEd25519SessionRecordByThresholdSessionId,
      readWarmSessionStatusFromWorker: (sessionId) =>
        warmSessionWorkerClient.readStatus(sessionId),
      restoreEcdsaSigningSessionMaterialFromSealedRecord: (restoreArgs) =>
        restoreEcdsaSigningSessionMaterialFromSealedRecord(restoreArgs),
      recordSessionMaterialRestored: (sessionId, status) =>
        this.sealedRefreshPolicy.recordSessionMaterialRestored(sessionId, status),
      shouldLogDiagnostic: (key) => this.shouldLogSealedRefreshDiagnostic(key),
      requireRpId: (operation) => this.runtimeConfig.requireRpId(operation),
    });
    this.warmSessionRuntime = new EmailOtpWarmSessionRuntime({
      workerClient: warmSessionWorkerClient,
      sealedRefreshPolicy: this.sealedRefreshPolicy,
      sealedRestoreOrchestrator: this.sealedRestoreOrchestrator,
    });
    this.ed25519Warmup = new EmailOtpEd25519Warmup({
      configs: deps.configs,
      getSignerWorkerContext: deps.getSignerWorkerContext,
      persistEmailOtpThresholdEd25519LocalMetadata:
        deps.persistEmailOtpThresholdEd25519LocalMetadata,
      persistWarmSessionEd25519Capability: deps.persistWarmSessionEd25519Capability,
      recoveryCodeSigningSessionHydration,
      readExactSealedSession: deps.readExactSealedSession,
      getThresholdEcdsaSessionRecordByThresholdSessionId:
        deps.getThresholdEcdsaSessionRecordByThresholdSessionId,
      getThresholdEd25519SessionRecordByThresholdSessionId:
        deps.getThresholdEd25519SessionRecordByThresholdSessionId,
      registerSigningSession: (record) =>
        this.sealedSessionRegistry.registerSigningSession(record),
      requireRelayUrl: () => this.runtimeConfig.requireRelayUrl(),
      requireShamirPrimeB64u: () => this.runtimeConfig.requireShamirPrimeB64u(),
      requireRpId: (operation) => this.runtimeConfig.requireRpId(operation),
      resolveAppSessionJwt: (request) => this.resolveAppSessionJwt(request),
      listThresholdEcdsaSessionRecordsForWallet: deps.listThresholdEcdsaSessionRecordsForWallet,
      loginWithEcdsaCapabilityInternal: (request) =>
        this.loginWithEcdsaCapabilityInternal(request),
    });
  }

  private clearEcdsaRestoreCaches(): void {
    this.sealedRestoreOrchestrator.clearCache();
  }

  private shouldLogSealedRefreshDiagnostic(key: string, nowMs = Date.now()): boolean {
    const normalizedKey = String(key || '').trim();
    if (!normalizedKey) return false;
    const lastLoggedAtMs = this.sealedRefreshDiagnosticLogAtMsByKey.get(normalizedKey) || 0;
    if (nowMs - lastLoggedAtMs < 60_000) return false;
    this.sealedRefreshDiagnosticLogAtMsByKey.set(normalizedKey, nowMs);
    return true;
  }

  async discoverPersistedSessionsForWallet(
    args: DiscoverPersistedSessionsForWalletInput,
  ): Promise<DiscoverPersistedSessionsForWalletResult> {
    return await this.sealedRestoreOrchestrator.discoverPersistedSessionsForWallet(args);
  }

  async restorePersistedSessionForSigning(
    args: RestorePersistedSessionForSigningInput,
  ): Promise<RestorePersistedSessionForSigningResult> {
    return await this.sealedRestoreOrchestrator.restorePersistedSessionForSigning(args);
  }

  async readPersistedSessionSnapshot(
    args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
  ): Promise<AvailableSigningLanes> {
    return await readEmailOtpPersistedSessionSnapshot(args, {
      configs: this.deps.configs,
      listExactSealedSessionsForWallet: this.deps.listExactSealedSessionsForWallet,
      readWarmSessionStatusOnly: (sessionId) => this.readWarmSessionStatusOnly(sessionId),
    });
  }

  async attachEd25519SessionToEmailOtpSigningSessionSeal(args: {
    ecdsaThresholdSessionId: string;
    ed25519ThresholdSessionId: string;
  }) {
    return await this.sealedSessionRegistry.attachEd25519SessionToEmailOtpSigningSessionSeal(args);
  }

  async readWarmSessionStatusOnly(sessionId: string): Promise<WarmSessionStatusResult> {
    return await this.warmSessionRuntime.readWarmSessionStatusOnly(sessionId);
  }

  async claimWarmSessionMaterial(args: {
    sessionId: string;
    uses?: number;
    consume?: boolean;
    curve?: 'ed25519' | 'ecdsa';
    chain?: 'near';
    chainTarget?: ThresholdEcdsaChainTarget;
  }): Promise<WarmSessionClaimResult> {
    return await this.warmSessionRuntime.claimWarmSessionMaterial(args);
  }

  async consumeWarmSessionUses(args: {
    sessionId: string;
    uses?: number;
    curve?: 'ed25519' | 'ecdsa';
    chain?: 'near';
    chainTarget?: ThresholdEcdsaChainTarget;
  }): Promise<WarmSessionStatusResult> {
    return await this.warmSessionRuntime.consumeWarmSessionUses(args);
  }

  async clearVolatileWarmSessionMaterial(sessionId: string): Promise<void> {
    await this.warmSessionRuntime.clearVolatileWarmSessionMaterial(sessionId);
  }

  rememberAppSessionJwt(args: { walletSession: WalletSessionRef; appSessionJwt?: string }): void {
    this.appSessionJwtCache.remember(args);
  }

  async resolveAppSessionJwt(args: {
    walletSession: WalletSessionRef;
    relayUrl: string;
  }): Promise<string> {
    return await this.appSessionJwtCache.resolveJwt(args);
  }

  isEd25519WarmupPending(args: { nearAccountId: AccountId }): boolean {
    return this.ed25519Warmup.isPending(args);
  }

  async waitForPendingEd25519Warmup(args: { nearAccountId: AccountId }): Promise<boolean> {
    return await this.ed25519Warmup.waitForPending(args);
  }

  async requestTransactionSigningChallenge(
    args: RequestEmailOtpChallengeArgs,
  ): Promise<{ challengeId: string; emailHint?: string }> {
    return await this.exportRecoveryRuntime.requestTransactionSigningChallenge(args);
  }

  async requestExportChallenge(
    args: RequestEmailOtpChallengeArgs,
  ): Promise<{ challengeId: string; emailHint?: string }> {
    return await this.exportRecoveryRuntime.requestExportChallenge(args);
  }

  async exportEd25519SeedWithAuthorization(
    args: ExportEd25519SeedWithAuthorizationArgs,
  ): Promise<EmailOtpEd25519ExportArtifact> {
    return await this.exportRecoveryRuntime.exportEd25519SeedWithAuthorization(args);
  }

  async exportEcdsaKeyWithAuthorization(
    args: ExportEcdsaKeyWithAuthorizationArgs,
  ): Promise<EmailOtpEcdsaExportArtifact> {
    return await this.exportRecoveryRuntime.exportEcdsaKeyWithAuthorization(args);
  }

  async exportEcdsaKeyWithFreshEmailOtpLane(
    args: ExportEcdsaKeyWithFreshEmailOtpLaneArgs,
  ): Promise<EmailOtpEcdsaExportArtifact> {
    return await this.exportRecoveryRuntime.exportEcdsaKeyWithFreshEmailOtpLane(args);
  }

  async loginWithEcdsaCapabilityForSigning(
    args: LoginEmailOtpEcdsaCapabilityForSigningArgs,
  ): Promise<EmailOtpThresholdEcdsaLoginResult> {
    return await this.ecdsaLifecycleRuntime.loginWithEcdsaCapabilityForSigning(args);
  }

  async loginWithEcdsaCapabilityInternal(
    args: LoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpThresholdEcdsaLoginResult> {
    return await this.ecdsaLifecycleRuntime.loginWithEcdsaCapabilityInternal(args);
  }

  async loginWithEd25519CapabilityInternal(
    args: LoginEmailOtpEd25519CapabilityArgs,
  ): Promise<EmailOtpThresholdEd25519LoginResult> {
    return await this.ed25519Warmup.loginWithEd25519CapabilityInternal(args);
  }

  async enrollAndLoginWithEcdsaCapabilityInternal(
    args: EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpThresholdEcdsaEnrollmentResult> {
    return await this.ecdsaLifecycleRuntime.enrollAndLoginWithEcdsaCapabilityInternal(args);
  }

  async loginWithEd25519CapabilityForSigning(args: {
    nearAccountId: AccountId;
    challengeId: string;
    otpCode: string;
    committedLane: Ed25519SigningLane;
    record?: never;
    routeAuth?: never;
    authLane?: never;
    remainingUses?: number;
  }): Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }> {
    return await this.ed25519Warmup.loginForSigning(args);
  }

  async reconstructEd25519Session(
    args: ReconstructEmailOtpEd25519SessionArgs,
  ): Promise<EmailOtpThresholdEd25519ProvisioningResult> {
    return await this.ed25519Warmup.reconstructSession(args);
  }

}

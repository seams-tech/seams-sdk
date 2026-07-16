import type {
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
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
import { createEmailOtpEcdsaSigningSessionMaterialRestorer } from './ecdsaRecovery';
import {
  EmailOtpAppSessionJwtCache,
  emailOtpAppSessionBindingFromJwt,
  type EmailOtpAppSessionBinding,
} from './appSessionJwtCache';
import type { EmailOtpWalletSessionCoordinatorDeps } from './ports';
import { readEmailOtpPersistedSessionSnapshot } from './persistedSnapshot';
import {
  type EmailOtpThresholdEcdsaLoginResult,
  type LoginEmailOtpEcdsaCapabilityArgs,
  type LoginEmailOtpEcdsaCapabilityForSigningArgs,
} from './ecdsaLogin';
import type { EmailOtpEcdsaPublicReauthLane } from '../../flows/signEvmFamily/ecdsaSelection';
import type { EmailOtpEcdsaPublicReauthExportAuthority } from '../../flows/recovery/ecdsaExportMaterial';
import {
  type EmailOtpThresholdEcdsaEnrollmentResult,
  type EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaEnrollment';
import { EmailOtpEcdsaLifecycleRuntime } from './ecdsaLifecycleRuntime';
import {
  EmailOtpExportRecoveryRuntime,
  type EmailOtpEcdsaExportArtifact,
  type ExportEcdsaKeyWithAuthorizationArgs,
  type ExportEcdsaKeyWithDurableAuthorizationArgs,
  type ExportEd25519YaoSeedWithFreshEmailOtpLaneArgs,
  type RequestEmailOtpChallengeArgs,
} from './exportRecoveryRuntime';
import { EmailOtpRuntimeConfig } from './runtimeConfig';
import { EmailOtpSealedSessionRegistry } from './sealedSessionRegistry';
import { EmailOtpSealedRefreshPolicy } from './sealedRefreshPolicy';
import { EmailOtpSealedRestoreOrchestrator } from './sealedRestoreOrchestrator';
import {
  createEmailOtpWarmSessionWorkerClient,
  EmailOtpWarmSessionRuntime,
} from './warmSessionRuntime';

export type {
  EmailOtpThresholdEcdsaLoginResult,
  LoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaLogin';
export type {
  EmailOtpThresholdEcdsaEnrollmentResult,
  EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaEnrollment';
export type {
  EmailOtpCoordinatorRuntimePorts,
  EmailOtpEcdsaSessionPorts,
  EmailOtpSealedSessionStorePorts,
  EmailOtpWalletSessionCoordinatorDeps,
} from './ports';

export class EmailOtpWalletSessionRuntime {
  private readonly appSessionJwtCache: EmailOtpAppSessionJwtCache;
  private sealedRefreshDiagnosticLogAtMsByKey: Map<string, number> = new Map();
  private readonly sealedRefreshPolicy: EmailOtpSealedRefreshPolicy;
  private readonly sealedRestoreOrchestrator: EmailOtpSealedRestoreOrchestrator;
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
      clearEcdsaRestoreCaches: () => this.clearEcdsaRestoreCaches(),
    });
    this.ecdsaLifecycleRuntime = new EmailOtpEcdsaLifecycleRuntime({
      configs: deps.configs,
      getSignerWorkerContext: deps.getSignerWorkerContext,
      runtimeConfig: this.runtimeConfig,
      rememberAppSessionJwt: (request) => this.rememberAppSessionJwt(request),
      publicationPorts: () => this.sealedSessionRegistry.ecdsaPublicationPorts(),
    });
    this.exportRecoveryRuntime = new EmailOtpExportRecoveryRuntime({
      getSignerWorkerContext: deps.getSignerWorkerContext,
      requireRelayUrl: () => this.runtimeConfig.requireRelayUrl(),
      requireShamirPrimeB64u: () => this.runtimeConfig.requireShamirPrimeB64u(),
      loginWithEcdsaCapabilityInternal: (request) =>
        this.ecdsaLifecycleRuntime.loginWithEcdsaCapabilityInternal(request),
    });
    const restoreEcdsaSigningSessionMaterialFromSealedRecord =
      createEmailOtpEcdsaSigningSessionMaterialRestorer({
        configs: deps.configs,
        getSignerWorkerContext: deps.getSignerWorkerContext,
        commitEvmFamilyThresholdEcdsaSessions: deps.commitEvmFamilyThresholdEcdsaSessions,
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
      readWarmSessionStatusFromWorker: (sessionId) => warmSessionWorkerClient.readStatus(sessionId),
      restoreEcdsaSigningSessionMaterialFromSealedRecord: (restoreArgs) =>
        restoreEcdsaSigningSessionMaterialFromSealedRecord(restoreArgs),
      recordSessionMaterialRestored: (sessionId, status) =>
        this.sealedRefreshPolicy.recordSessionMaterialRestored(sessionId, status),
      shouldLogDiagnostic: (key) => this.shouldLogSealedRefreshDiagnostic(key),
    });
    this.warmSessionRuntime = new EmailOtpWarmSessionRuntime({
      workerClient: warmSessionWorkerClient,
      sealedRefreshPolicy: this.sealedRefreshPolicy,
      sealedRestoreOrchestrator: this.sealedRestoreOrchestrator,
    });
  }

  async persistEd25519YaoSessionForRefresh(
    args: Parameters<EmailOtpSealedSessionRegistry['persistEd25519YaoSessionForRefresh']>[0],
  ): Promise<void> {
    await this.sealedSessionRegistry.persistEd25519YaoSessionForRefresh(args);
  }

  async persistEcdsaSessionForRefresh(
    args: Parameters<EmailOtpSealedSessionRegistry['persistEcdsaSessionForRefresh']>[0],
  ): Promise<void> {
    await this.sealedSessionRegistry.persistEcdsaSessionForRefresh(args);
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

  rememberAppSessionJwt(args: { walletId: WalletId; appSessionJwt: string }): void {
    this.appSessionJwtCache.remember(emailOtpAppSessionBindingFromJwt(args));
  }

  rememberAppSessionBinding(binding: EmailOtpAppSessionBinding): void {
    this.appSessionJwtCache.remember(binding);
  }

  async resolveAppSessionJwt(args: {
    walletSession: WalletSessionRef;
    relayUrl: string;
  }): Promise<string> {
    return await this.appSessionJwtCache.resolveJwt(args);
  }

  async requestTransactionSigningChallenge(
    args: RequestEmailOtpChallengeArgs,
  ): Promise<{ challengeId: string; emailHint?: string }> {
    return await this.exportRecoveryRuntime.requestTransactionSigningChallenge(args);
  }

  async requestPublicReauthTransactionSigningChallenge(args: {
    walletSession: WalletSessionRef;
    chain: ThresholdEcdsaChainTarget['kind'];
  }): Promise<{ challengeId: string; emailHint?: string }> {
    const appSessionJwt = await this.resolveAppSessionJwt({
      walletSession: args.walletSession,
      relayUrl: this.runtimeConfig.requireRelayUrl(),
    });
    return await this.exportRecoveryRuntime.requestTransactionSigningChallenge({
      kind: 'wallet_public_reauth_challenge',
      walletSession: args.walletSession,
      chain: args.chain,
      appSessionJwt,
    });
  }

  async requestExportChallenge(
    args: RequestEmailOtpChallengeArgs,
  ): Promise<{ challengeId: string; emailHint?: string }> {
    return await this.exportRecoveryRuntime.requestExportChallenge(args);
  }

  async requestPublicReauthExportChallenge(args: {
    walletSession: WalletSessionRef;
    chain: ThresholdEcdsaChainTarget['kind'];
  }): Promise<{ challengeId: string; emailHint?: string }> {
    const appSessionJwt = await this.resolveAppSessionJwt({
      walletSession: args.walletSession,
      relayUrl: this.runtimeConfig.requireRelayUrl(),
    });
    return await this.exportRecoveryRuntime.requestExportChallenge({
      kind: 'wallet_public_reauth_challenge',
      walletSession: args.walletSession,
      chain: args.chain,
      appSessionJwt,
    });
  }

  async exportEcdsaKeyWithAuthorization(
    args: ExportEcdsaKeyWithAuthorizationArgs,
  ): Promise<EmailOtpEcdsaExportArtifact> {
    return await this.exportRecoveryRuntime.exportEcdsaKeyWithAuthorization(args);
  }

  async exportEcdsaKeyWithDurableAuthorization(
    args: ExportEcdsaKeyWithDurableAuthorizationArgs,
  ): Promise<EmailOtpEcdsaExportArtifact> {
    return await this.exportRecoveryRuntime.exportEcdsaKeyWithDurableAuthorization(args);
  }

  async exportEcdsaKeyWithPublicReauthAuthorization(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    publicReauthAuthority: EmailOtpEcdsaPublicReauthExportAuthority;
  }): Promise<EmailOtpEcdsaExportArtifact> {
    const appSessionJwt = await this.resolveAppSessionJwt({
      walletSession: args.walletSession,
      relayUrl: this.runtimeConfig.requireRelayUrl(),
    });
    return await this.exportRecoveryRuntime.exportEcdsaKeyWithPublicReauthAuthorization({
      walletSession: args.walletSession,
      chainTarget: args.chainTarget,
      challengeId: args.challengeId,
      otpCode: args.otpCode,
      appSessionJwt,
      publicReauthAuthority: args.publicReauthAuthority,
    });
  }

  async exportEd25519YaoSeedWithFreshEmailOtpLane(
    args: ExportEd25519YaoSeedWithFreshEmailOtpLaneArgs,
  ): Promise<{ artifactKind: 'near-ed25519-seed-v1'; publicKey: string; privateKey: string }> {
    return await this.exportRecoveryRuntime.exportEd25519YaoSeedWithFreshEmailOtpLane(args);
  }

  async loginWithEcdsaCapabilityForSigning(
    args: LoginEmailOtpEcdsaCapabilityForSigningArgs,
  ): Promise<EmailOtpThresholdEcdsaLoginResult> {
    return await this.ecdsaLifecycleRuntime.loginWithEcdsaCapabilityForSigning(args);
  }

  async loginWithEcdsaPublicReauthCapabilityForSigning(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    reauthLane: EmailOtpEcdsaPublicReauthLane;
    remainingUses: number;
  }): Promise<EmailOtpThresholdEcdsaLoginResult> {
    const appSessionJwt = await this.resolveAppSessionJwt({
      walletSession: args.walletSession,
      relayUrl: this.runtimeConfig.requireRelayUrl(),
    });
    return await this.ecdsaLifecycleRuntime.loginWithEcdsaPublicReauthCapabilityForSigning({
      walletSession: args.walletSession,
      chainTarget: args.chainTarget,
      challengeId: args.challengeId,
      otpCode: args.otpCode,
      reauthLane: args.reauthLane,
      appSessionJwt,
      remainingUses: args.remainingUses,
    });
  }

  async loginWithEcdsaCapabilityInternal(
    args: LoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpThresholdEcdsaLoginResult> {
    return await this.ecdsaLifecycleRuntime.loginWithEcdsaCapabilityInternal(args);
  }

  async enrollAndLoginWithEcdsaCapabilityInternal(
    args: EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpThresholdEcdsaEnrollmentResult> {
    return await this.ecdsaLifecycleRuntime.enrollAndLoginWithEcdsaCapabilityInternal(args);
  }
}

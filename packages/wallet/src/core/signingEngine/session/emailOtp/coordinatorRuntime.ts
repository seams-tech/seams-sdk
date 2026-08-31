import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type {
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletResult,
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionForSigningResult,
} from '@/core/signingEngine/session/sealedRecovery/sealedRecovery.types';
import { createEmailOtpEcdsaSigningSessionMaterialRestorer } from './ecdsaRecovery';
import type { EmailOtpWalletSessionCoordinatorDeps } from './ports';
import type { EmailOtpWarmMaterialTarget } from '@/core/signingEngine/workerManager/workerTypes';
import type { EmailOtpTransactionSigningChallenge } from './publicTypes';
import {
  type EmailOtpThresholdEcdsaLoginResult,
  type LoginEmailOtpEcdsaCapabilityArgs,
  type LoginEmailOtpEcdsaCapabilityForSigningArgs,
} from './ecdsaLogin';
import { EmailOtpEcdsaLifecycleRuntime } from './ecdsaLifecycleRuntime';
import {
  EmailOtpExportRecoveryRuntime,
  type EmailOtpEcdsaExportArtifact,
  type ExportEcdsaKeyWithDurableAuthorizationArgs,
  type ExportEd25519YaoSeedWithFreshEmailOtpLaneArgs,
  type RequestEmailOtpChallengeArgs,
  type RequestEmailOtpExportChallengeArgs,
} from './exportRecoveryRuntime';
import { EmailOtpRuntimeConfig } from './runtimeConfig';
import { EmailOtpSealedSessionRegistry } from './sealedSessionRegistry';
import { EmailOtpSealedRefreshPolicy } from './sealedRefreshPolicy';
import type { WarmSessionMaterialOperationTarget } from './sealedRuntimePurpose';
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
  EmailOtpCoordinatorRuntimePorts,
  EmailOtpEcdsaSessionPorts,
  EmailOtpSealedSessionStorePorts,
  EmailOtpWalletSessionCoordinatorDeps,
} from './ports';

export class EmailOtpWalletSessionRuntime {
  private sealedRefreshDiagnosticLogAtMsByKey: Map<string, number> = new Map();
  private readonly sealedRefreshPolicy: EmailOtpSealedRefreshPolicy;
  private readonly sealedRestoreOrchestrator: EmailOtpSealedRestoreOrchestrator;
  private readonly runtimeConfig: EmailOtpRuntimeConfig;
  private readonly sealedSessionRegistry: EmailOtpSealedSessionRegistry;
  private readonly warmSessionRuntime: EmailOtpWarmSessionRuntime;
  private readonly exportRecoveryRuntime: EmailOtpExportRecoveryRuntime;
  private readonly ecdsaLifecycleRuntime: EmailOtpEcdsaLifecycleRuntime;

  constructor(private readonly deps: EmailOtpWalletSessionCoordinatorDeps) {
    this.runtimeConfig = new EmailOtpRuntimeConfig({
      configs: deps.configs,
      getRpId: deps.getRpId,
    });
    this.sealedSessionRegistry = new EmailOtpSealedSessionRegistry({
      configs: deps.configs,
      getSignerWorkerContext: deps.getSignerWorkerContext,
      commitEvmFamilyThresholdEcdsaSessions: deps.commitEvmFamilyThresholdEcdsaSessions,
      listActiveEcdsaCapabilityManifestsForWallet: deps.listActiveEcdsaCapabilityManifestsForWallet,
      writeExactSealedSession: deps.writeExactSealedSession,
      readExactSealedSession: deps.readExactSealedSession,
      clearEcdsaRestoreCaches: () => this.clearEcdsaRestoreCaches(),
    });
    this.ecdsaLifecycleRuntime = new EmailOtpEcdsaLifecycleRuntime({
      configs: deps.configs,
      getSignerWorkerContext: deps.getSignerWorkerContext,
      loadWalletCustodyEd25519Material: deps.loadWalletCustodyEd25519Material,
      restoreWalletCustodyEcdsaContinuity: deps.restoreWalletCustodyEcdsaContinuity,
      provisionThresholdEcdsaSession: deps.provisionThresholdEcdsaSession,
      provisionEmailOtpEcdsaExplicitExportSession: deps.provisionEmailOtpEcdsaExplicitExportSession,
      runtimeConfig: this.runtimeConfig,
      ownerLaneScopeStores: deps.ownerLaneScopeStores,
      resolveSelectedWalletAuthority: deps.resolveSelectedWalletAuthority,
      resolveCurrentEcdsaCapabilityRuntime: deps.resolveCurrentEcdsaCapabilityRuntime,
      publicationPorts: () => this.sealedSessionRegistry.ecdsaPublicationPorts(),
    });
    this.exportRecoveryRuntime = new EmailOtpExportRecoveryRuntime({
      getSignerWorkerContext: deps.getSignerWorkerContext,
      requireRelayUrl: () => this.runtimeConfig.requireRelayUrl(),
      requireSigningSessionSealGroupId: () => this.runtimeConfig.requireSigningSessionSealGroupId(),
      resolveSelectedWalletAuthority: deps.resolveSelectedWalletAuthority,
      prepareEcdsaExportCapability: (request) =>
        this.ecdsaLifecycleRuntime.prepareEcdsaExportCapability(request),
    });
    const restoreEcdsaSigningSessionMaterialFromSealedRecord =
      createEmailOtpEcdsaSigningSessionMaterialRestorer({
        configs: deps.configs,
        withThresholdEcdsaSigningQueue: deps.withThresholdEcdsaSigningQueue,
        getSignerWorkerContext: deps.getSignerWorkerContext,
        resolveSelectedWalletAuthority: deps.resolveSelectedWalletAuthority,
        readExactWalletSessionAuthorization: deps.readExactWalletSessionAuthorization,
        provisionThresholdEcdsaSession: deps.provisionThresholdEcdsaSession,
        commitEvmFamilyThresholdEcdsaSessions: deps.commitEvmFamilyThresholdEcdsaSessions,
        resolveCurrentEcdsaCapabilityRuntime: deps.resolveCurrentEcdsaCapabilityRuntime,
      });
    const warmSessionWorkerClient = createEmailOtpWarmSessionWorkerClient({
      worker: deps.signerWorkerManager,
    });
    this.sealedRefreshPolicy = new EmailOtpSealedRefreshPolicy({
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
      readWarmSessionStatusFromWorker: (thresholdSessionId) =>
        warmSessionWorkerClient.readStatus({
          kind: 'ecdsa',
          thresholdSessionId,
        }),
      restoreEcdsaSigningSessionMaterialFromSealedRecord: (restoreArgs) =>
        restoreEcdsaSigningSessionMaterialFromSealedRecord(restoreArgs),
      recordSessionMaterialRestored: (purpose, status) =>
        this.sealedRefreshPolicy.recordSessionMaterialRestored(purpose, status),
      shouldLogDiagnostic: (key) => this.shouldLogSealedRefreshDiagnostic(key),
    });
    this.warmSessionRuntime = new EmailOtpWarmSessionRuntime({
      workerClient: warmSessionWorkerClient,
      sealedRefreshPolicy: this.sealedRefreshPolicy,
      sealedRestoreOrchestrator: this.sealedRestoreOrchestrator,
    });
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

  async readWarmSessionStatusOnly(
    target: EmailOtpWarmMaterialTarget,
  ): Promise<WarmSessionStatusResult> {
    return await this.warmSessionRuntime.readWarmSessionStatusOnly(target);
  }

  async consumeWarmSessionUses(
    args: WarmSessionMaterialOperationTarget & {
      uses?: number;
    },
  ): Promise<WarmSessionStatusResult> {
    return await this.warmSessionRuntime.consumeWarmSessionUses(args);
  }

  async clearVolatileWarmSessionMaterial(target: EmailOtpWarmMaterialTarget): Promise<void> {
    await this.warmSessionRuntime.clearVolatileWarmSessionMaterial(target);
  }

  async requestTransactionSigningChallenge(
    args: RequestEmailOtpChallengeArgs,
  ): Promise<EmailOtpTransactionSigningChallenge> {
    return await this.exportRecoveryRuntime.requestTransactionSigningChallenge(args);
  }

  async requestExportChallenge(
    args: RequestEmailOtpExportChallengeArgs,
  ): Promise<EmailOtpTransactionSigningChallenge> {
    return await this.exportRecoveryRuntime.requestExportChallenge(args);
  }

  async exportEcdsaKeyWithDurableAuthorization(
    args: ExportEcdsaKeyWithDurableAuthorizationArgs,
  ): Promise<EmailOtpEcdsaExportArtifact> {
    return await this.exportRecoveryRuntime.exportEcdsaKeyWithDurableAuthorization(args);
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

  async loginWithEcdsaCapabilityInternal(
    args: LoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpThresholdEcdsaLoginResult> {
    return await this.ecdsaLifecycleRuntime.loginWithEcdsaCapabilityInternal(args);
  }
}

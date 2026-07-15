import type { RuntimePorts } from '@/core/platform';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import { readPersistedAvailableSigningLanesForSigning as readPersistedAvailableSigningLanesForSigningOperation } from '@/core/signingEngine/session/availability/persistedAvailableSigningLanes';
import { readTrustedWalletSigningBudgetStatus as readTrustedWalletSigningBudgetStatusOperation } from '@/core/signingEngine/session/budget/budgetStatusReader';
import type { EmailOtpWalletSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import {
  clearThresholdEcdsaSessionRecordForExactIdentity as clearThresholdEcdsaSessionRecordForExactIdentityOperation,
  consumeSingleUseEmailOtpEcdsaLane as consumeSingleUseEmailOtpEcdsaLaneOperation,
  getThresholdEcdsaSessionRecordByKey as getThresholdEcdsaSessionRecordByIdentityOperation,
  getThresholdEcdsaSessionRecordForWalletTarget as getThresholdEcdsaSessionRecordForWalletTargetOperation,
  listThresholdEcdsaKeyRefsForWalletTarget as listThresholdEcdsaKeyRefsForWalletTargetOperation,
  listThresholdEcdsaSessionRecordsForWalletTarget as listThresholdEcdsaSessionRecordsForWalletTargetOperation,
  markThresholdEd25519EmailOtpSessionConsumedForWallet as markThresholdEd25519EmailOtpSessionConsumedForWalletOperation,
  upsertThresholdEcdsaSessionFromBootstrap as upsertThresholdEcdsaSessionFromBootstrapOperation,
  type ThresholdEcdsaSessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { markRouterAbEcdsaHssWorkerMaterialRuntimeValidated } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import type { TouchIdPrompt } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import { provisionThresholdEcdsaSession as provisionThresholdEcdsaSessionOperation } from '@/core/signingEngine/session/passkey/ecdsaSessionProvision';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import { provisionThresholdEd25519Session as provisionThresholdEd25519SessionOperation } from '@/core/signingEngine/session/passkey/ed25519SessionProvision';
import {
  persistThresholdEcdsaBootstrapForWalletTarget as persistThresholdEcdsaBootstrapForWalletTargetOperation,
  type ThresholdEcdsaBootstrapStorePort,
} from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';
import { createSigningEnginePorts } from '@/core/signingEngine/assembly/createPorts';
import type { SigningEngineStorePorts } from '@/core/signingEngine/assembly/ports/shared';
import {
  configuredThresholdEcdsaChainTargets,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { signEvmFamily as signEvmFamilyOperation } from '@/core/signingEngine/flows/signEvmFamily/signEvmFamily';
import type { NonceCoordinator } from '@/core/signingEngine/nonce/NonceCoordinator';
import {
  withThresholdEcdsaSigningQueue,
  type ThresholdEcdsaSigningQueueByKey,
} from '@/core/signingEngine/threshold/ecdsa/signingQueue';
import {
  withThresholdEd25519CommitQueue,
  type ThresholdEd25519CommitQueueByKey,
} from '@/core/signingEngine/threshold/ed25519/commitQueue';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { UiConfirmRuntimeBridgePort } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { WarmSigningPorts } from '@/core/signingEngine/assembly/ports/warmSigning';
import type { WorkerResourceWarmupPolicy } from '@/core/signingEngine/assembly/warmup';
import type { SeamsConfigsReadonly, ThemeMode } from '@/core/types/seams';
import type { AccountId } from '@/core/types/accountIds';
import * as registrationPublic from '@/core/signingEngine/flows/registration/public';
import type { Ed25519YaoPublicCapabilityReferenceStorePort } from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import { recoverEmailOtpEd25519CapabilityForSigningV1 } from '@/core/signingEngine/session/emailOtp/ed25519YaoBudgetRecovery';

type SigningEnginePorts = ReturnType<typeof createSigningEnginePorts>;
type EmailOtpEd25519RecoveryRequest = Omit<
  Parameters<typeof recoverEmailOtpEd25519CapabilityForSigningV1>[0],
  | 'workerContext'
  | 'shamirPrimeB64u'
  | 'resolveActiveCapability'
  | 'activateCapability'
  | 'expectedOperationalPublicKey'
>;

function markEcdsaBootstrapWorkerMaterialRuntimeValidated(args: {
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  record: ThresholdEcdsaSessionRecord;
}): void {
  if (
    args.bootstrap.thresholdEcdsaKeyRef.backendBinding?.materialKind !== 'role_local_worker_handle'
  ) {
    return;
  }
  if (markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(args.record)) return;
  throw new Error(
    '[SigningEngine] ECDSA-HSS bootstrap returned worker material that could not be runtime-validated',
  );
}

async function recoverEmailOtpEd25519CapabilityForSigning(args: {
  assembly: BrowserSigningSurfaceEnginePortsArgs;
  request: EmailOtpEd25519RecoveryRequest;
}) {
  const user = await registrationPublic.getUserBySignerSlot(
    args.assembly.getRegistrationPublicDeps(),
    args.request.nearAccountId,
    args.request.record.signerSlot,
  );
  if (
    !user ||
    String(user.walletId) !== String(args.request.record.walletId) ||
    user.authMethod !== 'email_otp'
  ) {
    throw new Error('Email OTP Ed25519 recovery requires one exact persisted signer projection');
  }
  const recovered = await recoverEmailOtpEd25519CapabilityForSigningV1({
    nearAccountId: args.request.nearAccountId,
    record: args.request.record,
    committedLane: args.request.committedLane,
    challengeId: args.request.challengeId,
    otpCode: args.request.otpCode,
    remainingUses: args.request.remainingUses,
    expectedOperationalPublicKey: user.operationalPublicKey,
    workerContext: args.assembly.signerWorkerManager.getContext(),
    shamirPrimeB64u: args.assembly.seamsWebConfigs.signing.sessionSeal.shamirPrimeB64u,
    resolveActiveCapability: (identity) =>
      args.assembly.getEnginePorts().ed25519YaoActiveClients.resolve(identity),
    activateCapability: (capability) =>
      args.assembly.getEnginePorts().ed25519YaoActiveClients.activate(capability),
  });
  await args.assembly.emailOtpSessions.persistEd25519YaoSessionForRefresh({
    record: recovered.record,
    rpId: args.assembly.touchIdPrompt.getRpId(),
  });
  return recovered;
}

export type BrowserSigningSurfaceEnginePortsArgs = {
  runtimePorts: RuntimePorts;
  stores: SigningEngineStorePorts;
  ed25519YaoPublicCapabilityReferences: Ed25519YaoPublicCapabilityReferenceStorePort;
  seamsWebConfigs: SeamsConfigsReadonly;
  nearClient: NearClient;
  touchIdPrompt: TouchIdPrompt;
  userPreferencesManager: UserPreferencesManager;
  nonceCoordinator: NonceCoordinator;
  touchConfirm: UiConfirmRuntimeBridgePort;
  signerWorkerManager: SignerWorkerManager;
  emailOtpSessions: EmailOtpWalletSessionCoordinator;
  warmSigning: WarmSigningPorts;
  ecdsaBootstrapStore: ThresholdEcdsaBootstrapStorePort;
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  thresholdEcdsaSigningQueueByKey: ThresholdEcdsaSigningQueueByKey;
  thresholdEd25519CommitQueueByKey: ThresholdEd25519CommitQueueByKey;
  getWorkerBaseOrigin: () => string;
  workerWarmupPolicy: WorkerResourceWarmupPolicy;
  getTheme: () => ThemeMode;
  ensureSealedRefreshStartupParity: () => Promise<void>;
  getEnginePorts: () => SigningEnginePorts;
  getRegistrationPublicDeps: () => registrationPublic.RegistrationPublicDeps;
  recoverPasskeyEd25519YaoCapabilityForSigning: Parameters<
    typeof createSigningEnginePorts
  >[0]['recoverPasskeyEd25519YaoCapabilityForSigning'];
  recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning: Parameters<
    typeof createSigningEnginePorts
  >[0]['recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning'];
};

export function createBrowserSigningSurfaceEnginePorts(
  args: BrowserSigningSurfaceEnginePortsArgs,
): SigningEnginePorts {
  return createSigningEnginePorts({
    runtimePorts: args.runtimePorts,
    stores: args.stores,
    ed25519YaoPublicCapabilityReferences: args.ed25519YaoPublicCapabilityReferences,
    seamsWebConfigs: args.seamsWebConfigs,
    nearClient: args.nearClient,
    touchIdPrompt: args.touchIdPrompt,
    userPreferencesManager: args.userPreferencesManager,
    nonceCoordinator: args.nonceCoordinator,
    ensureSealedRefreshStartupParity: args.ensureSealedRefreshStartupParity,
    touchConfirm: args.touchConfirm,
    getEmailOtpWarmSessionStatus: (sessionId) =>
      args.emailOtpSessions.readWarmSessionStatusOnly(sessionId),
    consumeEmailOtpWarmSessionUses: (consumeArgs) =>
      args.emailOtpSessions.consumeWarmSessionUses(consumeArgs),
    getWalletSigningBudgetStatus: (statusArgs) =>
      readTrustedWalletSigningBudgetStatusOperation(
        {
          ecdsaSessions: args.warmSigning.ecdsaSessions,
        },
        statusArgs,
      ),
    signerWorkerManager: args.signerWorkerManager,
    getWorkerBaseOrigin: args.getWorkerBaseOrigin,
    workerWarmupPolicy: args.workerWarmupPolicy,
    getTheme: args.getTheme,
    signTempo: (signArgs) =>
      signEvmFamilyOperation(args.getEnginePorts().tempoSigningDeps, signArgs),
    activateAuthenticatedWalletState: (activationArgs) =>
      registrationPublic.activateAuthenticatedWalletState(args.getRegistrationPublicDeps(), {
        walletId: activationArgs.walletId,
        nearAccountId: activationArgs.nearAccountId,
        signerSlot: activationArgs.signerSlot,
        nearClient: activationArgs.nearClient,
      }),
    persistThresholdEcdsaBootstrapForWalletTarget: (persistArgs) =>
      persistThresholdEcdsaBootstrapForWalletTargetOperation({
        bootstrapStore: args.ecdsaBootstrapStore,
        walletId: persistArgs.walletId,
        chainTarget: persistArgs.chainTarget,
        bootstrap: persistArgs.bootstrap,
        signerAuth: persistArgs.signerAuth,
      }),
    upsertThresholdEcdsaSessionFromBootstrap: (upsertArgs) => {
      if (upsertArgs.hasEmailOtpAuthContext) {
        const record = upsertThresholdEcdsaSessionFromBootstrapOperation(
          args.warmSigning.ecdsaSessions,
          {
            walletId: upsertArgs.walletId,
            chainTarget: upsertArgs.chainTarget,
            bootstrap: upsertArgs.bootstrap,
            source: 'email_otp',
            emailOtpAuthContext: upsertArgs.emailOtpAuthContext,
          },
        );
        markEcdsaBootstrapWorkerMaterialRuntimeValidated({
          bootstrap: upsertArgs.bootstrap,
          record,
        });
        return;
      }
      const record = upsertThresholdEcdsaSessionFromBootstrapOperation(
        args.warmSigning.ecdsaSessions,
        {
          walletId: upsertArgs.walletId,
          chainTarget: upsertArgs.chainTarget,
          bootstrap: upsertArgs.bootstrap,
          source: upsertArgs.source,
        },
      );
      markEcdsaBootstrapWorkerMaterialRuntimeValidated({
        bootstrap: upsertArgs.bootstrap,
        record,
      });
    },
    listThresholdEcdsaKeyRefsForWalletTarget: (listArgs) =>
      listThresholdEcdsaKeyRefsForWalletTargetOperation(args.warmSigning.ecdsaSessions, listArgs),
    listThresholdEcdsaSessionRecordsForWalletTarget: (listArgs) =>
      listThresholdEcdsaSessionRecordsForWalletTargetOperation(
        args.warmSigning.ecdsaSessions,
        listArgs,
      ),
    getThresholdEcdsaSessionRecordByKey: (identity) =>
      getThresholdEcdsaSessionRecordByIdentityOperation(args.warmSigning.ecdsaSessions, identity),
    getPasskeyThresholdEcdsaSessionRecordForSigning: (recordArgs) =>
      getThresholdEcdsaSessionRecordForWalletTargetOperation(args.warmSigning.ecdsaSessions, {
        walletId: recordArgs.walletId,
        chainTarget: recordArgs.chainTarget,
        source: recordArgs.source,
      }),
    requestEmailOtpTransactionSigningChallenge: (challengeArgs) =>
      args.emailOtpSessions.requestTransactionSigningChallenge({
        kind: 'wallet_session_challenge',
        walletSession: challengeArgs.walletSession,
        chain: challengeArgs.chain,
        authLane: challengeArgs.authLane,
      }),
    requestEmailOtpEd25519SigningChallenge: (challengeArgs) =>
      args.emailOtpSessions.requestTransactionSigningChallenge({
        kind: 'near_account_challenge',
        walletSession: challengeArgs.walletSession,
        nearAccountId: challengeArgs.nearAccountId,
        chain: 'near',
        authLane: challengeArgs.authLane,
      }),
    recoverEmailOtpEd25519CapabilityForSigning: (recoveryArgs) =>
      recoverEmailOtpEd25519CapabilityForSigning({ assembly: args, request: recoveryArgs }),
    recoverPasskeyEd25519YaoCapabilityForSigning: args.recoverPasskeyEd25519YaoCapabilityForSigning,
    recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning:
      args.recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning,
    provisionThresholdEd25519Session: (provisionArgs) =>
      provisionThresholdEd25519SessionOperation(
        {
          credentialStore: args.stores.recoveryAndDeviceLinking.credentialStore,
          touchIdPrompt: args.touchIdPrompt,
          touchConfirm: args.touchConfirm,
          defaultRelayerUrl: args.seamsWebConfigs.network.relayer?.url || '',
          getSignerWorkerContext: () =>
            args.getEnginePorts().walletSessionActivationDeps.getSignerWorkerContext(),
        },
        provisionArgs,
      ),
    loginWithEmailOtpEcdsaCapabilityForSigning: (loginArgs) =>
      args.emailOtpSessions.loginWithEcdsaCapabilityForSigning(loginArgs),
    restorePersistedSessionForSigning: (restoreArgs) =>
      restoreArgs.authMethod === 'passkey'
        ? args.touchConfirm.restorePersistedSessionForSigning({
            ...restoreArgs,
            authMethod: 'passkey',
          })
        : args.emailOtpSessions.restorePersistedSessionForSigning(restoreArgs),
    readAvailableSigningLanesForSigning: (readArgs) =>
      readPersistedAvailableSigningLanesForSigningOperation(
        {
          ecdsaSessions: args.warmSigning.ecdsaSessions,
          statusReader: args.warmSigning.statusUiConfirm,
          getEmailOtpWarmSessionStatus: (sessionId) =>
            args.warmSigning.statusUiConfirm.getWarmSessionStatus({ sessionId }),
          getWalletSigningBudgetStatus: (statusArgs) =>
            args.getEnginePorts().signingSessionCoordinator.getAvailableStatus(statusArgs),
        },
        readArgs,
        configuredThresholdEcdsaChainTargets(args.seamsWebConfigs.network.chains),
      ),
    consumeSingleUseEmailOtpEcdsaLane: (command) =>
      consumeSingleUseEmailOtpEcdsaLaneOperation(args.warmSigning.ecdsaSessions, command),
    markThresholdEd25519EmailOtpSessionConsumedForWallet: (markArgs) =>
      markThresholdEd25519EmailOtpSessionConsumedForWalletOperation(markArgs),
    clearThresholdEcdsaSessionRecordForExactIdentity: (identity) =>
      clearThresholdEcdsaSessionRecordForExactIdentityOperation(
        args.warmSigning.ecdsaSessions,
        identity,
      ),
    provisionThresholdEcdsaSession: (provisionArgs) =>
      provisionThresholdEcdsaSessionOperation(
        {
          queueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
          activationDeps: args.getEnginePorts().walletSessionActivationDeps,
          touchConfirm: args.touchConfirm,
          persistEcdsaRoleLocalReadyRecord:
            args.runtimePorts.storage.persistEcdsaRoleLocalReadyRecord,
          resolveSealTransport: ({ lane }) =>
            args.warmSigning.capabilityReader.resolveEcdsaSealTransportByThresholdSessionId({
              lane,
            }),
        },
        provisionArgs,
      ),
    withThresholdEcdsaSigningQueue: (queueArgs) =>
      withThresholdEcdsaSigningQueue({
        queueByKey: args.thresholdEcdsaSigningQueueByKey,
        ...queueArgs,
        walletId: toWalletId(queueArgs.walletId),
      }),
    withThresholdEd25519CommitQueue: (queueArgs) =>
      withThresholdEd25519CommitQueue({
        queueByKey: args.thresholdEd25519CommitQueueByKey,
        ...queueArgs,
      }),
  });
}

export type BrowserSigningSurfaceEnginePorts = SigningEnginePorts;

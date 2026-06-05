import type { RuntimePorts } from '@/core/platform';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import { readPersistedAvailableSigningLanesForSigning as readPersistedAvailableSigningLanesForSigningOperation } from '@/core/signingEngine/session/availability/persistedAvailableSigningLanes';
import { readTrustedWalletSigningBudgetStatus as readTrustedWalletSigningBudgetStatusOperation } from '@/core/signingEngine/session/budget/budgetStatusReader';
import type { EmailOtpThresholdSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpThresholdSessionCoordinator';
import {
  consumeSingleUseEmailOtpEcdsaLane as consumeSingleUseEmailOtpEcdsaLaneOperation,
  clearThresholdEcdsaSessionRecordForWalletTarget as clearThresholdEcdsaSessionRecordForWalletTargetOperation,
  getThresholdEcdsaSessionRecordByKey as getThresholdEcdsaSessionRecordByIdentityOperation,
  getThresholdEcdsaSessionRecordForWalletTarget as getThresholdEcdsaSessionRecordForWalletTargetOperation,
  listThresholdEcdsaKeyRefsForWalletTarget as listThresholdEcdsaKeyRefsForWalletTargetOperation,
  listThresholdEcdsaSessionRecordsForWalletTarget as listThresholdEcdsaSessionRecordsForWalletTargetOperation,
  markThresholdEd25519EmailOtpSessionConsumedForAccount as markThresholdEd25519EmailOtpSessionConsumedForAccountOperation,
  upsertThresholdEcdsaSessionFromBootstrap as upsertThresholdEcdsaSessionFromBootstrapOperation,
} from '@/core/signingEngine/session/persistence/records';
import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import type { TouchIdPrompt } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import { provisionThresholdEcdsaSession as provisionThresholdEcdsaSessionOperation } from '@/core/signingEngine/session/passkey/ecdsaSessionProvision';
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
  withThresholdEcdsaCommitQueue,
  type ThresholdEcdsaCommitQueueByKey,
} from '@/core/signingEngine/threshold/ecdsa/commitQueue';
import {
  withThresholdEd25519CommitQueue,
  type ThresholdEd25519CommitQueueByKey,
} from '@/core/signingEngine/threshold/ed25519/commitQueue';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { UiConfirmRuntimeBridgePort } from '@/core/signingEngine/uiConfirm/types';
import type { WarmSigningPorts } from '@/core/signingEngine/assembly/ports/warmSigning';
import type { SeamsConfigsReadonly, ThemeName } from '@/core/types/seams';
import type { AccountId } from '@/core/types/accountIds';
import * as registrationPublic from '@/core/signingEngine/flows/registration/public';

type SigningEnginePorts = ReturnType<typeof createSigningEnginePorts>;

export type BrowserSigningSurfaceEnginePortsArgs = {
  runtimePorts: RuntimePorts;
  stores: SigningEngineStorePorts;
  seamsWebConfigs: SeamsConfigsReadonly;
  nearClient: NearClient;
  touchIdPrompt: TouchIdPrompt;
  userPreferencesManager: UserPreferencesManager;
  nonceCoordinator: NonceCoordinator;
  touchConfirm: UiConfirmRuntimeBridgePort;
  signerWorkerManager: SignerWorkerManager;
  emailOtpSessions: EmailOtpThresholdSessionCoordinator;
  warmSigning: WarmSigningPorts;
  ecdsaBootstrapStore: ThresholdEcdsaBootstrapStorePort;
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  thresholdEcdsaCommitQueueByKey: ThresholdEcdsaCommitQueueByKey;
  thresholdEd25519CommitQueueByKey: ThresholdEd25519CommitQueueByKey;
  getWorkerBaseOrigin: () => string;
  shouldPrewarmWorkers: (workerBaseOrigin: string) => boolean;
  getTheme: () => ThemeName;
  ensureSealedRefreshStartupParity: () => Promise<void>;
  getEnginePorts: () => SigningEnginePorts;
  getRegistrationPublicDeps: () => registrationPublic.RegistrationPublicDeps;
};

export function createBrowserSigningSurfaceEnginePorts(
  args: BrowserSigningSurfaceEnginePortsArgs,
): SigningEnginePorts {
  return createSigningEnginePorts({
    runtimePorts: args.runtimePorts,
    stores: args.stores,
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
    shouldPrewarmWorkers: args.shouldPrewarmWorkers,
    getTheme: args.getTheme,
    signTempo: (signArgs) =>
      signEvmFamilyOperation(args.getEnginePorts().tempoSigningDeps, signArgs),
    extractCosePublicKey: (attestationObjectBase64url: string) =>
      registrationPublic.extractCosePublicKey(
        args.getRegistrationPublicDeps(),
        attestationObjectBase64url,
      ),
    activateAuthenticatedWalletState: (nearAccountId: AccountId, nearClientArg?: NearClient) =>
      registrationPublic.activateAuthenticatedWalletState(args.getRegistrationPublicDeps(), {
        nearAccountId,
        nearClient: nearClientArg,
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
        upsertThresholdEcdsaSessionFromBootstrapOperation(args.warmSigning.ecdsaSessions, {
          walletId: upsertArgs.walletId,
          chainTarget: upsertArgs.chainTarget,
          bootstrap: upsertArgs.bootstrap,
          source: 'email_otp',
          emailOtpAuthContext: upsertArgs.emailOtpAuthContext,
        });
        return;
      }
      upsertThresholdEcdsaSessionFromBootstrapOperation(args.warmSigning.ecdsaSessions, {
        walletId: upsertArgs.walletId,
        chainTarget: upsertArgs.chainTarget,
        bootstrap: upsertArgs.bootstrap,
        source: upsertArgs.source,
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
    getEmailOtpThresholdEcdsaSessionRecordForSigning: (recordArgs) =>
      getThresholdEcdsaSessionRecordForWalletTargetOperation(args.warmSigning.ecdsaSessions, {
        walletId: recordArgs.walletId,
        chainTarget: recordArgs.chainTarget,
        source: 'email_otp',
      }),
    getPasskeyThresholdEcdsaSessionRecordForSigning: (recordArgs) =>
      getThresholdEcdsaSessionRecordForWalletTargetOperation(args.warmSigning.ecdsaSessions, {
        walletId: recordArgs.walletId,
        chainTarget: recordArgs.chainTarget,
        source: recordArgs.source,
      }),
    requestEmailOtpTransactionSigningChallenge: (challengeArgs) =>
      'walletSession' in challengeArgs
        ? args.emailOtpSessions.requestTransactionSigningChallenge({
            kind: 'wallet_session_challenge',
            walletSession: challengeArgs.walletSession,
            chain: challengeArgs.chain,
            ...(challengeArgs.authLane ? { authLane: challengeArgs.authLane } : {}),
          })
        : args.emailOtpSessions.requestTransactionSigningChallenge({
            kind: 'near_account_challenge',
            nearAccountId: challengeArgs.nearAccountId,
            chain: challengeArgs.chain,
            ...(challengeArgs.authLane ? { authLane: challengeArgs.authLane } : {}),
          }),
    isEmailOtpEd25519WarmupPending: (warmupArgs) =>
      args.emailOtpSessions.isEd25519WarmupPending(warmupArgs),
    waitForPendingEmailOtpEd25519Warmup: (warmupArgs) =>
      args.emailOtpSessions.waitForPendingEd25519Warmup(warmupArgs),
    loginWithEmailOtpEd25519CapabilityForSigning: (loginArgs) =>
      args.emailOtpSessions.loginWithEd25519CapabilityForSigning(loginArgs),
    provisionThresholdEd25519Session: (provisionArgs) =>
      provisionThresholdEd25519SessionOperation(
        {
          credentialStore: args.stores.recoveryAndDeviceLinking.credentialStore,
          touchIdPrompt: args.touchIdPrompt,
          touchConfirm: args.touchConfirm,
          defaultRelayerUrl: args.seamsWebConfigs.network.relayer?.url || '',
          getSignerWorkerContext: () =>
            args.getEnginePorts().thresholdSessionActivationDeps.getSignerWorkerContext(),
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
            args.emailOtpSessions.readWarmSessionStatusOnly(sessionId),
          getWalletSigningBudgetStatus: (statusArgs) =>
            args.getEnginePorts().signingSessionCoordinator.getAvailableStatus(statusArgs),
        },
        readArgs,
        configuredThresholdEcdsaChainTargets(args.seamsWebConfigs.network.chains),
      ),
    consumeSingleUseEmailOtpEcdsaLane: (command) =>
      consumeSingleUseEmailOtpEcdsaLaneOperation(args.warmSigning.ecdsaSessions, command),
    markThresholdEd25519EmailOtpSessionConsumedForAccount: (markArgs) =>
      markThresholdEd25519EmailOtpSessionConsumedForAccountOperation(markArgs),
    clearThresholdEcdsaSessionRecordForWalletTarget: (clearArgs) =>
      clearThresholdEcdsaSessionRecordForWalletTargetOperation(
        args.warmSigning.ecdsaSessions,
        clearArgs,
      ),
    provisionThresholdEcdsaSession: (provisionArgs) =>
      provisionThresholdEcdsaSessionOperation(
        {
          queueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
          activationDeps: args.getEnginePorts().thresholdSessionActivationDeps,
          touchConfirm: args.touchConfirm,
          resolveSealTransport: ({ thresholdSessionId, chainTarget }) =>
            args.warmSigning.capabilityReader.resolveEcdsaSealTransportByThresholdSessionId({
              thresholdSessionId,
              chainTarget,
            }),
        },
        provisionArgs,
      ),
    withThresholdEcdsaCommitQueue: (queueArgs) =>
      withThresholdEcdsaCommitQueue({
        queueByKey: args.thresholdEcdsaCommitQueueByKey,
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

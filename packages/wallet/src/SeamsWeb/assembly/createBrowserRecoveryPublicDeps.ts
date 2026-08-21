import type { SeamsConfigsReadonly, ThemeMode } from '@/core/types/seams';
import { walletSessionAuthorizations } from '@/core/indexedDB';
import type {
  PasskeyMpcExportPort,
  PasskeyMpcSessionPort,
  UiConfirmRuntimeBridgePort,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { EmailOtpWalletSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import type { WarmSigningPorts } from '@/core/signingEngine/assembly/ports/warmSigning';
import { createRecoveryPublicDeps } from '@/core/signingEngine/assembly/ports/recovery';
import { provisionPasskeyEcdsaExplicitExportSession as provisionPasskeyEcdsaExplicitExportSessionOperation } from '@/core/signingEngine/session/passkey/ecdsaSessionProvision';
import type { RuntimePorts } from '@/core/platform';
import type { WalletSessionActivationDeps } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import type { RecoveryPublicDeps } from '@/core/signingEngine/flows/recovery/public';
import { createCanonicalWalletSessionStatusReader } from '@/core/signingEngine/session/lifecycle/canonicalWalletSessionStatus';
import type { WarmSessionCapabilityReader } from '@/core/signingEngine/session/warmCapabilities/types';
import { readClientWalletSessionAuthorization } from '@/core/signingEngine/session/persistence/clientSessionPersistence';
import type { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import type { PersistedAvailableSigningLanesDeps } from '@/core/signingEngine/session/availability/persistedAvailableSigningLanes';
import {
  withThresholdEcdsaSigningQueue,
  type ThresholdEcdsaSigningQueueByKey,
} from '@/core/signingEngine/threshold/ecdsa/signingQueue';
import {
  withThresholdEd25519CommitQueue,
  type ThresholdEd25519CommitQueueByKey,
} from '@/core/signingEngine/threshold/ed25519/commitQueue';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  resolveOwnerLaneScope,
  type OwnerLaneScopeStores,
} from '@/core/signingEngine/session/identity/ownerLaneScope';

export function createBrowserRecoveryPublicDeps(args: {
  seamsWebConfigs: SeamsConfigsReadonly;
  runtimePorts: RuntimePorts;
  signerWorkerManager: SignerWorkerManager;
  warmSigning: WarmSigningPorts;
  touchConfirm: UiConfirmRuntimeBridgePort;
  passkeyMpcSession: PasskeyMpcSessionPort;
  passkeyMpcExport: PasskeyMpcExportPort;
  emailOtpSessions: EmailOtpWalletSessionCoordinator;
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  thresholdEcdsaSigningQueueByKey: ThresholdEcdsaSigningQueueByKey;
  thresholdEd25519CommitQueueByKey: ThresholdEd25519CommitQueueByKey;
  getWalletSessionActivationDeps: () => WalletSessionActivationDeps;
  resolvePasskeyEd25519YaoExportContext: RecoveryPublicDeps['ed25519Yao']['resolvePasskeyExportContext'];
  resolveEmailOtpEd25519YaoExportContext: RecoveryPublicDeps['ed25519Yao']['emailOtp']['resolveExportContext'];
  getSigningSessionCoordinator: () => SigningSessionCoordinator;
  getTheme: () => ThemeMode;
  readActiveWalletSessionAuthorization: PersistedAvailableSigningLanesDeps['readActiveWalletSessionAuthorization'];
  readActiveExecutionBundleForWallet: PersistedAvailableSigningLanesDeps['readActiveExecutionBundleForWallet'];
  readActiveEcdsaExportContextForWallet: PersistedAvailableSigningLanesDeps['readActiveEcdsaExportContextForWallet'];
  ed25519YaoPublicCapabilityLanes: PersistedAvailableSigningLanesDeps['ed25519YaoPublicCapabilityLanes'];
  isEd25519YaoPublicCapabilityActive: PersistedAvailableSigningLanesDeps['isEd25519YaoPublicCapabilityActive'];
  listEcdsaSigningCapabilitiesForWallet: PersistedAvailableSigningLanesDeps['listEcdsaSigningCapabilitiesForWallet'];
  ownerLaneScopeStores: OwnerLaneScopeStores;
}): RecoveryPublicDeps {
  const readCanonicalWalletSessionStatus = createCanonicalWalletSessionStatusReader({
    relayerUrl: String(args.seamsWebConfigs.network.relayer?.url || '').trim(),
    readAuthorization: async (walletId) => {
      const read = await walletSessionAuthorizations.readActiveForWallet(toWalletId(walletId));
      return read.kind === 'found' ? read.projection : null;
    },
  });
  return createRecoveryPublicDeps({
    seamsWebConfigs: args.seamsWebConfigs,
    signerWorkerManager: args.signerWorkerManager,
    getTheme: args.getTheme,
    withThresholdEcdsaSigningQueue: (queueArgs) =>
      withThresholdEcdsaSigningQueue({
        queueByKey: args.thresholdEcdsaSigningQueueByKey,
        ...queueArgs,
      }),
    withThresholdEd25519CommitQueue: (queueArgs) =>
      withThresholdEd25519CommitQueue({
        queueByKey: args.thresholdEd25519CommitQueueByKey,
        ...queueArgs,
      }),
    ecdsaSessions: args.warmSigning.ecdsaSessions,
    relayerUrl: String(args.seamsWebConfigs.network.relayer?.url || '').trim(),
    readActiveWalletSessionAuthorization: args.readActiveWalletSessionAuthorization,
    readActiveExecutionBundleForWallet: args.readActiveExecutionBundleForWallet,
    readActiveEcdsaExportContextForWallet: args.readActiveEcdsaExportContextForWallet,
    ed25519YaoPublicCapabilityLanes: args.ed25519YaoPublicCapabilityLanes,
    isEd25519YaoPublicCapabilityActive: args.isEd25519YaoPublicCapabilityActive,
    listEcdsaSigningCapabilitiesForWallet: args.listEcdsaSigningCapabilitiesForWallet,
    resolveOwnerLaneScope: async (walletId) => {
      const read = await walletSessionAuthorizations.readActiveForWallet(toWalletId(walletId));
      if (read.kind !== 'found') {
        throw new Error('Key export requires an active Wallet Session authorization');
      }
      return await resolveOwnerLaneScope({
        authorityRef: read.projection.authority,
        stores: args.ownerLaneScopeStores,
      });
    },
    touchConfirm: args.touchConfirm,
    passkeyMpcSession: args.passkeyMpcSession,
    passkeyMpcExport: args.passkeyMpcExport,
    emailOtpSessions: {
      readWarmSessionStatusOnly: (target) =>
        args.emailOtpSessions.readWarmSessionStatusOnly(target),
      requestExportChallenge: (request) => args.emailOtpSessions.requestExportChallenge(request),
      exportEcdsaKeyWithDurableAuthorization: (request) =>
        args.emailOtpSessions.exportEcdsaKeyWithDurableAuthorization(request),
      exportEd25519YaoSeedWithFreshEmailOtpLane: (request) =>
        args.emailOtpSessions.exportEd25519YaoSeedWithFreshEmailOtpLane(request),
    },
    provisionPasskeyEcdsaExplicitExportSession: (provisionArgs) =>
      provisionPasskeyEcdsaExplicitExportSessionOperation(
        {
          queueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
          activationDeps: args.getWalletSessionActivationDeps(),
          persistEcdsaRoleLocalReadyRecord:
            args.runtimePorts.storage.persistEcdsaRoleLocalReadyRecord,
        },
        provisionArgs,
      ),
    getWalletSessionStatus: (statusArgs) => readCanonicalWalletSessionStatus(statusArgs),
    resolvePasskeyEd25519YaoExportContext: args.resolvePasskeyEd25519YaoExportContext,
    resolveEmailOtpEd25519YaoExportContext: args.resolveEmailOtpEd25519YaoExportContext,
    sessionLifecycle: {
      readAuthorization: async (request) => await readClientWalletSessionAuthorization(request),
      invalidateExpiredAuthorization: async (request) => {
        const result = await args.getSigningSessionCoordinator().invalidateExpiredWalletSession({
          state: request.state,
          source: request.source,
        });
        if (result.kind === 'unavailable') {
          throw new Error('[SigningEngine][key-export] expired Wallet Session cleanup failed');
        }
      },
    },
  });
}

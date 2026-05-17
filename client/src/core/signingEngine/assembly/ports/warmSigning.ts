import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { base64UrlDecode } from '@shared/utils/base64';
import type { ThresholdEcdsaCanonicalExportArtifact } from '../../interfaces/signing';
import { toAccountId } from '@/core/types/accountIds';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getThresholdEcdsaSessionRecordByThresholdSessionId,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from '../../session/persistence/records';
import { createWarmSessionCapabilityReader } from '../../session/warmCapabilities/capabilityReader';
import {
  createWarmSessionStatusReader,
  type WarmSigningStatusReader,
} from '../../session/warmCapabilities/statusReader';
import type { WarmSessionCapabilityReader } from '../../session/warmCapabilities/types';
import type {
  HydrateSigningSessionInput,
  PersistThresholdEcdsaBootstrapForWalletTargetInput,
  WarmCapabilitiesPublicDeps,
} from '../../session/warmCapabilities/public';
import type { PasskeyPublicDeps } from '../../session/passkey/public';
import { createWarmSessionStatusOnlyUiConfirm } from '../../uiConfirm/warmSessionUiConfirm';
import type { UiConfirmRuntimeBridgePort, WarmSessionStatusResult } from '../../uiConfirm/types';
import { persistThresholdEcdsaBootstrapForWalletTarget } from '../../session/warmCapabilities/ecdsaBootstrapPersistence';
import {
  bootstrapWarmEcdsaCapabilityResult,
  reuseWarmEcdsaBootstrapFailureToError,
} from '../../session/passkey/ecdsaWarmCapabilityBootstrap';
import { provisionThresholdEd25519Session } from '../../session/passkey/ed25519SessionProvision';
import { clearVolatileWarmSigningMaterial } from '../../session/warmCapabilities/clearVolatileWarmSigningMaterial';
import {
  cacheSigningSessionPrfFirst,
} from '../../session/passkey/prfCache';
import {
  claimEmailOtpEcdsaSigningShare32,
  resolveEmailOtpWorkerShareSessionId,
} from '../../session/emailOtp/workerRequests';
import type { ThresholdSessionActivationDeps } from '../../session/passkey/ecdsaBootstrap';
import type { SigningEnginePorts } from './shared';
import type { TouchIdPrompt } from '../../stepUpConfirmation/passkeyPrompt/touchIdPrompt';

type WarmSigningPortsArgs = {
  touchConfirm: UiConfirmRuntimeBridgePort;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
  signingSessionSeal: SeamsConfigsReadonly['signing']['sessionSeal'];
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>;
  exportArtifactsByLane: Map<string, ThresholdEcdsaCanonicalExportArtifact>;
};

export type WarmSigningPorts = {
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps & {
    exportArtifactsByLane: Map<string, ThresholdEcdsaCanonicalExportArtifact>;
  };
  statusUiConfirm: UiConfirmRuntimeBridgePort;
  capabilityReader: WarmSessionCapabilityReader;
  statusReader: WarmSigningStatusReader;
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
};

export function createWarmSigningPorts(args: WarmSigningPortsArgs): WarmSigningPorts {
  const ecdsaSessions: WarmSigningPorts['ecdsaSessions'] = {
    recordsByLane: args.recordsByLane,
    exportArtifactsByLane: args.exportArtifactsByLane,
  };
  const getSessionRecordByThresholdSessionId: WarmSigningPorts['getThresholdEcdsaSessionRecordByThresholdSessionId'] =
    (thresholdSessionIdRaw) => {
      const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
      if (!thresholdSessionId) return null;
      return (
        getThresholdEcdsaSessionRecordByThresholdSessionId(ecdsaSessions, thresholdSessionId) ||
        getStoredThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId)
      );
    };
  const statusUiConfirm = createWarmSessionStatusOnlyUiConfirm({
    base: args.touchConfirm,
    secondary: {
      readWarmSessionStatusOnly: args.getEmailOtpWarmSessionStatus,
    },
  });
  const statusReader = createWarmSessionStatusReader({
    touchConfirm: statusUiConfirm,
    getThresholdEcdsaSessionRecordByThresholdSessionId: getSessionRecordByThresholdSessionId,
    getEmailOtpWarmSessionStatus: args.getEmailOtpWarmSessionStatus,
  });
  const capabilityReader = createWarmSessionCapabilityReader({
    touchConfirm: args.touchConfirm,
    signingSessionSeal: args.signingSessionSeal,
    getThresholdEcdsaSessionRecordByThresholdSessionId: getSessionRecordByThresholdSessionId,
    getEmailOtpWarmSessionStatus: args.getEmailOtpWarmSessionStatus,
  });

  return {
    ecdsaSessions,
    statusUiConfirm,
    capabilityReader,
    statusReader,
    getThresholdEcdsaSessionRecordByThresholdSessionId: getSessionRecordByThresholdSessionId,
  };
}

export function createPasskeyPublicDeps(args: {
  seamsPasskeyConfigs: {
    network: SeamsConfigsReadonly['network'];
    signing: SeamsConfigsReadonly['signing'];
  };
  indexedDB: SigningEnginePorts['indexedDB'];
  touchIdPrompt: TouchIdPrompt;
  touchConfirm: UiConfirmRuntimeBridgePort;
  warmSigning: Pick<WarmSigningPorts, 'ecdsaSessions' | 'capabilityReader' | 'statusReader'>;
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  ensureSealedRefreshStartupParity: () => Promise<void>;
  thresholdSessionActivationDeps: ThresholdSessionActivationDeps;
}): PasskeyPublicDeps {
  return {
    getWarmSession: (nearAccountId) =>
      args.warmSigning.capabilityReader.getWarmSession(nearAccountId),
    provisionThresholdEd25519Session: async (provisionArgs) =>
      await provisionThresholdEd25519Session(
        {
          indexedDB: args.indexedDB,
          touchIdPrompt: args.touchIdPrompt,
          touchConfirm: args.touchConfirm,
          defaultRelayerUrl: args.seamsPasskeyConfigs.network.relayer?.url || '',
          getSignerWorkerContext: () =>
            args.thresholdSessionActivationDeps.getSignerWorkerContext(),
        },
        provisionArgs,
      ),
    bootstrapEcdsaSession: async (bootstrapArgs) => {
      const result = await bootstrapWarmEcdsaCapabilityResult(
        {
          ensureSealedRefreshStartupParity: args.ensureSealedRefreshStartupParity,
          queueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
          activationDeps: args.thresholdSessionActivationDeps,
          touchConfirm: args.touchConfirm,
          ecdsaSessions: args.warmSigning.ecdsaSessions,
          capabilityReader: args.warmSigning.capabilityReader,
        },
        bootstrapArgs,
      );
      if (result.ok) return result.bootstrap;
      const failureKind = result.kind;
      switch (failureKind) {
        case 'reuse_failed':
          throw reuseWarmEcdsaBootstrapFailureToError(result.failure);
      }
      failureKind satisfies never;
      throw new Error('[SigningEngine][ecdsa] unsupported warm bootstrap result');
    },
  };
}

export function createWarmCapabilitiesPublicDeps(args: {
  seamsPasskeyConfigs: {
    network: SeamsConfigsReadonly['network'];
    signing: SeamsConfigsReadonly['signing'];
  };
  indexedDB: SigningEnginePorts['indexedDB'];
  touchConfirm: UiConfirmRuntimeBridgePort;
  warmSigning: Pick<WarmSigningPorts, 'ecdsaSessions' | 'capabilityReader' | 'statusReader'>;
  thresholdSessionActivationDeps: ThresholdSessionActivationDeps;
  resolveCanonicalThresholdEcdsaSessionIdForSubjectTarget: SigningEnginePorts['resolveCanonicalThresholdEcdsaSessionIdForSubjectTarget'];
  signingSessionCoordinator: Pick<
    SigningEnginePorts['signingSessionCoordinator'],
    'getAvailableStatus'
  >;
}): WarmCapabilitiesPublicDeps {
  return {
    statusReader: args.warmSigning.statusReader,
    persistThresholdEcdsaBootstrapForWalletTarget: async (
      persistArgs: PersistThresholdEcdsaBootstrapForWalletTargetInput,
    ) =>
      await persistThresholdEcdsaBootstrapForWalletTarget({
        indexedDB: args.indexedDB,
        walletId: toAccountId(persistArgs.walletId),
        chainTarget: persistArgs.chainTarget,
        bootstrap: persistArgs.bootstrap,
        ensureEmailOtpNearAccountMapping: persistArgs.ensureEmailOtpNearAccountMapping,
      }),
    hydrateSigningSession: async (hydrateArgs: HydrateSigningSessionInput) =>
      await cacheSigningSessionPrfFirst(args.touchConfirm, hydrateArgs),
    clearVolatileWarmSigningMaterial: async (walletId) =>
      await clearVolatileWarmSigningMaterial(
        {
          touchConfirm: args.touchConfirm,
          ecdsaSessions: args.warmSigning.ecdsaSessions,
          clearVolatileThresholdSessionMaterial: async (command) =>
            await args.touchConfirm.clearVolatileWarmSessionMaterial(command),
        },
        walletId,
      ),
    getWalletSigningBudgetStatus: (statusArgs) =>
      args.signingSessionCoordinator.getAvailableStatus(statusArgs),
    resolveCanonicalThresholdEcdsaSessionIdForSubjectTarget: (subjectId, chainTarget) =>
      args.resolveCanonicalThresholdEcdsaSessionIdForSubjectTarget(subjectId, chainTarget),
    thresholdEcdsaPresignPoolPolicy: args.seamsPasskeyConfigs.signing.thresholdEcdsa.presignPool,
    getSignerWorkerContext: () => args.thresholdSessionActivationDeps.getSignerWorkerContext(),
    resolveClientSigningShare32: async (keyRef) => {
      const emailOtpWorkerShareSessionId = resolveEmailOtpWorkerShareSessionId(keyRef);
      if (emailOtpWorkerShareSessionId) {
        return await claimEmailOtpEcdsaSigningShare32({
          workerCtx: args.thresholdSessionActivationDeps.getSignerWorkerContext(),
          sessionId: emailOtpWorkerShareSessionId,
        });
      }
      const clientAdditiveShare32B64u = String(
        keyRef.backendBinding?.clientAdditiveShare32B64u || '',
      ).trim();
      if (!clientAdditiveShare32B64u) {
        throw new Error('missing ECDSA signing material');
      }
      let clientSigningShare32: Uint8Array;
      try {
        clientSigningShare32 = base64UrlDecode(clientAdditiveShare32B64u);
      } catch {
        throw new Error('clientAdditiveShare32B64u must be valid base64url');
      }
      if (clientSigningShare32.length !== 32) {
        throw new Error('clientAdditiveShare32B64u must decode to 32 bytes');
      }
      return clientSigningShare32;
    },
  };
}

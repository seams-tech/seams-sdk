import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { base64UrlDecode } from '@shared/utils/base64';
import type { ThresholdEcdsaCanonicalExportArtifact } from '../../interfaces/signing';
import { toAccountId } from '@/core/types/accountIds';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getThresholdEcdsaSessionRecordByThresholdSessionId,
  listThresholdEcdsaSessionRecordsForSubject,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from '../../session/persistence/records';
import {
  createWarmSessionCapabilityReader,
} from '../../session/warmCapabilities/capabilityReader';
import {
  createWarmSessionStatusReader,
  type WarmSigningStatusReader,
} from '../../session/warmCapabilities/statusReader';
import type { WarmSessionCapabilityReader } from '../../session/warmCapabilities/types';
import type {
  HydrateSigningSessionInput,
  PersistThresholdEcdsaBootstrapChainAccountInput,
  WarmCapabilitiesPublicDeps,
} from '../../session/warmCapabilities/public';
import type { PasskeyPublicDeps } from '../../session/passkey/public';
import { createWarmSessionStatusOnlyUiConfirm } from '../../uiConfirm/warmSessionUiConfirm';
import type {
  UiConfirmRuntimeBridgePort,
  WarmSessionStatusResult,
} from '../../uiConfirm/types';
import type { WalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { persistThresholdEcdsaBootstrapChainAccount } from '../../session/warmCapabilities/ecdsaBootstrapPersistence';
import { bootstrapWarmEcdsaCapability } from '../../session/passkey/ecdsaWarmCapabilityBootstrap';
import { provisionThresholdEd25519Session } from '../../session/passkey/ed25519SessionProvision';
import { clearWarmSigningSessions } from '../../session/warmCapabilities/clearWarmSigningSessions';
import {
  cacheSigningSessionPrfFirst,
  clearSigningSessionPrfFirstBestEffort,
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
  listThresholdEcdsaSessionRecordsForSubject: (args: {
    subjectId: WalletSubjectId;
  }) => ThresholdEcdsaSessionRecord[];
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
};

export function createWarmSigningPorts(args: WarmSigningPortsArgs): WarmSigningPorts {
  const ecdsaSessions: WarmSigningPorts['ecdsaSessions'] = {
    recordsByLane: args.recordsByLane,
    exportArtifactsByLane: args.exportArtifactsByLane,
  };
  const listSessionRecordsForSubject: WarmSigningPorts['listThresholdEcdsaSessionRecordsForSubject'] =
    (subjectArgs) => listThresholdEcdsaSessionRecordsForSubject(ecdsaSessions, subjectArgs);
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
    listThresholdEcdsaSessionRecordsForSubject: listSessionRecordsForSubject,
    getThresholdEcdsaSessionRecordByThresholdSessionId: getSessionRecordByThresholdSessionId,
    getEmailOtpWarmSessionStatus: args.getEmailOtpWarmSessionStatus,
  });
  const capabilityReader = createWarmSessionCapabilityReader({
    touchConfirm: args.touchConfirm,
    signingSessionSeal: args.signingSessionSeal,
    listThresholdEcdsaSessionRecordsForSubject: listSessionRecordsForSubject,
    getThresholdEcdsaSessionRecordByThresholdSessionId: getSessionRecordByThresholdSessionId,
    getEmailOtpWarmSessionStatus: args.getEmailOtpWarmSessionStatus,
  });

  return {
    ecdsaSessions,
    statusUiConfirm,
    capabilityReader,
    statusReader,
    listThresholdEcdsaSessionRecordsForSubject: listSessionRecordsForSubject,
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
  warmSigning: Pick<
    WarmSigningPorts,
    'ecdsaSessions' | 'capabilityReader' | 'statusReader'
  >;
  thresholdEcdsaBootstrapQueueByAccount: Map<string, Promise<void>>;
  ensureSealedRefreshStartupParity: () => Promise<void>;
  thresholdSessionActivationDeps: ThresholdSessionActivationDeps;
}): PasskeyPublicDeps {
  return {
    getWarmSession: (nearAccountId) => args.warmSigning.capabilityReader.getWarmSession(nearAccountId),
    provisionThresholdEd25519Session: async (provisionArgs) =>
      await provisionThresholdEd25519Session(
        {
          indexedDB: args.indexedDB,
          touchIdPrompt: args.touchIdPrompt,
          touchConfirm: args.touchConfirm,
          defaultRelayerUrl: args.seamsPasskeyConfigs.network.relayer?.url || '',
          getSignerWorkerContext: () => args.thresholdSessionActivationDeps.getSignerWorkerContext(),
        },
        provisionArgs,
      ),
    bootstrapEcdsaSession: async (bootstrapArgs) =>
      await bootstrapWarmEcdsaCapability(
        {
          ensureSealedRefreshStartupParity: args.ensureSealedRefreshStartupParity,
          queueByAccount: args.thresholdEcdsaBootstrapQueueByAccount,
          activationDeps: args.thresholdSessionActivationDeps,
          touchConfirm: args.touchConfirm,
          ecdsaSessions: args.warmSigning.ecdsaSessions,
          capabilityReader: args.warmSigning.capabilityReader,
        },
        bootstrapArgs,
      ),
  };
}

export function createWarmCapabilitiesPublicDeps(args: {
  seamsPasskeyConfigs: {
    network: SeamsConfigsReadonly['network'];
    signing: SeamsConfigsReadonly['signing'];
  };
  indexedDB: SigningEnginePorts['indexedDB'];
  touchConfirm: UiConfirmRuntimeBridgePort;
  warmSigning: Pick<
    WarmSigningPorts,
    'ecdsaSessions' | 'capabilityReader' | 'statusReader'
  >;
  thresholdSessionActivationDeps: ThresholdSessionActivationDeps;
  resolveCanonicalThresholdEcdsaSessionIdForChain: SigningEnginePorts['resolveCanonicalThresholdEcdsaSessionIdForChain'];
  signingSessionCoordinator: Pick<SigningEnginePorts['signingSessionCoordinator'], 'getAvailableStatus'>;
}): WarmCapabilitiesPublicDeps {
  return {
    statusReader: args.warmSigning.statusReader,
    persistThresholdEcdsaBootstrapChainAccount: async (
      persistArgs: PersistThresholdEcdsaBootstrapChainAccountInput,
    ) =>
      await persistThresholdEcdsaBootstrapChainAccount({
        indexedDB: args.indexedDB,
        nearAccountId: toAccountId(persistArgs.nearAccountId),
        chainTarget: persistArgs.chainTarget,
        bootstrap: persistArgs.bootstrap,
        smartAccount: persistArgs.smartAccount,
        deployment: persistArgs.deployment,
        ensureEmailOtpNearAccountMapping: persistArgs.ensureEmailOtpNearAccountMapping,
      }),
    hydrateSigningSession: async (hydrateArgs: HydrateSigningSessionInput) =>
      await cacheSigningSessionPrfFirst(args.touchConfirm, hydrateArgs),
    clearWarmSigningSessions: async (nearAccountId) =>
      await clearWarmSigningSessions(
        {
          touchConfirm: args.touchConfirm,
          ecdsaSessions: args.warmSigning.ecdsaSessions,
          clearThresholdSessionMaterial: async (sessionId) =>
            await clearSigningSessionPrfFirstBestEffort(args.touchConfirm, sessionId),
        },
        nearAccountId,
      ),
    getWalletSigningBudgetStatus: (statusArgs) =>
      args.signingSessionCoordinator.getAvailableStatus(statusArgs),
    resolveCanonicalThresholdEcdsaSessionIdForChain: (nearAccountId, chainTarget) =>
      args.resolveCanonicalThresholdEcdsaSessionIdForChain(nearAccountId, chainTarget),
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

import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { ThresholdEcdsaActivationRequest } from '../../session/passkey/ecdsaSessionProvision';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type {
  UiConfirmContextPort,
  UiConfirmSecureConfirmationPort,
  UiConfirmSigningPort,
  DurableSealedSessionPort,
  VolatileWarmMaterialPort,
  WarmSessionStatusResult,
} from '../../uiConfirm/uiConfirm.types';
import { createWarmSessionCapabilityReader } from '../../session/warmCapabilities/capabilityReader';
import { ensureWarmEcdsaCapabilityReady } from '../../useCases/provisionEcdsaSession';
import type {
  ThresholdWarmSessionStatusReader,
  WarmSessionCapabilityReader,
  WarmSessionProvisioner,
} from '../../session/warmCapabilities/types';
import {
  createWarmSessionStatusReader,
  type WarmSessionStatusReaderDeps,
} from '../../session/warmCapabilities/statusReader';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import { type ThresholdEcdsaSessionStoreSource } from '../../session/identity/laneIdentity';
import type { EvmFamilyEcdsaSessionReaderDeps } from '../../interfaces/operationDeps';
import type { EvmFamilyChain } from './types';
import {
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type EvmFamilyWarmSessionServicesDeps = EvmFamilyEcdsaSessionReaderDeps & {
  getSignerWorkerContext: () => WorkerOperationContext;
  touchConfirm: UiConfirmContextPort &
    UiConfirmSigningPort &
    UiConfirmSecureConfirmationPort &
    Pick<VolatileWarmMaterialPort, 'getWarmSessionStatus'> &
    Partial<Pick<DurableSealedSessionPort, 'restorePersistedSessionForSigning'>> &
    Partial<Pick<VolatileWarmMaterialPort, 'clearVolatileWarmSessionMaterial'>>;
  provisionThresholdEcdsaSession: (
    args: ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  resolveActiveEcdsaWalletSessionAuthorization?: WarmSessionStatusReaderDeps['resolveActiveEcdsaWalletSessionAuthorization'];
};

export type EvmFamilyWarmSessionServices = Pick<
  WarmSessionCapabilityReader,
  'getWarmSession' | 'resolveEcdsaSealTransportByThresholdSessionId'
> &
  Pick<
    ThresholdWarmSessionStatusReader,
    'assertEcdsaSigningSessionReady' | 'getEcdsaSigningSessionStatus'
  > &
  Pick<WarmSessionProvisioner, 'ensureEcdsaCapabilityReady'>;

export function createEvmFamilyWarmSessionServices(
  deps: EvmFamilyWarmSessionServicesDeps,
): EvmFamilyWarmSessionServices {
  const reconnectInFlightByCapability = new Map<
    string,
    ReturnType<WarmSessionProvisioner['ensureEcdsaCapabilityReady']>
  >();
  const getEmailOtpWarmSessionStatus =
    deps.getEmailOtpWarmSessionStatus ||
    (async (sessionId: string): Promise<WarmSessionStatusResult> =>
      deps.touchConfirm.getWarmSessionStatus({ sessionId }));
  const listThresholdEcdsaRecordsForWalletTarget = ({
    walletId,
    chainTarget,
    source,
  }: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => {
    return deps
      .listThresholdEcdsaSessionRecordsForSigning({
        walletId,
        chainTarget,
        ...(source ? { source } : {}),
      })
      .map((record) => ({
        source: record.source,
        record,
      }));
  };
  const resolveActiveEcdsaWalletSessionAuthorization =
    deps.resolveActiveEcdsaWalletSessionAuthorization;
  const capabilityReader = createWarmSessionCapabilityReader({
    touchConfirm: deps.touchConfirm,
    signingSessionSeal: null,
    getEmailOtpWarmSessionStatus,
    ...(resolveActiveEcdsaWalletSessionAuthorization
      ? { resolveActiveEcdsaWalletSessionAuthorization }
      : {}),
  });
  const statusReader = createWarmSessionStatusReader({
    touchConfirm: deps.touchConfirm,
    getEmailOtpWarmSessionStatus,
    ...(resolveActiveEcdsaWalletSessionAuthorization
      ? { resolveActiveEcdsaWalletSessionAuthorization }
      : {}),
  });
  return {
    getWarmSession: (walletId) => capabilityReader.getWarmSession(walletId),
    resolveEcdsaSealTransportByThresholdSessionId: (args) =>
      capabilityReader.resolveEcdsaSealTransportByThresholdSessionId(args),
    assertEcdsaSigningSessionReady: (readyArgs) =>
      statusReader.assertEcdsaSigningSessionReady(readyArgs),
    getEcdsaSigningSessionStatus: (statusArgs) =>
      statusReader.getEcdsaSigningSessionStatus(statusArgs),
    ensureEcdsaCapabilityReady: (readyArgs) =>
      ensureWarmEcdsaCapabilityReady(
        {
          getWarmSession: (walletId) => capabilityReader.getWarmSession(walletId),
          listThresholdEcdsaRecordsForWalletTarget,
          canProvisionEcdsaCapability: true,
          provisionThresholdEcdsaSession: (provisionRequest) =>
            deps.provisionThresholdEcdsaSession(provisionRequest),
          touchConfirm: deps.touchConfirm,
          resolveExactEcdsaRecord: (recordArgs) => statusReader.resolveExactEcdsaRecord(recordArgs),
          readEcdsaCapabilityForLane: (lane) => capabilityReader.getEcdsaCapabilityForLane(lane),
          reconnectInFlightByCapability,
        },
        readyArgs,
      ),
  };
}

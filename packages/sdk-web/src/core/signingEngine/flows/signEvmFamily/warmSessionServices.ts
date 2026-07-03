import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { ThresholdEcdsaActivationRequest } from '../../session/passkey/ecdsaSessionProvision';
import { clearRouterAbEcdsaHssClientPresignaturesForLane } from '../../routerAb/ecdsaHss/presignaturePool';
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
import {
  applyWarmSessionEcdsaPostSignPolicy,
  assertWarmSessionEcdsaOperationAllowed,
} from '../../session/operationState/warmSessionPolicyAdapter';
import type {
  ThresholdWarmSessionStatusReader,
  WarmSessionCapabilityReader,
  WarmSessionPostSignPolicy,
  WarmSessionProvisioner,
} from '../../session/warmCapabilities/types';
import { createWarmSessionStatusReader } from '../../session/warmCapabilities/statusReader';
import { createClearVolatileWarmSessionMaterialCommand } from '../../session/warmCapabilities/volatileWarmMaterialCommands';
import { parseVolatileWarmSessionId } from '../../session/warmCapabilities/volatileWarmSessionId';
import type {
  ConsumeSingleUseEmailOtpEcdsaLaneCommand,
  ConsumeSingleUseEmailOtpEcdsaLaneResult,
  ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import {
  type ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import {
  toVerifiedEcdsaPublicFactsFromRecord,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { EvmFamilyEcdsaSessionReaderDeps } from '../../interfaces/operationDeps';
import type { EvmFamilyChain } from './types';
import {
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type EvmFamilyWarmSessionServicesDeps = EvmFamilyEcdsaSessionReaderDeps & {
  touchConfirm: UiConfirmContextPort &
    UiConfirmSigningPort &
    UiConfirmSecureConfirmationPort &
    Pick<VolatileWarmMaterialPort, 'getWarmSessionStatus'> &
    Partial<Pick<DurableSealedSessionPort, 'restorePersistedSessionForSigning'>> &
    Partial<Pick<VolatileWarmMaterialPort, 'clearVolatileWarmSessionMaterial'>>;
  consumeSingleUseEmailOtpEcdsaLane?: (
    command: ConsumeSingleUseEmailOtpEcdsaLaneCommand,
  ) => ConsumeSingleUseEmailOtpEcdsaLaneResult;
  provisionThresholdEcdsaSession: (
    args: ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
};

export type EvmFamilyWarmSessionServices = Pick<
  WarmSessionCapabilityReader,
  'getWarmSession' | 'resolveEcdsaSealTransportByThresholdSessionId'
> &
  Pick<
    ThresholdWarmSessionStatusReader,
    'assertEcdsaSigningSessionReady' | 'getEcdsaSigningSessionStatus'
  > &
  Pick<WarmSessionProvisioner, 'ensureEcdsaCapabilityReady'> &
  Pick<WarmSessionPostSignPolicy, 'applyEcdsaPostSignPolicy' | 'assertEcdsaOperationAllowed'>;

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
  const clearEcdsaEphemeralMaterial = async (
    record: ThresholdEcdsaSessionRecord,
    thresholdSessionIdOverride: string | undefined,
  ): Promise<void> => {
    const publicFacts = await toVerifiedEcdsaPublicFactsFromRecord({ record });
    if (record.routerAbEcdsaHssNormalSigning) {
      clearRouterAbEcdsaHssClientPresignaturesForLane({
        relayerUrl: record.relayerUrl,
        scope: record.routerAbEcdsaHssNormalSigning.scope,
        participantIds: publicFacts.participantIds.map((participantId) => Number(participantId)),
      });
    }
    const thresholdSessionId = parseVolatileWarmSessionId(
      thresholdSessionIdOverride || record.thresholdSessionId || '',
    );
    if (
      thresholdSessionId &&
      typeof deps.touchConfirm.clearVolatileWarmSessionMaterial === 'function'
    ) {
      await deps.touchConfirm
        .clearVolatileWarmSessionMaterial(
          createClearVolatileWarmSessionMaterialCommand(thresholdSessionId),
        )
        .catch(() => undefined);
    }
  };
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
  const capabilityReader = createWarmSessionCapabilityReader({
    touchConfirm: deps.touchConfirm,
    signingSessionSeal: null,
    getEmailOtpWarmSessionStatus,
  });
  const statusReader = createWarmSessionStatusReader({
    touchConfirm: deps.touchConfirm,
    getEmailOtpWarmSessionStatus,
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
          resolveExactEcdsaRecord: (recordArgs) =>
            statusReader.resolveExactEcdsaRecord(recordArgs),
          readEcdsaCapabilityForLane: (lane) => capabilityReader.getEcdsaCapabilityForLane(lane),
          reconnectInFlightByCapability,
        },
        readyArgs,
      ),
    applyEcdsaPostSignPolicy: (policyArgs) =>
      applyWarmSessionEcdsaPostSignPolicy(
        {
          getWarmSession: (walletId) => capabilityReader.getWarmSession(walletId),
          resolveExactEcdsaRecord: (recordArgs) =>
            statusReader.resolveExactEcdsaRecord(recordArgs),
          consumeSingleUseEmailOtpEcdsaLane: deps.consumeSingleUseEmailOtpEcdsaLane,
          clearEcdsaEphemeralMaterial: ({ record, thresholdSessionId }) =>
            clearEcdsaEphemeralMaterial(record, thresholdSessionId),
        },
        policyArgs,
      ),
    assertEcdsaOperationAllowed: (operationArgs) =>
      assertWarmSessionEcdsaOperationAllowed(
        {
          getWarmSession: (walletId) => capabilityReader.getWarmSession(walletId),
          resolveExactEcdsaRecord: (recordArgs) =>
            statusReader.resolveExactEcdsaRecord(recordArgs),
        },
        operationArgs,
      ),
  };
}

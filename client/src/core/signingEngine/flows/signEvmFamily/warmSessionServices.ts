import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { ThresholdEcdsaActivationRequest } from '../../session/passkey/ecdsaSessionProvision';
import { clearThresholdEcdsaClientPresignaturesForLane } from '../../threshold/ecdsa/presignPool';
import type {
  UiConfirmContextPort,
  UiConfirmSecureConfirmationPort,
  UiConfirmSigningPort,
  DurableSealedSessionPort,
  VolatileWarmMaterialPort,
  WarmSessionStatusResult,
} from '../../uiConfirm/types';
import { createWarmSessionCapabilityReader } from '../../session/warmCapabilities/capabilityReader';
import { ensureWarmEcdsaCapabilityReady } from '../../session/passkey/ecdsaProvisioner';
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
  ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import {
  THRESHOLD_ECDSA_SESSION_STORE_SOURCES,
  type ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import {
  getThresholdEcdsaKeyRefForLane,
  getThresholdEcdsaSessionRecordForLane,
} from './ecdsaLanes';
import type { EvmFamilyEcdsaSessionReaderDeps } from '../../interfaces/operationDeps';
import type { EvmFamilyChain } from './types';
import {
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type EvmFamilyWarmSessionServicesDeps = EvmFamilyEcdsaSessionReaderDeps & {
  touchConfirm: UiConfirmContextPort &
    UiConfirmSigningPort &
    UiConfirmSecureConfirmationPort &
    Pick<VolatileWarmMaterialPort, 'getWarmSessionStatus'> &
    Partial<Pick<DurableSealedSessionPort, 'restorePersistedSessionForSigning'>> &
    Partial<Pick<VolatileWarmMaterialPort, 'clearVolatileWarmSessionMaterial'>>;
  markThresholdEcdsaEmailOtpSessionConsumedForLane?: (args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    walletSigningSessionId: string;
    thresholdSessionId: string;
    uses?: number;
  }) => void;
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
    clearThresholdEcdsaClientPresignaturesForLane({
      relayerUrl: record.relayerUrl,
      ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
      participantIds: record.participantIds,
    });
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
  const listThresholdEcdsaKeyRefsForWalletTarget = ({
    subjectId,
    chainTarget,
    source,
  }: {
    walletId: string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => {
    const sources = source ? [source] : THRESHOLD_ECDSA_SESSION_STORE_SOURCES;
    const keyRefs = [];
    for (const candidateSource of sources) {
      try {
        keyRefs.push({
          source: candidateSource,
          keyRef: getThresholdEcdsaKeyRefForLane({
            deps,
            subjectId,
            chainTarget,
            source: candidateSource,
          }),
        });
      } catch {}
    }
    return keyRefs;
  };
  const capabilityReader = createWarmSessionCapabilityReader({
    touchConfirm: deps.touchConfirm,
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
          listThresholdEcdsaKeyRefsForWalletTarget,
          canProvisionEcdsaCapability: true,
          provisionThresholdEcdsaSession: (provisionRequest) =>
            deps.provisionThresholdEcdsaSession(provisionRequest),
          touchConfirm: deps.touchConfirm,
          resolveExactEcdsaRecord: (recordArgs) =>
            statusReader.resolveExactEcdsaRecord(recordArgs),
          readEcdsaCapabilityByThresholdSessionId: (thresholdSessionId) =>
            capabilityReader.getEcdsaCapabilityByThresholdSessionId(thresholdSessionId),
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
          markEmailOtpSessionConsumed: deps.markThresholdEcdsaEmailOtpSessionConsumedForLane,
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

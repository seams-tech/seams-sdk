import type { AccountId } from '@/core/types/accountIds';
import type { BootstrapEcdsaSessionArgs } from '../thresholdLifecycle/thresholdSessionActivation';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../orchestration/thresholdActivation';
import { clearThresholdEcdsaClientPresignaturesForLane } from '../../orchestration/walletOrigin/thresholdEcdsaCoordinator';
import type {
  TouchConfirmContextPort,
  TouchConfirmSecureConfirmationPort,
  TouchConfirmSigningPort,
  WarmSessionMaterialClearer,
  WarmSessionPersistedRestorer,
  WarmSessionStatusReader,
  WarmSessionStatusResult,
} from '../../touchConfirm';
import { createWarmSessionCapabilityReader } from '../../session/warmSigning/capabilityReader';
import {
  ensureWarmEcdsaCapabilityReady,
  provisionWarmEcdsaCapability,
} from '../../session/warmSigning/ecdsaProvisioner';
import {
  applyWarmSessionEcdsaPostSignPolicy,
  assertWarmSessionEcdsaOperationAllowed,
} from '../../session/warmSigning/postSignPolicyAdapter';
import type {
  ThresholdWarmSessionStatusReader,
  WarmSessionCapabilityReader,
  WarmSessionPostSignPolicy,
  WarmSessionProvisioner,
} from '../../session/warmSigning/types';
import { createWarmSessionStatusReader } from '../../session/warmSigning/statusReader';
import { claimWarmSessionPrfFirst } from '../../session/warmSigning/runtime';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../thresholdLifecycle/thresholdSessionStore';
import { THRESHOLD_ECDSA_SESSION_STORE_SOURCES } from '../thresholdLifecycle/thresholdSessionStore';
import {
  getThresholdEcdsaKeyRefForLane,
  getThresholdEcdsaSessionRecordForLane,
  type EvmFamilyEcdsaSessionReaderDeps,
} from './ecdsaLanes';
import type { EvmFamilyChain } from './types';
import {
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
} from '../../session/signingSession/ecdsaChainTarget';

export type EvmFamilyWarmSessionServicesDeps = EvmFamilyEcdsaSessionReaderDeps & {
  touchConfirm: TouchConfirmContextPort &
    TouchConfirmSigningPort &
    TouchConfirmSecureConfirmationPort &
    WarmSessionStatusReader &
    Partial<WarmSessionPersistedRestorer> &
    Partial<WarmSessionMaterialClearer>;
  markThresholdEcdsaEmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: string;
    chainTarget: ThresholdEcdsaChainTarget;
    uses?: number;
  }) => void;
  provisionThresholdEcdsaSession: (
    args: BootstrapEcdsaSessionArgs,
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
  const clearEcdsaEphemeralMaterial = async (args: {
    record: ThresholdEcdsaSessionRecord;
    thresholdSessionId?: string;
  }): Promise<void> => {
    clearThresholdEcdsaClientPresignaturesForLane({
      relayerUrl: args.record.relayerUrl,
      ecdsaThresholdKeyId: args.record.ecdsaThresholdKeyId,
      participantIds: args.record.participantIds,
    });
    const thresholdSessionId = String(
      args.thresholdSessionId || args.record.thresholdSessionId || '',
    ).trim();
    if (thresholdSessionId && typeof deps.touchConfirm.clearWarmSessionMaterial === 'function') {
      await deps.touchConfirm
        .clearWarmSessionMaterial({ sessionId: thresholdSessionId })
        .catch(() => undefined);
    }
  };
  const listThresholdEcdsaKeyRefsForAccountTarget = ({
    nearAccountId,
    chainTarget,
    source,
  }: {
    nearAccountId: AccountId | string;
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
            subjectId: toWalletSubjectId(String(nearAccountId)),
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
  const provisionEcdsaCapability: WarmSessionProvisioner['provisionEcdsaCapability'] = (
    provisionArgs,
  ) =>
    provisionWarmEcdsaCapability(
      {
        getWarmSession: (nearAccountId) => capabilityReader.getWarmSession(nearAccountId),
        listThresholdEcdsaKeyRefsForAccountTarget,
        provisionThresholdEcdsaSession: (provisionRequest) =>
          deps.provisionThresholdEcdsaSession(provisionRequest),
        claimPrfFirstByThresholdSessionId: (claimArgs) =>
          claimWarmSessionPrfFirst({
            touchConfirm: deps.touchConfirm,
            thresholdSessionId: claimArgs.thresholdSessionId,
            errorContext: claimArgs.errorContext,
            uses: claimArgs.uses,
            ...(typeof claimArgs.consume === 'boolean' ? { consume: claimArgs.consume } : {}),
            ...(claimArgs.curve ? { curve: claimArgs.curve } : {}),
            ...(claimArgs.chainTarget ? { chainTarget: claimArgs.chainTarget } : {}),
            restoreBeforeClaim: async () => {
              if (claimArgs.authMethod !== 'passkey') return;
              if (typeof deps.touchConfirm.restorePersistedSessionForSigning !== 'function') return;
              const walletId = String(claimArgs.walletId || '').trim();
              const walletSigningSessionId = String(claimArgs.walletSigningSessionId || '').trim();
              const thresholdSessionId = String(claimArgs.thresholdSessionId || '').trim();
              if (!walletId || !walletSigningSessionId || !thresholdSessionId) return;
              const chainTarget =
                claimArgs.chainTarget ||
                provisionArgs.chainTarget;
              await deps.touchConfirm.restorePersistedSessionForSigning({
                walletId,
                authMethod: 'passkey',
                curve: 'ecdsa',
                chainTarget,
                walletSigningSessionId,
                thresholdSessionId,
                reason: 'transaction',
              });
            },
          }),
      },
      provisionArgs,
    );

  return {
    getWarmSession: (nearAccountId) => capabilityReader.getWarmSession(nearAccountId),
    resolveEcdsaSealTransportByThresholdSessionId: (args) =>
      capabilityReader.resolveEcdsaSealTransportByThresholdSessionId(args),
    assertEcdsaSigningSessionReady: (readyArgs) =>
      statusReader.assertEcdsaSigningSessionReady(readyArgs),
    getEcdsaSigningSessionStatus: (statusArgs) =>
      statusReader.getEcdsaSigningSessionStatus(statusArgs),
    ensureEcdsaCapabilityReady: (readyArgs) =>
      ensureWarmEcdsaCapabilityReady(
        {
          getWarmSession: (nearAccountId) => capabilityReader.getWarmSession(nearAccountId),
          listThresholdEcdsaKeyRefsForAccountTarget,
          canProvisionEcdsaCapability: true,
          provisionEcdsaCapability,
          resolveCurrentEcdsaRecord: (recordArgs) =>
            statusReader.resolveCurrentEcdsaRecord(recordArgs),
          readEcdsaCapabilityByThresholdSessionId: (thresholdSessionId) =>
            capabilityReader.getEcdsaCapabilityByThresholdSessionId(thresholdSessionId),
          reconnectInFlightByCapability,
        },
        readyArgs,
      ),
    applyEcdsaPostSignPolicy: (policyArgs) =>
      applyWarmSessionEcdsaPostSignPolicy(
        {
          getWarmSession: (nearAccountId) => capabilityReader.getWarmSession(nearAccountId),
          resolveCurrentEcdsaRecord: (recordArgs) =>
            statusReader.resolveCurrentEcdsaRecord(recordArgs),
          markEmailOtpSessionConsumed: deps.markThresholdEcdsaEmailOtpSessionConsumedForAccount,
          clearEcdsaEphemeralMaterial,
        },
        policyArgs,
      ),
    assertEcdsaOperationAllowed: (operationArgs) =>
      assertWarmSessionEcdsaOperationAllowed(
        {
          getWarmSession: (nearAccountId) => capabilityReader.getWarmSession(nearAccountId),
          resolveCurrentEcdsaRecord: (recordArgs) =>
            statusReader.resolveCurrentEcdsaRecord(recordArgs),
        },
        operationArgs,
      ),
  };
}

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

export type EvmFamilyWarmSessionServicesDeps = EvmFamilyEcdsaSessionReaderDeps & {
  touchConfirm: TouchConfirmContextPort &
    TouchConfirmSigningPort &
    TouchConfirmSecureConfirmationPort &
    WarmSessionStatusReader &
    Partial<WarmSessionPersistedRestorer> &
    Partial<WarmSessionMaterialClearer>;
  markThresholdEcdsaEmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: string;
    chain: EvmFamilyChain;
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
    nearAccountId: AccountId | string;
    chain: EvmFamilyChain;
    thresholdSessionId?: string;
    source?: ThresholdEcdsaSessionStoreSource;
  }): Promise<void> => {
    if (!args.source) {
      throw new Error(
        '[SigningEngine] ECDSA signing source is required for signing-artifact cleanup',
      );
    }
    const record = getThresholdEcdsaSessionRecordForLane({
      deps,
      nearAccountId: String(args.nearAccountId),
      chain: args.chain,
      source: args.source,
    });
    clearThresholdEcdsaClientPresignaturesForLane({
      relayerUrl: record.relayerUrl,
      ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
      participantIds: record.participantIds,
    });
    const thresholdSessionId = String(
      args.thresholdSessionId || record.thresholdSessionId || '',
    ).trim();
    if (thresholdSessionId && typeof deps.touchConfirm.clearWarmSessionMaterial === 'function') {
      await deps.touchConfirm
        .clearWarmSessionMaterial({ sessionId: thresholdSessionId })
        .catch(() => undefined);
    }
  };
  const listThresholdEcdsaSessionRecordsForLookup = ({
    nearAccountId,
    chain,
  }: {
    nearAccountId: AccountId | string;
    chain: EvmFamilyChain;
  }): ThresholdEcdsaSessionRecord[] => {
    const records: ThresholdEcdsaSessionRecord[] = [];
    for (const source of THRESHOLD_ECDSA_SESSION_STORE_SOURCES) {
      try {
        records.push(
          getThresholdEcdsaSessionRecordForLane({
            deps,
            nearAccountId: String(nearAccountId),
            chain,
            source,
          }),
        );
      } catch {}
    }
    return records;
  };
  const listThresholdEcdsaKeyRefsForLookup = ({
    nearAccountId,
    chain,
    source,
  }: {
    nearAccountId: AccountId | string;
    chain: EvmFamilyChain;
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
            nearAccountId: String(nearAccountId),
            chain,
            source: candidateSource,
          }),
        });
      } catch {}
    }
    return keyRefs;
  };
  const capabilityReader = createWarmSessionCapabilityReader({
    touchConfirm: deps.touchConfirm,
    listThresholdEcdsaSessionRecordsForLookup,
    getEmailOtpWarmSessionStatus,
  });
  const statusReader = createWarmSessionStatusReader({
    touchConfirm: deps.touchConfirm,
    getEmailOtpWarmSessionStatus,
    listThresholdEcdsaSessionRecordsForLookup,
  });
  const provisionEcdsaCapability: WarmSessionProvisioner['provisionEcdsaCapability'] = (
    provisionArgs,
  ) =>
    provisionWarmEcdsaCapability(
      {
        getWarmSession: (nearAccountId) => capabilityReader.getWarmSession(nearAccountId),
        listThresholdEcdsaKeyRefsForLookup,
        provisionThresholdEcdsaSession: deps.provisionThresholdEcdsaSession,
        claimPrfFirstByThresholdSessionId: (claimArgs) =>
          claimWarmSessionPrfFirst({
            touchConfirm: deps.touchConfirm,
            thresholdSessionId: claimArgs.thresholdSessionId,
            errorContext: claimArgs.errorContext,
            uses: claimArgs.uses,
            ...(typeof claimArgs.consume === 'boolean' ? { consume: claimArgs.consume } : {}),
            ...(claimArgs.curve ? { curve: claimArgs.curve } : {}),
            ...(claimArgs.chain ? { chain: claimArgs.chain } : {}),
            restoreBeforeClaim: async () => {
              if (claimArgs.authMethod !== 'passkey') return;
              if (typeof deps.touchConfirm.restorePersistedSessionForSigning !== 'function') return;
              const walletId = String(claimArgs.walletId || '').trim();
              const walletSigningSessionId = String(claimArgs.walletSigningSessionId || '').trim();
              const thresholdSessionId = String(claimArgs.thresholdSessionId || '').trim();
              if (!walletId || !walletSigningSessionId || !thresholdSessionId) return;
              await deps.touchConfirm.restorePersistedSessionForSigning({
                walletId,
                authMethod: 'passkey',
                curve: 'ecdsa',
                chain:
                  claimArgs.chain === 'tempo' || claimArgs.chain === 'evm'
                    ? claimArgs.chain
                    : provisionArgs.chain,
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
    resolveEcdsaSealTransportByThresholdSessionId: (thresholdSessionId) =>
      capabilityReader.resolveEcdsaSealTransportByThresholdSessionId(thresholdSessionId),
    assertEcdsaSigningSessionReady: (readyArgs) =>
      statusReader.assertEcdsaSigningSessionReady(readyArgs),
    getEcdsaSigningSessionStatus: (statusArgs) =>
      statusReader.getEcdsaSigningSessionStatus(statusArgs),
    ensureEcdsaCapabilityReady: (readyArgs) =>
      ensureWarmEcdsaCapabilityReady(
        {
          getWarmSession: (nearAccountId) => capabilityReader.getWarmSession(nearAccountId),
          listThresholdEcdsaKeyRefsForLookup,
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

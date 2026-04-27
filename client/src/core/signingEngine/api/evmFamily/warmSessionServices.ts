import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { AccountId } from '@/core/types/accountIds';
import type { BootstrapEcdsaSessionArgs } from '../thresholdLifecycle/thresholdSessionActivation';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../orchestration/thresholdActivation';
import { clearThresholdEcdsaClientPresignaturesForLane } from '../../orchestration/walletOrigin/thresholdEcdsaCoordinator';
import type {
  TouchConfirmContextPort,
  TouchConfirmSecureConfirmationPort,
  TouchConfirmSigningPort,
  WarmSessionMaterialClearer,
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
import type { WarmSessionSealedRestoreEvent } from '../../session/warmSigning/sealedRefreshRestorer';
import type { SigningSessionSealedStoreRecord } from '../session/signingSessionSealedStore';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../thresholdLifecycle/thresholdSessionStore';
import { THRESHOLD_ECDSA_SESSION_STORE_SOURCES } from '../thresholdLifecycle/thresholdSessionStore';
import {
  getThresholdEcdsaKeyRefForLane,
  getThresholdEcdsaSessionRecordForLane,
  type EvmFamilyEcdsaSessionReaderDeps,
} from './ecdsaLanes';
import { emitEvmFamilySigningEvent } from './events';
import type { EvmFamilyChain, EvmFamilyLifecycleEventCallback } from './types';

export type EvmFamilyWarmSessionServicesDeps = EvmFamilyEcdsaSessionReaderDeps & {
  touchConfirm: TouchConfirmContextPort &
    TouchConfirmSigningPort &
    TouchConfirmSecureConfirmationPort &
    WarmSessionStatusReader &
    Partial<WarmSessionMaterialClearer>;
  markThresholdEcdsaEmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: string;
    chain: EvmFamilyChain;
  }) => void;
  provisionThresholdEcdsaSession: (
    args: BootstrapEcdsaSessionArgs,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord?: (args: {
    sealedRecord: SigningSessionSealedStoreRecord;
    ecdsaRecord: ThresholdEcdsaSessionRecord;
    ed25519Record?: ThresholdEd25519SessionRecord | null;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    remainingUses: number;
    expiresAtMs: number;
  } | null>;
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
  onEvent?: EvmFamilyLifecycleEventCallback,
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
      throw new Error('[SigningEngine] ECDSA signing source is required for signing-artifact cleanup');
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
    if (
      thresholdSessionId &&
      typeof deps.touchConfirm.clearWarmSessionMaterial === 'function'
    ) {
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
  const onSealedRestore = (event: WarmSessionSealedRestoreEvent): void => {
    const chain = event.chain === 'evm' ? 'evm' : 'tempo';
    if (event.status === 'started') {
      emitEvmFamilySigningEvent(onEvent, {
        phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
        status: 'waiting_for_user',
        accountId: String(event.accountId),
        message: 'Restoring signing session...',
        interaction: { kind: 'transaction_confirmation', overlay: 'show' },
        data: {
          chain,
          thresholdSessionId: event.thresholdSessionId,
          ...(event.walletSigningSessionId
            ? { walletSigningSessionId: event.walletSigningSessionId }
            : {}),
        },
      });
      return;
    }
    if (event.status === 'restored') {
      emitEvmFamilySigningEvent(onEvent, {
        phase: SigningEventPhase.STEP_06_AUTH_WARM_SESSION_CLAIMED,
        status: 'succeeded',
        accountId: String(event.accountId),
        message: 'Signing session restored',
        interaction: { kind: 'none', overlay: 'none' },
        data: {
          chain,
          thresholdSessionId: event.thresholdSessionId,
          ...(event.walletSigningSessionId
            ? { walletSigningSessionId: event.walletSigningSessionId }
            : {}),
        },
      });
    }
  };
  const capabilityReader = createWarmSessionCapabilityReader({
    touchConfirm: deps.touchConfirm,
    clearEcdsaEphemeralMaterial,
    listThresholdEcdsaSessionRecordsForLookup,
    rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord:
      deps.rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord,
    getEmailOtpWarmSessionStatus,
    onSealedRestore,
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

import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { SigningOperationIntent } from '../../session/operationState/types';
import {
  createEvmFamilyWarmSessionServices,
  type EvmFamilyWarmSessionServicesDeps,
} from './warmSessionServices';
import { type ResolvedEvmFamilyEcdsaSigningLane } from './ecdsaLanes';
import { emitEvmFamilySigningEvent } from './events';
import type { EvmFamilyLifecycleEventCallback } from './types';
import { throwIfEvmFamilySigningCancelled } from './errors';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../../session/identity/laneIdentity';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaSessionIdentity,
  getEcdsaSessionProvisionIdentity,
  type EcdsaSessionProvisionPlan,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';

export type EvmFamilyThresholdEcdsaReadinessDeps = EvmFamilyWarmSessionServicesDeps & {
  seamsWebConfigs: SeamsConfigsReadonly;
};

type EvmFamilyThresholdEcdsaReadinessBaseArgs = {
  deps: EvmFamilyThresholdEcdsaReadinessDeps;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  chainId: number;
  reconnectSessionIdentity: {
    thresholdSessionId: string;
    walletSigningSessionId: string;
  };
  operationUsesNeeded?: number;
  sessionBudgetUses: number;
  shouldAbort?: () => boolean;
  onEvent?: EvmFamilyLifecycleEventCallback;
};

type EvmFamilyThresholdEcdsaExistingRecordPlan = Extract<
  EcdsaSessionProvisionPlan,
  {
    kind:
      | 'wallet_session_ecdsa_reconnect'
      | 'passkey_ecdsa_session_provision';
  }
>;

type EvmFamilyThresholdEcdsaFreshProvisionPlan = Extract<
  EcdsaSessionProvisionPlan,
  { kind: 'email_otp_ecdsa_session_provision' }
>;

type PlannedEvmFamilyThresholdEcdsaReadinessArgs =
  | (EvmFamilyThresholdEcdsaReadinessBaseArgs & {
      record: ThresholdEcdsaSessionRecord;
      keyRef?: never;
      reconnectPlan: EvmFamilyThresholdEcdsaExistingRecordPlan;
    })
  | (EvmFamilyThresholdEcdsaReadinessBaseArgs & {
      record: ThresholdEcdsaSessionRecord | null;
      keyRef?: never;
      reconnectPlan: EvmFamilyThresholdEcdsaFreshProvisionPlan;
    });

function resolveManagedRuntimeScopeBootstrap(
  configs: SeamsConfigsReadonly,
): { environmentId: string; publishableKey: string } | undefined {
  const registration = configs.registration;
  if (registration.mode !== 'managed') return undefined;
  const environmentId = String(registration.environmentId || '').trim();
  const publishableKey = String(registration.publishableKey || '').trim();
  if (!environmentId || !publishableKey) return undefined;
  return { environmentId, publishableKey };
}

function requireEcdsaStoreSource(
  lane: ResolvedEvmFamilyEcdsaSigningLane,
): ThresholdEcdsaSessionStoreSource {
  switch (lane.storageSource) {
    case 'login':
    case 'registration':
    case 'manual-bootstrap':
    case 'email_otp':
      return lane.storageSource;
    default:
      throw new Error('[SigningEngine] ECDSA key-ref readiness requires an ECDSA storage source');
  }
}

export async function ensureEvmFamilyThresholdEcdsaRecordReady(
  args: PlannedEvmFamilyThresholdEcdsaReadinessArgs,
): Promise<ThresholdEcdsaSessionRecord> {
  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  const chain = args.lane.chainFamily;
  const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
    chain,
    chainId: args.chainId,
  });
  const source = requireEcdsaStoreSource(args.lane);
  const walletId = toWalletId(args.lane.walletId);
  const reconnectSessionIdentity = buildEcdsaSessionIdentity({
    thresholdSessionId: args.reconnectSessionIdentity.thresholdSessionId,
    walletSigningSessionId: args.reconnectSessionIdentity.walletSigningSessionId,
  });
  const warmSessionServices = createEvmFamilyWarmSessionServices(args.deps);
  const operationUsesNeeded = Math.max(1, Math.floor(Number(args.operationUsesNeeded) || 1));
  const sessionBudgetUses = Math.max(1, Math.floor(Number(args.sessionBudgetUses) || 1));
  const selectedRecord = args.record;
  const reconnectPlan = args.reconnectPlan;
  const reconnectPlanIdentity = getEcdsaSessionProvisionIdentity(reconnectPlan);
  if (
    reconnectPlanIdentity.thresholdSessionId !== reconnectSessionIdentity.thresholdSessionId ||
    reconnectPlanIdentity.walletSigningSessionId !== reconnectSessionIdentity.walletSigningSessionId
  ) {
    throw new Error(
      '[SigningEngine][ecdsa] reconnect plan identity does not match requested reconnect identity',
    );
  }
  try {
    emitEvmFamilySigningEvent(args.onEvent, {
      phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
      status: 'running',
      accountId: walletId,
      interaction: { kind: 'none', overlay: 'none' },
      data: { chain },
    });
  } catch {}
  const readyCapabilityArgs = {
    walletId,
    chainTarget,
    source,
    runtimeScopeBootstrap: resolveManagedRuntimeScopeBootstrap(args.deps.seamsWebConfigs),
    usesNeeded: operationUsesNeeded,
    sessionBudgetUses,
    operationIntent: SigningOperationIntent.TransactionSign,
    assertNotCancelled: () => {
      throwIfEvmFamilySigningCancelled(args.shouldAbort);
    },
  };
  const readyCapability =
    reconnectPlan.kind === 'wallet_session_ecdsa_reconnect' ||
    reconnectPlan.kind === 'passkey_ecdsa_session_provision'
      ? await (async () => {
          if (!selectedRecord) {
            throw new Error('[SigningEngine][ecdsa] reconnect readiness requires session record');
          }
          return await warmSessionServices.ensureEcdsaCapabilityReady({
            ...readyCapabilityArgs,
            plan: reconnectPlan,
            record: selectedRecord,
          });
        })()
      : await warmSessionServices.ensureEcdsaCapabilityReady({
          ...readyCapabilityArgs,
          plan: reconnectPlan,
          record: selectedRecord,
        });

  const refreshedRecord = readyCapability.capability.record;
  if (!refreshedRecord) {
    throw new Error('[SigningEngine] ECDSA reconnect did not return a ready session record');
  }
  const refreshedSessionIdentity = buildEcdsaSessionIdentity({
    thresholdSessionId: refreshedRecord.thresholdSessionId,
    walletSigningSessionId: refreshedRecord.walletSigningSessionId,
  });
  if (
    refreshedSessionIdentity.thresholdSessionId !== reconnectSessionIdentity.thresholdSessionId ||
    refreshedSessionIdentity.walletSigningSessionId !== reconnectSessionIdentity.walletSigningSessionId
  ) {
    throw new Error(
      [
        '[SigningEngine] ECDSA reconnect returned a different exact session identity',
        `expected=${reconnectSessionIdentity.walletSigningSessionId}:${reconnectSessionIdentity.thresholdSessionId}`,
        `actual=${refreshedSessionIdentity.walletSigningSessionId}:${refreshedSessionIdentity.thresholdSessionId}`,
      ].join(' '),
    );
  }

  emitEvmFamilySigningEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_SUCCEEDED,
    status: 'succeeded',
    accountId: walletId,
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain },
  });

  return refreshedRecord;
}

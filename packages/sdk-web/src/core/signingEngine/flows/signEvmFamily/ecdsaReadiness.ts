import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { SigningOperationIntent } from '../../session/operationState/types';
import {
  createEvmFamilyWarmSessionServices,
  type EvmFamilyWarmSessionServicesDeps,
} from './warmSessionServices';
import {
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import { emitEvmFamilySigningEvent } from './events';
import type { EvmFamilyLifecycleEventCallback } from './types';
import { throwIfEvmFamilySigningCancelled } from './errors';
import type {
  ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
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

type PlannedEvmFamilyThresholdEcdsaReadinessArgs = EvmFamilyThresholdEcdsaReadinessBaseArgs & {
  record: ThresholdEcdsaSessionRecord;
  keyRef?: never;
  reconnectPlan: EcdsaSessionProvisionPlan;
};

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
  const { thresholdSessionId, walletSigningSessionId } = reconnectSessionIdentity;
  const warmSessionServices = createEvmFamilyWarmSessionServices(args.deps);
  const operationUsesNeeded = Math.max(
    1,
    Math.floor(Number(args.operationUsesNeeded) || 1),
  );
  const sessionBudgetUses = Math.max(
    1,
    Math.floor(Number(args.sessionBudgetUses) || 1),
  );
  const selectedRecord = args.record;
  const reconnectPlan = args.reconnectPlan;
  const reconnectPlanIdentity = getEcdsaSessionProvisionIdentity(reconnectPlan);
  if (
    reconnectPlanIdentity.thresholdSessionId !== thresholdSessionId ||
    reconnectPlanIdentity.walletSigningSessionId !== walletSigningSessionId
  ) {
    throw new Error('[SigningEngine][ecdsa] reconnect plan identity does not match requested reconnect identity');
  }
  const readyCapability = await warmSessionServices.ensureEcdsaCapabilityReady({
    walletId,
    chainTarget,
    plan: reconnectPlan,
    record: selectedRecord,
    source,
    runtimeScopeBootstrap: resolveManagedRuntimeScopeBootstrap(args.deps.seamsWebConfigs),
    usesNeeded: operationUsesNeeded,
    sessionBudgetUses,
    operationIntent: SigningOperationIntent.TransactionSign,
    beforeReconnect: async () => {
      try {
        emitEvmFamilySigningEvent(args.onEvent, {
          phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
          status: 'running',
          accountId: walletId,
          interaction: { kind: 'none', overlay: 'none' },
          data: { chain },
        });
      } catch {}
    },
    assertNotCancelled: () => {
      throwIfEvmFamilySigningCancelled(args.shouldAbort);
    },
  });

  const refreshedRecord = readyCapability.capability.record;
  if (!refreshedRecord) {
    throw new Error('[SigningEngine] ECDSA reconnect did not return a ready session record');
  }
  const refreshedThresholdSessionId = String(refreshedRecord.thresholdSessionId).trim();
  const refreshedWalletSigningSessionId = String(
    refreshedRecord.walletSigningSessionId,
  ).trim();
  if (
    refreshedThresholdSessionId !== thresholdSessionId ||
    refreshedWalletSigningSessionId !== walletSigningSessionId
  ) {
    throw new Error(
      [
        '[SigningEngine] ECDSA reconnect returned a different exact session identity',
        `expected=${walletSigningSessionId}:${thresholdSessionId}`,
        `actual=${refreshedWalletSigningSessionId || 'missing'}:${refreshedThresholdSessionId || 'missing'}`,
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

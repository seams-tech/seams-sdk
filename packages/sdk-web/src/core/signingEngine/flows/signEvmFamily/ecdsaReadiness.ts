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
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaSessionIdentity,
  getEcdsaProvisionPlanLaneIdentity,
  type EcdsaSessionProvisionPlan,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import { requireEvmFamilyEcdsaSigner } from '../../session/identity/exactSigningLaneIdentity';

export type EvmFamilyThresholdEcdsaReadinessDeps = EvmFamilyWarmSessionServicesDeps & {
  seamsWebConfigs: SeamsConfigsReadonly;
};

type EvmFamilyThresholdEcdsaReadinessBaseArgs = {
  deps: EvmFamilyThresholdEcdsaReadinessDeps;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  chainId: number;
  reconnectSessionIdentity: {
    thresholdSessionId: string;
    signingGrantId: string;
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
): { projectEnvironmentId: string; publishableKey: string } | undefined {
  const registration = configs.registration;
  if (registration.mode !== 'managed') return undefined;
  const projectEnvironmentId = String(registration.projectEnvironmentId || '').trim();
  const publishableKey = String(registration.publishableKey || '').trim();
  if (!projectEnvironmentId || !publishableKey) return undefined;
  return { projectEnvironmentId, publishableKey };
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

  const signer = requireEvmFamilyEcdsaSigner(
    args.lane.identity,
    'EVM-family threshold ECDSA readiness',
  );
  const chain = signer.chainTarget.kind;
  const chainTarget = signer.chainTarget;
  if (Number(chainTarget.chainId) !== Number(args.chainId)) {
    throw new Error('[SigningEngine][ecdsa] reconnect chain id does not match selected lane');
  }
  const source = requireEcdsaStoreSource(args.lane);
  const walletId = toWalletId(signer.walletId);
  const reconnectSessionIdentity = buildEcdsaSessionIdentity({
    thresholdSessionId: args.reconnectSessionIdentity.thresholdSessionId,
    signingGrantId: args.reconnectSessionIdentity.signingGrantId,
  });
  const warmSessionServices = createEvmFamilyWarmSessionServices(args.deps);
  const operationUsesNeeded = Math.max(1, Math.floor(Number(args.operationUsesNeeded) || 1));
  const sessionBudgetUses = Math.max(1, Math.floor(Number(args.sessionBudgetUses) || 1));
  const selectedRecord = args.record;
  const reconnectPlan = args.reconnectPlan;
  const reconnectPlanIdentity = getEcdsaProvisionPlanLaneIdentity(reconnectPlan);
  if (
    reconnectPlanIdentity.thresholdSessionId !== reconnectSessionIdentity.thresholdSessionId ||
    reconnectPlanIdentity.signingGrantId !== reconnectSessionIdentity.signingGrantId
  ) {
    throw new Error(
      '[SigningEngine][ecdsa] reconnect plan identity does not match requested reconnect identity',
    );
  }
  try {
    emitEvmFamilySigningEvent(args.onEvent, {
      phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
      status: 'running',
      walletId,
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
    signingGrantId: refreshedRecord.signingGrantId,
  });
  if (
    refreshedSessionIdentity.thresholdSessionId !== reconnectSessionIdentity.thresholdSessionId ||
    refreshedSessionIdentity.signingGrantId !== reconnectSessionIdentity.signingGrantId
  ) {
    throw new Error(
      [
        '[SigningEngine] ECDSA reconnect returned a different exact session identity',
        `expected=${reconnectSessionIdentity.signingGrantId}:${reconnectSessionIdentity.thresholdSessionId}`,
        `actual=${refreshedSessionIdentity.signingGrantId}:${refreshedSessionIdentity.thresholdSessionId}`,
      ].join(' '),
    );
  }

  emitEvmFamilySigningEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_SUCCEEDED,
    status: 'succeeded',
    walletId,
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain },
  });

  return refreshedRecord;
}

import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import { SigningOperationIntent } from '../../session/operationState/types';
import {
  createEvmFamilyWarmSessionServices,
  type EvmFamilyWarmSessionServicesDeps,
} from './warmSessionServices';
import {
  readSelectedEcdsaKeyRefForLane,
  readSelectedEcdsaRecordForLane,
  summarizeEvmFamilyEcdsaKeyRef,
  summarizeEvmFamilyEcdsaLane,
  summarizeEvmFamilyEcdsaSessionRecord,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import { emitEvmFamilySigningEvent } from './events';
import type { EvmFamilyLifecycleEventCallback } from './types';
import { throwIfEvmFamilySigningCancelled } from './errors';
import type {
  ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../../session/identity/laneIdentity';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type EvmFamilyThresholdEcdsaReadinessDeps = EvmFamilyWarmSessionServicesDeps & {
  seamsPasskeyConfigs: SeamsConfigsReadonly;
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

export async function ensureEvmFamilyThresholdEcdsaKeyRefReady(args: {
  deps: EvmFamilyThresholdEcdsaReadinessDeps;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  chainId: number;
  keyRef: ThresholdEcdsaSecp256k1KeyRef | undefined;
  reconnectSessionIdentity: {
    thresholdSessionId: string;
    walletSigningSessionId: string;
  };
  clientRootShare32B64u?: string;
  webauthnAuthentication?: WebAuthnAuthenticationCredential;
  remainingUses?: number;
  operationUsesNeeded?: number;
  sessionBudgetUses: number;
  shouldAbort?: () => boolean;
  onEvent?: EvmFamilyLifecycleEventCallback;
}): Promise<ThresholdEcdsaSecp256k1KeyRef> {
  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  const chain = args.lane.chainFamily;
  const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
    chain,
    chainId: args.chainId,
  });
  const source = requireEcdsaStoreSource(args.lane);
  const nearAccountId = String(args.lane.accountId);
  const thresholdSessionId = String(args.reconnectSessionIdentity.thresholdSessionId || '').trim();
  const walletSigningSessionId = String(
    args.reconnectSessionIdentity.walletSigningSessionId || '',
  ).trim();
  if (!thresholdSessionId || !walletSigningSessionId) {
    throw new Error('[SigningEngine] ECDSA reconnect requires exact fresh session identity');
  }
  const warmSessionServices = createEvmFamilyWarmSessionServices(args.deps);
  const operationUsesNeeded = Math.max(
    1,
    Math.floor(Number(args.operationUsesNeeded ?? args.remainingUses) || 1),
  );
  const sessionBudgetUses = Math.max(
    1,
    Math.floor(Number(args.sessionBudgetUses) || 1),
  );
  const resolvedKeyRef =
    args.keyRef ||
    readSelectedEcdsaKeyRefForLane({
      deps: args.deps,
      lane: args.lane,
    });
  let selectedRecord: ThresholdEcdsaSessionRecord | undefined;
  try {
    selectedRecord = readSelectedEcdsaRecordForLane({
      deps: args.deps,
      lane: args.lane,
    });
  } catch {
    selectedRecord = undefined;
  }
  try {
    console.info('[SigningEngine][ecdsa][reconnect-selected-lane]', {
      nearAccountId,
      chain,
      chainId: args.chainId,
      source,
      selectedLane: summarizeEvmFamilyEcdsaLane(args.lane),
      requestedReconnectIdentity: {
        thresholdSessionId,
        walletSigningSessionId,
      },
      selectedKeyRef: summarizeEvmFamilyEcdsaKeyRef(resolvedKeyRef),
      selectedRecord: summarizeEvmFamilyEcdsaSessionRecord(selectedRecord),
      operationUsesNeeded,
      sessionBudgetUses,
    });
  } catch {}

  const readyCapability = await warmSessionServices.ensureEcdsaCapabilityReady({
    nearAccountId,
    subjectId: args.lane.subjectId,
    chainTarget,
    keyRef: resolvedKeyRef,
    source,
    runtimeScopeBootstrap: resolveManagedRuntimeScopeBootstrap(args.deps.seamsPasskeyConfigs),
    usesNeeded: operationUsesNeeded,
    sessionBudgetUses,
    operationIntent: SigningOperationIntent.TransactionSign,
    sessionId: thresholdSessionId,
    walletSigningSessionId,
    ...(args.clientRootShare32B64u ? { clientRootShare32B64u: args.clientRootShare32B64u } : {}),
    ...(args.webauthnAuthentication ? { webauthnAuthentication: args.webauthnAuthentication } : {}),
    beforeReconnect: async () => {
      try {
        emitEvmFamilySigningEvent(args.onEvent, {
          phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
          status: 'running',
          accountId: nearAccountId,
          interaction: { kind: 'none', overlay: 'none' },
          data: { chain },
        });
      } catch {}
    },
    assertNotCancelled: () => {
      throwIfEvmFamilySigningCancelled(args.shouldAbort);
    },
  });

  const refreshedThresholdSessionId = String(
    readyCapability.keyRef?.thresholdSessionId || '',
  ).trim();
  const refreshedWalletSigningSessionId = String(
    readyCapability.keyRef?.walletSigningSessionId || '',
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
    accountId: nearAccountId,
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain },
  });

  return readyCapability.keyRef;
}

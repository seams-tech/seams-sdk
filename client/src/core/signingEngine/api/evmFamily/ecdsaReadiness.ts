import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { TatchiConfigsReadonly } from '@/core/types/tatchi';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import { SigningOperationIntent } from '../../session/signingSession/types';
import {
  createEvmFamilyWarmSessionServices,
  type EvmFamilyWarmSessionServicesDeps,
} from './warmSessionServices';
import {
  readSelectedEcdsaKeyRefForLane,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import { emitEvmFamilySigningEvent } from './events';
import type { EvmFamilyLifecycleEventCallback } from './types';
import { throwIfEvmFamilySigningCancelled } from './errors';
import type { ThresholdEcdsaSessionStoreSource } from '../thresholdLifecycle/thresholdSessionStore';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';

export type EvmFamilyThresholdEcdsaReadinessDeps = EvmFamilyWarmSessionServicesDeps & {
  tatchiPasskeyConfigs: TatchiConfigsReadonly;
};

function resolveManagedRuntimeScopeBootstrap(
  configs: TatchiConfigsReadonly,
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
  keyRef: ThresholdEcdsaSecp256k1KeyRef | undefined;
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
  const source = requireEcdsaStoreSource(args.lane);
  const nearAccountId = String(args.lane.accountId);
  const thresholdSessionId = String(args.lane.thresholdSessionId);
  const walletSigningSessionId = String(args.lane.walletSigningSessionId);
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

  const readyCapability = await warmSessionServices.ensureEcdsaCapabilityReady({
    nearAccountId,
    chain,
    keyRef: resolvedKeyRef,
    source,
    runtimeScopeBootstrap: resolveManagedRuntimeScopeBootstrap(args.deps.tatchiPasskeyConfigs),
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

  emitEvmFamilySigningEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_SUCCEEDED,
    status: 'succeeded',
    accountId: nearAccountId,
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain },
  });

  return readyCapability.keyRef;
}

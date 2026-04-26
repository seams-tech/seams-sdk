import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { TatchiConfigsReadonly } from '@/core/types/tatchi';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import { SigningOperationIntent, type SigningLaneContext } from '../../session/signingSessionTypes';
import {
  createEvmFamilySigningSessionCoordinator,
  type EvmFamilySigningSessionCoordinatorDeps,
} from './signingSessionCoordinator';
import {
  readSelectedEcdsaKeyRefForLane,
} from './ecdsaLanes';
import { emitEvmFamilySigningEvent } from './events';
import type { EvmFamilyChain, EvmFamilyLifecycleEventCallback } from './types';
import { throwIfEvmFamilySigningCancelled } from './errors';
import type { ThresholdEcdsaSessionStoreSource } from '../thresholdLifecycle/thresholdSessionStore';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';

export type EvmFamilyThresholdEcdsaReadinessDeps = EvmFamilySigningSessionCoordinatorDeps & {
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

function requireEvmFamilyEcdsaChain(lane: SigningLaneContext): EvmFamilyChain {
  if (lane.curve !== 'ecdsa' || lane.keyKind !== 'threshold_ecdsa_secp256k1') {
    throw new Error('[SigningEngine] ECDSA key-ref readiness requires an ECDSA signing lane');
  }
  if (lane.chainFamily === 'evm' || lane.chainFamily === 'tempo') return lane.chainFamily;
  throw new Error('[SigningEngine] ECDSA key-ref readiness requires an EVM-family chain lane');
}

function requireEcdsaStoreSource(lane: SigningLaneContext): ThresholdEcdsaSessionStoreSource {
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
  lane: SigningLaneContext;
  keyRef: ThresholdEcdsaSecp256k1KeyRef | undefined;
  sessionId?: string;
  walletSigningSessionId?: string;
  clientRootShare32B64u?: string;
  webauthnAuthentication?: WebAuthnAuthenticationCredential;
  remainingUses?: number;
  shouldAbort?: () => boolean;
  onEvent?: EvmFamilyLifecycleEventCallback;
}): Promise<ThresholdEcdsaSecp256k1KeyRef> {
  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  const chain = requireEvmFamilyEcdsaChain(args.lane);
  const source = requireEcdsaStoreSource(args.lane);
  const nearAccountId = String(args.lane.accountId);
  const signingSessionCoordinator = createEvmFamilySigningSessionCoordinator(args.deps, args.onEvent);
  const resolvedKeyRef =
    args.keyRef ||
    readSelectedEcdsaKeyRefForLane({
      deps: args.deps,
      lane: args.lane,
    });

  const readyCapability = await signingSessionCoordinator.ensureEcdsaCapabilityReady({
    nearAccountId,
    chain,
    keyRef: resolvedKeyRef,
    source,
    runtimeScopeBootstrap: resolveManagedRuntimeScopeBootstrap(args.deps.tatchiPasskeyConfigs),
    usesNeeded: Math.max(1, Math.floor(Number(args.remainingUses) || 1)),
    operationIntent: SigningOperationIntent.TransactionSign,
    ...(args.sessionId ? { sessionId: args.sessionId } : {}),
    ...(args.walletSigningSessionId ? { walletSigningSessionId: args.walletSigningSessionId } : {}),
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

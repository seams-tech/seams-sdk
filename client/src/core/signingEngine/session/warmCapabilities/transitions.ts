import type { AccountId } from '@/core/types/accountIds';
import type {
  WarmSessionEcdsaCapabilityState,
  WarmSessionEd25519CapabilityState,
  WarmSessionEnvelope,
  WarmSessionPrfClaim,
} from './types';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type WarmSessionTransitionCapabilitySnapshot = {
  state: WarmSessionEd25519CapabilityState['state'] | WarmSessionEcdsaCapabilityState['state'];
  thresholdSessionId: string | null;
  authState: 'present' | 'missing';
  prfClaimState: WarmSessionPrfClaim['state'] | null;
  remainingUses?: number;
  expiresAtMs?: number;
};

export type WarmSessionTransitionSnapshot = {
  accountId: AccountId;
  capabilities: {
    ed25519: WarmSessionTransitionCapabilitySnapshot;
    ecdsa: {
      evm: WarmSessionTransitionCapabilitySnapshot;
      tempo: WarmSessionTransitionCapabilitySnapshot;
    };
  };
  updatedAtMs: number;
};

export type WarmSessionTransitionEvent =
  | {
      type: 'ed25519_capability_provisioned';
      accountId: AccountId;
      thresholdSessionId: string;
      before: WarmSessionTransitionSnapshot;
      after: WarmSessionTransitionSnapshot;
    }
  | {
      type: 'ecdsa_capability_provisioned' | 'ecdsa_capability_reconnected';
      accountId: AccountId;
      chainTarget: ThresholdEcdsaChainTarget;
      thresholdSessionId: string;
      before: WarmSessionTransitionSnapshot;
      after: WarmSessionTransitionSnapshot;
    };

function summarizeWarmSessionCapabilityTransition(
  capability: WarmSessionEd25519CapabilityState | WarmSessionEcdsaCapabilityState,
): WarmSessionTransitionCapabilitySnapshot {
  const thresholdSessionId = capability.record?.thresholdSessionId
    ? String(capability.record.thresholdSessionId).trim()
    : null;
  return {
    state: capability.state,
    thresholdSessionId: thresholdSessionId || null,
    authState: capability.auth ? 'present' : 'missing',
    prfClaimState: capability.prfClaim?.state || null,
    ...(capability.prfClaim?.state === 'warm'
      ? {
          remainingUses: capability.prfClaim.remainingUses,
          expiresAtMs: capability.prfClaim.expiresAtMs,
        }
      : {}),
  };
}

export function summarizeWarmSessionTransition(
  envelope: WarmSessionEnvelope,
): WarmSessionTransitionSnapshot {
  return {
    accountId: envelope.accountId,
    capabilities: {
      ed25519: summarizeWarmSessionCapabilityTransition(envelope.capabilities.ed25519),
      ecdsa: {
        evm: summarizeWarmSessionCapabilityTransition(envelope.capabilities.ecdsa.evm),
        tempo: summarizeWarmSessionCapabilityTransition(envelope.capabilities.ecdsa.tempo),
      },
    },
    updatedAtMs: envelope.updatedAtMs,
  };
}

export function emitWarmSessionTransition(args: {
  onTransition?: (event: WarmSessionTransitionEvent) => void | Promise<void>;
  event: WarmSessionTransitionEvent;
}): void {
  if (typeof args.onTransition !== 'function') return;
  try {
    const pending = args.onTransition(args.event);
    if (pending && typeof (pending as PromiseLike<unknown>).then === 'function') {
      void Promise.resolve(pending).catch((error) => {
        console.warn('[WarmSessionStore] warm-session transition callback failed', {
          type: args.event.type,
          accountId: args.event.accountId,
          error,
        });
      });
    }
  } catch (error) {
    console.warn('[WarmSessionStore] warm-session transition callback failed', {
      type: args.event.type,
      accountId: args.event.accountId,
      error,
    });
  }
}

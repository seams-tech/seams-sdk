import type { AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaSessionJwtSource,
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '../api/thresholdLifecycle/thresholdSessionStore';
import type { ThresholdEcdsaActivationChain } from '../orchestration/thresholdActivation';

export type WarmSessionCapability = 'ed25519' | 'ecdsa';
export type WarmSessionPrfClaimState = 'missing' | 'warm' | 'expired' | 'exhausted' | 'unavailable';

export type WarmSessionPrfClaim = {
  state: WarmSessionPrfClaimState;
  sessionId: string;
  expiresAtMs?: number;
  remainingUses?: number;
  code?: string;
};

export type WarmSessionEd25519AuthMaterial = {
  capability: 'ed25519';
  record: ThresholdEd25519SessionRecord;
  thresholdSessionJwt?: string;
  thresholdSessionJwtSource: 'ed25519' | 'none';
};

export type WarmSessionEcdsaAuthMaterial = {
  capability: 'ecdsa';
  chain: ThresholdEcdsaActivationChain;
  record: ThresholdEcdsaSessionRecord;
  thresholdSessionJwt?: string;
  thresholdSessionJwtSource: Exclude<ThresholdEcdsaSessionJwtSource, 'ed25519'>;
};

export type WarmSessionEd25519CapabilityState = {
  capability: 'ed25519';
  record: ThresholdEd25519SessionRecord | null;
  auth: WarmSessionEd25519AuthMaterial | null;
  prfClaim: WarmSessionPrfClaim | null;
  state: 'missing' | 'ready' | 'auth_missing' | 'prf_missing' | 'prf_unavailable';
};

export type WarmSessionEcdsaCapabilityState = {
  capability: 'ecdsa';
  chain: ThresholdEcdsaActivationChain;
  record: ThresholdEcdsaSessionRecord | null;
  auth: WarmSessionEcdsaAuthMaterial | null;
  prfClaim: WarmSessionPrfClaim | null;
  state: 'missing' | 'ready' | 'auth_missing' | 'prf_missing' | 'prf_unavailable';
};

export type WarmSessionEnvelope = {
  accountId: AccountId;
  capabilities: {
    ed25519: WarmSessionEd25519CapabilityState;
    ecdsa: {
      evm: WarmSessionEcdsaCapabilityState;
      tempo: WarmSessionEcdsaCapabilityState;
    };
  };
  updatedAtMs: number;
};

function assertCapabilityStateInvariant(args: {
  accountId: AccountId;
  label: string;
  capability:
    | WarmSessionEd25519CapabilityState
    | WarmSessionEcdsaCapabilityState;
}): void {
  const { capability } = args;
  const record = capability.record;
  const auth = capability.auth;
  const prfClaim = capability.prfClaim;
  const sessionId = String(record?.thresholdSessionId || '').trim();

  if (!record) {
    if (capability.state !== 'missing') {
      throw new Error(
        `[WarmSessionManager] invalid ${args.label} capability: missing record must have state=missing`,
      );
    }
    if (auth) {
      throw new Error(
        `[WarmSessionManager] invalid ${args.label} capability: missing record cannot have auth`,
      );
    }
    if (prfClaim) {
      throw new Error(
        `[WarmSessionManager] invalid ${args.label} capability: missing record cannot have warm-session status`,
      );
    }
    return;
  }

  if (String(record.nearAccountId) !== String(args.accountId)) {
    throw new Error(
      `[WarmSessionManager] invalid ${args.label} capability: record account does not match envelope account`,
    );
  }
  if (!sessionId) {
    throw new Error(
      `[WarmSessionManager] invalid ${args.label} capability: record is missing thresholdSessionId`,
    );
  }

  if (auth) {
    if (auth.record !== record) {
      throw new Error(
        `[WarmSessionManager] invalid ${args.label} capability: auth.record must reference the capability record`,
      );
    }
    if (auth.capability !== capability.capability) {
      throw new Error(
        `[WarmSessionManager] invalid ${args.label} capability: auth capability does not match capability state`,
      );
    }
    if (
      capability.capability === 'ecdsa' &&
      'chain' in auth &&
      auth.chain !== capability.chain
    ) {
      throw new Error(
        `[WarmSessionManager] invalid ${args.label} capability: auth chain does not match capability chain`,
      );
    }
  }

  if (prfClaim) {
    if (String(prfClaim.sessionId || '').trim() !== sessionId) {
      throw new Error(
        `[WarmSessionManager] invalid ${args.label} capability: warm-session status sessionId does not match record sessionId`,
      );
    }
    if (
      prfClaim.state === 'warm' &&
      (typeof prfClaim.remainingUses !== 'number' ||
        prfClaim.remainingUses <= 0 ||
        typeof prfClaim.expiresAtMs !== 'number' ||
        prfClaim.expiresAtMs <= 0)
    ) {
      throw new Error(
        `[WarmSessionManager] invalid ${args.label} capability: warm warm-session status requires positive remainingUses and expiresAtMs`,
      );
    }
  }

  const requiresJwt = record.thresholdSessionKind === 'jwt';
  const hasJwt = Boolean(String(auth?.thresholdSessionJwt || '').trim());
  const expectedState = !auth || (requiresJwt && !hasJwt)
    ? 'auth_missing'
    : !prfClaim
      ? 'prf_missing'
      : prfClaim.state === 'unavailable'
        ? 'prf_unavailable'
        : prfClaim.state !== 'warm'
          ? 'prf_missing'
          : 'ready';
  if (capability.state !== expectedState) {
    throw new Error(
      `[WarmSessionManager] invalid ${args.label} capability: state=${capability.state} does not match derived state=${expectedState}`,
    );
  }
}

export function assertWarmSessionEnvelopeInvariant(envelope: WarmSessionEnvelope): WarmSessionEnvelope {
  assertCapabilityStateInvariant({
    accountId: envelope.accountId,
    label: 'ed25519',
    capability: envelope.capabilities.ed25519,
  });
  assertCapabilityStateInvariant({
    accountId: envelope.accountId,
    label: 'ecdsa.evm',
    capability: envelope.capabilities.ecdsa.evm,
  });
  assertCapabilityStateInvariant({
    accountId: envelope.accountId,
    label: 'ecdsa.tempo',
    capability: envelope.capabilities.ecdsa.tempo,
  });
  return envelope;
}

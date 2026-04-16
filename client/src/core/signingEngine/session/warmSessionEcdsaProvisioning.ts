import type { AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../interfaces/signing';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../orchestration/thresholdActivation';
import type {
  WarmSessionEcdsaCapabilityState,
  WarmSessionEnvelope,
} from './warmSessionTypes';
import { hasSufficientWarmClaim } from './warmSessionReadModel';

export type WarmSessionEcdsaCapabilityRef = {
  nearAccountId: AccountId | string;
  chain: ThresholdEcdsaActivationChain;
  thresholdSessionId?: string;
};

export function getMatchingReadyEcdsaCapability(args: {
  warmSession: WarmSessionEnvelope;
  chain: ThresholdEcdsaActivationChain;
  keyRef: ThresholdEcdsaSecp256k1KeyRef | null;
  usesNeeded?: number;
}): WarmSessionEcdsaCapabilityState | null {
  const capability = args.warmSession.capabilities.ecdsa[args.chain];
  if (!args.keyRef || capability.state !== 'ready') return null;

  const recordSessionId = String(capability.record?.thresholdSessionId || '').trim();
  const keyRefSessionId = String(args.keyRef.thresholdSessionId || '').trim();
  if (!recordSessionId || !keyRefSessionId || recordSessionId !== keyRefSessionId) {
    return null;
  }

  const recordThresholdKeyId = String(capability.record?.ecdsaThresholdKeyId || '').trim();
  const keyRefThresholdKeyId = String(args.keyRef.ecdsaThresholdKeyId || '').trim();
  if (!recordThresholdKeyId || (keyRefThresholdKeyId && recordThresholdKeyId !== keyRefThresholdKeyId)) {
    return null;
  }

  if (!hasSufficientWarmClaim(capability.prfClaim, args.usesNeeded)) {
    return null;
  }

  return capability;
}

export function normalizeParticipantIds(participantIds: unknown): number[] | undefined {
  if (!Array.isArray(participantIds)) return undefined;
  const normalized = participantIds
    .map((value) => Number(value))
    .filter((value) => Number.isFinite(value));
  return normalized.length ? normalized : undefined;
}

export function toOptionalNonEmptyString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

export function getEcdsaCapabilityCandidates(args: {
  warmSession: WarmSessionEnvelope;
  chain: ThresholdEcdsaActivationChain;
}): WarmSessionEcdsaCapabilityState[] {
  const primary = args.warmSession.capabilities.ecdsa[args.chain];
  const secondary =
    args.chain === 'tempo'
      ? args.warmSession.capabilities.ecdsa.evm
      : args.warmSession.capabilities.ecdsa.tempo;
  return primary === secondary ? [primary] : [primary, secondary];
}

export function getPrimaryAndSecondaryEcdsaCapabilities(args: {
  warmSession: WarmSessionEnvelope;
  chain: ThresholdEcdsaActivationChain;
}): {
  primary: WarmSessionEcdsaCapabilityState;
  secondary: WarmSessionEcdsaCapabilityState;
} {
  return {
    primary: args.warmSession.capabilities.ecdsa[args.chain],
    secondary:
      args.chain === 'tempo'
        ? args.warmSession.capabilities.ecdsa.evm
        : args.warmSession.capabilities.ecdsa.tempo,
  };
}

export function buildReusableEcdsaBootstrapResult(args: {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  capability: WarmSessionEcdsaCapabilityState;
  source: 'login' | 'registration' | 'manual-bootstrap' | 'email_otp';
}): ThresholdEcdsaSessionBootstrapResult | null {
  const record = args.capability.record;
  const auth = args.capability.auth;
  const prfClaim = args.capability.prfClaim;
  if (!record || !auth || !prfClaim || prfClaim.state !== 'warm') return null;

  const clientVerifyingShareB64u = String(record.clientVerifyingShareB64u || '').trim();
  const relayerKeyId = String(record.relayerKeyId || '').trim();
  const sessionId = String(record.thresholdSessionId || '').trim();
  if (!clientVerifyingShareB64u || !relayerKeyId || !sessionId) return null;

  return {
    thresholdEcdsaKeyRef: {
      ...args.keyRef,
      relayerUrl: String(record.relayerUrl || args.keyRef.relayerUrl || '').trim(),
      ecdsaThresholdKeyId: String(
        record.ecdsaThresholdKeyId || args.keyRef.ecdsaThresholdKeyId || '',
      ).trim(),
      participantIds: record.participantIds,
      thresholdSessionKind: record.thresholdSessionKind,
      thresholdSessionId: sessionId,
      thresholdSessionJwt: String(
        auth.thresholdSessionJwt || args.keyRef.thresholdSessionJwt || '',
      ).trim(),
    },
    keygen: {
      ok: true,
      ecdsaThresholdKeyId: String(record.ecdsaThresholdKeyId || '').trim(),
      relayerKeyId,
      clientVerifyingShareB64u,
      ...(String(record.clientAdditiveShare32B64u || '').trim()
        ? { clientAdditiveShare32B64u: String(record.clientAdditiveShare32B64u || '').trim() }
        : {}),
      participantIds: record.participantIds,
      thresholdEcdsaPublicKeyB64u: record.thresholdEcdsaPublicKeyB64u,
      ethereumAddress: record.ethereumAddress,
      relayerVerifyingShareB64u: record.relayerVerifyingShareB64u,
    },
    session: {
      ok: true,
      sessionId,
      ...(String(auth.thresholdSessionJwt || '').trim()
        ? { jwt: String(auth.thresholdSessionJwt || '').trim() }
        : {}),
      expiresAtMs: prfClaim.expiresAtMs,
      remainingUses: prfClaim.remainingUses,
      clientVerifyingShareB64u,
    },
  };
}

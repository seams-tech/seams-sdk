import type { ThresholdEd25519_2p_V1Material } from '@/core/indexedDB/passkeyNearKeysDB.types';
import type { ThresholdPrfFirstCachePeekPort } from '@/core/signingEngine/touchConfirm';
import type { SigningAuthMode } from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import { buildEd25519SessionPolicy } from '@/core/signingEngine/threshold/session/sessionPolicy';

export type ThresholdSessionPolicyPlan = Awaited<ReturnType<typeof buildEd25519SessionPolicy>>;

export function normalizeOptionalPositiveInt(value?: number): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) && value > 0
    ? Math.floor(value)
    : undefined;
}

export function resolveDesiredSessionOptions(args: {
  signingSessionTtlMs?: number;
  signingSessionRemainingUses?: number;
}): { desiredTtlMs?: number; desiredRemainingUses?: number } {
  return {
    desiredTtlMs: normalizeOptionalPositiveInt(args.signingSessionTtlMs),
    desiredRemainingUses: normalizeOptionalPositiveInt(args.signingSessionRemainingUses),
  };
}

export async function buildEd25519SessionPolicyForNearSigning(args: {
  nearAccountId: string;
  getRpId: () => string | null;
  thresholdKeyMaterial: ThresholdEd25519_2p_V1Material;
  usesNeeded: number;
  desiredTtlMs?: number;
  desiredRemainingUses?: number;
}): Promise<ThresholdSessionPolicyPlan> {
  const rpId = String(args.getRpId() || '').trim();
  return await buildEd25519SessionPolicy({
    nearAccountId: args.nearAccountId,
    rpId,
    relayerKeyId: args.thresholdKeyMaterial.relayerKeyId,
    participantIds: args.thresholdKeyMaterial.participants.map((p) => p.id),
    ...(args.desiredTtlMs !== undefined ? { ttlMs: args.desiredTtlMs } : {}),
    remainingUses: Math.max(args.usesNeeded, args.desiredRemainingUses ?? args.usesNeeded),
  });
}

export async function resolveInitialThresholdSigningAuthPlan(args: {
  threshold: {
    thresholdKeyMaterial: ThresholdEd25519_2p_V1Material;
    thresholdSessionJwt: string | undefined;
  } | null;
  sessionId: string;
  usesNeeded: number;
  nearAccountId: string;
  getRpId: () => string | null;
  touchConfirm: ThresholdPrfFirstCachePeekPort;
  desiredTtlMs?: number;
  desiredRemainingUses?: number;
}): Promise<{
  signingAuthMode: SigningAuthMode | undefined;
  thresholdSessionPlan: ThresholdSessionPolicyPlan | null;
}> {
  if (!args.threshold) {
    return {
      signingAuthMode: undefined,
      thresholdSessionPlan: null,
    };
  }

  const hasJwt = !!args.threshold.thresholdSessionJwt;
  let warmOk = false;
  if (hasJwt) {
    const peek = await args.touchConfirm.peekPrfFirstForThresholdSession({
      sessionId: args.sessionId,
    });
    warmOk = peek.ok && peek.remainingUses >= args.usesNeeded;
  }

  const signingAuthMode: SigningAuthMode = warmOk ? 'warmSession' : 'webauthn';
  const thresholdSessionPlan = warmOk
    ? null
    : await buildEd25519SessionPolicyForNearSigning({
        nearAccountId: args.nearAccountId,
        getRpId: args.getRpId,
        thresholdKeyMaterial: args.threshold.thresholdKeyMaterial,
        usesNeeded: args.usesNeeded,
        desiredTtlMs: args.desiredTtlMs,
        desiredRemainingUses: args.desiredRemainingUses,
      });

  return {
    signingAuthMode,
    thresholdSessionPlan,
  };
}

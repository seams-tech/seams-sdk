import type { SeamsWebContext } from '@/web/SeamsWeb/signingSurface/types';
import { clampThresholdSessionPolicy } from '@/core/signingEngine/threshold/sessionPolicy';

export function resolveThresholdWarmSessionDefaults(
  context: Pick<SeamsWebContext, 'configs'>,
): { ttlMs: number; remainingUses: number } | null {
  const clamped = clampThresholdSessionPolicy({
    ttlMs: Number(context.configs?.signing.sessionDefaults?.ttlMs),
    remainingUses: Number(context.configs?.signing.sessionDefaults?.remainingUses),
  });
  if (clamped.ttlMs <= 0 || clamped.remainingUses <= 0) return null;
  return clamped;
}

export function shouldRequireThresholdWarmSession(
  context: Pick<SeamsWebContext, 'configs'>,
): boolean {
  return resolveThresholdWarmSessionDefaults(context) != null;
}

import type { SeamsWebContext } from './index';
import { clampThresholdSessionPolicy } from '@/core/signingEngine/threshold/sessionPolicy';

export function resolveThresholdWarmSessionDefaults(
  context: SeamsWebContext,
): { ttlMs: number; remainingUses: number } | null {
  const clamped = clampThresholdSessionPolicy({
    ttlMs: Number(context.configs?.signing.sessionDefaults?.ttlMs),
    remainingUses: Number(context.configs?.signing.sessionDefaults?.remainingUses),
  });
  if (clamped.ttlMs <= 0 || clamped.remainingUses <= 0) return null;
  return clamped;
}

export function shouldRequireThresholdWarmSession(context: SeamsWebContext): boolean {
  return resolveThresholdWarmSessionDefaults(context) != null;
}

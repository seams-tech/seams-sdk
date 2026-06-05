import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { clampThresholdSessionPolicy } from '@/core/signingEngine/threshold/sessionPolicy';

type ThresholdWarmSessionConfigContext = { configs: SeamsConfigsReadonly };

export function resolveThresholdWarmSessionDefaults(
  context: ThresholdWarmSessionConfigContext,
): { ttlMs: number; remainingUses: number } | null {
  const clamped = clampThresholdSessionPolicy({
    ttlMs: Number(context.configs?.signing.sessionDefaults?.ttlMs),
    remainingUses: Number(context.configs?.signing.sessionDefaults?.remainingUses),
  });
  if (clamped.ttlMs <= 0 || clamped.remainingUses <= 0) return null;
  return clamped;
}

export function shouldRequireThresholdWarmSession(
  context: ThresholdWarmSessionConfigContext,
): boolean {
  return resolveThresholdWarmSessionDefaults(context) != null;
}

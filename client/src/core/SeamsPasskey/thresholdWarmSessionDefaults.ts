import type { PasskeyManagerContext } from './index';
import { clampThresholdSessionPolicy } from '../signingEngine/threshold/session/sessionPolicy';

export function resolveThresholdWarmSessionDefaults(
  context: PasskeyManagerContext,
): { ttlMs: number; remainingUses: number } | null {
  const clamped = clampThresholdSessionPolicy({
    ttlMs: Number(context.configs?.signing.sessionDefaults?.ttlMs),
    remainingUses: Number(context.configs?.signing.sessionDefaults?.remainingUses),
  });
  if (clamped.ttlMs <= 0 || clamped.remainingUses <= 0) return null;
  return clamped;
}

export function shouldRequireThresholdWarmSession(context: PasskeyManagerContext): boolean {
  return resolveThresholdWarmSessionDefaults(context) != null;
}

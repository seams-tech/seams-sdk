import { normalizeJwtCookieSessionKind } from '@shared/utils/normalize';

export type ThresholdEcdsaSessionKind = 'jwt' | 'cookie';

export function normalizeThresholdEcdsaSessionKind(value: unknown): ThresholdEcdsaSessionKind {
  return normalizeJwtCookieSessionKind(value);
}

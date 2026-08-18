import { normalizeLowercaseString, normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export function normalizeLastUserScope(scope: unknown): string | null {
  const normalized = normalizeOptionalNonEmptyString(scope);
  if (!normalized || normalized === 'null') return null;
  return normalized;
}

export function normalizeIndexedDbChainIdKey(chainIdKey: unknown): string {
  return normalizeLowercaseString(chainIdKey);
}

export function normalizeIndexedDbAccountAddress(address: unknown): string {
  return normalizeLowercaseString(address);
}

export function normalizeIndexedDbAccountModel<T extends string = string>(model: unknown): T {
  return normalizeLowercaseString(model) as T;
}

export function normalizeIndexedDbOptionalChainIdNumber(
  value: unknown,
  options: { allowChainIdKeySuffix?: boolean } = {},
): number | undefined {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
    return value;
  }
  const raw = normalizeOptionalNonEmptyString(value);
  if (!raw) return undefined;
  const normalized = raw.toLowerCase();
  const candidate =
    options.allowChainIdKeySuffix && normalized.includes(':')
      ? normalized.slice(normalized.lastIndexOf(':') + 1)
      : normalized;
  if (!/^\d+$/.test(candidate)) return undefined;
  const parsed = Number(candidate);
  if (!Number.isSafeInteger(parsed) || parsed < 0) return undefined;
  return parsed;
}

export function toIndexedDbChainTargetKey(chainTarget: ThresholdEcdsaChainTarget): string {
  return thresholdEcdsaChainTargetKey(chainTarget);
}

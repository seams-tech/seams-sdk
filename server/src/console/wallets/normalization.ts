import type { ConsoleWalletSortBy, ConsoleWalletSortOrder } from './types';
import { normalizeBoundedPositiveInteger } from '@shared/utils/normalize';

const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;

export function normalizeWalletSortBy(value: ConsoleWalletSortBy | undefined): ConsoleWalletSortBy {
  return value || 'createdAt';
}

export function normalizeWalletSortOrder(
  value: ConsoleWalletSortOrder | undefined,
): ConsoleWalletSortOrder {
  return value || 'desc';
}

export function normalizeWalletLimit(limit: number | undefined): number {
  return normalizeBoundedPositiveInteger(limit, {
    fallback: DEFAULT_LIMIT,
    max: MAX_LIMIT,
  });
}

export function slugifyWalletToken(value: string): string {
  return (
    String(value || '')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'default'
  );
}

function stableHash32(input: string): number {
  let hash = 2166136261;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

export function makeDeterministicWalletAddress(seed: string): string {
  let hex = '';
  let state = stableHash32(seed);
  while (hex.length < 40) {
    state = Math.imul(state ^ 0x9e3779b1, 0x85ebca6b) >>> 0;
    hex += state.toString(16).padStart(8, '0');
  }
  return `0x${hex.slice(0, 40)}`;
}

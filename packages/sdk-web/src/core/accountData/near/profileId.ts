import type { AccountId } from '../../types/accountIds';

export const NEAR_PROFILE_PREFIX = 'near-profile' as const;

export type NearAccountProjectionProfileId = string & {
  readonly __nearAccountProjectionProfileIdBrand: unique symbol;
};

export type NearProfileId = NearAccountProjectionProfileId & {
  readonly __nearProfileIdBrand: unique symbol;
};

export type NearAccountProjectionProfileIdParseResult =
  | { readonly ok: true; readonly value: NearAccountProjectionProfileId }
  | { readonly ok: false; readonly message: string };

export function parseNearAccountProjectionProfileId(
  raw: unknown,
): NearAccountProjectionProfileIdParseResult {
  if (typeof raw !== 'string') {
    return { ok: false, message: 'NEAR account projection profile id must be a string' };
  }
  const value = raw.trim();
  if (!value) {
    return { ok: false, message: 'NEAR account projection profile id is required' };
  }
  return { ok: true, value: value as NearAccountProjectionProfileId };
}

export function buildNearProfileId(accountId: AccountId): NearProfileId {
  return `${NEAR_PROFILE_PREFIX}:${String(accountId)}` as NearProfileId;
}

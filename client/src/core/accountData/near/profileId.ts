import type { AccountId } from '../../types/accountIds';

export const NEAR_PROFILE_PREFIX = 'near-profile' as const;

export function buildNearProfileId(accountId: AccountId): string {
  return `${NEAR_PROFILE_PREFIX}:${String(accountId)}`;
}

import type { PasskeyClientDBManager } from '@/core/indexedDB';
import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import { resolveProfileAccountContextFromCandidates } from '@/core/indexedDB/profileAccountProjection';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { parseSignerSlot } from '@shared/utils/signerSlot';

export { parseSignerSlot };

/**
 * Return the active signer slot for the last logged-in user for the given
 * account. This uses the app-state "last user" pointer only; if it does not
 * match the requested account, an error is thrown instead of silently falling
 * back.
 */
export async function getLastLoggedInSignerSlot(
  nearAccountId: AccountId | string,
  clientDB: Pick<PasskeyClientDBManager, 'resolveProfileAccountContext' | 'getLastProfileState'>,
): Promise<number> {
  const accountId = toAccountId(nearAccountId);
  const context = await resolveProfileAccountContextFromCandidates(
    clientDB,
    buildNearAccountRefs(accountId),
  ).catch(() => null);
  if (!context?.profileId) {
    throw new Error(`No profile/account mapping for account ${accountId}`);
  }

  const lastProfile = await clientDB.getLastProfileState().catch(() => null);
  if (!lastProfile?.profileId || lastProfile.profileId !== context.profileId) {
    throw new Error(`No last user session for account ${accountId}`);
  }

  const signerSlot = parseSignerSlot(lastProfile.activeSignerSlot, { min: 1 });
  if (signerSlot === null) {
    throw new Error(`Invalid last-user signerSlot for account ${accountId}`);
  }
  return signerSlot;
}

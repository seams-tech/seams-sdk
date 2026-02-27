import type { PasskeyClientDBManager } from '@/core/indexedDB';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { parseDeviceNumber } from '@shared/utils/deviceNumber';

export { parseDeviceNumber } from '@shared/utils/deviceNumber';

/**
 * Return the deviceNumber for the last logged-in user for the given account.
 * This uses the app-state "last user" pointer only; if it does not match the
 * requested account, an error is thrown instead of silently falling back.
 */
export async function getLastLoggedInDeviceNumber(
  nearAccountId: AccountId | string,
  clientDB: PasskeyClientDBManager,
): Promise<number> {
  const accountId = toAccountId(nearAccountId);
  const context = await clientDB.resolveNearAccountContext(accountId).catch(() => null);
  if (!context?.profileId) {
    throw new Error(`No profile/account mapping for account ${accountId}`);
  }

  const lastProfile = await clientDB.getLastProfileState().catch(() => null);
  if (!lastProfile?.profileId || lastProfile.profileId !== context.profileId) {
    throw new Error(`No last user session for account ${accountId}`);
  }

  const deviceNumber = parseDeviceNumber(lastProfile.deviceNumber, { min: 1 });
  if (deviceNumber === null) {
    throw new Error(`Invalid last-user deviceNumber for account ${accountId}`);
  }
  return deviceNumber;
}

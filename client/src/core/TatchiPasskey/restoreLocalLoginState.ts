import type { AccountId } from '../types/accountIds';
import { toAccountId } from '../types/accountIds';
import { normalizePositiveInteger } from '@shared/utils/normalize';
import { getWalletSession } from './login';
import type { PasskeyManagerContext } from './index';

export async function restoreLocalLoginState(args: {
  context: PasskeyManagerContext;
  nearAccountId: AccountId | string;
  deviceNumber: number;
}): Promise<{ nearAccountId: AccountId; deviceNumber: number; isLoggedIn: boolean }> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const deviceNumber = normalizePositiveInteger(args.deviceNumber) ?? 1;

  await args.context.signingEngine.setLastUser(nearAccountId, deviceNumber).catch(() => undefined);
  await args.context.signingEngine.updateLastLogin(nearAccountId).catch(() => undefined);
  await args.context.signingEngine
    .initializeCurrentUser(nearAccountId, args.context.nearClient)
    .catch(() => undefined);

  const { login } = await getWalletSession(args.context, nearAccountId);
  return {
    nearAccountId,
    deviceNumber,
    isLoggedIn: Boolean(login?.isLoggedIn),
  };
}

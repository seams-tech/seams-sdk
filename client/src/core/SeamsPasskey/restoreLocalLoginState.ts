import type { AccountId } from '../types/accountIds';
import { normalizePositiveInteger } from '@shared/utils/normalize';
import { getWalletSession } from './login';
import type { PasskeyManagerContext } from './index';

export async function restoreLocalLoginState(args: {
  context: PasskeyManagerContext;
  nearAccountId: AccountId;
  signerSlot: number;
}): Promise<{ nearAccountId: AccountId; signerSlot: number; isLoggedIn: boolean }> {
  const nearAccountId = args.nearAccountId;
  const signerSlot = normalizePositiveInteger(args.signerSlot) ?? 1;

  await args.context.signingEngine.setLastUser(nearAccountId, signerSlot).catch(() => undefined);
  await args.context.signingEngine.updateLastLogin(nearAccountId).catch(() => undefined);
  await args.context.signingEngine
    .initializeCurrentUser(nearAccountId, args.context.nearClient)
    .catch(() => undefined);

  const { login } = await getWalletSession(args.context, nearAccountId);
  return {
    nearAccountId,
    signerSlot,
    isLoggedIn: Boolean(login?.isLoggedIn),
  };
}

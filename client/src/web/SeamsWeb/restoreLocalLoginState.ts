import type { AccountId } from '@/core/types/accountIds';
import { normalizePositiveInteger } from '@shared/utils/normalize';
import { getWalletSession } from './login';
import type { SeamsWebContext } from './index';

export async function restoreLocalLoginState(args: {
  context: SeamsWebContext;
  nearAccountId: AccountId;
  signerSlot: number;
}): Promise<{ nearAccountId: AccountId; signerSlot: number; isLoggedIn: boolean }> {
  const nearAccountId = args.nearAccountId;
  const signerSlot = normalizePositiveInteger(args.signerSlot) ?? 1;
  const registrationAccounts = args.context.signingRuntime.services.registrationAccounts;

  await registrationAccounts.setLastUser(nearAccountId, signerSlot).catch(() => undefined);
  await registrationAccounts.updateLastLogin(nearAccountId).catch(() => undefined);
  await registrationAccounts
    .initializeCurrentUser({ nearAccountId, nearClient: args.context.nearClient })
    .catch(() => undefined);

  const { login } = await getWalletSession(args.context, nearAccountId);
  return {
    nearAccountId,
    signerSlot,
    isLoggedIn: Boolean(login?.isLoggedIn),
  };
}

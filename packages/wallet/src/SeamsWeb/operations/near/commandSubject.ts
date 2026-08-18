import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import {
  nearAccountRefFromAccountId,
  type NearCommandSubject,
  type WalletSessionRef,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export function resolveNearCommandSubject(args: {
  nearAccountId: AccountId | string;
  walletSession: WalletSessionRef;
}): NearCommandSubject {
  const nearAccountId = toAccountId(args.nearAccountId);
  const nearAccount = nearAccountRefFromAccountId(nearAccountId);
  const walletSession = walletSessionRefFromSession(args.walletSession);
  return {
    walletSession,
    nearAccount,
  };
}

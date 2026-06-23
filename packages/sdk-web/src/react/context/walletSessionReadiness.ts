import type { WalletSession } from '@/core/types/seams';

export function isWalletSessionReadyForUi(args: {
  session: Pick<WalletSession, 'login' | 'signingSession'>;
}): boolean {
  const { session } = args;
  return Boolean(session?.login?.isLoggedIn && session.login.walletId);
}

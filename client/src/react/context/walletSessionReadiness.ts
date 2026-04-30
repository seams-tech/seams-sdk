import type { WalletSession } from '@/core/types/seams';

export function isWalletSessionReadyForUi(args: {
  session: Pick<WalletSession, 'login' | 'signingSession'>;
}): boolean {
  const { session } = args;
  if (!session?.login?.isLoggedIn || !session?.login?.nearAccountId) return false;
  return (
    session?.signingSession?.status === 'active' &&
    String(session?.signingSession?.sessionId || '').trim().length > 0
  );
}

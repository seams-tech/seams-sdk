import type { WalletSession } from '@/core/types/seams';

export function isWalletSessionReadyForUi(args: {
  session: Pick<WalletSession, 'appIdentity' | 'authentication'>;
}): boolean {
  if (args.session.appIdentity.kind !== 'resolved') return false;
  if (args.session.authentication.kind === 'signed_out') return false;
  return String(args.session.appIdentity.walletId) === String(args.session.authentication.walletId);
}

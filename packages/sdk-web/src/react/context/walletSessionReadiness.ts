import type { WalletSession } from '@/core/types/seams';

export function shouldPreserveReactLoginForWalletSessionRead(
  session: Pick<WalletSession, 'reusableWalletSession'>,
): boolean {
  switch (session.reusableWalletSession.kind) {
    case 'unavailable':
    case 'superseded':
      return true;
    case 'not_requested':
    case 'active':
    case 'exhausted':
    case 'expired':
    case 'missing':
    case 'invalid':
      return false;
  }
  session.reusableWalletSession satisfies never;
  return false;
}

export function isWalletSessionReadyForUi(args: {
  session: Pick<WalletSession, 'appIdentity' | 'reusableWalletSession'>;
}): boolean {
  if (args.session.appIdentity.kind !== 'resolved') return false;
  switch (args.session.reusableWalletSession.kind) {
    case 'active':
    case 'exhausted':
      return (
        String(args.session.appIdentity.walletId) ===
        String(args.session.reusableWalletSession.walletId)
      );
    // `superseded` is stale rather than usable: not ready for the UI now, and
    // ready again once the caller re-resolves to current state.
    case 'not_requested':
    case 'expired':
    case 'missing':
    case 'unavailable':
    case 'invalid':
    case 'superseded':
      return false;
  }
  args.session.reusableWalletSession satisfies never;
  return false;
}

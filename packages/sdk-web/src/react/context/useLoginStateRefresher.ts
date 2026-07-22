import { useCallback, useEffect } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import type { SeamsWeb } from '@/SeamsWeb';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { LoginState, SeamsContextType } from '../types';
import { isWalletSessionReadyForUi } from './walletSessionReadiness';
import {
  buildReactLoggedInLoginStateFromSession,
  buildReactLoggedOutLoginState,
} from './reactLoginStateBuilders';

function syncInputUsernameFromWalletId(
  setInputUsername: SeamsContextType['setInputUsername'],
  walletId: string | null | undefined,
): void {
  const value = String(walletId || '').trim();
  if (value) setInputUsername(value);
}

function resolveExactReactLoginWalletId(
  seams: SeamsWeb,
  requestedWalletId: string | undefined,
): string | null {
  const walletId = String(requestedWalletId || seams.preferences.getCurrentWalletId() || '').trim();
  return walletId || null;
}

export function useLoginStateRefresher(args: {
  seams: SeamsWeb;
  walletIframeConnected: boolean;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
  setInputUsername: SeamsContextType['setInputUsername'];
}) {
  const { seams, walletIframeConnected, setLoginState, setInputUsername } = args;

  const refreshLoginState: SeamsContextType['refreshLoginState'] = useCallback(
    async (walletId?: string) => {
      try {
        const exactWalletId = resolveExactReactLoginWalletId(seams, walletId);
        if (!exactWalletId) {
          setLoginState(buildReactLoggedOutLoginState());
          return;
        }

        const session = await seams.auth.getWalletSession(exactWalletId);
        if (!isWalletSessionReadyForUi({ session })) {
          setLoginState(buildReactLoggedOutLoginState());
          return;
        }
        const { login: ls } = session;
        if (ls.walletId) {
          seams.preferences.setCurrentWallet(toWalletId(ls.walletId));
          syncInputUsernameFromWalletId(setInputUsername, ls.walletId);
        }
        const nextLoginState = buildReactLoggedInLoginStateFromSession(session);
        setLoginState(nextLoginState ?? buildReactLoggedOutLoginState());
      } catch (error) {
        console.error('Error refreshing login state:', error);
      }
    },
    [setInputUsername, setLoginState, seams],
  );

  useEffect(() => {
    if (seams.configs.wallet.mode === 'iframe' && !walletIframeConnected) return;
    void refreshLoginState();
  }, [refreshLoginState, seams, walletIframeConnected]);

  return refreshLoginState;
}

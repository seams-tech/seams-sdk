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

export function useLoginStateRefresher(args: {
  seams: SeamsWeb;
  walletIframeConnected: boolean;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
  setInputUsername: SeamsContextType['setInputUsername'];
}) {
  const { seams, setLoginState, setInputUsername } = args;

  const refreshLoginState: SeamsContextType['refreshLoginState'] = useCallback(
    async (walletId?: string) => {
      try {
        const selectedWalletId = String(
          walletId || seams.preferences.getCurrentWalletId() || '',
        ).trim();
        if (!selectedWalletId) {
          setLoginState(buildReactLoggedOutLoginState());
          return;
        }

        const session = await seams.auth.getWalletSession(selectedWalletId);
        const { login: ls } = session;
        if (isWalletSessionReadyForUi({ session })) {
          if (ls.walletId) {
            try {
              seams.preferences.setCurrentWallet(toWalletId(ls.walletId));
            } catch {}
          }
          if (ls.walletId) {
            syncInputUsernameFromWalletId(setInputUsername, ls.walletId);
          }
          const nextLoginState = buildReactLoggedInLoginStateFromSession(session);
          setLoginState(nextLoginState ?? buildReactLoggedOutLoginState());
        } else {
          setLoginState(buildReactLoggedOutLoginState());
        }
      } catch (error) {
        console.error('Error refreshing login state:', error);
      }
    },
    [setInputUsername, setLoginState, seams],
  );

  useEffect(() => {
    void refreshLoginState();
  }, [refreshLoginState]);

  return refreshLoginState;
}

import { useEffect } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import type { SeamsWeb } from '@/SeamsWeb';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { LoginState } from '../types';
import { isWalletSessionReadyForUi } from './walletSessionReadiness';
import {
  buildReactLoggedInLoginStateFromSession,
  buildReactLoggedOutLoginState,
} from './reactLoginStateBuilders';

export function useWalletIframeLifecycle(args: {
  seams: SeamsWeb;
  setWalletIframeConnected: Dispatch<SetStateAction<boolean>>;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
}) {
  const { seams, setWalletIframeConnected, setLoginState } = args;

  useEffect(() => {
    let offReady: (() => void) | undefined;
    let offLogin: (() => void) | undefined;
    let offPrefs: (() => void) | undefined;
    let cancelled = false;

    (async () => {
      try {
        const useIframe = seams.configs.wallet.mode === 'iframe';
        if (!useIframe) {
          setWalletIframeConnected(false);
          return;
        }

        await seams.initWalletIframe();
        if (cancelled) return;

        setWalletIframeConnected(seams.isWalletIframeReady());
        offReady = seams.onWalletIframeReady(() => setWalletIframeConnected(true));

        offLogin = seams.onWalletIframeLoginStatusChanged(
          async (status: { isLoggedIn: boolean; walletId: string | null }) => {
            if (cancelled) return;
            if (status?.isLoggedIn && status?.walletId) {
              const session = await seams.auth.getWalletSession(status.walletId);
              if (isWalletSessionReadyForUi({ session })) {
                const nextLoginState = buildReactLoggedInLoginStateFromSession(session);
                if (nextLoginState) {
                  seams.preferences.setCurrentWallet(toWalletId(nextLoginState.walletId));
                  setLoginState(nextLoginState);
                } else {
                  setLoginState(buildReactLoggedOutLoginState());
                }
              } else {
                setLoginState(buildReactLoggedOutLoginState());
              }
            } else if (status && status.isLoggedIn === false) {
              setLoginState(buildReactLoggedOutLoginState());
            }
          },
        );

        // Preferences changes (including current-user changes from wallet-host flows like device linking)
        // should update login state on the app origin as well.
        offPrefs = seams.onWalletIframePreferencesChanged(async (payload) => {
          if (cancelled) return;
          const walletId = payload?.walletId;
          if (walletId) {
            try {
              const session = await seams.auth.getWalletSession(walletId);
              if (isWalletSessionReadyForUi({ session })) {
                const nextLoginState = buildReactLoggedInLoginStateFromSession(session);
                if (nextLoginState) {
                  seams.preferences.setCurrentWallet(toWalletId(nextLoginState.walletId));
                  setLoginState(nextLoginState);
                  return;
                }
              }
            } catch {}
          }
          setLoginState(buildReactLoggedOutLoginState());
        });
      } catch (err) {
        console.warn('[SeamsContextProvider] WalletIframe init failed:', err);
      }
    })();

    return () => {
      cancelled = true;
      offReady && offReady();
      offLogin && offLogin();
      offPrefs && offPrefs();
    };
  }, [setLoginState, setWalletIframeConnected, seams]);
}

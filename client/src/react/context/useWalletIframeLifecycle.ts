import { useEffect } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import type { TatchiPasskey } from '@/core/TatchiPasskey';
import { toAccountId } from '@/core/types/accountIds';
import type { LoginState } from '../types';
import { isLoginSessionReadyForUi } from './loginReadiness';

export function useWalletIframeLifecycle(args: {
  tatchi: TatchiPasskey;
  setWalletIframeConnected: Dispatch<SetStateAction<boolean>>;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
}) {
  const {
    tatchi,
    setWalletIframeConnected,
    setLoginState,
  } = args;

  useEffect(() => {
    let offReady: (() => void) | undefined;
    let offLogin: (() => void) | undefined;
    let offPrefs: (() => void) | undefined;
    let cancelled = false;

    (async () => {
      try {
        const signerMode = tatchi.configs?.signerMode;
        const useIframe = !!tatchi.configs.iframeWallet?.walletOrigin;
        if (!useIframe) {
          setWalletIframeConnected(false);
          return;
        }

        await tatchi.initWalletIframe();
        if (cancelled) return;

        setWalletIframeConnected(tatchi.isWalletIframeReady());
        offReady = tatchi.onWalletIframeReady(() => setWalletIframeConnected(true));

        offLogin = tatchi.onWalletIframeLoginStatusChanged(async (status: { isLoggedIn: boolean; nearAccountId: string | null }) => {
          if (cancelled) return;
          if (status?.isLoggedIn && status?.nearAccountId) {
            const session = await tatchi.auth.getSession(status.nearAccountId);
            const { login: state } = session;
            if (isLoginSessionReadyForUi({ session, signerMode })) {
              tatchi.preferences.setCurrentUser(toAccountId(status.nearAccountId));
              setLoginState(prev => ({
                ...prev,
                isLoggedIn: true,
                nearAccountId: status.nearAccountId,
                nearPublicKey: state.publicKey || null,
              }));
            } else {
              setLoginState(prev => ({
                ...prev,
                isLoggedIn: false,
                nearAccountId: null,
                nearPublicKey: null,
              }));
            }
          } else if (status && status.isLoggedIn === false) {
            setLoginState(prev => ({
              ...prev,
              isLoggedIn: false,
              nearAccountId: null,
              nearPublicKey: null,
            }));
          }
        });

        // Preferences changes (including current-user changes from wallet-host flows like device linking)
        // should update login state on the app origin as well.
        offPrefs = tatchi.onWalletIframePreferencesChanged(async (payload) => {
          if (cancelled) return;
          const acct = payload?.nearAccountId;
          if (acct) {
            try {
              const session = await tatchi.auth.getSession(acct);
              const { login: state } = session;
              if (isLoginSessionReadyForUi({ session, signerMode }) && state?.nearAccountId) {
                tatchi.preferences.setCurrentUser(toAccountId(state.nearAccountId));
                setLoginState(prev => ({
                  ...prev,
                  isLoggedIn: true,
                  nearAccountId: state.nearAccountId,
                  nearPublicKey: state.publicKey || null,
                }));
                return;
              }
            } catch {}
          }
          setLoginState(prev => ({
            ...prev,
            isLoggedIn: false,
            nearAccountId: null,
            nearPublicKey: null,
          }));
        });

        const session = await tatchi.auth.getSession();
        const { login: st } = session;
        if (isLoginSessionReadyForUi({ session, signerMode })) {
          setLoginState(prev => ({
            ...prev,
            isLoggedIn: true,
            nearAccountId: st.nearAccountId,
            nearPublicKey: st.publicKey || null,
          }));
        }

      } catch (err) {
        console.warn('[TatchiContextProvider] WalletIframe init failed:', err);
      }
    })();

    return () => {
      cancelled = true;
      offReady && offReady();
      offLogin && offLogin();
      offPrefs && offPrefs();
    };
  }, [setLoginState, setWalletIframeConnected, tatchi]);
}

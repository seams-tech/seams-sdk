import { useEffect } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import type { TatchiPasskey } from '@/core/TatchiPasskey';
import { toAccountId } from '@/core/types/accountIds';
import type { LoginState } from '../types';
import { isWalletSessionReadyForUi } from './walletSessionReadiness';

export function useWalletIframeLifecycle(args: {
  tatchi: TatchiPasskey;
  setWalletIframeConnected: Dispatch<SetStateAction<boolean>>;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
}) {
  const { tatchi, setWalletIframeConnected, setLoginState } = args;

  useEffect(() => {
    let offReady: (() => void) | undefined;
    let offLogin: (() => void) | undefined;
    let offPrefs: (() => void) | undefined;
    let cancelled = false;

    (async () => {
      try {
        const useIframe = tatchi.configs.wallet.mode === 'iframe';
        if (!useIframe) {
          setWalletIframeConnected(false);
          return;
        }

        await tatchi.initWalletIframe();
        if (cancelled) return;

        setWalletIframeConnected(tatchi.isWalletIframeReady());
        offReady = tatchi.onWalletIframeReady(() => setWalletIframeConnected(true));

        offLogin = tatchi.onWalletIframeLoginStatusChanged(
          async (status: { isLoggedIn: boolean; nearAccountId: string | null }) => {
            if (cancelled) return;
            if (status?.isLoggedIn && status?.nearAccountId) {
              const session = await tatchi.auth.getWalletSession(status.nearAccountId);
              const { login: state } = session;
              if (isWalletSessionReadyForUi({ session })) {
                tatchi.preferences.setCurrentUser(toAccountId(status.nearAccountId));
                setLoginState((prev) => ({
                  ...prev,
                  isLoggedIn: true,
                  nearAccountId: status.nearAccountId,
                  nearPublicKey: state.publicKey || null,
                  authMethod: session.authMethod || state.authMethod || null,
                  thresholdEcdsaEthereumAddress: state.thresholdEcdsaEthereumAddress || null,
                  thresholdEcdsaPublicKeyB64u: state.thresholdEcdsaPublicKeyB64u || null,
                }));
              } else {
                setLoginState((prev) => ({
                  ...prev,
                  isLoggedIn: false,
                  nearAccountId: null,
                  nearPublicKey: null,
                  authMethod: null,
                  thresholdEcdsaEthereumAddress: null,
                  thresholdEcdsaPublicKeyB64u: null,
                }));
              }
            } else if (status && status.isLoggedIn === false) {
              setLoginState((prev) => ({
                ...prev,
                isLoggedIn: false,
                nearAccountId: null,
                nearPublicKey: null,
                authMethod: null,
                thresholdEcdsaEthereumAddress: null,
                thresholdEcdsaPublicKeyB64u: null,
              }));
            }
          },
        );

        // Preferences changes (including current-user changes from wallet-host flows like device linking)
        // should update login state on the app origin as well.
        offPrefs = tatchi.onWalletIframePreferencesChanged(async (payload) => {
          if (cancelled) return;
          const acct = payload?.nearAccountId;
          if (acct) {
            try {
              const session = await tatchi.auth.getWalletSession(acct);
              const { login: state } = session;
              if (isWalletSessionReadyForUi({ session }) && state?.nearAccountId) {
                tatchi.preferences.setCurrentUser(toAccountId(state.nearAccountId));
                setLoginState((prev) => ({
                  ...prev,
                  isLoggedIn: true,
                  nearAccountId: state.nearAccountId,
                  nearPublicKey: state.publicKey || null,
                  authMethod: session.authMethod || state.authMethod || null,
                  thresholdEcdsaEthereumAddress: state.thresholdEcdsaEthereumAddress || null,
                  thresholdEcdsaPublicKeyB64u: state.thresholdEcdsaPublicKeyB64u || null,
                }));
                return;
              }
            } catch {}
          }
          setLoginState((prev) => ({
            ...prev,
            isLoggedIn: false,
            nearAccountId: null,
            nearPublicKey: null,
            authMethod: null,
            thresholdEcdsaEthereumAddress: null,
            thresholdEcdsaPublicKeyB64u: null,
          }));
        });

        const session = await tatchi.auth.getWalletSession();
        const { login: st } = session;
        if (isWalletSessionReadyForUi({ session })) {
          setLoginState((prev) => ({
            ...prev,
            isLoggedIn: true,
            nearAccountId: st.nearAccountId,
            nearPublicKey: st.publicKey || null,
            authMethod: session.authMethod || st.authMethod || null,
            thresholdEcdsaEthereumAddress: st.thresholdEcdsaEthereumAddress || null,
            thresholdEcdsaPublicKeyB64u: st.thresholdEcdsaPublicKeyB64u || null,
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

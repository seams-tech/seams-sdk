import { useEffect } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import type { SeamsWeb } from '@/web/SeamsWeb';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { LoginState } from '../types';
import { isWalletSessionReadyForUi } from './walletSessionReadiness';

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
              const { login: state } = session;
              if (isWalletSessionReadyForUi({ session })) {
                seams.preferences.setCurrentWallet(toWalletId(status.walletId));
                setLoginState((prev) => ({
                  ...prev,
                  isLoggedIn: true,
                  nearAccountId: state.nearAccountId,
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
        offPrefs = seams.onWalletIframePreferencesChanged(async (payload) => {
          if (cancelled) return;
          const walletId = payload?.walletId;
          if (walletId) {
            try {
              const session = await seams.auth.getWalletSession(walletId);
              const { login: state } = session;
              if (isWalletSessionReadyForUi({ session }) && state?.nearAccountId) {
                seams.preferences.setCurrentWallet(toWalletId(walletId));
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

        const session = await seams.auth.getWalletSession();
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

import { useCallback, useEffect } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import type { SeamsWeb } from '@/SeamsWeb';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { LoginState, SeamsContextType } from '../types';
import { isWalletSessionReadyForUi } from './walletSessionReadiness';

export function useLoginStateRefresher(args: {
  seams: SeamsWeb;
  walletIframeConnected: boolean;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
}) {
  const { seams, walletIframeConnected, setLoginState } = args;

  const refreshLoginState: SeamsContextType['refreshLoginState'] = useCallback(
    async (walletId?: string) => {
      try {
        if (walletIframeConnected) {
          try {
            const session = await seams.auth.getWalletSession();
            const { login: st } = session;
            if (isWalletSessionReadyForUi({ session })) {
              setLoginState((prevState) => ({
                ...prevState,
                nearAccountId: st.nearAccountId,
                nearPublicKey: st.publicKey || null,
                authMethod: session.authMethod || st.authMethod || null,
                thresholdEcdsaEthereumAddress: st.thresholdEcdsaEthereumAddress || null,
                thresholdEcdsaPublicKeyB64u: st.thresholdEcdsaPublicKeyB64u || null,
                isLoggedIn: true,
              }));
              return;
            }
          } catch {}
        }

        const session = await seams.auth.getWalletSession(walletId);
        const { login: ls } = session;
        if (isWalletSessionReadyForUi({ session })) {
          if (ls.nearAccountId) {
            try {
              seams.preferences.setCurrentWallet(toWalletId(ls.nearAccountId));
            } catch {}
          }
          setLoginState((prevState) => ({
            ...prevState,
            nearAccountId: ls.nearAccountId,
            nearPublicKey: ls.publicKey || null,
            authMethod: session.authMethod || ls.authMethod || null,
            thresholdEcdsaEthereumAddress: ls.thresholdEcdsaEthereumAddress || null,
            thresholdEcdsaPublicKeyB64u: ls.thresholdEcdsaPublicKeyB64u || null,
            isLoggedIn: true,
          }));
        } else {
          setLoginState((prevState) => ({
            ...prevState,
            nearAccountId: null,
            nearPublicKey: null,
            authMethod: null,
            thresholdEcdsaEthereumAddress: null,
            thresholdEcdsaPublicKeyB64u: null,
            isLoggedIn: false,
          }));
        }
      } catch (error) {
        console.error('Error refreshing login state:', error);
      }
    },
    [setLoginState, seams, walletIframeConnected],
  );

  useEffect(() => {
    void refreshLoginState();
  }, [refreshLoginState]);

  return refreshLoginState;
}

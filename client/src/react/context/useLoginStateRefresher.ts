import { useCallback, useEffect } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import type { TatchiPasskey } from '@/core/TatchiPasskey';
import { toAccountId } from '@/core/types/accountIds';
import type { LoginState, TatchiContextType } from '../types';
import { isWalletSessionReadyForUi } from './walletSessionReadiness';

export function useLoginStateRefresher(args: {
  tatchi: TatchiPasskey;
  walletIframeConnected: boolean;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
}) {
  const { tatchi, walletIframeConnected, setLoginState } = args;

  const refreshLoginState: TatchiContextType['refreshLoginState'] = useCallback(
    async (nearAccountId?: string) => {
      try {
        if (walletIframeConnected) {
          try {
            const session = await tatchi.auth.getWalletSession();
            const { login: st } = session;
            if (isWalletSessionReadyForUi({ session })) {
              setLoginState((prevState) => ({
                ...prevState,
                nearAccountId: st.nearAccountId,
                nearPublicKey: st.publicKey || null,
                thresholdEcdsaEthereumAddress: st.thresholdEcdsaEthereumAddress || null,
                thresholdEcdsaPublicKeyB64u: st.thresholdEcdsaPublicKeyB64u || null,
                isLoggedIn: true,
              }));
              return;
            }
          } catch {}
        }

        const session = await tatchi.auth.getWalletSession(nearAccountId);
        const { login: ls } = session;
        if (isWalletSessionReadyForUi({ session })) {
          if (ls.nearAccountId) {
            try {
              tatchi.preferences.setCurrentUser(toAccountId(ls.nearAccountId));
            } catch {}
          }
          setLoginState((prevState) => ({
            ...prevState,
            nearAccountId: ls.nearAccountId,
            nearPublicKey: ls.publicKey || null,
            thresholdEcdsaEthereumAddress: ls.thresholdEcdsaEthereumAddress || null,
            thresholdEcdsaPublicKeyB64u: ls.thresholdEcdsaPublicKeyB64u || null,
            isLoggedIn: true,
          }));
        } else {
          setLoginState((prevState) => ({
            ...prevState,
            nearAccountId: null,
            nearPublicKey: null,
            thresholdEcdsaEthereumAddress: null,
            thresholdEcdsaPublicKeyB64u: null,
            isLoggedIn: false,
          }));
        }
      } catch (error) {
        console.error('Error refreshing login state:', error);
      }
    },
    [setLoginState, tatchi, walletIframeConnected],
  );

  useEffect(() => {
    void refreshLoginState();
  }, [refreshLoginState]);

  return refreshLoginState;
}

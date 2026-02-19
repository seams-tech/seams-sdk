import { useCallback, useEffect } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import type { TatchiPasskey } from '@/core/TatchiPasskey';
import { toAccountId } from '@/core/types/accountIds';
import type { LoginState, TatchiContextType } from '../types';
import { isLoginSessionReadyForUi } from './loginReadiness';

export function useLoginStateRefresher(args: {
  tatchi: TatchiPasskey;
  walletIframeConnected: boolean;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
}) {
  const { tatchi, walletIframeConnected, setLoginState } = args;

  const refreshLoginState: TatchiContextType['refreshLoginState'] = useCallback(async (nearAccountId?: string) => {
    try {
      const signerMode = tatchi.configs?.signerMode;
      if (walletIframeConnected) {
        try {
          const session = await tatchi.getLoginSession();
          const { login: st } = session;
          if (isLoginSessionReadyForUi({ session, signerMode })) {
            setLoginState(prevState => ({
              ...prevState,
              nearAccountId: st.nearAccountId,
              nearPublicKey: st.publicKey || null,
              isLoggedIn: true,
            }));
            return;
          }
        } catch {}
      }

      const session = await tatchi.getLoginSession(nearAccountId);
      const { login: ls } = session;
      if (isLoginSessionReadyForUi({ session, signerMode })) {
        if (ls.nearAccountId) {
          try { tatchi.preferences.setCurrentUser(toAccountId(ls.nearAccountId)); } catch {}
        }
        setLoginState(prevState => ({
          ...prevState,
          nearAccountId: ls.nearAccountId,
          nearPublicKey: ls.publicKey || null,
          isLoggedIn: true,
        }));
      } else {
        setLoginState(prevState => ({
          ...prevState,
          nearAccountId: null,
          nearPublicKey: null,
          isLoggedIn: false,
        }));
      }
    } catch (error) {
      console.error('Error refreshing login state:', error);
    }
  }, [setLoginState, tatchi, walletIframeConnected]);

  useEffect(() => {
    void refreshLoginState();
  }, [refreshLoginState]);

  return refreshLoginState;
}

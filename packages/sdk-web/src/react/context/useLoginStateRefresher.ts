import { useCallback, useEffect } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import type { SeamsWeb } from '@/SeamsWeb';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { LoginState, SeamsContextType } from '../types';
import {
  isWalletSessionReadyForUi,
  shouldPreserveReactLoginForWalletSessionRead,
} from './walletSessionReadiness';
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
  setLoginState: Dispatch<SetStateAction<LoginState>>;
  setInputUsername: SeamsContextType['setInputUsername'];
}) {
  const { seams, setLoginState, setInputUsername } = args;

  const refreshLoginState: SeamsContextType['refreshLoginState'] = useCallback(
    async (walletId?: string) => {
      try {
        let exactWalletId: string | null;
        if (seams.configs.wallet.mode === 'iframe') {
          const state = await seams.getWalletIframeExactSessionState();
          switch (state.kind) {
            case 'active_session':
              exactWalletId = state.walletId;
              break;
            case 'wallet_unlocked_without_signing_session':
              switch (state.reason) {
                // On `superseded` the wallet is still unlocked and only the
                // reusable session was replaced. Keep the wallet and let this
                // refresh resolve current state; logging out would be wrong.
                case 'exhausted':
                case 'superseded':
                  exactWalletId = state.walletId;
                  break;
                case 'unavailable':
                case 'budget_unknown':
                  return;
                case 'not_found':
                case 'invalid':
                  setLoginState(buildReactLoggedOutLoginState());
                  return;
                default:
                  state.reason satisfies never;
                  return;
              }
              break;
            case 'expired_session':
            case 'wallet_locked':
              setLoginState(buildReactLoggedOutLoginState());
              return;
            default:
              state satisfies never;
              return;
          }
        } else {
          exactWalletId = resolveExactReactLoginWalletId(seams, walletId);
        }
        if (!exactWalletId) {
          setLoginState(buildReactLoggedOutLoginState());
          return;
        }

        const session = await seams.auth.getWalletSession(exactWalletId);
        if (shouldPreserveReactLoginForWalletSessionRead(session)) return;
        if (!isWalletSessionReadyForUi({ session })) {
          setLoginState(buildReactLoggedOutLoginState());
          return;
        }
        if (session.appIdentity.kind !== 'resolved') {
          setLoginState(buildReactLoggedOutLoginState());
          return;
        }
        const resolvedWalletId = session.appIdentity.walletId;
        if (resolvedWalletId) {
          seams.preferences.setCurrentWallet(toWalletId(resolvedWalletId));
          syncInputUsernameFromWalletId(setInputUsername, resolvedWalletId);
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
    if (seams.configs.wallet.mode === 'iframe') return;
    void refreshLoginState();
  }, [refreshLoginState, seams]);

  return refreshLoginState;
}

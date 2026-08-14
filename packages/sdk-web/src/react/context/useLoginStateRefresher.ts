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

async function refreshLocalLoginState(args: {
  seams: SeamsWeb;
  refreshLoginState: SeamsContextType['refreshLoginState'];
}): Promise<void> {
  await args.refreshLoginState();
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
          const requestedWalletId = String(walletId || '').trim();
          if (requestedWalletId) {
            exactWalletId = requestedWalletId;
          } else {
            const state = await seams.getWalletIframeExactSessionState();
            switch (state.kind) {
              case 'active_session':
              case 'expired_session':
              case 'wallet_authenticated_identity_unresolvable':
              case 'wallet_unlocked_without_signing_session':
                exactWalletId = state.walletId;
                break;
              case 'wallet_locked':
                setLoginState(buildReactLoggedOutLoginState());
                return;
              default:
                state satisfies never;
                return;
            }
          }
        } else {
          exactWalletId = resolveExactReactLoginWalletId(seams, walletId);
        }
        if (!exactWalletId) {
          setLoginState(buildReactLoggedOutLoginState());
          return;
        }

        const session = await seams.auth.getWalletSession(exactWalletId);
        if (
          session.authentication.kind === 'authenticated' &&
          session.appIdentity.kind !== 'resolved'
        ) {
          return;
        }
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
    void refreshLocalLoginState({ seams, refreshLoginState });
  }, [refreshLoginState, seams]);

  return refreshLoginState;
}

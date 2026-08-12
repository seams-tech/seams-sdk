import { useEffect } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import type { SeamsWeb } from '@/SeamsWeb';
import type { WalletIframeExactSessionState } from '@/SeamsWeb/walletIframe/shared/exactSessionState';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { LoginState } from '../types';
import {
  buildReactLoggedInLoginStateFromSession,
  buildReactLoggedOutLoginState,
} from './reactLoginStateBuilders';

type WalletIframeReactLifecycle = {
  cancelled: boolean;
  revision: number;
};

function setReactLoggedOutIfCurrent(args: {
  lifecycle: WalletIframeReactLifecycle;
  revision: number;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
}): void {
  if (!args.lifecycle.cancelled && args.lifecycle.revision === args.revision) {
    args.setLoginState(buildReactLoggedOutLoginState());
  }
}

async function applyExactWalletIframeSessionState(args: {
  seams: SeamsWeb;
  lifecycle: WalletIframeReactLifecycle;
  revision: number;
  state: WalletIframeExactSessionState;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
}): Promise<void> {
  switch (args.state.kind) {
    case 'active_session':
    case 'expired_session':
    case 'wallet_authenticated_identity_unresolvable':
    case 'wallet_unlocked_without_signing_session':
      break;
    case 'wallet_locked':
      setReactLoggedOutIfCurrent(args);
      return;
    default:
      args.state satisfies never;
      return;
  }

  await applyWalletIframeSession({
    seams: args.seams,
    lifecycle: args.lifecycle,
    revision: args.revision,
    walletId: args.state.walletId,
    setLoginState: args.setLoginState,
  });
}

async function applyWalletIframeSession(args: {
  seams: SeamsWeb;
  lifecycle: WalletIframeReactLifecycle;
  revision: number;
  walletId: string;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
}): Promise<void> {
  const session = await args.seams.auth.getWalletSession(args.walletId);
  if (args.lifecycle.cancelled || args.lifecycle.revision !== args.revision) return;
  if (session.authentication.kind === 'authenticated' && session.appIdentity.kind !== 'resolved') {
    return;
  }
  const nextLoginState = buildReactLoggedInLoginStateFromSession(session);
  if (nextLoginState === null) {
    args.setLoginState(buildReactLoggedOutLoginState());
    return;
  }
  args.seams.preferences.setCurrentWallet(toWalletId(nextLoginState.walletId));
  args.setLoginState(nextLoginState);
}

function applyWalletIframeLoginStatus(args: {
  seams: SeamsWeb;
  lifecycle: WalletIframeReactLifecycle;
  status: { isLoggedIn: boolean; walletId: string | null };
  setLoginState: Dispatch<SetStateAction<LoginState>>;
}): void {
  const revision = ++args.lifecycle.revision;
  if (!args.status.isLoggedIn || !args.status.walletId) {
    setReactLoggedOutIfCurrent({
      lifecycle: args.lifecycle,
      revision,
      setLoginState: args.setLoginState,
    });
    return;
  }
  void applyWalletIframeSession({
    seams: args.seams,
    lifecycle: args.lifecycle,
    revision,
    walletId: args.status.walletId,
    setLoginState: args.setLoginState,
  }).catch((error: unknown) => {
    console.warn('[SeamsContextProvider] WalletIframe login-state reconciliation failed:', error);
  });
}

async function reconcileExactWalletIframeSessionState(args: {
  seams: SeamsWeb;
  lifecycle: WalletIframeReactLifecycle;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
}): Promise<void> {
  const revision = ++args.lifecycle.revision;
  const state = await args.seams.getWalletIframeExactSessionState();
  if (args.lifecycle.cancelled || args.lifecycle.revision !== revision) return;
  await applyExactWalletIframeSessionState({
    seams: args.seams,
    lifecycle: args.lifecycle,
    revision,
    state,
    setLoginState: args.setLoginState,
  });
}

function reconcileExactWalletIframeSessionStateInBackground(args: {
  seams: SeamsWeb;
  lifecycle: WalletIframeReactLifecycle;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
}): void {
  void reconcileExactWalletIframeSessionState(args).catch((error: unknown) => {
    console.warn('[SeamsContextProvider] WalletIframe state refresh failed:', error);
  });
}

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
    const lifecycle: WalletIframeReactLifecycle = { cancelled: false, revision: 0 };

    (async () => {
      try {
        const useIframe = seams.configs.wallet.mode === 'iframe';
        if (!useIframe) {
          setWalletIframeConnected(false);
          return;
        }

        await seams.initWalletIframe();
        if (lifecycle.cancelled) return;

        setWalletIframeConnected(seams.isWalletIframeReady());
        offReady = seams.onWalletIframeReady(() => setWalletIframeConnected(true));

        offLogin = seams.onWalletIframeLoginStatusChanged((status) => {
          applyWalletIframeLoginStatus({
            seams,
            lifecycle,
            status,
            setLoginState,
          });
        });

        offPrefs = seams.onWalletIframePreferencesChanged(() => {
          reconcileExactWalletIframeSessionStateInBackground({
            seams,
            lifecycle,
            setLoginState,
          });
        });
        await reconcileExactWalletIframeSessionState({
          seams,
          lifecycle,
          setLoginState,
        });
      } catch (err) {
        console.warn('[SeamsContextProvider] WalletIframe init failed:', err);
      }
    })();

    return () => {
      lifecycle.cancelled = true;
      lifecycle.revision += 1;
      offReady && offReady();
      offLogin && offLogin();
      offPrefs && offPrefs();
    };
  }, [setLoginState, setWalletIframeConnected, seams]);
}

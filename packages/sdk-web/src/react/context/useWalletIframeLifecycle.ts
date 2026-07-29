import { useEffect } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import type { SeamsWeb } from '@/SeamsWeb';
import type { WalletIframeExactSessionState } from '@/SeamsWeb/walletIframe/shared/exactSessionState';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { LoginState } from '../types';
import { isWalletSessionReadUnavailable } from './walletSessionReadiness';
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
      break;
    case 'wallet_unlocked_without_signing_session':
      switch (args.state.reason) {
        // `superseded` is replaced, not broken: the wallet stays unlocked and
        // the lifecycle continues against whatever current state resolves to.
        case 'exhausted':
        case 'superseded':
          break;
        case 'unavailable':
        case 'budget_unknown':
          return;
        case 'not_found':
        case 'invalid':
          setReactLoggedOutIfCurrent(args);
          return;
        default:
          args.state.reason satisfies never;
          return;
      }
      break;
    case 'expired_session':
    case 'wallet_locked':
      setReactLoggedOutIfCurrent(args);
      return;
    default:
      args.state satisfies never;
      return;
  }

  const session = await args.seams.auth.getWalletSession(args.state.walletId);
  if (args.lifecycle.cancelled || args.lifecycle.revision !== args.revision) return;
  if (isWalletSessionReadUnavailable(session)) return;
  const nextLoginState = buildReactLoggedInLoginStateFromSession(session);
  if (nextLoginState === null) {
    args.setLoginState(buildReactLoggedOutLoginState());
    return;
  }
  args.seams.preferences.setCurrentWallet(toWalletId(nextLoginState.walletId));
  args.setLoginState(nextLoginState);
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

        offLogin = seams.onWalletIframeLoginStatusChanged(() => {
          reconcileExactWalletIframeSessionStateInBackground({
            seams,
            lifecycle,
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

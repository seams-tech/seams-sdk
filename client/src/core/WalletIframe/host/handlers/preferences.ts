import { toWalletId } from '../../../signingEngine/interfaces/ecdsaChainTarget';
import type { HandlerDeps, HandlerMap, Req } from './types';
import { respondOk, respondOkResult } from './shared';

export function createPreferencesWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_SET_CONFIRM_BEHAVIOR: async (req: Req<'PM_SET_CONFIRM_BEHAVIOR'>) => {
      const pm = deps.getSeamsWeb();
      const { behavior, walletId } = req.payload!;
      if (walletId) {
        pm.preferences.setCurrentWallet(toWalletId(walletId));
      }
      pm.setConfirmBehavior(behavior);
      respondOk(deps, req.requestId);
    },

    PM_SET_CONFIRMATION_CONFIG: async (req: Req<'PM_SET_CONFIRMATION_CONFIG'>) => {
      const pm = deps.getSeamsWeb();
      const { walletId } = req.payload || {};
      const incoming = (req.payload?.config || {}) as Record<string, unknown>;
      let patch: Record<string, unknown> = { ...incoming };
      if (walletId) {
        pm.preferences.setCurrentWallet(toWalletId(walletId));
        await pm.auth
          .getWalletSession(walletId)
          .then(({ login }) => {
            const existing = (login?.userData?.preferences?.confirmationConfig || {}) as Record<
              string,
              unknown
            >;
            patch = { ...existing, ...incoming };
          })
          .catch(() => undefined);
      }
      const base = pm.getConfirmationConfig();
      pm.setConfirmationConfig({ ...base, ...patch });
      respondOk(deps, req.requestId);
    },

    PM_GET_CONFIRMATION_CONFIG: async (req: Req<'PM_GET_CONFIRMATION_CONFIG'>) => {
      const pm = deps.getSeamsWeb();
      const result = pm.getConfirmationConfig();
      respondOkResult(deps, req.requestId, result);
    },

    PM_SET_THEME: async (req: Req<'PM_SET_THEME'>) => {
      const pm = deps.getSeamsWeb();
      const { theme } = req.payload!;
      try {
        pm.setTheme(theme);
      } catch {}
      try {
        if (theme === 'light' || theme === 'dark') {
          document.documentElement.setAttribute('data-w3a-theme', theme);
        }
      } catch {}
      respondOk(deps, req.requestId);
    },
  };
}

import type { LoginHooksOptions } from '@/core/types/sdkSentEvents';
import type { WalletSession } from '@/core/types/seams';
import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOk, respondOkResult, withProgress } from './shared';
import {
  exactSessionIdentitiesMatch,
  exactSessionStateFromWalletSession,
  parseWalletIframeExactSessionIdentity,
  type WalletIframeExactSessionState,
} from '../../shared/exactSessionState';
import {
  pmUnlockPayloadToLoginHooksOptions,
  requirePMUnlockPayload,
} from '../../shared/unlockOptions';
import type { PMGetExactWalletSessionStatePayload } from '../../shared/messages';
import {
  activeWalletOrHostedAppSessionJwt,
  clearWalletOriginAppSession,
  rememberWalletOriginAppSession,
} from '../hostedWalletSeamsSession';
import { createHostedAuthMenuHandlers } from './authMenu';

function assertUnlockPayloadHasNoParentBearer(payload: unknown): void {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return;
  const record = payload as Record<string, unknown>;
  const options =
    record.options && typeof record.options === 'object' && !Array.isArray(record.options)
      ? (record.options as Record<string, unknown>)
      : null;
  const inventoryOption =
    options?.ecdsaKeyFactsInventory &&
    typeof options.ecdsaKeyFactsInventory === 'object' &&
    !Array.isArray(options.ecdsaKeyFactsInventory)
      ? (options.ecdsaKeyFactsInventory as Record<string, unknown>)
      : null;
  const inventory =
    inventoryOption?.value &&
    typeof inventoryOption.value === 'object' &&
    !Array.isArray(inventoryOption.value)
      ? (inventoryOption.value as Record<string, unknown>)
      : null;
  if (inventory && Object.prototype.hasOwnProperty.call(inventory, 'appSessionJwt')) {
    throw new Error('wallet iframe unlock requests must not carry appSessionJwt');
  }
}

function walletOriginUnlockOptions(
  options: LoginHooksOptions,
  relayUrl: string,
  walletId: string,
): LoginHooksOptions {
  const optionsWithSession = options.session
    ? options
    : {
        ...options,
        session: {
          kind: 'jwt' as const,
          exchange: { type: 'passkey_assertion' as const },
        },
      };
  const inventory = optionsWithSession.ecdsaKeyFactsInventory;
  if (!inventory || inventory.mode === 'webauthn') return optionsWithSession;
  const appSessionJwt = activeWalletOrHostedAppSessionJwt(
    optionsWithSession.session?.relayUrl || relayUrl,
    walletId,
  );
  if (!appSessionJwt) {
    throw new Error('hosted-wallet Seams Session is required for app-session ECDSA inventory');
  }
  return {
    ...optionsWithSession,
    ecdsaKeyFactsInventory: {
      ...inventory,
      appSessionJwt,
    },
  };
}

function walletSessionRequestWalletId(
  pm: Pick<ReturnType<HandlerDeps['getSeamsWeb']>, 'preferences'>,
  payload: Req<'PM_GET_WALLET_SESSION'>['payload'],
): string | undefined {
  const requestedWalletId = String(payload?.walletId || '').trim();
  if (requestedWalletId) return requestedWalletId;
  const currentWalletId = String(pm.preferences.getCurrentWalletId() || '').trim();
  return currentWalletId || undefined;
}

async function resolveExactWalletSessionState(
  pm: ReturnType<HandlerDeps['getSeamsWeb']>,
  payload: PMGetExactWalletSessionStatePayload,
): Promise<WalletIframeExactSessionState> {
  let walletId: string | undefined;
  switch (payload.wallet.kind) {
    case 'current':
      walletId = pm.preferences.getCurrentWalletId() ?? undefined;
      break;
    case 'exact':
      walletId = payload.wallet.walletId.trim();
      if (!walletId) throw new Error('Wallet iframe exact session walletId is invalid');
      break;
  }
  if (payload.authenticationRead === 'restore') {
    await pm.restoreWalletAuthenticationStateFromHostSession(walletId);
  }
  const session = await pm.auth.getWalletSession(walletId);
  return exactSessionStateFromWalletSession(session);
}

export function createAuthWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    ...createHostedAuthMenuHandlers(deps),
    PM_UNLOCK: async (req: Req<'PM_UNLOCK'>) => {
      const pm = deps.getSeamsWeb();
      assertUnlockPayloadHasNoParentBearer(req.payload);
      const payload = requirePMUnlockPayload(req.payload);
      const requestedOptions = pmUnlockPayloadToLoginHooksOptions(payload);
      const localPasskeyUnlock = requestedOptions.session === undefined;
      const options = walletOriginUnlockOptions(
        requestedOptions,
        pm.configs.network.relayer.url,
        payload.walletId,
      );
      const passkeySessionUnlock =
        localPasskeyUnlock || requestedOptions.session?.exchange?.type === 'passkey_assertion';
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.auth.unlock(
        payload.walletId,
        withProgress(deps, req.requestId, options) as LoginHooksOptions,
      );
      if (deps.respondIfCancelled(req.requestId)) return;
      if (result.success && passkeySessionUnlock && result.jwt) {
        rememberWalletOriginAppSession({
          appSessionJwt: result.jwt,
          relayUrl: pm.configs.network.relayer.url,
          walletId: result.walletId,
        });
      } else if (!result.success && localPasskeyUnlock) {
        clearWalletOriginAppSession();
      }
      respondOkResult(deps, req.requestId, result);
    },

    PM_LOCK: async (req: Req<'PM_LOCK'>) => {
      const pm = deps.getSeamsWeb();
      await pm.auth.lock();
      clearWalletOriginAppSession();
      respondOk(deps, req.requestId);
    },

    PM_LOCK_EXACT_WALLET_SESSION: async (req: Req<'PM_LOCK_EXACT_WALLET_SESSION'>) => {
      const pm = deps.getSeamsWeb();
      const expected = parseWalletIframeExactSessionIdentity(req.payload);
      const current = await resolveExactWalletSessionState(pm, {
        authenticationRead: 'current',
        wallet: { kind: 'current' },
      });
      if (
        (current.kind !== 'active_session' && current.kind !== 'expired_session') ||
        !exactSessionIdentitiesMatch(current, expected)
      ) {
        respondOkResult(deps, req.requestId, { kind: 'stale_session', expected, current });
        return;
      }
      await pm.auth.lock();
      clearWalletOriginAppSession();
      respondOkResult(deps, req.requestId, { kind: 'locked', identity: expected });
    },

    PM_GET_WALLET_SESSION: async (req: Req<'PM_GET_WALLET_SESSION'>) => {
      const pm = deps.getSeamsWeb();
      const walletId = walletSessionRequestWalletId(pm, req.payload);
      const result: WalletSession = await pm.auth.getWalletSession(walletId);
      respondOkResult(deps, req.requestId, result);
    },

    PM_GET_EXACT_WALLET_SESSION_STATE: async (req: Req<'PM_GET_EXACT_WALLET_SESSION_STATE'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload;
      if (
        !payload ||
        (payload.authenticationRead !== 'restore' && payload.authenticationRead !== 'current') ||
        !payload.wallet ||
        (payload.wallet.kind !== 'current' && payload.wallet.kind !== 'exact') ||
        (payload.authenticationRead === 'restore' && payload.wallet.kind !== 'current')
      ) {
        throw new Error('Wallet iframe exact session read mode is invalid');
      }
      respondOkResult(deps, req.requestId, await resolveExactWalletSessionState(pm, payload));
    },

    PM_GET_RECENT_UNLOCKS: async (req: Req<'PM_GET_RECENT_UNLOCKS'>) => {
      const pm = deps.getSeamsWeb();
      const result = await pm.auth.getRecentUnlocks();
      respondOkResult(deps, req.requestId, result);
    },
  };
}

import type { LoginHooksOptions } from '@/core/types/sdkSentEvents';
import type { WalletSession } from '@/core/types/seams';
import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOk, respondOkResult, withProgress } from './shared';
import {
  exactSessionIdentitiesMatch,
  exactSessionStateFromWalletSession,
  parseWalletIframeExactSessionIdentity,
  parseWalletIframeMissingSessionIdentity,
  type WalletIframeExactSessionState,
} from '../../shared/exactSessionState';
import {
  pmUnlockPayloadToLoginHooksOptions,
  requirePMUnlockPayload,
} from '../../shared/unlockOptions';
import { activeHostedWalletAppSessionJwt } from '../hostedWalletSeamsSession';

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
): LoginHooksOptions {
  const inventory = options.ecdsaKeyFactsInventory;
  if (!inventory || inventory.mode === 'webauthn') return options;
  const appSessionJwt = activeHostedWalletAppSessionJwt(options.session?.relayUrl || relayUrl);
  if (!appSessionJwt) {
    throw new Error('hosted-wallet Seams Session is required for app-session ECDSA inventory');
  }
  return {
    ...options,
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
): Promise<WalletIframeExactSessionState> {
  const currentWalletId = String(pm.preferences.getCurrentWalletId() || '').trim();
  const recentUnlocks = currentWalletId ? null : await pm.auth.getRecentUnlocks();
  const recentWalletId = String(recentUnlocks?.lastUsedAccount?.walletId || '').trim();
  const walletId = currentWalletId || recentWalletId;
  if (!walletId) return { kind: 'wallet_locked' };
  const session = await pm.auth.getWalletSession(walletId);
  return exactSessionStateFromWalletSession(session);
}

export function createAuthWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_UNLOCK: async (req: Req<'PM_UNLOCK'>) => {
      const pm = deps.getSeamsWeb();
      assertUnlockPayloadHasNoParentBearer(req.payload);
      const payload = requirePMUnlockPayload(req.payload);
      const options = walletOriginUnlockOptions(
        pmUnlockPayloadToLoginHooksOptions(payload),
        pm.configs.network.relayer.url,
      );
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.auth.unlock(
        payload.walletId,
        withProgress(deps, req.requestId, options) as LoginHooksOptions,
      );
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_LOCK: async (req: Req<'PM_LOCK'>) => {
      const pm = deps.getSeamsWeb();
      await pm.auth.lock();
      respondOk(deps, req.requestId);
    },

    PM_LOCK_EXACT_WALLET_SESSION: async (req: Req<'PM_LOCK_EXACT_WALLET_SESSION'>) => {
      const pm = deps.getSeamsWeb();
      const expected = parseWalletIframeExactSessionIdentity(req.payload);
      const current = await resolveExactWalletSessionState(pm);
      if (
        (current.kind !== 'active_session' && current.kind !== 'expired_session') ||
        !exactSessionIdentitiesMatch(current, expected)
      ) {
        respondOkResult(deps, req.requestId, { kind: 'stale_session', expected, current });
        return;
      }
      await pm.auth.lock();
      respondOkResult(deps, req.requestId, { kind: 'locked', identity: expected });
    },

    PM_LOCK_MISSING_WALLET_SESSION: async (
      req: Req<'PM_LOCK_MISSING_WALLET_SESSION'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const expected = parseWalletIframeMissingSessionIdentity(req.payload);
      const current = await resolveExactWalletSessionState(pm);
      if (
        current.kind !== 'wallet_unlocked_without_signing_session' ||
        current.walletId !== expected.walletId ||
        current.reason !== expected.reason
      ) {
        respondOkResult(deps, req.requestId, { kind: 'stale_session', expected, current });
        return;
      }
      await pm.auth.lock();
      respondOkResult(deps, req.requestId, { kind: 'locked', identity: expected });
    },

    PM_GET_WALLET_SESSION: async (req: Req<'PM_GET_WALLET_SESSION'>) => {
      const pm = deps.getSeamsWeb();
      const walletId = walletSessionRequestWalletId(pm, req.payload);
      const result: WalletSession = await pm.auth.getWalletSession(walletId);
      respondOkResult(deps, req.requestId, result);
    },

    PM_GET_EXACT_WALLET_SESSION_STATE: async (
      req: Req<'PM_GET_EXACT_WALLET_SESSION_STATE'>,
    ) => {
      const pm = deps.getSeamsWeb();
      respondOkResult(deps, req.requestId, await resolveExactWalletSessionState(pm));
    },

    PM_GET_RECENT_UNLOCKS: async (req: Req<'PM_GET_RECENT_UNLOCKS'>) => {
      const pm = deps.getSeamsWeb();
      const result = await pm.auth.getRecentUnlocks();
      respondOkResult(deps, req.requestId, result);
    },
  };
}

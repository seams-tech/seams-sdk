import type { LoginHooksOptions } from '@/core/types/sdkSentEvents';
import type { WalletSession } from '@/core/types/seams';
import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOk, respondOkResult, withProgress } from './shared';
import {
  exactSessionIdentitiesMatch,
  parseWalletIframeExactSessionIdentity,
  readSelectedWalletIframeExactSessionState,
  type WalletIframeExactSessionReadDependencies,
  type WalletIframeExactSessionStatus,
  type WalletIframeExactSessionState,
} from '../../shared/exactSessionState';
import {
  reconcileWalletIframeExactSessions,
  type WalletIframeExactSessionReconciliationDependencies,
} from '../../shared/exactSessionReconciliation';
import {
  pmUnlockPayloadToLoginHooksOptions,
  requirePMUnlockPayload,
  type PMUnlockLoginHooksOptions,
} from '../../shared/unlockOptions';
import type { PMGetExactWalletSessionStatePayload } from '../../shared/messages';
import {
  activeHostedWalletSessionOperationCredential,
  clearHostedWalletSessions,
} from '../hostedWalletSeamsSession';
import { createHostedAuthMenuHandlers } from './authMenu';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { IndexedDBManager } from '@/core/indexedDB';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { createRelayerExactWalletSessionStatusPort } from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';

async function readWalletIframeExactSessionStatus(
  relayUrl: string,
  input: Parameters<WalletIframeExactSessionReadDependencies['readStatus']>[0],
): Promise<WalletIframeExactSessionStatus> {
  const normalizedRelayUrl = String(relayUrl || '').trim();
  if (!normalizedRelayUrl) throw new Error('Wallet iframe relayer URL is required');
  return await createRelayerExactWalletSessionStatusPort({
    relayerUrl: normalizedRelayUrl,
    operationCredential: input.operationCredential,
  }).read({
    walletSessionId: input.operationCredential.walletSessionId,
    quotaId: input.authorization.quotaId,
  });
}

function exactSessionReadDependenciesForRelay(
  relayUrl: string,
): WalletIframeExactSessionReadDependencies & WalletIframeExactSessionReconciliationDependencies {
  return {
    resolveSelectedWalletAuthority:
      IndexedDBManager.resolveSelectedWalletAuthority.bind(IndexedDBManager),
    listWalletAuthMethodsV2ForWallet:
      IndexedDBManager.listWalletAuthMethodsV2ForWallet.bind(IndexedDBManager),
    resolveWalletAuthorityForMethod:
      IndexedDBManager.resolveWalletAuthorityForMethod.bind(IndexedDBManager),
    readExactActiveForWallet: walletSessionAuthorizations.readExactActiveForWallet.bind(
      walletSessionAuthorizations,
    ),
    readStatus: readWalletIframeExactSessionStatus.bind(null, relayUrl),
    writeExactWithOperationCredential:
      walletSessionAuthorizations.writeExactWithOperationCredential.bind(
        walletSessionAuthorizations,
      ),
    nowMs: Date.now,
  };
}

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
  if (
    inventory &&
    (Object.prototype.hasOwnProperty.call(inventory, 'walletSessionToken') ||
      Object.prototype.hasOwnProperty.call(inventory, 'operationCredential'))
  ) {
    throw new Error('wallet iframe unlock requests must not carry a Wallet Session bearer');
  }
}

function walletOriginUnlockOptions(
  options: PMUnlockLoginHooksOptions,
  relayUrl: string,
): LoginHooksOptions {
  const inventory = options.ecdsaKeyFactsInventory;
  const { ecdsaKeyFactsInventory: _inventory, ...optionsWithoutInventory } = options;
  if (!inventory) return optionsWithoutInventory;
  if (inventory.mode === 'webauthn') {
    return { ...optionsWithoutInventory, ecdsaKeyFactsInventory: inventory };
  }
  const operationCredential = activeHostedWalletSessionOperationCredential(relayUrl);
  if (!operationCredential) {
    throw new Error('Hosted-wallet Wallet Session is required for opaque key-facts lookup');
  }
  return {
    ...optionsWithoutInventory,
    ecdsaKeyFactsInventory: {
      mode: 'wallet_session_operation_credential_v1',
      operationCredential,
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

async function resolvePersistedCurrentWalletId(
  pm: ReturnType<HandlerDeps['getSeamsWeb']>,
): Promise<string | undefined> {
  const currentWalletId = String(pm.preferences.getCurrentWalletId() || '').trim();
  if (currentWalletId) return currentWalletId;
  const recentUnlocks = await pm.auth.getRecentUnlocks();
  const lastUsedWalletId = String(recentUnlocks.lastUsedAccount?.walletId || '').trim();
  if (lastUsedWalletId) return lastUsedWalletId;
  const walletIds = recentUnlocks.walletIds
    .map((walletId) => String(walletId).trim())
    .filter(Boolean);
  return walletIds.length === 1 ? walletIds[0] : undefined;
}

async function resolveExactWalletSessionState(
  pm: ReturnType<HandlerDeps['getSeamsWeb']>,
  payload: PMGetExactWalletSessionStatePayload,
): Promise<WalletIframeExactSessionState> {
  let walletId: string | undefined;
  switch (payload.wallet.kind) {
    case 'current': {
      walletId = await resolvePersistedCurrentWalletId(pm);
      if (walletId) {
        pm.preferences.setCurrentWallet(toWalletId(walletId));
      }
      break;
    }
    case 'exact':
      walletId = payload.wallet.walletId.trim();
      if (!walletId) throw new Error('Wallet iframe exact session walletId is invalid');
      break;
  }
  if (!walletId) return { kind: 'wallet_locked' };
  const dependencies = exactSessionReadDependenciesForRelay(pm.configs.network.relayer.url);
  const reconciliation = await reconcileWalletIframeExactSessions(
    { walletId: toWalletId(walletId) },
    dependencies,
  );
  if (reconciliation.kind === 'failed') {
    return {
      kind: 'wallet_unlocked_without_signing_session',
      walletId: toWalletId(walletId),
      reason: reconciliation.reason,
    };
  }
  return await readSelectedWalletIframeExactSessionState(
    { walletId: toWalletId(walletId) },
    dependencies,
  );
}

export function createAuthWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    ...createHostedAuthMenuHandlers(deps),
    PM_UNLOCK: async (req: Req<'PM_UNLOCK'>) => {
      const pm = deps.getSeamsWeb();
      assertUnlockPayloadHasNoParentBearer(req.payload);
      const payload = requirePMUnlockPayload(req.payload);
      const requestedOptions = pmUnlockPayloadToLoginHooksOptions(payload);
      const options = walletOriginUnlockOptions(requestedOptions, pm.configs.network.relayer.url);
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.auth.unlock(
        payload.walletId,
        withProgress(deps, req.requestId, options) as LoginHooksOptions,
      );
      if (deps.respondIfCancelled(req.requestId)) return;
      if (!result.success) clearHostedWalletSessions();
      respondOkResult(deps, req.requestId, result);
    },

    PM_LOCK: async (req: Req<'PM_LOCK'>) => {
      const pm = deps.getSeamsWeb();
      clearHostedWalletSessions();
      await pm.auth.lock();
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
      clearHostedWalletSessions();
      await pm.auth.lock();
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

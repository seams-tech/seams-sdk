import { expect, test } from '@playwright/test';
import { createAuthWalletIframeHandlers } from '@/SeamsWeb/walletIframe/host/handlers/auth';
import type { HandlerDeps } from '@/SeamsWeb/walletIframe/host/handlers/walletIframeHandler.types';
import type {
  ChildToParentEnvelope,
  ParentToChildEnvelope,
} from '@/SeamsWeb/walletIframe/shared/messages';
import type { WalletSession } from '@/core/types/seams';
import { toAccountId } from '@/core/types/accountIds';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { buildNoCurrentWalletAuthMethod } from '@shared/utils/walletCapabilityBindings';
import {
  activeWalletSessionToken,
  clearHostedWalletSessions,
  redeemHostedWalletSeamsSession,
} from '@/SeamsWeb/walletIframe/host/hostedWalletSeamsSession';
import type { WalletAuthenticationRestoreAuth } from '@/SeamsWeb/signingSurface/ports';

const RELAY_URL = 'https://relay.example.test';
const WALLET_ORIGIN = 'https://wallet.example.test';
const HOST_WALLET_SESSION_TOKEN = 'wst_host-origin-token';

/**
 * Seeds the wallet host's own opaque Wallet Session the way a real hosted handoff does:
 * the host redeems a single-use exchange capability and keeps the token in its origin.
 */
async function seedHostedWalletSession(): Promise<void> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        ok: true,
        walletSessionId: 'wallet-session-1',
        walletSessionToken: HOST_WALLET_SESSION_TOKEN,
        curve: 'ecdsa',
        expiresAtMs: Date.now() + 60_000,
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    );
  try {
    await redeemHostedWalletSeamsSession(
      {
        exchangeCode: 'exchange-1',
        nonce: 'nonce-1',
        curve: 'ecdsa',
        appOrigin: 'https://app.example.test',
        walletOrigin: WALLET_ORIGIN,
        relayUrl: RELAY_URL,
      },
      RELAY_URL,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
}

function loggedInWalletSession(walletId: string): WalletSession {
  return {
    login: {
      isLoggedIn: true,
      walletId: walletIdFromString(walletId),
      nearAccountId: toAccountId(`${walletId}.near`),
      publicKey: 'ed25519:public-key',
      userData: null,
      currentAuthMethod: buildNoCurrentWalletAuthMethod(),
      authMethods: [],
      thresholdEcdsaEthereumAddress: null,
      thresholdEcdsaPublicKeyB64u: null,
    },
    signingSession: {
      sessionId: 'session-1',
      status: 'active',
      remainingUses: 3,
      expiresAtMs: Date.now() + 60_000,
    },
    currentAuthMethod: buildNoCurrentWalletAuthMethod(),
    authMethods: [],
    authMethod: 'passkey',
    retention: 'session',
    nonceDiagnostics: null,
  };
}

function createDeps(input: {
  currentWalletId: string | null;
  onGetWalletSession(walletId: string | undefined): WalletSession;
  onUnlock?: (...args: unknown[]) => unknown;
  onLock?: () => Promise<void>;
  onRestoreWalletAuthenticationState?: (
    walletId: string | undefined,
    auth: WalletAuthenticationRestoreAuth,
  ) => unknown;
  onRestoreWalletAuthenticationStateFromHostSession?: (walletId: string | undefined) => unknown;
  posted: ChildToParentEnvelope[];
}): HandlerDeps {
  const seamsWeb = {
    configs: {
      network: {
        relayer: { url: 'https://relay.example.test' },
      },
    },
    preferences: {
      getCurrentWalletId: () =>
        input.currentWalletId ? walletIdFromString(input.currentWalletId) : null,
    },
    auth: {
      getWalletSession: async (walletId: string | undefined) => input.onGetWalletSession(walletId),
      unlock: async (...args: unknown[]) =>
        input.onUnlock?.(...args) ?? { success: false, error: 'captured' },
      lock: async () => {
        await input.onLock?.();
      },
      restoreWalletAuthenticationState: async (
        walletId: string | undefined,
        auth: WalletAuthenticationRestoreAuth,
      ) => input.onRestoreWalletAuthenticationState?.(walletId, auth),
    },
    restoreWalletAuthenticationState: async (
      walletId: string | undefined,
      auth: WalletAuthenticationRestoreAuth,
    ) => input.onRestoreWalletAuthenticationState?.(walletId, auth),
    restoreWalletAuthenticationStateFromHostSession: async (walletId: string | undefined) =>
      input.onRestoreWalletAuthenticationStateFromHostSession?.(walletId),
  } as unknown as ReturnType<HandlerDeps['getSeamsWeb']>;

  return {
    getSeamsWeb: () => seamsWeb,
    post: (msg) => input.posted.push(msg),
    postProgress: () => undefined,
    isCancelled: () => false,
    respondIfCancelled: () => false,
  };
}

test.describe('wallet iframe auth handlers', () => {
  test('resolves wallet-session reads without payload walletId from host current wallet', async () => {
    const posted: ChildToParentEnvelope[] = [];
    const requestedWalletIds: (string | undefined)[] = [];
    const deps = createDeps({
      currentWalletId: 'harbor-current',
      posted,
      onGetWalletSession: (walletId) => {
        requestedWalletIds.push(walletId);
        return loggedInWalletSession(walletId || 'anonymous');
      },
    });
    const handlers = createAuthWalletIframeHandlers(deps);
    const request: Extract<ParentToChildEnvelope, { type: 'PM_GET_WALLET_SESSION' }> = {
      type: 'PM_GET_WALLET_SESSION',
      requestId: 'req-1',
    };

    await handlers.PM_GET_WALLET_SESSION!(request);

    expect(requestedWalletIds).toEqual(['harbor-current']);
    expect(posted).toHaveLength(1);
    expect(posted[0]).toMatchObject({
      type: 'PM_RESULT',
      requestId: 'req-1',
      payload: {
        ok: true,
        result: {
          login: {
            isLoggedIn: true,
            walletId: 'harbor-current',
          },
        },
      },
    });
  });

  test('rejects a parent-supplied wallet session token on unlock', async () => {
    const posted: ChildToParentEnvelope[] = [];
    const unlockCalls: unknown[][] = [];
    const deps = createDeps({
      currentWalletId: 'harbor-current',
      posted,
      onGetWalletSession: (walletId) => loggedInWalletSession(walletId || 'anonymous'),
      onUnlock: (...args) => {
        unlockCalls.push(args);
        return { success: false, error: 'captured' };
      },
    });
    const handlers = createAuthWalletIframeHandlers(deps);

    await expect(
      handlers.PM_UNLOCK!({
        type: 'PM_UNLOCK',
        requestId: 'unlock-parent-bearer',
        payload: {
          kind: 'custom_options',
          walletId: 'harbor-current',
          options: {
            kind: 'pm_unlock_options_v1',
            signerSlot: { kind: 'default' },
            signingSession: { kind: 'default' },
            unlockSelection: { kind: 'default' },
            ecdsaKeyFactsInventory: {
              kind: 'value',
              value: {
                mode: 'opaque_wallet_session',
                curve: 'ecdsa_secp256k1',
                walletSessionToken: 'wst_parent-supplied-token',
              },
            },
          },
        },
      }),
    ).rejects.toThrow('wallet iframe unlock requests must not carry walletSessionToken');

    expect(unlockCalls).toHaveLength(0);
  });

  test('injects the host-origin wallet session token for opaque key-facts lookups', async () => {
    const originalWindow = Reflect.get(globalThis, 'window');
    const posted: ChildToParentEnvelope[] = [];
    const unlockCalls: unknown[][] = [];
    const deps = createDeps({
      currentWalletId: 'harbor-current',
      posted,
      onGetWalletSession: (walletId) => loggedInWalletSession(walletId || 'anonymous'),
      onUnlock: (...args) => {
        unlockCalls.push(args);
        return { success: false, error: 'captured' };
      },
    });
    Reflect.set(globalThis, 'window', { location: { origin: WALLET_ORIGIN } });

    try {
      await seedHostedWalletSession();
      const handlers = createAuthWalletIframeHandlers(deps);

      await handlers.PM_UNLOCK!({
        type: 'PM_UNLOCK',
        requestId: 'unlock-opaque',
        payload: {
          kind: 'custom_options',
          walletId: 'harbor-current',
          options: {
            kind: 'pm_unlock_options_v1',
            signerSlot: { kind: 'default' },
            signingSession: { kind: 'default' },
            unlockSelection: { kind: 'default' },
            ecdsaKeyFactsInventory: {
              kind: 'value',
              value: { mode: 'opaque_wallet_session', curve: 'ecdsa_secp256k1' },
            },
          },
        },
      });

      expect(unlockCalls).toHaveLength(1);
      expect(unlockCalls[0]).toEqual([
        'harbor-current',
        expect.objectContaining({
          ecdsaKeyFactsInventory: {
            mode: 'opaque_wallet_session',
            curve: 'ecdsa_secp256k1',
            walletSessionToken: HOST_WALLET_SESSION_TOKEN,
          },
        }),
      ]);
    } finally {
      clearHostedWalletSessions();
      if (originalWindow === undefined) Reflect.deleteProperty(globalThis, 'window');
      else Reflect.set(globalThis, 'window', originalWindow);
    }
  });

  test('passes webauthn key-facts lookups through without a wallet session token', async () => {
    const posted: ChildToParentEnvelope[] = [];
    const unlockCalls: unknown[][] = [];
    const deps = createDeps({
      currentWalletId: 'harbor-current',
      posted,
      onGetWalletSession: (walletId) => loggedInWalletSession(walletId || 'anonymous'),
      onUnlock: (...args) => {
        unlockCalls.push(args);
        return { success: false, error: 'captured' };
      },
    });
    const handlers = createAuthWalletIframeHandlers(deps);

    await handlers.PM_UNLOCK!({
      type: 'PM_UNLOCK',
      requestId: 'unlock-webauthn',
      payload: {
        kind: 'custom_options',
        walletId: 'harbor-current',
        options: {
          kind: 'pm_unlock_options_v1',
          signerSlot: { kind: 'default' },
          signingSession: { kind: 'default' },
          unlockSelection: { kind: 'default' },
          ecdsaKeyFactsInventory: { kind: 'value', value: { mode: 'webauthn' } },
        },
      },
    });

    expect(unlockCalls).toHaveLength(1);
    expect(unlockCalls[0]).toEqual([
      'harbor-current',
      expect.objectContaining({ ecdsaKeyFactsInventory: { mode: 'webauthn' } }),
    ]);
  });

  test('clears the host-origin wallet session when the wallet locks', async () => {
    const originalWindow = Reflect.get(globalThis, 'window');
    const posted: ChildToParentEnvelope[] = [];
    const deps = createDeps({
      currentWalletId: 'harbor-current',
      posted,
      onGetWalletSession: (walletId) => loggedInWalletSession(walletId || 'anonymous'),
    });
    Reflect.set(globalThis, 'window', { location: { origin: WALLET_ORIGIN } });

    try {
      await seedHostedWalletSession();
      expect(activeWalletSessionToken('ecdsa', RELAY_URL)).toBe(HOST_WALLET_SESSION_TOKEN);

      const handlers = createAuthWalletIframeHandlers(deps);
      await handlers.PM_LOCK!({ type: 'PM_LOCK', requestId: 'lock-hosted' });

      expect(activeWalletSessionToken('ecdsa', RELAY_URL)).toBeUndefined();
    } finally {
      clearHostedWalletSessions();
      if (originalWindow === undefined) Reflect.deleteProperty(globalThis, 'window');
      else Reflect.set(globalThis, 'window', originalWindow);
    }
  });

  test('acknowledges host lock before linked-device cleanup completes', async () => {
    let releaseCleanup!: () => void;
    let cleanupCompleted = false;
    const cleanup = new Promise<void>((resolve) => {
      releaseCleanup = resolve;
    });
    const posted: ChildToParentEnvelope[] = [];
    const deps = createDeps({
      currentWalletId: 'harbor-current',
      posted,
      onGetWalletSession: (walletId) => loggedInWalletSession(walletId || 'anonymous'),
      onLock: async () => {
        await cleanup;
        cleanupCompleted = true;
      },
    });
    const handlers = createAuthWalletIframeHandlers(deps);

    const handlerPromise = handlers.PM_LOCK!({
      type: 'PM_LOCK',
      requestId: 'lock-before-cleanup',
    });
    await expect.poll(() => posted.length).toBe(1);
    expect(posted[0]).toMatchObject({
      type: 'PM_RESULT',
      requestId: 'lock-before-cleanup',
      payload: { ok: true },
    });
    expect(cleanupCompleted).toBe(false);

    releaseCleanup();
    await handlerPromise;
    await expect.poll(() => cleanupCompleted).toBe(true);
  });

  test('passes unscoped wallet-session reads through when host current wallet is cold', async () => {
    const posted: ChildToParentEnvelope[] = [];
    const requestedWalletIds: (string | undefined)[] = [];
    const deps = createDeps({
      currentWalletId: null,
      posted,
      onGetWalletSession: (walletId) => {
        requestedWalletIds.push(walletId);
        return loggedInWalletSession(walletId || 'restored-from-last-profile');
      },
    });
    const handlers = createAuthWalletIframeHandlers(deps);
    const request: Extract<ParentToChildEnvelope, { type: 'PM_GET_WALLET_SESSION' }> = {
      type: 'PM_GET_WALLET_SESSION',
      requestId: 'req-2',
    };

    await handlers.PM_GET_WALLET_SESSION!(request);

    expect(requestedWalletIds).toEqual([undefined]);
    expect(posted).toHaveLength(1);
    expect(posted[0]).toMatchObject({
      type: 'PM_RESULT',
      requestId: 'req-2',
      payload: {
        ok: true,
        result: {
          login: {
            isLoggedIn: true,
            walletId: 'restored-from-last-profile',
          },
        },
      },
    });
  });
});

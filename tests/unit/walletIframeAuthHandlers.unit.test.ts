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
  activeHostedWalletAppSessionJwt,
  activeWalletOriginAppSessionJwt,
  clearWalletOriginAppSession,
} from '@/SeamsWeb/walletIframe/host/hostedWalletSeamsSession';
import { activeWalletSessionFixture } from './helpers/walletSessionReadProjection.fixtures';
import type { WalletAuthenticationRestoreAuth } from '@/SeamsWeb/signingSurface/ports';

function encoded(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

class MemoryStorage implements Storage {
  private readonly values = new Map<string, string>();

  get length(): number {
    return this.values.size;
  }

  clear(): void {
    this.values.clear();
  }

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  key(index: number): string | null {
    return Array.from(this.values.keys())[index] ?? null;
  }

  removeItem(key: string): void {
    this.values.delete(key);
  }

  setItem(key: string, value: string): void {
    this.values.set(key, String(value));
  }
}

function walletOriginPasskeyJwt(walletId: string): string {
  return `${encoded({ alg: 'none', typ: 'JWT' })}.${encoded({
    kind: 'app_session_v1',
    tenantId: 'tenant-1',
    sub: walletId,
    seamsSessionId: 'session-1',
    deviceId: 'device-1',
    provider: 'passkey',
    authSource: { kind: 'passkey', credentialIdB64u: 'credential-1' },
    sessionAudience: { kind: 'first_party_web', origin: 'https://wallet.example.test' },
    exp: Math.floor(Date.now() / 1000) + 3600,
  })}.signature`;
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
      lock: async () => undefined,
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

  test('defaults hosted passkey unlock to a JWT session and preserves explicit sessions', async () => {
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
      requestId: 'unlock-default',
      payload: { kind: 'default_options', walletId: 'harbor-current' },
    });
    await handlers.PM_UNLOCK!({
      type: 'PM_UNLOCK',
      requestId: 'unlock-explicit',
      payload: {
        kind: 'custom_options',
        walletId: 'harbor-current',
        options: {
          kind: 'pm_unlock_options_v1',
          signerSlot: { kind: 'default' },
          session: {
            kind: 'value',
            value: {
              kind: 'jwt',
              relayUrl: 'https://explicit-relay.example.test',
              route: '/explicit-exchange',
              exchange: { type: 'passkey_assertion' },
            },
          },
          signingSession: { kind: 'default' },
          unlockSelection: { kind: 'default' },
          ecdsaKeyFactsInventory: { kind: 'default' },
        },
      },
    });

    expect(unlockCalls).toHaveLength(2);
    expect(unlockCalls[0]).toEqual([
      'harbor-current',
      expect.objectContaining({
        session: {
          kind: 'jwt',
          exchange: { type: 'passkey_assertion' },
        },
      }),
    ]);
    expect(unlockCalls[1]).toEqual([
      'harbor-current',
      expect.objectContaining({
        session: {
          kind: 'jwt',
          relayUrl: 'https://explicit-relay.example.test',
          route: '/explicit-exchange',
          exchange: { type: 'passkey_assertion' },
        },
      }),
    ]);
  });

  test('stores local passkey app session JWT and clears it when the wallet locks', async () => {
    const originalWindow = Reflect.get(globalThis, 'window');
    const walletId = 'harbor-current';
    const freshJwt = walletOriginPasskeyJwt(walletId);
    const posted: ChildToParentEnvelope[] = [];
    const deps = createDeps({
      currentWalletId: walletId,
      posted,
      onGetWalletSession: (requestedWalletId) =>
        loggedInWalletSession(requestedWalletId || walletId),
      onUnlock: async () => ({
        success: true,
        kind: 'near_wallet_unlocked',
        walletId: walletIdFromString(walletId),
        nearAccountId: toAccountId(`${walletId}.near`),
        loggedInNearAccountId: `${walletId}.near`,
        operationalPublicKey: 'ed25519:public-key',
        jwt: freshJwt,
      }),
    });
    Reflect.set(globalThis, 'window', { location: { origin: 'https://wallet.example.test' } });

    try {
      const handlers = createAuthWalletIframeHandlers(deps);
      await handlers.PM_UNLOCK!({
        type: 'PM_UNLOCK',
        requestId: 'unlock-local',
        payload: { kind: 'default_options', walletId },
      });

      expect(activeWalletOriginAppSessionJwt('https://relay.example.test', walletId)).toBe(
        freshJwt,
      );
      expect(activeHostedWalletAppSessionJwt('https://relay.example.test')).toBeUndefined();

      await handlers.PM_LOCK!({ type: 'PM_LOCK', requestId: 'lock-local' });
      expect(
        activeWalletOriginAppSessionJwt('https://relay.example.test', walletId),
      ).toBeUndefined();
    } finally {
      clearWalletOriginAppSession();
      if (originalWindow === undefined) Reflect.deleteProperty(globalThis, 'window');
      else Reflect.set(globalThis, 'window', originalWindow);
    }
  });

  test('restores a persisted wallet-origin app session with a cold wallet read and rejects mismatches', async () => {
    const originalWindow = Reflect.get(globalThis, 'window');
    const originalSessionStorage = Reflect.get(globalThis, 'sessionStorage');
    const storageKey = 'seams:wallet-origin-app-session:v1';
    const walletId = 'harbor-current';
    const freshJwt = walletOriginPasskeyJwt(walletId);
    const posted: ChildToParentEnvelope[] = [];
    const restoreCalls: Array<string | undefined> = [];
    const deps = createDeps({
      currentWalletId: null,
      posted,
      onGetWalletSession: (requestedWalletId) =>
        activeWalletSessionFixture({ walletId: requestedWalletId || walletId }),
      onUnlock: async () => ({
        success: true,
        kind: 'near_wallet_unlocked',
        walletId: walletIdFromString(walletId),
        nearAccountId: toAccountId(`${walletId}.near`),
        loggedInNearAccountId: `${walletId}.near`,
        operationalPublicKey: 'ed25519:public-key',
        jwt: freshJwt,
      }),
      onRestoreWalletAuthenticationStateFromHostSession: (requestedWalletId) => {
        restoreCalls.push(requestedWalletId);
      },
    });
    Reflect.set(globalThis, 'window', { location: { origin: 'https://wallet.example.test' } });
    Reflect.set(globalThis, 'sessionStorage', new MemoryStorage());

    try {
      sessionStorage.removeItem(storageKey);
      const handlers = createAuthWalletIframeHandlers(deps);
      await handlers.PM_UNLOCK!({
        type: 'PM_UNLOCK',
        requestId: 'unlock-for-refresh',
        payload: { kind: 'default_options', walletId },
      });
      const persisted = sessionStorage.getItem(storageKey);
      expect(persisted).not.toBeNull();

      clearWalletOriginAppSession();
      sessionStorage.setItem(storageKey, persisted!);
      await handlers.PM_GET_EXACT_WALLET_SESSION_STATE!({
        type: 'PM_GET_EXACT_WALLET_SESSION_STATE',
        requestId: 'restore-after-refresh',
        payload: { authenticationRead: 'restore', wallet: { kind: 'current' } },
      });
      expect(restoreCalls).toEqual([undefined]);

      clearWalletOriginAppSession();
      sessionStorage.setItem(storageKey, persisted!);
      expect(
        activeWalletOriginAppSessionJwt('https://relay.example.test', 'harbor-other'),
      ).toBeUndefined();
      expect(sessionStorage.getItem(storageKey)).toBeNull();

      clearWalletOriginAppSession();
      sessionStorage.setItem(storageKey, persisted!);
      expect(activeWalletOriginAppSessionJwt('https://other-relay.example.test', walletId)).toBe(
        undefined,
      );
      expect(sessionStorage.getItem(storageKey)).toBeNull();
    } finally {
      clearWalletOriginAppSession();
      if (originalWindow === undefined) Reflect.deleteProperty(globalThis, 'window');
      else Reflect.set(globalThis, 'window', originalWindow);
      if (originalSessionStorage === undefined)
        Reflect.deleteProperty(globalThis, 'sessionStorage');
      else Reflect.set(globalThis, 'sessionStorage', originalSessionStorage);
    }
  });

  test('caches explicit passkey JWT unlocks and preserves the source for cookie unlocks', async () => {
    const originalWindow = Reflect.get(globalThis, 'window');
    const walletId = 'harbor-current';
    const freshJwt = walletOriginPasskeyJwt(walletId);
    const posted: ChildToParentEnvelope[] = [];
    let unlockCount = 0;
    const deps = createDeps({
      currentWalletId: walletId,
      posted,
      onGetWalletSession: (requestedWalletId) =>
        loggedInWalletSession(requestedWalletId || walletId),
      onUnlock: async () => {
        unlockCount += 1;
        return {
          success: true,
          kind: 'ecdsa_wallet_unlocked',
          walletId: walletIdFromString(walletId),
          ...(unlockCount === 1 ? { jwt: freshJwt } : {}),
        };
      },
    });
    Reflect.set(globalThis, 'window', { location: { origin: 'https://wallet.example.test' } });

    try {
      const handlers = createAuthWalletIframeHandlers(deps);
      await handlers.PM_UNLOCK!({
        type: 'PM_UNLOCK',
        requestId: 'unlock-explicit-jwt',
        payload: {
          kind: 'custom_options',
          walletId,
          options: {
            kind: 'pm_unlock_options_v1',
            signerSlot: { kind: 'default' },
            session: {
              kind: 'value',
              value: {
                kind: 'jwt',
                exchange: { type: 'passkey_assertion' },
              },
            },
            signingSession: { kind: 'default' },
            unlockSelection: { kind: 'default' },
            ecdsaKeyFactsInventory: { kind: 'default' },
          },
        },
      });

      expect(activeWalletOriginAppSessionJwt('https://relay.example.test', walletId)).toBe(
        freshJwt,
      );

      await handlers.PM_UNLOCK!({
        type: 'PM_UNLOCK',
        requestId: 'unlock-cookie',
        payload: {
          kind: 'custom_options',
          walletId,
          options: {
            kind: 'pm_unlock_options_v1',
            signerSlot: { kind: 'default' },
            session: {
              kind: 'value',
              value: {
                kind: 'cookie',
                exchange: { type: 'passkey_assertion' },
              },
            },
            signingSession: { kind: 'default' },
            unlockSelection: { kind: 'default' },
            ecdsaKeyFactsInventory: { kind: 'default' },
          },
        },
      });

      expect(activeWalletOriginAppSessionJwt('https://relay.example.test', walletId)).toBe(
        freshJwt,
      );
    } finally {
      clearWalletOriginAppSession();
      if (originalWindow === undefined) Reflect.deleteProperty(globalThis, 'window');
      else Reflect.set(globalThis, 'window', originalWindow);
    }
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

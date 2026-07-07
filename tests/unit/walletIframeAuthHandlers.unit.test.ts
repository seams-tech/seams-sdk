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
  posted: ChildToParentEnvelope[];
}): HandlerDeps {
  const seamsWeb = {
    preferences: {
      getCurrentWalletId: () =>
        input.currentWalletId ? walletIdFromString(input.currentWalletId) : null,
    },
    auth: {
      getWalletSession: async (walletId: string | undefined) => input.onGetWalletSession(walletId),
    },
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

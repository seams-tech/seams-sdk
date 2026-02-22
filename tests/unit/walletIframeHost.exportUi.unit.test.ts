import { expect, test } from '@playwright/test';
import { createWalletIframeHandlers } from '@/core/WalletIframe/host/wallet-iframe-handlers';
import type { ChildToParentEnvelope } from '@/core/WalletIframe/shared/messages';

type Deferred<T> = {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
};

function createDeferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function makeExportKeypairReq(requestId: string): any {
  return {
    type: 'PM_EXPORT_KEYPAIR_UI',
    requestId,
    payload: {
      nearAccountId: 'alice.testnet',
      chain: 'near',
      variant: 'drawer',
      theme: 'dark',
    },
  };
}

test.describe('wallet iframe host export UI handlers', () => {
  test('PM_EXPORT_KEYPAIR_UI waits for export operation before PM_RESULT', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const deferred = createDeferred<void>();
    let exportCalls = 0;

    const handlers = createWalletIframeHandlers({
      getTatchiPasskey: () =>
        ({
          keys: {
            exportKeypairWithUI: async () => {
              exportCalls += 1;
              return await deferred.promise;
            },
          },
        } as any),
      post: (msg) => posts.push(msg),
      postProgress: () => undefined,
      isCancelled: () => false,
      respondIfCancelled: () => false,
    });

    const requestPromise = handlers.PM_EXPORT_KEYPAIR_UI!(makeExportKeypairReq('req-await') as any);
    await Promise.resolve();

    expect(exportCalls).toBe(1);
    expect(posts).toEqual([]);

    deferred.resolve(undefined);
    await requestPromise;

    expect(posts).toEqual([
      expect.objectContaining({
        type: 'PM_RESULT',
        requestId: 'req-await',
      }),
    ]);
  });

  test('PM_EXPORT_KEYPAIR_UI throws on non-cancellation export errors', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const parentPosts: unknown[] = [];

    const handlers = createWalletIframeHandlers({
      getTatchiPasskey: () =>
        ({
          keys: {
            exportKeypairWithUI: async () => {
              throw new Error('No key material found for account alice.testnet device 1');
            },
          },
        } as any),
      post: (msg) => posts.push(msg),
      postProgress: () => undefined,
      postToParent: (msg) => parentPosts.push(msg),
      isCancelled: () => false,
      respondIfCancelled: () => false,
    });

    await expect(handlers.PM_EXPORT_KEYPAIR_UI!(makeExportKeypairReq('req-error') as any)).rejects.toThrow(
      'No key material found for account alice.testnet device 1',
    );

    expect(posts).toEqual([]);
    expect(parentPosts).toContainEqual({
      type: 'WALLET_UI_CLOSED',
      error: 'No key material found for account alice.testnet device 1',
    });
  });

  test('PM_EXPORT_KEYPAIR_UI treats TouchID cancellation as non-fatal', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const parentPosts: unknown[] = [];

    const handlers = createWalletIframeHandlers({
      getTatchiPasskey: () =>
        ({
          keys: {
            exportKeypairWithUI: async () => {
              throw new Error('NotAllowedError: The operation either timed out or was not allowed.');
            },
          },
        } as any),
      post: (msg) => posts.push(msg),
      postProgress: () => undefined,
      postToParent: (msg) => parentPosts.push(msg),
      isCancelled: () => false,
      respondIfCancelled: () => false,
    });

    await handlers.PM_EXPORT_KEYPAIR_UI!(makeExportKeypairReq('req-cancel') as any);

    expect(posts).toEqual([
      expect.objectContaining({
        type: 'PM_RESULT',
        requestId: 'req-cancel',
      }),
    ]);
    expect(parentPosts).toContainEqual({
      type: 'EXPORT_KEYPAIR_CANCELLED',
      nearAccountId: 'alice.testnet',
      chain: 'near',
    });
    expect(parentPosts).toContainEqual({
      type: 'WALLET_UI_CLOSED',
    });
  });
});

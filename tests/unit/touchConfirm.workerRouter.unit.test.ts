import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  touchConfirmManager: '/sdk/esm/core/signingEngine/touchConfirm/TouchConfirmManager.js',
} as const;

test.describe('UserConfirm worker router', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('routes concurrent responses by request id with one long-lived listener', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.touchConfirmManager);
      const manager = mod.createTouchConfirmManager({}, {
        touchIdPrompt: {},
        nearClient: {},
        indexedDB: {},
        userPreferencesManager: {},
        nonceManager: {},
      } as any);

      const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
        message: [],
        error: [],
      };
      const postedMessages: any[] = [];

      const fakeWorker: Worker = {
        addEventListener: ((type: string, handler: (event: any) => void) => {
          if (type === 'message' || type === 'error') listeners[type].push(handler);
        }) as any,
        removeEventListener: ((type: string, handler: (event: any) => void) => {
          if (type !== 'message' && type !== 'error') return;
          listeners[type] = listeners[type].filter((fn) => fn !== handler);
        }) as any,
        postMessage: ((message: unknown) => {
          postedMessages.push(message);
        }) as any,
        terminate: (() => {}) as any,
      } as unknown as Worker;

      const emitMessage = (data: unknown) => {
        for (const handler of [...listeners.message]) {
          handler({ data, currentTarget: fakeWorker, target: fakeWorker });
        }
      };

      (manager as any).worker = fakeWorker;
      (manager as any).attachWorkerRouter(fakeWorker);

      const p1 = (manager as any).sendMessage({
        type: 'PING',
        id: 'req-1',
        payload: {},
      }, 1000);
      const p2 = (manager as any).sendMessage({
        type: 'THRESHOLD_PRF_FIRST_CACHE_PEEK',
        id: 'req-2',
        payload: { sessionId: 'session-1' },
      }, 1000);

      const listenersDuring = {
        message: listeners.message.length,
        error: listeners.error.length,
      };

      emitMessage({ id: 'req-2', success: true, data: { order: 2 } });
      emitMessage({ id: 'req-1', success: true, data: { order: 1 } });

      const [r1, r2] = await Promise.all([p1, p2]);

      return {
        listenersDuring,
        listenersAfter: {
          message: listeners.message.length,
          error: listeners.error.length,
        },
        pendingAfter: (manager as any).pendingWorkerRequests.size,
        postedIds: postedMessages.map((m) => (m as any)?.id),
        responseOrder: [(r1 as any)?.data?.order, (r2 as any)?.data?.order],
      };
    }, { paths: IMPORT_PATHS });

    expect(result.listenersDuring).toEqual({ message: 1, error: 1 });
    expect(result.listenersAfter).toEqual({ message: 1, error: 1 });
    expect(result.pendingAfter).toBe(0);
    expect(result.postedIds).toEqual(['req-1', 'req-2']);
    expect(result.responseOrder).toEqual([1, 2]);
  });

  test('cleans up pending request on timeout', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.touchConfirmManager);
      const manager = mod.createTouchConfirmManager({}, {
        touchIdPrompt: {},
        nearClient: {},
        indexedDB: {},
        userPreferencesManager: {},
        nonceManager: {},
      } as any);

      const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
        message: [],
        error: [],
      };

      const fakeWorker: Worker = {
        addEventListener: ((type: string, handler: (event: any) => void) => {
          if (type === 'message' || type === 'error') listeners[type].push(handler);
        }) as any,
        removeEventListener: ((type: string, handler: (event: any) => void) => {
          if (type !== 'message' && type !== 'error') return;
          listeners[type] = listeners[type].filter((fn) => fn !== handler);
        }) as any,
        postMessage: (() => {}) as any,
        terminate: (() => {}) as any,
      } as unknown as Worker;

      (manager as any).worker = fakeWorker;
      (manager as any).attachWorkerRouter(fakeWorker);

      const timeoutResult = await (manager as any).sendMessage({
        type: 'PING',
        id: 'req-timeout',
        payload: {},
      }, 20).then(
        () => ({ ok: true, error: '' }),
        (error: any) => ({ ok: false, error: String(error?.message || error) })
      );

      return {
        timeoutResult,
        pendingAfter: (manager as any).pendingWorkerRequests.size,
        listenersAfter: {
          message: listeners.message.length,
          error: listeners.error.length,
        },
      };
    }, { paths: IMPORT_PATHS });

    expect(result.timeoutResult.ok).toBe(false);
    expect(result.timeoutResult.error).toContain('communication timeout');
    expect(result.timeoutResult.error).toContain('PING');
    expect(result.pendingAfter).toBe(0);
    expect(result.listenersAfter).toEqual({ message: 1, error: 1 });
  });

  test('rejects all pending requests when worker emits an error event', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.touchConfirmManager);
      const manager = mod.createTouchConfirmManager({}, {
        touchIdPrompt: {},
        nearClient: {},
        indexedDB: {},
        userPreferencesManager: {},
        nonceManager: {},
      } as any);

      const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
        message: [],
        error: [],
      };

      const fakeWorker: Worker = {
        addEventListener: ((type: string, handler: (event: any) => void) => {
          if (type === 'message' || type === 'error') listeners[type].push(handler);
        }) as any,
        removeEventListener: ((type: string, handler: (event: any) => void) => {
          if (type !== 'message' && type !== 'error') return;
          listeners[type] = listeners[type].filter((fn) => fn !== handler);
        }) as any,
        postMessage: (() => {}) as any,
        terminate: (() => {}) as any,
      } as unknown as Worker;

      const emitError = (message: string) => {
        for (const handler of [...listeners.error]) {
          handler({ message, currentTarget: fakeWorker, target: fakeWorker });
        }
      };

      (manager as any).worker = fakeWorker;
      (manager as any).attachWorkerRouter(fakeWorker);

      const p1 = (manager as any).sendMessage({
        type: 'PING',
        id: 'req-error-1',
        payload: {},
      }, 1000).then(
        () => ({ ok: true, error: '' }),
        (error: any) => ({ ok: false, error: String(error?.message || error) })
      );
      const p2 = (manager as any).sendMessage({
        type: 'THRESHOLD_PRF_FIRST_CACHE_CLEAR',
        id: 'req-error-2',
        payload: { sessionId: 's1' },
      }, 1000).then(
        () => ({ ok: true, error: '' }),
        (error: any) => ({ ok: false, error: String(error?.message || error) })
      );

      emitError('simulated worker crash');
      const [r1, r2] = await Promise.all([p1, p2]);

      return {
        r1,
        r2,
        pendingAfter: (manager as any).pendingWorkerRequests.size,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.r1.ok).toBe(false);
    expect(result.r2.ok).toBe(false);
    expect(result.r1.error).toContain('UserConfirm worker failed: simulated worker crash');
    expect(result.r2.error).toContain('UserConfirm worker failed: simulated worker crash');
    expect(result.pendingAfter).toBe(0);
  });

  test('cleans up pending request when aborted', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.touchConfirmManager);
      const manager = mod.createTouchConfirmManager({}, {
        touchIdPrompt: {},
        nearClient: {},
        indexedDB: {},
        userPreferencesManager: {},
        nonceManager: {},
      } as any);

      const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
        message: [],
        error: [],
      };

      const fakeWorker: Worker = {
        addEventListener: ((type: string, handler: (event: any) => void) => {
          if (type === 'message' || type === 'error') listeners[type].push(handler);
        }) as any,
        removeEventListener: ((type: string, handler: (event: any) => void) => {
          if (type !== 'message' && type !== 'error') return;
          listeners[type] = listeners[type].filter((fn) => fn !== handler);
        }) as any,
        postMessage: (() => {}) as any,
        terminate: (() => {}) as any,
      } as unknown as Worker;

      (manager as any).worker = fakeWorker;
      (manager as any).attachWorkerRouter(fakeWorker);

      const controller = new AbortController();
      const aborted = (manager as any).sendMessage({
        type: 'PING',
        id: 'req-abort',
        payload: {},
      }, 1_000, controller.signal).then(
        () => ({ ok: true, error: '' }),
        (error: any) => ({ ok: false, error: String(error?.message || error) })
      );
      controller.abort();
      const result = await aborted;

      return {
        result,
        pendingAfter: (manager as any).pendingWorkerRequests.size,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.result.ok).toBe(false);
    expect(result.result.error).toContain('request aborted');
    expect(result.result.error).toContain('PING');
    expect(result.pendingAfter).toBe(0);
  });

  test('exportPrivateKeysWithUi strips secret fields from worker payload', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.touchConfirmManager);
      const manager = mod.createTouchConfirmManager({}, {
        touchIdPrompt: {},
        nearClient: {},
        indexedDB: {},
        userPreferencesManager: {},
        nonceManager: {},
      } as any);

      const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
        message: [],
        error: [],
      };
      const postedMessages: any[] = [];

      const fakeWorker: Worker = {
        addEventListener: ((type: string, handler: (event: any) => void) => {
          if (type === 'message' || type === 'error') listeners[type].push(handler);
        }) as any,
        removeEventListener: ((type: string, handler: (event: any) => void) => {
          if (type !== 'message' && type !== 'error') return;
          listeners[type] = listeners[type].filter((fn) => fn !== handler);
        }) as any,
        postMessage: ((message: unknown) => {
          postedMessages.push(message);
        }) as any,
        terminate: (() => {}) as any,
      } as unknown as Worker;

      const emitMessage = (data: unknown) => {
        for (const handler of [...listeners.message]) {
          handler({ data, currentTarget: fakeWorker, target: fakeWorker });
        }
      };

      (manager as any).worker = fakeWorker;
      (manager as any).attachWorkerRouter(fakeWorker);

      const exportPromise = manager.exportPrivateKeysWithUi({
        nearAccountId: 'alice.testnet',
        deviceNumber: 1,
        hasThresholdKeyMaterial: true,
        chain: 'near',
      } as any);
      const posted = await new Promise<any>((resolve, reject) => {
        let attempts = 0;
        const poll = () => {
          if (postedMessages.length) {
            resolve(postedMessages[0]);
            return;
          }
          attempts += 1;
          if (attempts > 50) {
            reject(new Error('No worker message posted for export request'));
            return;
          }
          setTimeout(poll, 0);
        };
        poll();
      });

      emitMessage({
        id: posted?.id,
        success: true,
        data: {
          ok: true,
          accountId: 'alice.testnet',
          exportedSchemes: ['ed25519'],
          privateKey: 'ed25519:SECRET',
          keys: [{ privateKey: 'ed25519:SECRET' }],
        },
      });

      const parsed = await exportPromise;
      return {
        postedType: posted?.type,
        parsed,
        hasPrivateKeyField: Object.prototype.hasOwnProperty.call(parsed, 'privateKey'),
        hasKeysField: Object.prototype.hasOwnProperty.call(parsed, 'keys'),
      };
    }, { paths: IMPORT_PATHS });

    expect(result.postedType).toBe('EXPORT_PRIVATE_KEYS_WITH_UI');
    expect(result.parsed).toEqual({
      ok: true,
      accountId: 'alice.testnet',
      exportedSchemes: ['ed25519'],
    });
    expect(result.hasPrivateKeyField).toBe(false);
    expect(result.hasKeysField).toBe(false);
  });

  test('exportPrivateKeysWithUi rejects malformed worker response payload', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.touchConfirmManager);
      const manager = mod.createTouchConfirmManager({}, {
        touchIdPrompt: {},
        nearClient: {},
        indexedDB: {},
        userPreferencesManager: {},
        nonceManager: {},
      } as any);

      const listeners: Record<'message' | 'error', Array<(event: any) => void>> = {
        message: [],
        error: [],
      };
      const postedMessages: any[] = [];

      const fakeWorker: Worker = {
        addEventListener: ((type: string, handler: (event: any) => void) => {
          if (type === 'message' || type === 'error') listeners[type].push(handler);
        }) as any,
        removeEventListener: ((type: string, handler: (event: any) => void) => {
          if (type !== 'message' && type !== 'error') return;
          listeners[type] = listeners[type].filter((fn) => fn !== handler);
        }) as any,
        postMessage: ((message: unknown) => {
          postedMessages.push(message);
        }) as any,
        terminate: (() => {}) as any,
      } as unknown as Worker;

      const emitMessage = (data: unknown) => {
        for (const handler of [...listeners.message]) {
          handler({ data, currentTarget: fakeWorker, target: fakeWorker });
        }
      };

      (manager as any).worker = fakeWorker;
      (manager as any).attachWorkerRouter(fakeWorker);

      const exportResult = manager.exportPrivateKeysWithUi({
        nearAccountId: 'alice.testnet',
        deviceNumber: 1,
        hasThresholdKeyMaterial: true,
        chain: 'near',
      } as any).then(
        () => ({ ok: true, error: '' }),
        (error: any) => ({ ok: false, error: String(error?.message || error) }),
      );

      const posted = await new Promise<any>((resolve, reject) => {
        let attempts = 0;
        const poll = () => {
          if (postedMessages.length) {
            resolve(postedMessages[0]);
            return;
          }
          attempts += 1;
          if (attempts > 50) {
            reject(new Error('No worker message posted for export request'));
            return;
          }
          setTimeout(poll, 0);
        };
        poll();
      });
      emitMessage({
        id: posted?.id,
        success: true,
        data: {
          ok: true,
          accountId: 'alice.testnet',
          exportedSchemes: ['rsa2048'],
        },
      });

      return {
        postedType: posted?.type,
        exportResult: await exportResult,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.postedType).toBe('EXPORT_PRIVATE_KEYS_WITH_UI');
    expect(result.exportResult.ok).toBe(false);
    expect(result.exportResult.error).toContain('invalid worker response payload');
  });
});

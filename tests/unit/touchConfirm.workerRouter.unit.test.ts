import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  touchConfirmManager: '/sdk/esm/core/signingEngine/touchConfirm/TouchConfirmManager.js',
  thresholdSessionStore:
    '/sdk/esm/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.js',
  sealedSessionStore: '/sdk/esm/core/signingEngine/session/sealedSessionStore.js',
} as const;

test.describe('UserConfirm worker router', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('routes concurrent responses by request id with one long-lived listener', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const manager = mod.createTouchConfirmManager({}, {
          touchIdPrompt: {},
          nearClient: {},
          indexedDB: {},
          userPreferencesManager: {},
          nearContextFixture: {},
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

        const p1 = (manager as any).sendMessage(
          {
            type: 'PING',
            id: 'req-1',
            payload: {},
          },
          1000,
        );
        const p2 = (manager as any).sendMessage(
          {
            type: 'WARM_SESSION_STATUS_READ',
            id: 'req-2',
            payload: { sessionId: 'session-1' },
          },
          1000,
        );

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
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.listenersDuring).toEqual({ message: 1, error: 1 });
    expect(result.listenersAfter).toEqual({ message: 1, error: 1 });
    expect(result.pendingAfter).toBe(0);
    expect(result.postedIds).toEqual(['req-1', 'req-2']);
    expect(result.responseOrder).toEqual([1, 2]);
  });

  test('cleans up pending request on timeout', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const manager = mod.createTouchConfirmManager({}, {
          touchIdPrompt: {},
          nearClient: {},
          indexedDB: {},
          userPreferencesManager: {},
          nearContextFixture: {},
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

        const timeoutResult = await (manager as any)
          .sendMessage(
            {
              type: 'PING',
              id: 'req-timeout',
              payload: {},
            },
            20,
          )
          .then(
            () => ({ ok: true, error: '' }),
            (error: any) => ({ ok: false, error: String(error?.message || error) }),
          );

        return {
          timeoutResult,
          pendingAfter: (manager as any).pendingWorkerRequests.size,
          listenersAfter: {
            message: listeners.message.length,
            error: listeners.error.length,
          },
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.timeoutResult.ok).toBe(false);
    expect(result.timeoutResult.error).toContain('communication timeout');
    expect(result.timeoutResult.error).toContain('PING');
    expect(result.pendingAfter).toBe(0);
    expect(result.listenersAfter).toEqual({ message: 1, error: 1 });
  });

  test('reads warm-session status snapshots in a single worker round trip', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const manager = mod.createTouchConfirmManager({}, {
          touchIdPrompt: {},
          nearClient: {},
          indexedDB: {},
          userPreferencesManager: {},
          nearContextFixture: {},
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

        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          throw new Error(`No worker message posted at index ${index}`);
        };

        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);

        const batchPromise = manager.getWarmSessionStatuses({
          sessionIds: ['sess-a', 'sess-b', 'sess-a'],
        });

        const posted = await waitForPosted(0);
        emitMessage({
          id: posted?.id,
          success: true,
          data: {
            results: [
              {
                sessionId: 'sess-a',
                result: {
                  ok: true,
                  remainingUses: 4,
                  expiresAtMs: Date.now() + 45_000,
                },
              },
              {
                sessionId: 'sess-b',
                result: {
                  ok: false,
                  code: 'not_found',
                  message: 'missing',
                },
              },
            ],
          },
        });

        const batchResult = await batchPromise;
        return {
          postedTypes: postedMessages.map((entry) => entry?.type),
          payloadSessionIds: postedMessages[0]?.payload?.sessionIds,
          batchResult,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.postedTypes).toEqual(['WARM_SESSION_STATUS_BATCH_READ']);
    expect(result.payloadSessionIds).toEqual(['sess-a', 'sess-b']);
    expect(result.batchResult).toEqual({
      results: [
        {
          sessionId: 'sess-a',
          result: {
            ok: true,
            remainingUses: expect.any(Number),
            expiresAtMs: expect.any(Number),
          },
        },
        {
          sessionId: 'sess-b',
          result: {
            ok: false,
            code: 'not_found',
            message: 'missing',
          },
        },
      ],
    });
  });

  test('rejects all pending requests when worker emits an error event', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const manager = mod.createTouchConfirmManager({}, {
          touchIdPrompt: {},
          nearClient: {},
          indexedDB: {},
          userPreferencesManager: {},
          nearContextFixture: {},
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

        const p1 = (manager as any)
          .sendMessage(
            {
              type: 'PING',
              id: 'req-error-1',
              payload: {},
            },
            1000,
          )
          .then(
            () => ({ ok: true, error: '' }),
            (error: any) => ({ ok: false, error: String(error?.message || error) }),
          );
        const p2 = (manager as any)
          .sendMessage(
            {
              type: 'WARM_SESSION_MATERIAL_CLEAR',
              id: 'req-error-2',
              payload: { sessionId: 's1' },
            },
            1000,
          )
          .then(
            () => ({ ok: true, error: '' }),
            (error: any) => ({ ok: false, error: String(error?.message || error) }),
          );

        emitError('simulated worker crash');
        const [r1, r2] = await Promise.all([p1, p2]);

        return {
          r1,
          r2,
          pendingAfter: (manager as any).pendingWorkerRequests.size,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.r1.ok).toBe(false);
    expect(result.r2.ok).toBe(false);
    expect(result.r1.error).toContain('UserConfirm worker failed: simulated worker crash');
    expect(result.r2.error).toContain('UserConfirm worker failed: simulated worker crash');
    expect(result.pendingAfter).toBe(0);
  });

  test('cleans up pending request when aborted', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const manager = mod.createTouchConfirmManager({}, {
          touchIdPrompt: {},
          nearClient: {},
          indexedDB: {},
          userPreferencesManager: {},
          nearContextFixture: {},
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
        const aborted = (manager as any)
          .sendMessage(
            {
              type: 'PING',
              id: 'req-abort',
              payload: {},
            },
            1_000,
            controller.signal,
          )
          .then(
            () => ({ ok: true, error: '' }),
            (error: any) => ({ ok: false, error: String(error?.message || error) }),
          );
        controller.abort();
        const result = await aborted;

        return {
          result,
          pendingAfter: (manager as any).pendingWorkerRequests.size,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.result.ok).toBe(false);
    expect(result.result.error).toContain('request aborted');
    expect(result.result.error).toContain('PING');
    expect(result.pendingAfter).toBe(0);
  });

  test('routes signing-session seal and rehydrate worker messages', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const manager = mod.createTouchConfirmManager(
          {
            signingSessionPersistenceMode: 'sealed_refresh_v1',
          },
          {
            touchIdPrompt: {},
            nearClient: {},
            indexedDB: {},
            userPreferencesManager: {},
            nearContextFixture: {},
          } as any,
        );

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

        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          throw new Error(`No worker message posted at index ${index}`);
        };

        await sealedStoreMod.clearAllSealedSessions();
        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);

        const sealPromise = manager.sealAndPersistWarmSessionMaterial({
          sessionId: 'session-seal',
          transport: {
            relayerUrl: 'https://relay.example',
            thresholdSessionJwt: 'jwt-session',
            shamirPrimeB64u: 'AQAB',
          },
        });
        const sealRequest = await waitForPosted(0);
        emitMessage({
          id: sealRequest?.id,
          success: true,
          data: {
            ok: true,
            sealedSecretB64u: 'sealed-b64u',
            keyVersion: 'kek-v1',
            remainingUses: 9,
            expiresAtMs: 1700000000000,
          },
        });
        const sealResult = await sealPromise;

        const rehydratePromise = manager.rehydrateWarmSessionMaterial({
          sessionId: 'session-seal',
          sealedSecretB64u: 'sealed-b64u',
          keyVersion: 'kek-v1',
          remainingUses: 9,
          expiresAtMs: 1700000000000,
          transport: {
            relayerUrl: 'https://relay.example',
            thresholdSessionJwt: 'jwt-session',
            shamirPrimeB64u: 'AQAB',
          },
        });
        const rehydrateRequest = await waitForPosted(1);
        emitMessage({
          id: rehydrateRequest?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 8,
            expiresAtMs: 1700000000500,
          },
        });
        const rehydrateResult = await rehydratePromise;

        return {
          postedTypes: postedMessages.map((entry) => entry?.type),
          sealResult,
          rehydrateResult,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.postedTypes).toEqual(['WARM_SESSION_SEAL_AND_PERSIST', 'WARM_SESSION_REHYDRATE']);
    expect(result.sealResult).toEqual({
      ok: true,
      sealedSecretB64u: 'sealed-b64u',
      keyVersion: 'kek-v1',
      remainingUses: 9,
      expiresAtMs: 1700000000000,
    });
    expect(result.rehydrateResult).toEqual({
      ok: true,
      remainingUses: 8,
      expiresAtMs: 1700000000500,
    });
  });

  test('sealed mode restores only through explicit signing restore command', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const manager = mod.createTouchConfirmManager(
          {
            signingSessionPersistenceMode: 'sealed_refresh_v1',
          },
          {
            touchIdPrompt: {},
            nearClient: {},
            indexedDB: {},
            userPreferencesManager: {},
            nearContextFixture: {},
          } as any,
        );

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

        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          throw new Error(`No worker message posted at index ${index}`);
        };

        await sealedStoreMod.clearAllSealedSessions();
        await sealedStoreMod.writeExactSealedSession({
          walletId: 'account.testnet',
          thresholdSessionId: 'session-rehydrate',
          walletSigningSessionId: 'wallet-session-rehydrate',
          curve: 'ecdsa',
          authMethod: 'passkey',
          ecdsaRestore: {
            chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
            thresholdSessionJwt: 'jwt-session',
            sessionKind: 'jwt',
            ecdsaThresholdKeyId: 'ecdsa-key',
            relayerKeyId: 'relayer-key',
            participantIds: [1, 2, 3],
          },
          sealedSecretB64u: 'sealed-prf',
          keyVersion: 'kek-v2',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 10,
          updatedAtMs: Date.now(),
        });

        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);
        (manager as any).resolveSealTransportInput = () => ({
          curve: 'ecdsa',
          relayerUrl: 'https://relay.example',
          walletSigningSessionId: 'wallet-session-rehydrate',
          thresholdSessionJwt: 'jwt-session',
          shamirPrimeB64u: 'AQAB',
        });

        const restorePromise = manager.restorePersistedSessionForSigning({
          walletId: 'account.testnet',
          authMethod: 'passkey',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
          walletSigningSessionId: 'wallet-session-rehydrate',
          thresholdSessionId: 'session-rehydrate',
          reason: 'transaction',
        });

        const rehydrate = await waitForPosted(0);
        emitMessage({
          id: rehydrate?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 8,
            expiresAtMs: Date.now() + 45_000,
          },
        });

        const restoredStatusRead = await waitForPosted(1);
        emitMessage({
          id: restoredStatusRead?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 8,
            expiresAtMs: Date.now() + 45_000,
          },
        });

        const restoreResult = await restorePromise;
        const statusPromise = manager.getWarmSessionStatus({
          sessionId: 'session-rehydrate',
        });
        const statusRead = await waitForPosted(2);
        emitMessage({
          id: statusRead?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 8,
            expiresAtMs: Date.now() + 45_000,
          },
        });
        const statusResult = await statusPromise;
        const persisted = await sealedStoreMod.readExactSealedSession(
          'session-rehydrate',
          {
            authMethod: 'passkey',
            curve: 'ecdsa',
            chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
          },
        );

        return {
          postedTypes: postedMessages.map((entry) => entry?.type),
          restoreResult,
          statusResult,
          persistedPolicy: {
            remainingUses: persisted?.remainingUses,
          },
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.postedTypes).toEqual([
      'WARM_SESSION_REHYDRATE',
      'WARM_SESSION_STATUS_READ',
      'WARM_SESSION_STATUS_READ',
    ]);
    expect(result.restoreResult).toEqual({ attempted: 1, restored: 1, deferred: 0 });
    expect(result.statusResult.ok).toBe(true);
    expect(result.statusResult.remainingUses).toBe(8);
    expect(result.persistedPolicy.remainingUses).toBe(8);
  });

  test('sealed mode persists signing-session seal using canonical Ed25519 session-record transport fallback', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const sessionStoreMod = await import(paths.thresholdSessionStore);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const manager = mod.createTouchConfirmManager(
          {
            signingSessionPersistenceMode: 'sealed_refresh_v1',
            signingSessionSealKeyVersion: 'kek-v-ed25519',
            signingSessionSealShamirPrimeB64u: 'AQAB',
          },
          {
            touchIdPrompt: {},
            nearClient: {},
            indexedDB: {},
            userPreferencesManager: {},
            nearContextFixture: {},
          } as any,
        );

        sessionStoreMod.upsertStoredThresholdEd25519SessionRecord({
          nearAccountId: 'alice.testnet',
          rpId: 'example.localhost',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-ed25519',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'session-from-record',
          walletSigningSessionId: 'wallet-session-from-record',
          thresholdSessionJwt: 'jwt:session-from-record',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 5,
          updatedAtMs: Date.now(),
          source: 'login',
        });
        await sealedStoreMod.clearAllSealedSessions();

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

        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          throw new Error(`No worker message posted at index ${index}`);
        };

        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);

        const putPromise = manager.putWarmSessionMaterial({
          sessionId: 'session-from-record',
          prfFirstB64u: 'prf-first-from-record',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 5,
        });

        const putRequest = await waitForPosted(0);
        emitMessage({
          id: putRequest?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 5,
            expiresAtMs: Date.now() + 60_000,
          },
        });

        const sealRequest = await waitForPosted(1);
        emitMessage({
          id: sealRequest?.id,
          success: true,
          data: {
            ok: true,
            sealedSecretB64u: 'sealed-prf-first',
            keyVersion: 'kek-v-ed25519',
            remainingUses: 5,
            expiresAtMs: Date.now() + 60_000,
          },
        });

        await putPromise;

        return {
          postedTypes: postedMessages.map((entry) => entry?.type),
          sealPayload: postedMessages[1]?.payload || null,
          persistedRecord:
            await sealedStoreMod.readExactSealedSession('session-from-record', {
              authMethod: 'passkey',
              curve: 'ed25519',
            }),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.postedTypes).toEqual([
      'WARM_SESSION_MATERIAL_PUT',
      'WARM_SESSION_SEAL_AND_PERSIST',
    ]);
    expect(result.sealPayload).toMatchObject({
      sessionId: 'session-from-record',
      transport: {
        relayerUrl: 'https://relay.example',
        walletSigningSessionId: 'wallet-session-from-record',
        thresholdSessionJwt: 'jwt:session-from-record',
        keyVersion: 'kek-v-ed25519',
        shamirPrimeB64u: 'AQAB',
      },
    });
    expect(result.persistedRecord?.thresholdSessionIds.ed25519).toBe('session-from-record');
    expect(result.persistedRecord?.sealedSecretB64u).toBe('sealed-prf-first');
  });

  test('sealed mode persists signing-session seal using canonical ECDSA session-record transport fallback', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const sessionStoreMod = await import(paths.thresholdSessionStore);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const deps = {
          recordsByLane: new Map<string, unknown>(),
          exportArtifactsByLane: new Map<string, unknown>(),
        };
        sessionStoreMod.clearAllThresholdEcdsaSessionRecords(deps);
        await sealedStoreMod.clearAllSealedSessions();
        sessionStoreMod.upsertThresholdEcdsaSessionFromBootstrap(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'evm',
          source: 'login',
          signingSessionSeal: {
            keyVersion: 'kek-v-ecdsa',
            shamirPrimeB64u: 'AQID',
          },
          bootstrap: {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay-ecdsa.example',
              ecdsaThresholdKeyId: 'ek-evm-1',
              signingRootId: 'sr-ecdsa-1',
              signingRootVersion: 'v1',
              backendBinding: {
                relayerKeyId: 'rk-ecdsa',
                clientVerifyingShareB64u: 'cvs-ecdsa',
              },
              participantIds: [3, 7],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-ecdsa-record',
              walletSigningSessionId: 'wallet-session-ecdsa-record',
              thresholdSessionJwt: 'jwt:session-ecdsa-record',
              chainTarget: {
                kind: 'evm',
                namespace: 'eip155',
                chainId: 5042002,
                networkSlug: 'arc-testnet',
              },
              ethereumAddress: '0x1111111111111111111111111111111111111111',
              thresholdEcdsaPublicKeyB64u: 'pub-ecdsa-b64u',
              relayerVerifyingShareB64u: 'relayer-ecdsa-share-b64u',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: 'ek-evm-1',
              clientVerifyingShareB64u: 'cvs-ecdsa',
              relayerKeyId: 'rk-ecdsa',
              participantIds: [3, 7],
              ethereumAddress: '0x1111111111111111111111111111111111111111',
              thresholdEcdsaPublicKeyB64u: 'pub-ecdsa-b64u',
              relayerVerifyingShareB64u: 'relayer-ecdsa-share-b64u',
            },
            session: {
              ok: true,
              sessionId: 'session-ecdsa-record',
              walletSigningSessionId: 'wallet-session-ecdsa-record',
              jwt: 'jwt:session-ecdsa-record',
              expiresAtMs: Date.now() + 60_000,
              remainingUses: 4,
              clientVerifyingShareB64u: 'cvs-ecdsa',
            },
          },
        });

        const manager = mod.createTouchConfirmManager(
          {
            signingSessionPersistenceMode: 'sealed_refresh_v1',
          },
          {
            touchIdPrompt: {},
            nearClient: {},
            indexedDB: {},
            userPreferencesManager: {},
            nearContextFixture: {},
          } as any,
        );

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

        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          throw new Error(`No worker message posted at index ${index}`);
        };

        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);

        const putPromise = manager.putWarmSessionMaterial({
          sessionId: 'session-ecdsa-record',
          prfFirstB64u: 'prf-first-ecdsa-record',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 4,
        });

        const putRequest = await waitForPosted(0);
        emitMessage({
          id: putRequest?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 4,
            expiresAtMs: Date.now() + 60_000,
          },
        });

        const sealRequest = await waitForPosted(1);
        emitMessage({
          id: sealRequest?.id,
          success: true,
          data: {
            ok: true,
            sealedSecretB64u: 'sealed-prf-first-ecdsa',
            keyVersion: 'kek-v-ecdsa',
            remainingUses: 4,
            expiresAtMs: Date.now() + 60_000,
          },
        });

        await putPromise;

        return {
          postedTypes: postedMessages.map((entry) => entry?.type),
          sealPayload: postedMessages[1]?.payload || null,
          persistedRecord:
            await sealedStoreMod.readExactSealedSession('session-ecdsa-record', {
              authMethod: 'passkey',
              curve: 'ecdsa',
              chainTarget: {
                kind: 'evm',
                namespace: 'eip155',
                chainId: 5042002,
                networkSlug: 'arc-testnet',
              },
            }),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.postedTypes).toEqual([
      'WARM_SESSION_MATERIAL_PUT',
      'WARM_SESSION_SEAL_AND_PERSIST',
    ]);
    expect(result.sealPayload).toMatchObject({
      sessionId: 'session-ecdsa-record',
      transport: {
        relayerUrl: 'https://relay-ecdsa.example',
        walletSigningSessionId: 'wallet-session-ecdsa-record',
        thresholdSessionJwt: 'jwt:session-ecdsa-record',
        keyVersion: 'kek-v-ecdsa',
        shamirPrimeB64u: 'AQID',
      },
    });
    expect(result.persistedRecord?.thresholdSessionIds.ecdsa).toBe('session-ecdsa-record');
    expect(result.persistedRecord?.sealedSecretB64u).toBe('sealed-prf-first-ecdsa');
  });

  test('sealed mode dedupes concurrent seal persistence requests (apply-server-seal single-flight)', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const manager = mod.createTouchConfirmManager(
          {
            signingSessionPersistenceMode: 'sealed_refresh_v1',
          },
          {
            touchIdPrompt: {},
            nearClient: {},
            indexedDB: {},
            userPreferencesManager: {},
            nearContextFixture: {},
          } as any,
        );

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

        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          throw new Error(`No worker message posted at index ${index}`);
        };

        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);

        await sealedStoreMod.clearAllSealedSessions();
        const p1 = manager.persistSigningSessionSealForThresholdSession({
          sessionId: 'session-single-flight-apply',
          transport: {
            curve: 'ed25519',
            relayerUrl: 'https://relay.example',
            walletSigningSessionId: 'wallet-single-flight-apply',
            thresholdSessionJwt: 'jwt-session',
            keyVersion: 'kek-v1',
            shamirPrimeB64u: 'AQAB',
          },
        });
        const p2 = manager.persistSigningSessionSealForThresholdSession({
          sessionId: 'session-single-flight-apply',
          transport: {
            curve: 'ed25519',
            relayerUrl: 'https://relay.example',
            walletSigningSessionId: 'wallet-single-flight-apply',
            thresholdSessionJwt: 'jwt-session',
            keyVersion: 'kek-v1',
            shamirPrimeB64u: 'AQAB',
          },
        });

        const posted = await waitForPosted(0);
        emitMessage({
          id: posted?.id,
          success: true,
          data: {
            ok: true,
            sealedSecretB64u: 'sealed-b64u',
            keyVersion: 'kek-v1',
            remainingUses: 9,
            expiresAtMs: Date.now() + 45_000,
          },
        });

        const [r1, r2] = await Promise.all([p1, p2]);
        return {
          postedTypes: postedMessages.map((entry) => entry?.type),
          r1,
          r2,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.postedTypes).toEqual(['WARM_SESSION_SEAL_AND_PERSIST']);
    expect(result.r1).toEqual(result.r2);
    expect(result.r1.ok).toBe(true);
  });

  test('sealed mode dedupes concurrent seal persistence across manager instances', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const baseConfig = {
          signingSessionPersistenceMode: 'sealed_refresh_v1' as const,
        };
        const baseContext = {
          touchIdPrompt: {},
          nearClient: {},
          indexedDB: {},
          userPreferencesManager: {},
          nearContextFixture: {},
        } as any;

        const managerA = mod.createTouchConfirmManager(baseConfig, baseContext);
        const managerB = mod.createTouchConfirmManager(baseConfig, baseContext);

        const listenersA: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const listenersB: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const postedA: any[] = [];
        const postedB: any[] = [];

        const makeWorker = (
          listeners: Record<'message' | 'error', Array<(event: any) => void>>,
          postedMessages: any[],
        ): Worker =>
          ({
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
          }) as unknown as Worker;

        const workerA = makeWorker(listenersA, postedA);
        const workerB = makeWorker(listenersB, postedB);

        const emitMessage = (
          listeners: Record<'message' | 'error', Array<(event: any) => void>>,
          worker: Worker,
          data: unknown,
        ) => {
          for (const handler of [...listeners.message]) {
            handler({ data, currentTarget: worker, target: worker });
          }
        };

        const waitForPosted = async (postedMessages: any[], index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          throw new Error(`No worker message posted at index ${index}`);
        };

        await sealedStoreMod.clearAllSealedSessions();
        (managerA as any).worker = workerA;
        (managerA as any).attachWorkerRouter(workerA);
        (managerB as any).worker = workerB;
        (managerB as any).attachWorkerRouter(workerB);

        const p1 = managerA.persistSigningSessionSealForThresholdSession({
          sessionId: 'session-cross-manager-apply',
          transport: {
            curve: 'ed25519',
            relayerUrl: 'https://relay.example',
            walletSigningSessionId: 'wallet-cross-manager-apply',
            thresholdSessionJwt: 'jwt-session',
            keyVersion: 'kek-v1',
            shamirPrimeB64u: 'AQAB',
          },
        });
        const p2 = managerB.persistSigningSessionSealForThresholdSession({
          sessionId: 'session-cross-manager-apply',
          transport: {
            curve: 'ed25519',
            relayerUrl: 'https://relay.example',
            walletSigningSessionId: 'wallet-cross-manager-apply',
            thresholdSessionJwt: 'jwt-session',
            keyVersion: 'kek-v1',
            shamirPrimeB64u: 'AQAB',
          },
        });

        const posted = await waitForPosted(postedA, 0);
        emitMessage(listenersA, workerA, {
          id: posted?.id,
          success: true,
          data: {
            ok: true,
            sealedSecretB64u: 'sealed-b64u',
            keyVersion: 'kek-v1',
            remainingUses: 9,
            expiresAtMs: Date.now() + 45_000,
          },
        });

        const [r1, r2] = await Promise.all([p1, p2]);
        return {
          postedTypesA: postedA.map((entry) => entry?.type),
          postedTypesB: postedB.map((entry) => entry?.type),
          r1,
          r2,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.postedTypesA).toEqual(['WARM_SESSION_SEAL_AND_PERSIST']);
    expect(result.postedTypesB).toEqual([]);
    expect(result.r1).toEqual(result.r2);
    expect(result.r1.ok).toBe(true);
  });

  test('sealed mode dedupes concurrent explicit restores (remove-server-seal single-flight)', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const manager = mod.createTouchConfirmManager(
          {
            signingSessionPersistenceMode: 'sealed_refresh_v1',
          },
          {
            touchIdPrompt: {},
            nearClient: {},
            indexedDB: {},
            userPreferencesManager: {},
            nearContextFixture: {},
          } as any,
        );

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

        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          throw new Error(`No worker message posted at index ${index}`);
        };

        await sealedStoreMod.clearAllSealedSessions();
        await sealedStoreMod.writeExactSealedSession({
          walletId: 'account.testnet',
          thresholdSessionId: 'session-single-flight-remove',
          walletSigningSessionId: 'wallet-session-single-flight-remove',
          curve: 'ecdsa',
          authMethod: 'passkey',
          ecdsaRestore: {
            chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
            thresholdSessionJwt: 'jwt-session',
            sessionKind: 'jwt',
            ecdsaThresholdKeyId: 'ecdsa-key',
            relayerKeyId: 'relayer-key',
            participantIds: [1, 2, 3],
          },
          sealedSecretB64u: 'sealed-prf',
          keyVersion: 'kek-v1',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 10,
          updatedAtMs: Date.now(),
        });

        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);
        (manager as any).resolveSealTransportInput = () => ({
          curve: 'ecdsa',
          relayerUrl: 'https://relay.example',
          walletSigningSessionId: 'wallet-session-single-flight-remove',
          thresholdSessionJwt: 'jwt-session',
          shamirPrimeB64u: 'AQAB',
          keyVersion: 'kek-v1',
        });

        const restoreInput = {
          walletId: 'account.testnet',
          authMethod: 'passkey' as const,
          curve: 'ecdsa' as const,
          chain: 'tempo' as const,
          chainTarget: { kind: 'tempo' as const, chainId: 42431, networkSlug: 'tempo-moderato' },
          walletSigningSessionId: 'wallet-session-single-flight-remove',
          thresholdSessionId: 'session-single-flight-remove',
          reason: 'transaction' as const,
        };
        const p1 = manager.restorePersistedSessionForSigning({
          ...restoreInput,
        });
        const p2 = manager.restorePersistedSessionForSigning({
          ...restoreInput,
        });

        const rehydrate = await waitForPosted(0);
        emitMessage({
          id: rehydrate?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 8,
            expiresAtMs: Date.now() + 45_000,
          },
        });

        const finalPeek = await waitForPosted(1);
        emitMessage({
          id: finalPeek?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 8,
            expiresAtMs: Date.now() + 45_000,
          },
        });

        const [r1, r2] = await Promise.all([p1, p2]);
        return {
          postedTypes: postedMessages.map((entry) => entry?.type),
          rehydrateMessageCount: postedMessages.filter(
            (entry) => entry?.type === 'WARM_SESSION_REHYDRATE',
          ).length,
          r1,
          r2,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.rehydrateMessageCount).toBe(1);
    expect(result.postedTypes).toEqual(['WARM_SESSION_REHYDRATE', 'WARM_SESSION_STATUS_READ']);
    expect(result.r1.restored + result.r2.restored).toBe(1);
    expect(result.r1.deferred + result.r2.deferred).toBe(0);
  });

  test('sealed mode dedupes concurrent explicit restores across manager instances', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const baseConfig = {
          signingSessionPersistenceMode: 'sealed_refresh_v1' as const,
        };
        const baseContext = {
          touchIdPrompt: {},
          nearClient: {},
          indexedDB: {},
          userPreferencesManager: {},
          nearContextFixture: {},
        } as any;

        const managerA = mod.createTouchConfirmManager(baseConfig, baseContext);
        const managerB = mod.createTouchConfirmManager(baseConfig, baseContext);

        const listenersA: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const listenersB: Record<'message' | 'error', Array<(event: any) => void>> = {
          message: [],
          error: [],
        };
        const postedA: any[] = [];
        const postedB: any[] = [];

        const makeWorker = (
          listeners: Record<'message' | 'error', Array<(event: any) => void>>,
          postedMessages: any[],
        ): Worker =>
          ({
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
          }) as unknown as Worker;

        const workerA = makeWorker(listenersA, postedA);
        const workerB = makeWorker(listenersB, postedB);

        const emitMessage = (
          listeners: Record<'message' | 'error', Array<(event: any) => void>>,
          worker: Worker,
          data: unknown,
        ) => {
          for (const handler of [...listeners.message]) {
            handler({ data, currentTarget: worker, target: worker });
          }
        };

        const waitForPosted = async (postedMessages: any[], index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          throw new Error(`No worker message posted at index ${index}`);
        };

        await sealedStoreMod.clearAllSealedSessions();
        await sealedStoreMod.writeExactSealedSession({
          walletId: 'account.testnet',
          thresholdSessionId: 'session-cross-manager-remove',
          walletSigningSessionId: 'wallet-session-cross-manager-remove',
          curve: 'ecdsa',
          authMethod: 'passkey',
          ecdsaRestore: {
            chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
            thresholdSessionJwt: 'jwt-session',
            sessionKind: 'jwt',
            ecdsaThresholdKeyId: 'ecdsa-key',
            relayerKeyId: 'relayer-key',
            participantIds: [1, 2, 3],
          },
          sealedSecretB64u: 'sealed-prf',
          keyVersion: 'kek-v1',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 10,
          updatedAtMs: Date.now(),
        });

        (managerA as any).worker = workerA;
        (managerA as any).attachWorkerRouter(workerA);
        (managerA as any).resolveSealTransportInput = () => ({
          curve: 'ecdsa',
          relayerUrl: 'https://relay.example',
          walletSigningSessionId: 'wallet-session-cross-manager-remove',
          thresholdSessionJwt: 'jwt-session',
          shamirPrimeB64u: 'AQAB',
          keyVersion: 'kek-v1',
        });
        (managerB as any).worker = workerB;
        (managerB as any).attachWorkerRouter(workerB);
        (managerB as any).resolveSealTransportInput = () => ({
          curve: 'ecdsa',
          relayerUrl: 'https://relay.example',
          walletSigningSessionId: 'wallet-session-cross-manager-remove',
          thresholdSessionJwt: 'jwt-session',
          shamirPrimeB64u: 'AQAB',
          keyVersion: 'kek-v1',
        });

        const restoreInput = {
          walletId: 'account.testnet',
          authMethod: 'passkey' as const,
          curve: 'ecdsa' as const,
          chain: 'tempo' as const,
          chainTarget: { kind: 'tempo' as const, chainId: 42431, networkSlug: 'tempo-moderato' },
          walletSigningSessionId: 'wallet-session-cross-manager-remove',
          thresholdSessionId: 'session-cross-manager-remove',
          reason: 'transaction' as const,
        };
        const p1 = managerA.restorePersistedSessionForSigning({
          ...restoreInput,
        });
        const p2 = managerB.restorePersistedSessionForSigning({
          ...restoreInput,
        });

        const rehydrateA = await waitForPosted(postedA, 0);
        emitMessage(listenersA, workerA, {
          id: rehydrateA?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 8,
            expiresAtMs: Date.now() + 45_000,
          },
        });

        const finalPeekA = await waitForPosted(postedA, 1);
        emitMessage(listenersA, workerA, {
          id: finalPeekA?.id,
          success: true,
          data: {
            ok: true,
            remainingUses: 8,
            expiresAtMs: Date.now() + 45_000,
          },
        });

        const [r1, r2] = await Promise.all([p1, p2]);
        return {
          postedTypesA: postedA.map((entry) => entry?.type),
          postedTypesB: postedB.map((entry) => entry?.type),
          totalRehydrateCount:
            postedA.filter((entry) => entry?.type === 'WARM_SESSION_REHYDRATE').length +
            postedB.filter((entry) => entry?.type === 'WARM_SESSION_REHYDRATE').length,
          r1,
          r2,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.postedTypesA).toEqual(['WARM_SESSION_REHYDRATE', 'WARM_SESSION_STATUS_READ']);
    expect(result.postedTypesB).toEqual([]);
    expect(result.totalRehydrateCount).toBe(1);
    expect(result.r1.restored + result.r2.restored).toBe(1);
    expect(result.r1.deferred + result.r2.deferred).toBe(0);
  });

  test('non-sealed mode does not rehydrate from persisted record on cache miss', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const manager = mod.createTouchConfirmManager(
          {
            signingSessionPersistenceMode: 'none',
          },
          {
            touchIdPrompt: {},
            nearClient: {},
            indexedDB: {},
            userPreferencesManager: {},
            nearContextFixture: {},
          } as any,
        );

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

        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          throw new Error(`No worker message posted at index ${index}`);
        };

        await sealedStoreMod.clearAllSealedSessions();
        await sealedStoreMod.writeExactSealedSession({
          thresholdSessionId: 'session-no-rehydrate',
          walletSigningSessionId: 'wallet-session-no-rehydrate',
          curve: 'ecdsa',
          authMethod: 'passkey',
          ecdsaRestore: {
            chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
            thresholdSessionJwt: 'jwt-session',
            sessionKind: 'jwt',
            ecdsaThresholdKeyId: 'ecdsa-key',
            relayerKeyId: 'relayer-key',
            participantIds: [1, 2, 3],
          },
          sealedSecretB64u: 'sealed-prf',
          keyVersion: 'kek-v2',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 10,
          updatedAtMs: Date.now(),
        });

        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);

        const statusPromise = manager.getWarmSessionStatus({
          sessionId: 'session-no-rehydrate',
        });
        const firstStatusRead = await waitForPosted(0);
        emitMessage({
          id: firstStatusRead?.id,
          success: true,
          data: {
            ok: false,
            code: 'not_found',
            message: 'Warm-session material is not available for threshold session',
          },
        });
        const statusResult = await statusPromise;
        await new Promise((resolve) => setTimeout(resolve, 5));

        return {
          postedTypes: postedMessages.map((entry) => entry?.type),
          statusResult,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.postedTypes).toEqual(['WARM_SESSION_STATUS_READ']);
    expect(result.statusResult).toEqual({
      ok: false,
      code: 'not_found',
      message: 'Warm-session material is not available for threshold session',
    });
  });

  test('non-sealed mode hard-blocks seal/rehydrate worker calls', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const manager = mod.createTouchConfirmManager(
          {
            signingSessionPersistenceMode: 'none',
          },
          {
            touchIdPrompt: {},
            nearClient: {},
            indexedDB: {},
            userPreferencesManager: {},
            nearContextFixture: {},
          } as any,
        );

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

        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);

        const sealed = await manager.sealAndPersistWarmSessionMaterial({
          sessionId: 'session-disabled',
          transport: {
            relayerUrl: 'https://relay.example',
            shamirPrimeB64u: 'AQAB',
          },
        });
        const rehydrated = await manager.rehydrateWarmSessionMaterial({
          sessionId: 'session-disabled',
          sealedSecretB64u: 'sealed-prf',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 5,
          transport: {
            relayerUrl: 'https://relay.example',
            shamirPrimeB64u: 'AQAB',
          },
        });

        return {
          sealed,
          rehydrated,
          postedTypes: postedMessages.map((entry) => entry?.type),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.sealed).toEqual({
      ok: false,
      code: 'not_enabled',
      message:
        '[TouchConfirm] signing-session seal and persist requires signingSessionPersistenceMode="sealed_refresh_v1"',
    });
    expect(result.rehydrated).toEqual({
      ok: false,
      code: 'not_enabled',
      message:
        '[TouchConfirm] signing-session rehydrate requires signingSessionPersistenceMode="sealed_refresh_v1"',
    });
    expect(result.postedTypes).toEqual([]);
  });

  test('sealed mode deletes persisted record only after worker reports expired restore', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const manager = mod.createTouchConfirmManager(
          {
            signingSessionPersistenceMode: 'sealed_refresh_v1',
          },
          {
            touchIdPrompt: {},
            nearClient: {},
            indexedDB: {},
            userPreferencesManager: {},
            nearContextFixture: {},
          } as any,
        );

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

        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          throw new Error(`No worker message posted at index ${index}`);
        };

        await sealedStoreMod.clearAllSealedSessions();
        await sealedStoreMod.writeExactSealedSession({
          walletId: 'account.testnet',
          thresholdSessionId: 'session-expired',
          walletSigningSessionId: 'wallet-session-expired',
          curve: 'ecdsa',
          authMethod: 'passkey',
          ecdsaRestore: {
            chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
            thresholdSessionJwt: 'jwt-session',
            sessionKind: 'jwt',
            ecdsaThresholdKeyId: 'ecdsa-key',
            relayerKeyId: 'relayer-key',
            participantIds: [1, 2, 3],
          },
          sealedSecretB64u: 'sealed-prf',
          keyVersion: 'kek-v2',
          expiresAtMs: Date.now() - 1_000,
          remainingUses: 2,
          updatedAtMs: Date.now() - 2_000,
        });

        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);
        (manager as any).resolveSealTransportInput = () => ({
          curve: 'ecdsa',
          relayerUrl: 'https://relay.example',
          walletSigningSessionId: 'wallet-session-expired',
          thresholdSessionJwt: 'jwt-session',
          shamirPrimeB64u: 'AQAB',
        });

        const restorePromise = manager.restorePersistedSessionForSigning({
          walletId: 'account.testnet',
          authMethod: 'passkey',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
          walletSigningSessionId: 'wallet-session-expired',
          thresholdSessionId: 'session-expired',
          reason: 'transaction',
        });
        const rehydrate = await waitForPosted(0);
        emitMessage({
          id: rehydrate?.id,
          success: true,
          data: {
            ok: false,
            code: 'expired',
            message: 'Warm-session material expired for threshold session',
          },
        });
        const restoreResult = await restorePromise;
        await new Promise((resolve) => setTimeout(resolve, 5));
        const persistedAfter =
          await sealedStoreMod.readExactSealedSession('session-expired', {
            authMethod: 'passkey',
            curve: 'ecdsa',
            chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
          });

        return {
          postedTypes: postedMessages.map((entry) => entry?.type),
          restoreResult,
          persistedAfter,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.postedTypes).toEqual(['WARM_SESSION_REHYDRATE']);
    expect(result.restoreResult).toEqual({ attempted: 1, restored: 0, deferred: 1 });
    expect(result.persistedAfter).toBeNull();
  });

  test('exportPrivateKeysWithUi strips secret fields from worker payload', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const manager = mod.createTouchConfirmManager({}, {
          touchIdPrompt: {},
          nearClient: {},
          indexedDB: {},
          userPreferencesManager: {},
          nearContextFixture: {},
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
          signerSlot: 1,
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
      },
      { paths: IMPORT_PATHS },
    );

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
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const manager = mod.createTouchConfirmManager({}, {
          touchIdPrompt: {},
          nearClient: {},
          indexedDB: {},
          userPreferencesManager: {},
          nearContextFixture: {},
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

        const exportResult = manager
          .exportPrivateKeysWithUi({
            nearAccountId: 'alice.testnet',
            signerSlot: 1,
            hasThresholdKeyMaterial: true,
            chain: 'near',
          } as any)
          .then(
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
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.postedType).toBe('EXPORT_PRIVATE_KEYS_WITH_UI');
    expect(result.exportResult.ok).toBe(false);
    expect(result.exportResult.error).toContain('invalid worker response payload');
  });
});

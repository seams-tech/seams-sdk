import { expect, test } from '@playwright/test';
import {
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
  THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND,
} from '@shared/utils/sessionTokens';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  touchConfirmManager: '/_test-sdk/esm/core/signingEngine/uiConfirm/UiConfirmManager.js',
  thresholdSessionStore:
    '/_test-sdk/esm/core/signingEngine/session/persistence/records.js',
  sealedSessionStore: '/_test-sdk/esm/core/signingEngine/session/persistence/sealedSessionStore.js',
  availableSigningLanes:
    '/_test-sdk/esm/core/signingEngine/session/availability/availableSigningLanes.js',
  selectLane: '/_test-sdk/esm/core/signingEngine/session/identity/selectLane.js',
} as const;

function unsignedJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.`;
}

function thresholdEcdsaSessionJwt(args: {
  walletId: string;
  thresholdSessionId: string;
  signingGrantId: string;
  keyHandle: string;
  chainTarget: Record<string, unknown>;
}): string {
  return unsignedJwt({
    kind: THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND,
    sub: args.walletId,
    walletId: args.walletId,
    keyHandle: args.keyHandle,
    chainTarget: args.chainTarget,
    sessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
  });
}

function thresholdEd25519SessionJwt(args: {
  walletId: string;
  thresholdSessionId: string;
  signingGrantId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
}): string {
  return unsignedJwt({
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    sub: args.walletId,
    walletId: args.walletId,
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    relayerKeyId: 'relayer-key-ed25519-expiry-anchor',
    rpId: 'example.localhost',
    thresholdExpiresAtMs: Date.now() + 60_000,
    participantIds: [1, 2],
    runtimePolicyScope: {
      orgId: 'org-test',
      projectId: 'sr-test',
      envId: 'dev',
      signingRootVersion: 'default',
    },
    routerAbNormalSigning: {
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: 'signing-worker-ed25519-expiry-anchor',
    },
  });
}

test.describe('UserConfirm worker router', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('routes concurrent responses by request id with one long-lived listener', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const manager = mod.createUiConfirmManager({}, {
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
        const manager = mod.createUiConfirmManager({}, {
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
        const manager = mod.createUiConfirmManager({}, {
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
        const manager = mod.createUiConfirmManager({}, {
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
              type: 'WARM_SESSION_VOLATILE_MATERIAL_CLEAR',
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
        const manager = mod.createUiConfirmManager({}, {
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
        const sessionStoreMod = await import(paths.thresholdSessionStore);
        const manager = mod.createUiConfirmManager(
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

        let restoreResolution: unknown = { state: 'pending' };
        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          return null;
        };

        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error || new Error('Failed to clear sealed session test database'));
          request.onblocked = () => resolve();
        });
        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);

        const sealPromise = manager.sealAndPersistWarmSessionMaterial({
          sessionId: 'session-seal',
          transport: {
            relayerUrl: 'https://relay.example',
            walletSessionJwt: 'jwt-session',
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
            walletSessionJwt: 'jwt-session',
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
        const manager = mod.createUiConfirmManager(
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

        let restoreResolution: unknown = { state: 'pending' };
        const waitForPosted = async (index: number) => {
          for (let i = 0; i < 100; i += 1) {
            if (postedMessages[index]) return postedMessages[index];
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          return null;
        };

        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error || new Error('Failed to clear sealed session test database'));
          request.onblocked = () => resolve();
        });
        await sealedStoreMod.writeExactSealedSession(sealedStoreMod.buildCurrentSealedSessionRecord({
          walletId: 'account.testnet',
          thresholdSessionId: 'session-rehydrate',
          signingGrantId: 'wallet-session-rehydrate',
          curve: 'ecdsa',
          authMethod: 'passkey',
          relayerUrl: 'https://relay.example',
          ecdsaRestore: {
            chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
            source: 'manual-bootstrap',
            rpId: 'example.com',
            sessionKind: 'cookie',
            keyHandle: 'key-handle-ecdsa',
            ecdsaThresholdKeyId: 'ecdsa-key',
            ethereumAddress: `0x${'33'.repeat(20)}`,
            relayerKeyId: 'relayer-key',
            clientVerifyingShareB64u: 'client-verifying-share',
            thresholdEcdsaPublicKeyB64u: 'AhERERERERERERERERERERERERERERERERERERERERER',
            participantIds: [1, 2, 3],
            runtimePolicyScope: {
              orgId: 'org-test',
              projectId: 'sr-test',
              envId: 'dev',
              signingRootVersion: 'default',
            },
          },
          sealedSecretB64u: 'sealed-prf',
          keyVersion: 'kek-v2',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 10,
          updatedAtMs: Date.now(),
        })!);

        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);
        const transportInputs: any[] = [];
        (manager as any).resolveSealTransportInput = (
          thresholdSessionId: string,
          explicitTransport: any,
        ) => {
          transportInputs.push({ thresholdSessionId, explicitTransport });
          return {
            curve: 'ecdsa',
            chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
            relayerUrl: 'https://relay.example',
            signingGrantId: 'wallet-session-rehydrate',
            walletSessionJwt: 'jwt-session',
            shamirPrimeB64u: 'AQAB',
          };
        };

        const restorePromise = manager.restorePersistedSessionForSigning({
          walletId: 'account.testnet',
          authMethod: 'passkey',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
          signingGrantId: 'wallet-session-rehydrate',
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
          transportInputs,
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
    expect(result.transportInputs[0]?.explicitTransport?.chainTarget).toEqual({
      kind: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-moderato',
    });
    expect(result.persistedPolicy.remainingUses).toBe(8);
  });

  test('sealed mode persists signing-session seal using explicit ECDSA transport and canonical record metadata', async ({
    page,
  }) => {
    const canonicalSessionJwt = thresholdEcdsaSessionJwt({
      walletId: 'alice.testnet',
      thresholdSessionId: 'session-ecdsa-record',
      signingGrantId: 'wallet-session-ecdsa-record',
      keyHandle: 'key-handle-ecdsa-record',
      chainTarget: {
        kind: 'evm',
        namespace: 'eip155',
        chainId: 5042002,
        networkSlug: 'arc-testnet',
      },
    });
    const result = await page.evaluate(
      async ({ paths, canonicalSessionJwt }) => {
        const mod = await import(paths.touchConfirmManager);
        const sessionStoreMod = await import(paths.thresholdSessionStore);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const deps = {
          recordsByLane: new Map<string, unknown>(),
          exportArtifactsByLane: new Map<string, unknown>(),
        };
        sessionStoreMod.clearAllThresholdEcdsaSessionRecords(deps);
        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error || new Error('Failed to clear sealed session test database'));
          request.onblocked = () => resolve();
        });
        sessionStoreMod.upsertThresholdEcdsaSessionFact(deps, {
          walletId: 'alice.testnet',
          rpId: 'example.localhost',
          relayerUrl: 'https://relay-ecdsa.example',
          chainTarget: {
            kind: 'evm',
            namespace: 'eip155',
            chainId: 5042002,
            networkSlug: 'arc-testnet',
          },
          keyHandle: 'key-handle-ecdsa-record',
          ecdsaThresholdKeyId: 'ek-evm-1',
          signingRootId: 'sr-ecdsa-1',
          signingRootVersion: 'v1',
          relayerKeyId: 'rk-ecdsa',
          clientVerifyingShareB64u: 'cvs-ecdsa',
          participantIds: [3, 7],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'session-ecdsa-record',
          signingGrantId: 'wallet-session-ecdsa-record',
          walletSessionJwt: canonicalSessionJwt,
          signingSessionSealKeyVersion: 'kek-v-ecdsa',
          signingSessionSealShamirPrimeB64u: 'AQID',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 4,
          ethereumAddress: '0x1111111111111111111111111111111111111111',
          thresholdEcdsaPublicKeyB64u: 'AhERERERERERERERERERERERERERERERERERERERERER',
          relayerVerifyingShareB64u: 'relayer-ecdsa-share-b64u',
          source: 'login',
        });

        const manager = mod.createUiConfirmManager(
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
          transport: {
            curve: 'ecdsa',
            chainTarget: {
              kind: 'evm',
              namespace: 'eip155',
              chainId: 5042002,
              networkSlug: 'arc-testnet',
            },
            relayerUrl: 'https://relay-ecdsa.example',
            signingGrantId: 'wallet-session-ecdsa-record',
            walletSessionJwt: canonicalSessionJwt,
            keyVersion: 'kek-v-ecdsa',
            shamirPrimeB64u: 'AQID',
          },
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
      { paths: IMPORT_PATHS, canonicalSessionJwt },
    );

    expect(result.postedTypes).toEqual([
      'WARM_SESSION_MATERIAL_PUT',
      'WARM_SESSION_SEAL_AND_PERSIST',
    ]);
    expect(result.sealPayload).toMatchObject({
      sessionId: 'session-ecdsa-record',
      transport: {
        relayerUrl: 'https://relay-ecdsa.example',
        signingGrantId: 'wallet-session-ecdsa-record',
        walletSessionJwt: canonicalSessionJwt,
        keyVersion: 'kek-v-ecdsa',
        shamirPrimeB64u: 'AQID',
      },
    });
    expect(result.persistedRecord?.thresholdSessionIds.ecdsa).toBe('session-ecdsa-record');
    expect(result.persistedRecord?.sealedSecretB64u).toBe('sealed-prf-first-ecdsa');
  });

  test('sealed mode refreshes ECDSA policy without top-level signing-root metadata', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () =>
            reject(request.error || new Error('Failed to clear sealed session test database'));
          request.onblocked = () => resolve();
        });

        const chainTarget = {
          kind: 'evm' as const,
          namespace: 'eip155' as const,
          chainId: 5042002,
          networkSlug: 'arc-testnet',
        };
        const record = sealedStoreMod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'session-ecdsa-policy-refresh',
          signingGrantId: 'wallet-session-ecdsa-policy-refresh',
          curve: 'ecdsa',
          authMethod: 'passkey',
          walletId: 'alice.testnet',
          relayerUrl: 'https://relay-ecdsa.example',
          sealedSecretB64u: 'sealed-ecdsa-policy-refresh',
          ecdsaRestore: {
            chainTarget,
            source: 'manual-bootstrap',
            rpId: 'example.localhost',
            sessionKind: 'cookie',
            keyHandle: 'key-handle-ecdsa-policy-refresh',
            ethereumAddress: '0x1111111111111111111111111111111111111111',
            relayerKeyId: 'rk-ecdsa',
            participantIds: [3, 7],
          },
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 4,
          updatedAtMs: Date.now(),
        });
        if (!record) throw new Error('invalid ECDSA sealed session fixture');
        await sealedStoreMod.writeExactSealedSession(record);

        const manager = mod.createUiConfirmManager(
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
        await (manager as any).recordSessionUseConsumed(
          'session-ecdsa-policy-refresh',
          {
            ok: true,
            expiresAtMs: Date.now() + 45_000,
            remainingUses: 2,
          },
          'ecdsa',
          chainTarget,
        );

        const refreshed = await sealedStoreMod.readExactSealedSession(
          'session-ecdsa-policy-refresh',
          {
            authMethod: 'passkey',
            curve: 'ecdsa',
            chainTarget,
          },
        );
        return {
          remainingUses: refreshed?.remainingUses ?? null,
          sealedSecretB64u: refreshed?.sealedSecretB64u ?? null,
          hasTopLevelSigningRoot:
            !!refreshed &&
            (Object.prototype.hasOwnProperty.call(refreshed, 'signingRootId') ||
              Object.prototype.hasOwnProperty.call(refreshed, 'signingRootVersion')),
          restoreChainId: refreshed?.ecdsaRestore?.chainTarget.chainId ?? null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.remainingUses).toBe(2);
    expect(result.sealedSecretB64u).toBe('sealed-ecdsa-policy-refresh');
    expect(result.hasTopLevelSigningRoot).toBe(false);
    expect(result.restoreChainId).toBe(5042002);
  });

  test('sealed mode retains expired passkey Ed25519 policy as an exact reauth anchor', async ({
    page,
  }) => {
    const walletSessionJwt = thresholdEd25519SessionJwt({
      walletId: 'alice.testnet',
      thresholdSessionId: 'session-ed25519-expiry-anchor',
      signingGrantId: 'wallet-session-ed25519-expiry-anchor',
      nearAccountId: 'alice.testnet',
      nearEd25519SigningKeyId: 'near-ed25519-key-expiry-anchor',
    });
    const result = await page.evaluate(
      async ({ paths, walletSessionJwt }) => {
        const mod = await import(paths.touchConfirmManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const availableLanesMod = await import(paths.availableSigningLanes);
        const selectLaneMod = await import(paths.selectLane);
        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () =>
            reject(request.error || new Error('Failed to clear sealed session test database'));
          request.onblocked = () => resolve();
        });

        const thresholdSessionId = 'session-ed25519-expiry-anchor';
        const signingGrantId = 'wallet-session-ed25519-expiry-anchor';
        const nowMs = Date.now();
        const ed25519Restore = {
          nearAccountId: 'alice.testnet',
          nearEd25519SigningKeyId: 'near-ed25519-key-expiry-anchor',
          rpId: 'example.localhost',
          credentialIdB64u: 'credential-ed25519-expiry-anchor',
          relayerKeyId: 'relayer-key-ed25519-expiry-anchor',
          participantIds: [1, 2],
          sessionKind: 'jwt' as const,
          walletSessionJwt,
          signerSlot: 1,
          routerAbNormalSigning: {
            kind: 'router_ab_ed25519_normal_signing_v1' as const,
            signingWorkerId: 'signing-worker-ed25519-expiry-anchor',
          },
          runtimePolicyScope: {
            orgId: 'org-test',
            projectId: 'sr-test',
            envId: 'dev',
            signingRootVersion: 'default',
          },
        };
        const initialRecord = sealedStoreMod.buildCurrentSealedSessionRecord({
          thresholdSessionId,
          signingGrantId,
          thresholdSessionIds: { ed25519: thresholdSessionId },
          curve: 'ed25519',
          authMethod: 'passkey',
          walletId: 'alice.testnet',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-secret-ed25519-expiry-anchor',
          keyVersion: 'signing-session-seal-kek-test-r1',
          shamirPrimeB64u: 'prime-b64u',
          ed25519Restore,
          issuedAtMs: nowMs - 1_000,
          expiresAtMs: nowMs + 60_000,
          remainingUses: 3,
          updatedAtMs: nowMs,
        });
        if (!initialRecord) throw new Error('invalid Ed25519 expiry-anchor fixture');
        await sealedStoreMod.writeExactSealedSession(initialRecord);
        const initialStored = await sealedStoreMod.readExactSealedSession(thresholdSessionId, {
          authMethod: 'passkey',
          curve: 'ed25519',
        });
        if (!initialStored) throw new Error('Ed25519 expiry-anchor fixture was not persisted');

        const manager = mod.createUiConfirmManager(
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
        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);

        const observedExpiredAtMs = Date.now();
        const consumePromise = manager.consumeWarmSessionUses({
          sessionId: thresholdSessionId,
          uses: 1,
          curve: 'ed25519',
          chain: 'near',
        });
        for (let attempts = 0; !postedMessages[0] && attempts < 100; attempts += 1) {
          await new Promise((resolve) => setTimeout(resolve, 0));
        }
        const consumeRequest = postedMessages[0];
        if (!consumeRequest) throw new Error('Warm-session consume request was not posted');
        for (const handler of [...listeners.message]) {
          handler({
            currentTarget: fakeWorker,
            target: fakeWorker,
            data: {
              id: consumeRequest.id,
              success: true,
              data: {
                ok: false,
                code: 'expired',
                message: 'Warm-session material expired for threshold session',
              },
            },
          });
        }
        const consumeResult = await consumePromise;
        const retained = await sealedStoreMod.readExactSealedSession(thresholdSessionId, {
          authMethod: 'passkey',
          curve: 'ed25519',
        });
        const availableLanes = await availableLanesMod.readAvailableSigningLanes(
          {
            walletId: 'alice.testnet',
            authMethod: 'passkey',
            ecdsaChainTargets: [],
          },
          {
            listSealedRecordsForWallet: async ({ walletId, filter }) =>
              filter.curve === 'ed25519'
                ? await sealedStoreMod.listExactSealedSessionsForWallet({
                    walletId,
                    filter: { authMethod: 'passkey', curve: 'ed25519' },
                  })
                : await sealedStoreMod.listExactSealedSessionsForWallet({
                    walletId,
                    filter: {
                      authMethod: 'passkey',
                      curve: 'ecdsa',
                      chainTarget: filter.chainTarget,
                    },
                  }),
            listRuntimeEcdsaLanesForWallet: async () => [],
            listRuntimeEd25519RecordsForWallet: async () => [],
          },
        );
        const selection = selectLaneMod.selectTransactionLane({
          intent: {
            walletId: 'alice.testnet',
            curve: 'ed25519',
            chain: 'near',
            signerSelection: {
              kind: 'near_account',
              nearAccountId: 'alice.testnet',
            },
            authSelectionPolicy: { kind: 'any' },
            operationUsesNeeded: 1,
          },
          availableLanes,
        });
        return {
          availableEd25519Candidates: availableLanes.candidates.ed25519.near,
          consumeResult,
          postedType: consumeRequest.type,
          retained,
          selection,
          observedExpiredAtMs,
        };
      },
      { paths: IMPORT_PATHS, walletSessionJwt },
    );

    expect(result.postedType).toBe('WARM_SESSION_MATERIAL_CONSUME');
    expect(result.consumeResult).toMatchObject({ ok: false, code: 'expired' });
    expect(result.retained).not.toBeNull();
    expect(result.retained?.expiresAtMs).toBeLessThanOrEqual(Date.now());
    expect(result.retained?.expiresAtMs).toBeGreaterThanOrEqual(result.observedExpiredAtMs);
    expect(result.retained).toMatchObject({
      curve: 'ed25519',
      authMethod: 'passkey',
      signingGrantId: 'wallet-session-ed25519-expiry-anchor',
      remainingUses: 3,
      sealedSecretB64u: 'sealed-secret-ed25519-expiry-anchor',
    });
    expect(result.availableEd25519Candidates).toHaveLength(1);
    expect(result.availableEd25519Candidates[0]).toMatchObject({
      state: 'expired',
      source: 'durable_sealed_record',
      signingGrantId: 'wallet-session-ed25519-expiry-anchor',
      thresholdSessionId: 'session-ed25519-expiry-anchor',
    });
    expect(result.selection).toMatchObject({
      ok: true,
      selectionCandidate: {
        kind: 'near_ed25519_transaction_reauth_lane',
      },
    });
  });

  test('sealed mode dedupes concurrent explicit restores (remove-server-seal single-flight)', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.touchConfirmManager);
        const sealedStoreMod = await import(paths.sealedSessionStore);
        const manager = mod.createUiConfirmManager(
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

        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error || new Error('Failed to clear sealed session test database'));
          request.onblocked = () => resolve();
        });
        await sealedStoreMod.writeExactSealedSession(sealedStoreMod.buildCurrentSealedSessionRecord({
          walletId: 'account.testnet',
          thresholdSessionId: 'session-single-flight-remove',
          signingGrantId: 'wallet-session-single-flight-remove',
          curve: 'ecdsa',
          authMethod: 'passkey',
          relayerUrl: 'https://relay.example',
          ecdsaRestore: {
            chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
            source: 'manual-bootstrap',
            rpId: 'example.com',
            sessionKind: 'cookie',
            keyHandle: 'key-handle-ecdsa',
            ecdsaThresholdKeyId: 'ecdsa-key',
            ethereumAddress: `0x${'33'.repeat(20)}`,
            relayerKeyId: 'relayer-key',
            clientVerifyingShareB64u: 'client-verifying-share',
            thresholdEcdsaPublicKeyB64u: 'AhERERERERERERERERERERERERERERERERERERERERER',
            participantIds: [1, 2, 3],
            runtimePolicyScope: {
              orgId: 'org-test',
              projectId: 'sr-test',
              envId: 'dev',
              signingRootVersion: 'default',
            },
          },
          sealedSecretB64u: 'sealed-prf',
          keyVersion: 'kek-v1',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 10,
          updatedAtMs: Date.now(),
        })!);

        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);
        (manager as any).resolveSealTransportInput = () => ({
          curve: 'ecdsa',
          chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
          relayerUrl: 'https://relay.example',
          signingGrantId: 'wallet-session-single-flight-remove',
          walletSessionJwt: 'jwt-session',
          shamirPrimeB64u: 'AQAB',
          keyVersion: 'kek-v1',
        });

        const restoreInput = {
          walletId: 'account.testnet',
          authMethod: 'passkey' as const,
          curve: 'ecdsa' as const,
          chain: 'tempo' as const,
          chainTarget: { kind: 'tempo' as const, chainId: 42431, networkSlug: 'tempo-moderato' },
          signingGrantId: 'wallet-session-single-flight-remove',
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

        const managerA = mod.createUiConfirmManager(baseConfig, baseContext);
        const managerB = mod.createUiConfirmManager(baseConfig, baseContext);

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

        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error || new Error('Failed to clear sealed session test database'));
          request.onblocked = () => resolve();
        });
        await sealedStoreMod.writeExactSealedSession(sealedStoreMod.buildCurrentSealedSessionRecord({
          walletId: 'account.testnet',
          thresholdSessionId: 'session-cross-manager-remove',
          signingGrantId: 'wallet-session-cross-manager-remove',
          curve: 'ecdsa',
          authMethod: 'passkey',
          relayerUrl: 'https://relay.example',
          ecdsaRestore: {
            chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
            source: 'manual-bootstrap',
            rpId: 'example.com',
            sessionKind: 'cookie',
            keyHandle: 'key-handle-ecdsa',
            ecdsaThresholdKeyId: 'ecdsa-key',
            ethereumAddress: `0x${'33'.repeat(20)}`,
            relayerKeyId: 'relayer-key',
            clientVerifyingShareB64u: 'client-verifying-share',
            thresholdEcdsaPublicKeyB64u: 'AhERERERERERERERERERERERERERERERERERERERERER',
            participantIds: [1, 2, 3],
            runtimePolicyScope: {
              orgId: 'org-test',
              projectId: 'sr-test',
              envId: 'dev',
              signingRootVersion: 'default',
            },
          },
          sealedSecretB64u: 'sealed-prf',
          keyVersion: 'kek-v1',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 10,
          updatedAtMs: Date.now(),
        })!);

        (managerA as any).worker = workerA;
        (managerA as any).attachWorkerRouter(workerA);
        (managerA as any).resolveSealTransportInput = () => ({
          curve: 'ecdsa',
          chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
          relayerUrl: 'https://relay.example',
          signingGrantId: 'wallet-session-cross-manager-remove',
          walletSessionJwt: 'jwt-session',
          shamirPrimeB64u: 'AQAB',
          keyVersion: 'kek-v1',
        });
        (managerB as any).worker = workerB;
        (managerB as any).attachWorkerRouter(workerB);
        (managerB as any).resolveSealTransportInput = () => ({
          curve: 'ecdsa',
          chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
          relayerUrl: 'https://relay.example',
          signingGrantId: 'wallet-session-cross-manager-remove',
          walletSessionJwt: 'jwt-session',
          shamirPrimeB64u: 'AQAB',
          keyVersion: 'kek-v1',
        });

        const restoreInput = {
          walletId: 'account.testnet',
          authMethod: 'passkey' as const,
          curve: 'ecdsa' as const,
          chain: 'tempo' as const,
          chainTarget: { kind: 'tempo' as const, chainId: 42431, networkSlug: 'tempo-moderato' },
          signingGrantId: 'wallet-session-cross-manager-remove',
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
        const manager = mod.createUiConfirmManager(
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

        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error || new Error('Failed to clear sealed session test database'));
          request.onblocked = () => resolve();
        });
        await sealedStoreMod.writeExactSealedSession(sealedStoreMod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'session-no-rehydrate',
          signingGrantId: 'wallet-session-no-rehydrate',
          curve: 'ecdsa',
          authMethod: 'passkey',
          relayerUrl: 'https://relay.example',
          ecdsaRestore: {
            chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
            source: 'manual-bootstrap',
            rpId: 'example.com',
            sessionKind: 'cookie',
            keyHandle: 'key-handle-ecdsa',
            ecdsaThresholdKeyId: 'ecdsa-key',
            ethereumAddress: `0x${'33'.repeat(20)}`,
            relayerKeyId: 'relayer-key',
            clientVerifyingShareB64u: 'client-verifying-share',
            thresholdEcdsaPublicKeyB64u: 'AhERERERERERERERERERERERERERERERERERERERERER',
            participantIds: [1, 2, 3],
            runtimePolicyScope: {
              orgId: 'org-test',
              projectId: 'sr-test',
              envId: 'dev',
              signingRootVersion: 'default',
            },
          },
          sealedSecretB64u: 'sealed-prf',
          keyVersion: 'kek-v2',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 10,
          updatedAtMs: Date.now(),
        })!);

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
        const manager = mod.createUiConfirmManager(
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
        '[UiConfirm] signing-session seal and persist requires signingSessionPersistenceMode="sealed_refresh_v1"',
    });
    expect(result.rehydrated).toEqual({
      ok: false,
      code: 'not_enabled',
      message:
        '[UiConfirm] signing-session rehydrate requires signingSessionPersistenceMode="sealed_refresh_v1"',
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
        const manager = mod.createUiConfirmManager(
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

        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error || new Error('Failed to clear sealed session test database'));
          request.onblocked = () => resolve();
        });
        await sealedStoreMod.writeExactSealedSession(sealedStoreMod.buildCurrentSealedSessionRecord({
          walletId: 'account.testnet',
          thresholdSessionId: 'session-expired',
          signingGrantId: 'wallet-session-expired',
          curve: 'ecdsa',
          authMethod: 'passkey',
          relayerUrl: 'https://relay.example',
          ecdsaRestore: {
            chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
            source: 'manual-bootstrap',
            rpId: 'example.com',
            sessionKind: 'cookie',
            keyHandle: 'key-handle-ecdsa',
            ecdsaThresholdKeyId: 'ecdsa-key',
            ethereumAddress: `0x${'33'.repeat(20)}`,
            relayerKeyId: 'relayer-key',
            clientVerifyingShareB64u: 'client-verifying-share',
            thresholdEcdsaPublicKeyB64u: 'AhERERERERERERERERERERERERERERERERERERERERER',
            participantIds: [1, 2, 3],
            runtimePolicyScope: {
              orgId: 'org-test',
              projectId: 'sr-test',
              envId: 'dev',
              signingRootVersion: 'default',
            },
          },
          sealedSecretB64u: 'sealed-prf',
          keyVersion: 'kek-v2',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 2,
          updatedAtMs: Date.now(),
        })!);

        (manager as any).worker = fakeWorker;
        (manager as any).attachWorkerRouter(fakeWorker);
        (manager as any).resolveSealTransportInput = () => ({
          curve: 'ecdsa',
          chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
          relayerUrl: 'https://relay.example',
          signingGrantId: 'wallet-session-expired',
          walletSessionJwt: 'jwt-session',
          shamirPrimeB64u: 'AQAB',
        });

        const restorePromise = manager.restorePersistedSessionForSigning({
          walletId: 'account.testnet',
          authMethod: 'passkey',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
          signingGrantId: 'wallet-session-expired',
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
        const manager = mod.createUiConfirmManager({}, {
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
        const manager = mod.createUiConfirmManager({}, {
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

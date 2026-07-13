import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  handle: '/_test-sdk/esm/core/signingEngine/uiConfirm/handlers/handlePromptFromWorker.js',
  types: '/_test-sdk/esm/core/signingEngine/stepUpConfirmation/channel/confirmTypes.js',
  events: '/_test-sdk/esm/core/browser/walletIframe/events.js',
  localOnly: '/_test-sdk/esm/core/signingEngine/uiConfirm/handlers/flows/localOnly.js',
  nonceCoordinator: '/_test-sdk/esm/core/signingEngine/nonce/NonceCoordinator.js',
} as const;

test.describe('confirmTxFlow – defensive paths', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await page.evaluate((nonceCoordinatorPath) => {
      (globalThis as any).__buildTestNearProfileAccountContext = ({
        chainIdKey,
        accountAddress,
      }: {
        chainIdKey: string;
        accountAddress: string;
      }) => ({
        profileId: `near-profile:${String(accountAddress)}`,
        accountRef: { chainIdKey, accountAddress },
      });
      const installIndexedDbClientForwarder = (
        methodName: string,
        fallback?: (...args: unknown[]) => unknown,
      ) => {
        if (Object.prototype.hasOwnProperty.call(Object.prototype, methodName)) return;
        Object.defineProperty(Object.prototype, methodName, {
          configurable: true,
          value: function (...args: unknown[]) {
            const clientDB = (this as { clientDB?: Record<string, unknown> })?.clientDB;
            const method = clientDB?.[methodName];
            if (typeof method === 'function') {
              return method.apply(clientDB, args);
            }
            if (fallback) return fallback.apply(this, args);
            throw new Error(`test indexedDB mock missing ${methodName}`);
          },
        });
      };
      installIndexedDbClientForwarder('resolveProfileAccountContext');
      installIndexedDbClientForwarder('listProfileAuthenticators');
      installIndexedDbClientForwarder('selectProfileAuthenticatorsForPrompt');
      installIndexedDbClientForwarder('listAccountSigners', async (args: any) => [
        {
          signerAuthMethod: 'passkey',
          metadata: {
            walletId: String(args?.accountAddress || 'test-wallet'),
            passkeyCredentialRawId: 'test-passkey',
          },
        },
      ]);
      (globalThis as any).__attachTestWebAuthnCredentialStore = (ctx: any) => {
        const indexedDB = ctx.indexedDB || (ctx.indexedDB = {});
        const clientDB = indexedDB.clientDB || {};
        const existingStore = ctx.webauthnCredentialStore || {};
        const ownFunction = (source: any, methodName: string) => {
          if (!Object.prototype.hasOwnProperty.call(source, methodName)) return undefined;
          const method = source[methodName];
          return typeof method === 'function' ? method.bind(source) : undefined;
        };
        const defaultStore = {
          resolveProfileAccountContext: async ({
            chainIdKey,
            accountAddress,
          }: {
            chainIdKey: string;
            accountAddress: string;
          }) =>
            (globalThis as any).__buildTestNearProfileAccountContext({
              chainIdKey,
              accountAddress,
            }),
          listProfileAuthenticators: async () => [{ credentialId: 'test-passkey', transports: [] }],
          listAccountSigners: async (args: any) => [
            {
              signerAuthMethod: 'passkey',
              metadata: {
                walletId: String(args?.accountAddress || 'test-wallet'),
                passkeyCredentialRawId: 'test-passkey',
              },
            },
          ],
          selectProfileAuthenticatorsForPrompt: async ({ authenticators }: any) => ({
            authenticatorsForPrompt: authenticators,
            wrongPasskeyError: undefined,
          }),
        };
        const credentialStore = {
          resolveProfileAccountContext:
            ownFunction(existingStore, 'resolveProfileAccountContext') ||
            ownFunction(clientDB, 'resolveProfileAccountContext') ||
            defaultStore.resolveProfileAccountContext,
          listProfileAuthenticators:
            ownFunction(existingStore, 'listProfileAuthenticators') ||
            ownFunction(clientDB, 'listProfileAuthenticators') ||
            defaultStore.listProfileAuthenticators,
          listAccountSigners:
            ownFunction(existingStore, 'listAccountSigners') ||
            ownFunction(clientDB, 'listAccountSigners') ||
            defaultStore.listAccountSigners,
          selectProfileAuthenticatorsForPrompt:
            ownFunction(existingStore, 'selectProfileAuthenticatorsForPrompt') ||
            ownFunction(clientDB, 'selectProfileAuthenticatorsForPrompt') ||
            defaultStore.selectProfileAuthenticatorsForPrompt,
        };
        ctx.webauthnCredentialStore = credentialStore;
        indexedDB.clientDB = { ...clientDB, ...credentialStore };
        return ctx;
      };
      (globalThis as any).__attachTestNonceCoordinator = async (ctx: any) => {
        (globalThis as any).__attachTestWebAuthnCredentialStore(ctx);
        const nonceCoordinatorMod = await import(nonceCoordinatorPath);
        const nearContextFixture = ctx.nearContextFixture || (ctx.nearContextFixture = {});
        if (typeof nearContextFixture.getNonceBlockHashAndHeight !== 'function') {
          nearContextFixture.getNonceBlockHashAndHeight = async () => ({
            nearPublicKeyStr: nearContextFixture.nearPublicKeyStr || 'ed25519:test-public-key',
            accessKeyInfo: { nonce: 30, permission: 'FullAccess' },
            nextNonce: '31',
            txBlockHeight: '1',
            txBlockHash: 'test-block',
          });
        }
        if (typeof nearContextFixture.reserveNonces !== 'function') {
          nearContextFixture.__nextNonce = Number(nearContextFixture.__nextNonce || 31);
          nearContextFixture.__reservedNonces = nearContextFixture.__reservedNonces || new Set();
          nearContextFixture.reserveNonces = (count: number) =>
            Array.from({ length: count }, () => {
              const nonce = String(nearContextFixture.__nextNonce++);
              nearContextFixture.__reservedNonces.add(nonce);
              return nonce;
            });
          nearContextFixture.releaseNonce = (nonce: string) =>
            nearContextFixture.__reservedNonces.delete(nonce);
          nearContextFixture.releaseAllNonces = () => nearContextFixture.__reservedNonces.clear();
        }
        if (typeof nearContextFixture.clear !== 'function') {
          nearContextFixture.clear = () => {};
        }
        const nearClient = ctx.nearClient || (ctx.nearClient = {});
        if (typeof nearClient.viewAccessKey !== 'function') {
          nearClient.viewAccessKey = async () => {
            const context = await nearContextFixture.getNonceBlockHashAndHeight(nearClient);
            nearContextFixture.__lastContext = context;
            return context.accessKeyInfo || { nonce: 30, permission: 'FullAccess' };
          };
        }
        if (typeof nearClient.viewBlock !== 'function') {
          nearClient.viewBlock = async () => {
            const context =
              nearContextFixture.__lastContext ||
              (await nearContextFixture.getNonceBlockHashAndHeight(nearClient));
            return {
              header: {
                height: Number(context.txBlockHeight || 1),
                hash: String(context.txBlockHash || 'test-block'),
              },
            };
          };
        }
        ctx.nonceCoordinator = nonceCoordinatorMod.createNonceCoordinator({
          evmNonceBackend: {
            fetchChainNonce: async () => 0n,
          },
          nearClient,
          onTrace: (event: any) => {
            if (event?.lease?.lane?.family !== 'near') return;
            if (event.event === 'nonce_lease_reserved') {
              nearContextFixture.__observedReserveIds =
                nearContextFixture.__observedReserveIds || new Set();
              if (!nearContextFixture.__observedReserveIds.has(event.lease.leaseId)) {
                nearContextFixture.__observedReserveIds.add(event.lease.leaseId);
                nearContextFixture.reserveNonces?.(1);
              }
            }
            if (event.event === 'nonce_lease_released') {
              nearContextFixture.releaseNonce?.(String(event.lease.nonce));
            }
          },
        });
        if (nearContextFixture.nearPublicKeyStr) {
          ctx.nonceCoordinator.initializeNearAccessKey({
            walletId: nearContextFixture.walletId || 'test-wallet',
            nearAccountId: nearContextFixture.nearAccountId || 'test-near-context.testnet',
            publicKey: nearContextFixture.nearPublicKeyStr,
          });
        }
        return ctx.nonceCoordinator;
      };
    }, IMPORT_PATHS.nonceCoordinator);
  });

  test('Signing flow: cancel releases reserved nonces', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.handle);
        const types = await import(paths.types);
        const events = await import(paths.events);
        const handle = mod.handlePromptFromWorker as Function;

        const reserved: string[] = [];
        const released: string[] = [];
        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 0,
            }),
          },
          nearContextFixture: {
            async getNonceBlockHashAndHeight() {
              return {
                nearPublicKeyStr: 'pk',
                accessKeyInfo: { nonce: 300 },
                nextNonce: '301',
                txBlockHeight: '3000',
                txBlockHash: 'h3000',
              };
            },
            reserveNonces(count: number) {
              const values = Array.from({ length: count }, (_, i) => String(301 + i));
              reserved.push(...values);
              return values;
            },
            releaseNonce(nonce: string) {
              released.push(nonce);
            },
          },
          nearClient: {},
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            getAuthenticationCredentialsSerializedForChallengeB64u: async () =>
              ({
                id: 'cred',
                rawId: 'AA',
                type: 'public-key',
                response: { clientDataJSON: 'AQ', authenticatorData: 'Ag', signature: 'Aw' },
                clientExtensionResults: { prf: { results: { first: 'BQ', second: 'Bg' } } },
              }) as any,
          },
          indexedDB: {
            clientDB: {
              resolveProfileAccountContext: async ({
                chainIdKey,
                accountAddress,
              }: {
                chainIdKey: string;
                accountAddress: string;
              }) =>
                (globalThis as any).__buildTestNearProfileAccountContext({
                  chainIdKey,
                  accountAddress,
                }),
              listProfileAuthenticators: async () => [
                { credentialId: 'test-passkey', transports: [] },
              ],
              selectProfileAuthenticatorsForPrompt: async ({ authenticators }: any) => ({
                authenticatorsForPrompt: authenticators,
                wrongPasskeyError: undefined,
              }),
            },
          },
        };
        await (globalThis as any).__attachTestNonceCoordinator(ctx);

        const request = {
          requestId: 'cancel-sign',
          type: types.UserConfirmationType.SIGN_TRANSACTION,
          summary: {},
          payload: {
            signingKind: 'transaction',
            walletId: 'cancel-wallet',
            intentDigest: 'intent-sign-cancel',
            signingAuthPlan: { kind: 'passkeyReauth', method: 'passkey' },
            nearAccountId: 'cancel.testnet',
            nearPublicKeyStr: 'pk',
            nearFundingRequest: {
              subject: {
                walletId: 'cancel-wallet',
                nearAccountId: 'cancel.testnet',
                nearPublicKeyStr: 'pk',
              },
              operation: {
                operationId: 'cancel-sign',
                operationFingerprint: 'intent-sign-cancel',
                intent: 'transaction_sign',
                accountId: 'cancel.testnet',
              },
              signatureUses: 1,
            },
            txSigningRequests: [{ receiverId: 'x', actions: [] }],
            rpcCall: {
              method: 'sign',
              argsJson: {},
              nearAccountId: 'cancel.testnet',
              nearRpcUrl: 'https://rpc.testnet.near.org',
            },
          },
        } as any;

        const workerMessages: any[] = [];
        const worker = { postMessage: (msg: any) => workerMessages.push(msg) } as unknown as Worker;

        const triggerCancel = () => {
          const attempt = () => {
            const portal = document.getElementById('w3a-confirm-portal');
            const host = portal?.firstElementChild as HTMLElement | null;
            if (host) {
              host.dispatchEvent(
                new CustomEvent(events.WalletIframeDomEvents.TX_CONFIRMER_CANCEL, {
                  bubbles: true,
                  composed: true,
                } as any),
              );
            } else {
              setTimeout(attempt, 20);
            }
          };
          setTimeout(attempt, 60);
        };

        triggerCancel();
        await handle(
          ctx,
          {
            type: types.UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
            data: request,
          },
          worker,
        );
        const response = workerMessages[0]?.data;
        await new Promise((resolve) => setTimeout(resolve, 50));
        return { reserved, released, response };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.reserved.length).toBeGreaterThan(0);
    expect(result.released).toEqual(result.reserved);
    expect(result.response.confirmed).toBe(false);
  });

  test('Signing flow: NEAR context failure is fail-fast (no synthetic tx-context fallback)', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.handle);
        const types = await import(paths.types);
        const handle = mod.handlePromptFromWorker as Function;

        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'none',
              behavior: 'skipClick',
              autoProceedDelay: 0,
            }),
          },
          nearContextFixture: {
            async getNonceBlockHashAndHeight() {
              throw new Error('NEAR context unavailable');
            },
            reserveNonces: () => ['never-used'],
            releaseNonce: () => {},
          },
          // Would be used by fallback paths, but signing should not use it.
          nearClient: {
            async viewBlock() {
              return { header: { height: 777, hash: 'h777' } };
            },
          },
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
          },
        };
        await (globalThis as any).__attachTestNonceCoordinator(ctx);

        const request = {
          requestId: 'fail-fast-signing',
          type: types.UserConfirmationType.SIGN_TRANSACTION,
          summary: {},
          payload: {
            signingKind: 'transaction',
            walletId: 'alice-wallet',
            intentDigest: 'intent-fail-fast',
            signingAuthPlan: { kind: 'passkeyReauth', method: 'passkey' },
            nearAccountId: 'alice.testnet',
            nearPublicKeyStr: 'pk',
            nearFundingRequest: {
              subject: {
                walletId: 'alice-wallet',
                nearAccountId: 'alice.testnet',
                nearPublicKeyStr: 'pk',
              },
              operation: {
                operationId: 'fail-fast-signing',
                operationFingerprint: 'intent-fail-fast',
                intent: 'transaction_sign',
                accountId: 'alice.testnet',
              },
              signatureUses: 1,
            },
            txSigningRequests: [{ receiverId: 'x', actions: [] }],
            rpcCall: {
              method: 'sign',
              argsJson: {},
              nearAccountId: 'alice.testnet',
              nearRpcUrl: 'https://rpc.testnet.near.org',
            },
          },
        } as any;

        const workerMessages: any[] = [];
        const worker = { postMessage: (msg: any) => workerMessages.push(msg) } as unknown as Worker;

        await handle(
          ctx,
          {
            type: types.UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
            data: request,
          },
          worker,
        );

        return { response: workerMessages[0]?.data, messageCount: workerMessages.length };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.messageCount).toBe(1);
    expect(result.response.confirmed).toBe(false);
    expect(String(result.response.error || '')).toContain('Failed to fetch NEAR data');
    expect(String(result.response.error || '')).toContain('NEAR context unavailable');
  });

  test('Registration flow: cancel does not reserve access-key nonces', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.handle);
        const types = await import(paths.types);
        const events = await import(paths.events);
        const handle = mod.handlePromptFromWorker as Function;

        const reserved: string[] = [];
        const released: string[] = [];
        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 0,
            }),
          },
          nearContextFixture: {
            nearPublicKeyStr: 'pk-reg',
            async getNonceBlockHashAndHeight() {
              return {
                nearPublicKeyStr: 'pk-reg',
                accessKeyInfo: { nonce: 10 },
                nextNonce: '11',
                txBlockHeight: '500',
                txBlockHash: 'h500',
              };
            },
            reserveNonces(count: number) {
              const values = Array.from({ length: count }, (_, i) => String(11 + i));
              reserved.push(...values);
              return values;
            },
            releaseNonce(nonce: string) {
              released.push(nonce);
            },
          },
          nearClient: {},
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            generateRegistrationCredentialsInternal: async () => ({}) as any,
          },
          indexedDB: {
            clientDB: {
              resolveProfileAccountContext: async ({
                chainIdKey,
                accountAddress,
              }: {
                chainIdKey: string;
                accountAddress: string;
              }) =>
                (globalThis as any).__buildTestNearProfileAccountContext({
                  chainIdKey,
                  accountAddress,
                }),
              listProfileAuthenticators: async () => [
                { credentialId: 'test-passkey', transports: [] },
              ],
              selectProfileAuthenticatorsForPrompt: async ({ authenticators }: any) => ({
                authenticatorsForPrompt: authenticators,
                wrongPasskeyError: undefined,
              }),
            },
          },
        };
        await (globalThis as any).__attachTestNonceCoordinator(ctx);

        const request = {
          requestId: 'cancel-reg',
          type: types.UserConfirmationType.REGISTER_ACCOUNT,
          summary: {},
          payload: {
            nearAccountId: 'cancel-reg.testnet',
            signerSlot: 1,
            rpcCall: { method: 'register', argsJson: {} },
          },
          intentDigest: 'register:cancel-reg.testnet:1',
        } as any;

        const workerMessages: any[] = [];
        const worker = { postMessage: (msg: any) => workerMessages.push(msg) } as unknown as Worker;

        const triggerCancel = () => {
          const attempt = () => {
            const portal = document.getElementById('w3a-confirm-portal');
            const host = portal?.firstElementChild as HTMLElement | null;
            if (host) {
              host.dispatchEvent(
                new CustomEvent(events.WalletIframeDomEvents.TX_CONFIRMER_CANCEL, {
                  bubbles: true,
                  composed: true,
                } as any),
              );
            } else {
              setTimeout(attempt, 20);
            }
          };
          setTimeout(attempt, 60);
        };

        triggerCancel();
        await handle(
          ctx,
          {
            type: types.UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
            data: request,
          },
          worker,
        );
        const response = workerMessages[0]?.data;
        await new Promise((resolve) => setTimeout(resolve, 50));
        return { reserved, released, response };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.reserved).toEqual([]);
    expect(result.released).toEqual([]);
    expect(result.response.confirmed).toBe(false);
  });

  test('NEP-413 flow: cancel does not reserve access-key nonces', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.handle);
        const types = await import(paths.types);
        const events = await import(paths.events);
        const handle = mod.handlePromptFromWorker as Function;

        const reserved: string[] = [];
        const released: string[] = [];
        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 0,
            }),
          },
          nearContextFixture: {
            async getNonceBlockHashAndHeight() {
              return {
                nearPublicKeyStr: 'pk-nep',
                accessKeyInfo: { nonce: 50 },
                nextNonce: '51',
                txBlockHeight: '1500',
                txBlockHash: 'h-nep',
              };
            },
            reserveNonces(count: number) {
              const values = Array.from({ length: count }, (_, i) => String(51 + i));
              reserved.push(...values);
              return values;
            },
            releaseNonce(nonce: string) {
              released.push(nonce);
            },
          },
          nearClient: {},
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            getAuthenticationCredentialsSerializedForChallengeB64u: async () =>
              ({
                id: 'cred',
                rawId: 'AA',
                type: 'public-key',
                response: { clientDataJSON: 'AQ', authenticatorData: 'Ag', signature: 'Aw' },
                clientExtensionResults: { prf: { results: { first: 'BQ', second: 'Bg' } } },
              }) as any,
          },
          indexedDB: {
            clientDB: {
              resolveProfileAccountContext: async ({
                chainIdKey,
                accountAddress,
              }: {
                chainIdKey: string;
                accountAddress: string;
              }) =>
                (globalThis as any).__buildTestNearProfileAccountContext({
                  chainIdKey,
                  accountAddress,
                }),
              listProfileAuthenticators: async () => [
                { credentialId: 'test-passkey', transports: [] },
              ],
              selectProfileAuthenticatorsForPrompt: async ({ authenticators }: any) => ({
                authenticatorsForPrompt: authenticators,
                wrongPasskeyError: undefined,
              }),
            },
          },
        };
        await (globalThis as any).__attachTestNonceCoordinator(ctx);

        const request = {
          requestId: 'cancel-nep',
          type: types.UserConfirmationType.SIGN_NEP413_MESSAGE,
          summary: {},
          payload: {
            signingAuthPlan: { kind: 'passkeyReauth', method: 'passkey' },
            nearAccountId: 'cancel-nep.testnet',
            nearPublicKeyStr: 'pk-nep',
            message: 'cancel-me',
            recipient: 'receiver.testnet',
          },
        } as any;

        const workerMessages: any[] = [];
        const worker = { postMessage: (msg: any) => workerMessages.push(msg) } as unknown as Worker;

        const triggerCancel = () => {
          const attempt = () => {
            const portal = document.getElementById('w3a-confirm-portal');
            const host = portal?.firstElementChild as HTMLElement | null;
            if (host) {
              host.dispatchEvent(
                new CustomEvent(events.WalletIframeDomEvents.TX_CONFIRMER_CANCEL, {
                  bubbles: true,
                  composed: true,
                } as any),
              );
            } else {
              setTimeout(attempt, 20);
            }
          };
          setTimeout(attempt, 60);
        };

        triggerCancel();
        await handle(
          ctx,
          {
            type: types.UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
            data: request,
          },
          worker,
        );
        const response = workerMessages[0]?.data;
        await new Promise((resolve) => setTimeout(resolve, 50));
        return { reserved, released, response };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.reserved).toEqual([]);
    expect(result.released).toEqual([]);
    expect(result.response.confirmed).toBe(false);
  });

  test('SHOW_SECURE_PRIVATE_KEY_UI keeps viewer mounted and returns confirmed', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.handle);
        const types = await import(paths.types);
        const handle = mod.handlePromptFromWorker as Function;

        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'drawer',
              behavior: 'requireClick',
              autoProceedDelay: 0,
            }),
          },
          nearContextFixture: {
            getNonceBlockHashAndHeight: async () => ({
              nearPublicKeyStr: '',
              accessKeyInfo: { nonce: 0 },
              nextNonce: '0',
              txBlockHeight: '1',
              txBlockHash: 'h1',
            }),
            reserveNonces: () => [],
            releaseNonce: () => {},
          },
          nearClient: {
            viewBlock: async () => ({ header: { height: 1, hash: 'h1' } }),
          },
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
          },
          indexedDB: {
            clientDB: {
              resolveProfileAccountContext: async ({
                chainIdKey,
                accountAddress,
              }: {
                chainIdKey: string;
                accountAddress: string;
              }) =>
                (globalThis as any).__buildTestNearProfileAccountContext({
                  chainIdKey,
                  accountAddress,
                }),
              listProfileAuthenticators: async () => [
                { credentialId: 'test-passkey', transports: [] },
              ],
              selectProfileAuthenticatorsForPrompt: async ({ authenticators }: any) => ({
                authenticatorsForPrompt: authenticators,
                wrongPasskeyError: undefined,
              }),
            },
          },
        };

        const request = {
          requestId: 'show-key',
          type: types.UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
          summary: {},
          payload: {
            subject: { kind: 'near_wallet', nearAccountId: 'viewer.testnet' },
            publicKey: 'ed25519:dummy',
            privateKey: 'ed25519:secret',
          },
        } as any;

        const workerMessages: any[] = [];
        const worker = { postMessage: (msg: any) => workerMessages.push(msg) } as unknown as Worker;

        await handle(
          ctx,
          {
            type: types.UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
            data: request,
          },
          worker,
        );
        const response = workerMessages[0]?.data;
        const viewer = document.querySelector('w3a-export-viewer-iframe');
        const stillMounted = !!viewer;
        viewer?.remove();
        return { confirmed: response?.confirmed, stillMounted };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.confirmed).toBe(true);
    expect(result.stillMounted).toBe(true);
  });

  test('DECRYPT_PRIVATE_KEY_WITH_PRF uses filtered authenticators for the current device', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.localOnly);
        const types = await import(paths.types);
        const handleLocalOnlyFlow = mod.handleLocalOnlyFlow as Function;

        const authOld = { credentialId: 'cred-old', signerSlot: 3, transports: [] };
        const authNew = { credentialId: 'cred-new', signerSlot: 6, transports: [] };
        let capturedAllow: any[] | null = null;

        const ctx: any = {
          indexedDB: {
            clientDB: {
              resolveProfileAccountContext: async ({
                chainIdKey,
                accountAddress,
              }: {
                chainIdKey: string;
                accountAddress: string;
              }) =>
                (globalThis as any).__buildTestNearProfileAccountContext({
                  chainIdKey,
                  accountAddress,
                }),
              listProfileAuthenticators: async () => [authOld, authNew],
              selectProfileAuthenticatorsForPrompt: async () => ({
                authenticatorsForPrompt: [authNew],
                wrongPasskeyError: undefined,
              }),
            },
          },
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            getAuthenticationCredentialsSerializedForChallengeB64u: async ({
              allowCredentials,
              includeSecondPrfOutput,
            }: any) => {
              capturedAllow = allowCredentials;
              return {
                id: 'cred-new',
                type: 'public-key',
                rawId: 'cred-new',
                response: {
                  clientDataJSON: 'AQ',
                  authenticatorData: 'Ag',
                  signature: 'Aw',
                  userHandle: undefined,
                },
                clientExtensionResults: {
                  prf: {
                    results: { first: 'BQ', second: includeSecondPrfOutput ? 'Bg' : undefined },
                  },
                },
              } as any;
            },
          },
        };

        const request = {
          requestId: 'decrypt-1',
          type: types.UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
          summary: {},
          payload: {
            subject: { kind: 'near_wallet', nearAccountId: 'alice.testnet' },
            publicKey: 'ed25519:test',
          },
        } as any;

        const workerMessages: any[] = [];
        const worker = { postMessage: (msg: any) => workerMessages.push(msg) } as unknown as Worker;

        (globalThis as any).__attachTestWebAuthnCredentialStore(ctx);
        await handleLocalOnlyFlow(ctx, request, worker, {
          confirmationConfig: { kind: 'silent', uiMode: 'none' },
          transactionSummary: {},
          theme: 'dark',
        });

        const response = workerMessages[0]?.data;
        return {
          confirmed: response?.confirmed,
          allowIds: (capturedAllow || []).map((c: any) => c.id),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.confirmed).toBe(true);
    expect(result.allowIds).toEqual(['cred-new']);
  });

  test('DECRYPT_PRIVATE_KEY_WITH_PRF forwards a caller-bound challenge when provided', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.localOnly);
        const types = await import(paths.types);
        const handleLocalOnlyFlow = mod.handleLocalOnlyFlow as Function;

        let capturedChallengeB64u: string | null = null;
        const ctx: any = {
          indexedDB: {
            clientDB: {
              resolveProfileAccountContext: async ({
                chainIdKey,
                accountAddress,
              }: {
                chainIdKey: string;
                accountAddress: string;
              }) =>
                (globalThis as any).__buildTestNearProfileAccountContext({
                  chainIdKey,
                  accountAddress,
                }),
              listProfileAuthenticators: async () => [
                { credentialId: 'test-passkey', transports: [] },
              ],
              selectProfileAuthenticatorsForPrompt: async ({ authenticators }: any) => ({
                authenticatorsForPrompt: authenticators,
                wrongPasskeyError: undefined,
              }),
            },
          },
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            getAuthenticationCredentialsSerializedForChallengeB64u: async ({
              challengeB64u,
            }: any) => {
              capturedChallengeB64u = String(challengeB64u || '');
              return {
                id: 'cred-new',
                type: 'public-key',
                rawId: 'cred-new',
                response: {
                  clientDataJSON: 'AQ',
                  authenticatorData: 'Ag',
                  signature: 'Aw',
                  userHandle: undefined,
                },
                clientExtensionResults: {
                  prf: {
                    results: { first: 'BQ', second: 'Bg' },
                  },
                },
              } as any;
            },
          },
        };

        const request = {
          requestId: 'decrypt-bound-challenge',
          type: types.UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
          summary: {},
          payload: {
            subject: { kind: 'near_wallet', nearAccountId: 'alice.testnet' },
            publicKey: 'ed25519:recovery-key',
            challengeB64u: 'bound-export-challenge-b64u',
          },
        } as any;

        const workerMessages: any[] = [];
        const worker = { postMessage: (msg: any) => workerMessages.push(msg) } as unknown as Worker;

        (globalThis as any).__attachTestWebAuthnCredentialStore(ctx);
        await handleLocalOnlyFlow(ctx, request, worker, {
          confirmationConfig: { kind: 'silent', uiMode: 'none' },
          transactionSummary: {},
          theme: 'dark',
        });

        return {
          confirmed: workerMessages[0]?.data?.confirmed,
          capturedChallengeB64u,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.confirmed).toBe(true);
    expect(result.capturedChallengeB64u).toBe('bound-export-challenge-b64u');
  });

  test('Signing flow: missing PRF output surfaces error', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.handle);
        const types = await import(paths.types);
        const handle = mod.handlePromptFromWorker as Function;

        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'none',
              behavior: 'skipClick',
              autoProceedDelay: 0,
            }),
          },
          nearContextFixture: {
            async getNonceBlockHashAndHeight() {
              return {
                nearPublicKeyStr: 'pk',
                accessKeyInfo: { nonce: 400 },
                nextNonce: '401',
                txBlockHeight: '4000',
                txBlockHash: 'h4000',
              };
            },
            reserveNonces: () => ['401'],
            releaseNonce: () => {},
          },
          nearClient: {},
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            getAuthenticationCredentialsSerializedForChallengeB64u: async () => {
              throw new Error(
                'Missing PRF result - PRF evaluation failed: results object is empty',
              );
            },
          },
          indexedDB: {
            clientDB: {
              resolveProfileAccountContext: async ({
                chainIdKey,
                accountAddress,
              }: {
                chainIdKey: string;
                accountAddress: string;
              }) =>
                (globalThis as any).__buildTestNearProfileAccountContext({
                  chainIdKey,
                  accountAddress,
                }),
              listProfileAuthenticators: async () => [
                { credentialId: 'test-passkey', transports: [] },
              ],
              selectProfileAuthenticatorsForPrompt: async ({ authenticators }: any) => ({
                authenticatorsForPrompt: authenticators,
                wrongPasskeyError: undefined,
              }),
              getLastUser: async () => ({ nearAccountId: 'error.testnet', signerSlot: 1 }),
              getUserBySignerSlot: async () => ({ signerSlot: 1 }),
            },
            nearKeysDB: {
              getKeyMaterial: async () => ({
                kind: 'local_near_sk_v3',
                nearAccountId: 'error.testnet',
                signerSlot: 1,
                publicKey: 'ed25519:pk',
                encryptedSk: 'ciphertext-b64u',
                chacha20NonceB64u: 'nonce-b64u',
                wrapKeySalt: 'salt-missing-prf',
                timestamp: Date.now(),
              }),
            },
          },
        };
        await (globalThis as any).__attachTestNonceCoordinator(ctx);

        const request = {
          requestId: 'prf-fail-sign',
          type: types.UserConfirmationType.SIGN_TRANSACTION,
          summary: {},
          payload: {
            signingKind: 'transaction',
            walletId: 'error-wallet',
            intentDigest: 'intent-error',
            signingAuthPlan: { kind: 'passkeyReauth', method: 'passkey' },
            nearAccountId: 'error.testnet',
            nearPublicKeyStr: 'pk',
            nearFundingRequest: {
              subject: {
                walletId: 'error-wallet',
                nearAccountId: 'error.testnet',
                nearPublicKeyStr: 'pk',
              },
              operation: {
                operationId: 'prf-fail-sign',
                operationFingerprint: 'intent-error',
                intent: 'transaction_sign',
                accountId: 'error.testnet',
              },
              signatureUses: 1,
            },
            txSigningRequests: [{ receiverId: 'x', actions: [] }],
            rpcCall: {
              method: 'sign',
              argsJson: {},
              nearAccountId: 'error.testnet',
              nearRpcUrl: 'https://rpc.testnet.near.org',
            },
          },
        } as any;

        const workerMessages: any[] = [];
        const worker = { postMessage: (msg: any) => workerMessages.push(msg) } as unknown as Worker;
        await handle(
          ctx,
          {
            type: types.UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
            data: request,
          },
          worker,
        );
        const response = workerMessages[0]?.data;
        return { response, messageCount: workerMessages.length };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.messageCount).toBe(1);
    expect(result.response.confirmed).toBe(false);
    expect(result.response.error).toContain('Missing PRF result');
  });

  test('Registration flow: missing PRF output surfaces error', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.handle);
        const types = await import(paths.types);
        const handle = mod.handlePromptFromWorker as Function;

        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'none',
              behavior: 'skipClick',
              autoProceedDelay: 0,
            }),
          },
          nearContextFixture: {
            nearPublicKeyStr: 'pk-reg',
            async getNonceBlockHashAndHeight() {
              return {
                nearPublicKeyStr: 'pk-reg',
                accessKeyInfo: { nonce: 22 },
                nextNonce: '23',
                txBlockHeight: '2200',
                txBlockHash: 'h2200',
              };
            },
            reserveNonces: () => ['23'],
            releaseNonce: () => {},
          },
          nearClient: {},
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            generateRegistrationCredentialsInternal: async () =>
              ({
                id: 'reg-cred',
                type: 'public-key',
                rawId: new Uint8Array([1]).buffer,
                response: {
                  clientDataJSON: new Uint8Array([1]).buffer,
                  attestationObject: new Uint8Array([2]).buffer,
                  getTransports: () => ['internal'],
                },
                getClientExtensionResults: () => ({ prf: { results: {} } }),
              }) as any,
          },
          indexedDB: {
            clientDB: {
              resolveProfileAccountContext: async ({
                chainIdKey,
                accountAddress,
              }: {
                chainIdKey: string;
                accountAddress: string;
              }) =>
                (globalThis as any).__buildTestNearProfileAccountContext({
                  chainIdKey,
                  accountAddress,
                }),
              listProfileAuthenticators: async () => [
                { credentialId: 'test-passkey', transports: [] },
              ],
              selectProfileAuthenticatorsForPrompt: async ({ authenticators }: any) => ({
                authenticatorsForPrompt: authenticators,
                wrongPasskeyError: undefined,
              }),
            },
          },
        };
        await (globalThis as any).__attachTestNonceCoordinator(ctx);

        const request = {
          requestId: 'prf-fail-reg',
          type: types.UserConfirmationType.REGISTER_ACCOUNT,
          summary: {},
          payload: {
            nearAccountId: 'error-reg.testnet',
            signerSlot: 1,
            rpcCall: { method: 'register', argsJson: {} },
          },
          intentDigest: 'register:error-reg.testnet:1',
        } as any;

        const workerMessages: any[] = [];
        const worker = { postMessage: (msg: any) => workerMessages.push(msg) } as unknown as Worker;
        await handle(
          ctx,
          {
            type: types.UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
            data: request,
          },
          worker,
        );
        const response = workerMessages[0]?.data;
        return { response, messageCount: workerMessages.length };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.messageCount).toBe(1);
    expect(result.response.confirmed).toBe(false);
    expect(result.response.error).toContain('Missing PRF result');
  });

  test('Signing flow: credential collection error returns response and releases nonces', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.handle);
        const types = await import(paths.types);
        const handle = mod.handlePromptFromWorker as Function;

        const reserved: string[] = [];
        const released: string[] = [];
        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'none',
              behavior: 'skipClick',
              autoProceedDelay: 0,
            }),
          },
          nearContextFixture: {
            async getNonceBlockHashAndHeight() {
              return {
                nearPublicKeyStr: 'pk',
                accessKeyInfo: { nonce: 500 },
                nextNonce: '501',
                txBlockHeight: '5000',
                txBlockHash: 'h5000',
              };
            },
            reserveNonces(count: number) {
              const values = Array.from({ length: count }, (_, i) => String(501 + i));
              reserved.push(...values);
              return values;
            },
            releaseNonce(nonce: string) {
              released.push(nonce);
            },
          },
          nearClient: {},
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            getAuthenticationCredentialsSerializedForChallengeB64u: async () => {
              throw new Error('Credential collection failed: wrong passkey or user cancelled');
            },
          },
          indexedDB: {
            clientDB: {
              resolveProfileAccountContext: async ({
                chainIdKey,
                accountAddress,
              }: {
                chainIdKey: string;
                accountAddress: string;
              }) =>
                (globalThis as any).__buildTestNearProfileAccountContext({
                  chainIdKey,
                  accountAddress,
                }),
              listProfileAuthenticators: async () => [
                { credentialId: 'test-passkey', transports: [] },
              ],
              selectProfileAuthenticatorsForPrompt: async ({ authenticators }: any) => ({
                authenticatorsForPrompt: authenticators,
                wrongPasskeyError: undefined,
              }),
            },
          },
        };
        await (globalThis as any).__attachTestNonceCoordinator(ctx);

        const request = {
          requestId: 'credential-collection-error',
          type: types.UserConfirmationType.SIGN_TRANSACTION,
          summary: {},
          payload: {
            signingKind: 'transaction',
            walletId: 'error-wallet',
            intentDigest: 'intent-credential-error',
            signingAuthPlan: { kind: 'passkeyReauth', method: 'passkey' },
            nearAccountId: 'error.testnet',
            nearPublicKeyStr: 'pk',
            nearFundingRequest: {
              subject: {
                walletId: 'error-wallet',
                nearAccountId: 'error.testnet',
                nearPublicKeyStr: 'pk',
              },
              operation: {
                operationId: 'credential-collection-error',
                operationFingerprint: 'intent-credential-error',
                intent: 'transaction_sign',
                accountId: 'error.testnet',
              },
              signatureUses: 1,
            },
            txSigningRequests: [{ receiverId: 'x', actions: [] }],
            rpcCall: {
              method: 'sign',
              argsJson: {},
              nearAccountId: 'error.testnet',
              nearRpcUrl: 'https://rpc.testnet.near.org',
            },
          },
        } as any;

        const workerMessages: any[] = [];
        const worker = { postMessage: (msg: any) => workerMessages.push(msg) } as unknown as Worker;

        await handle(
          ctx,
          {
            type: types.UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
            data: request,
          },
          worker,
        );

        const response = workerMessages[0]?.data;
        await new Promise((resolve) => setTimeout(resolve, 50));
        return { reserved, released, response };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.reserved.length).toBeGreaterThan(0);
    expect(result.released).toEqual(result.reserved);
    expect(result.response.confirmed).toBe(false);
    expect(result.response.error).toContain('User cancelled secure confirm request');
  });
});

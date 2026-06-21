import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { createHash } from 'node:crypto';

const IMPORT_PATHS = {
  handle: '/sdk/esm/core/signingEngine/uiConfirm/handlers/handlePromptFromWorker.js',
  types: '/sdk/esm/core/signingEngine/stepUpConfirmation/channel/confirmTypes.js',
  localOnly: '/sdk/esm/core/signingEngine/uiConfirm/handlers/flows/localOnly.js',
  litRegistry: '/sdk/esm/core/signingEngine/uiConfirm/ui/registry.js',
  nonceCoordinator: '/sdk/esm/core/signingEngine/nonce/NonceCoordinator.js',
} as const;

test.describe('confirmTxFlow – success paths', () => {
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
      (globalThis as any).__attachTestNonceCoordinator = async (ctx: any) => {
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
            accountId: nearContextFixture.nearAccountId || 'test-near-context.testnet',
            publicKey: nearContextFixture.nearPublicKeyStr,
          });
        }
        return ctx.nonceCoordinator;
      };
    }, IMPORT_PATHS.nonceCoordinator);
  });

  test('LocalOnly: decryptPrivateKeyWithPrf returns credential (no prfOutput)', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.handle);
        const types = await import(paths.types);
        const handle = mod.handlePromptFromWorker as Function;

        // Minimal ctx stub
        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'none',
              behavior: 'skipClick',
              autoProceedDelay: 0,
            }),
          },
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            getAuthenticationCredentialsSerializedForChallengeB64u: async ({
              includeSecondPrfOutput,
            }: any) =>
              ({
                id: 'cred-id',
                rawId: 'AQID',
                type: 'public-key',
                response: {
                  clientDataJSON: 'AQ',
                  authenticatorData: 'Ag',
                  signature: 'Aw',
                  userHandle: undefined,
                },
                clientExtensionResults: {
                  prf: {
                    results: {
                      first: 'Bw',
                      second: includeSecondPrfOutput ? 'CA' : undefined,
                    },
                  },
                },
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
              }) => (globalThis as any).__buildTestNearProfileAccountContext({ chainIdKey, accountAddress }),
              listProfileAuthenticators: async () => [{ credentialId: 'test-passkey', transports: [] }],
              selectProfileAuthenticatorsForPrompt: async ({ authenticators }: any) => ({
                authenticatorsForPrompt: authenticators,
                wrongPasskeyError: undefined,
              }),
            },
          },
          // not used in LocalOnly branch
          nearContextFixture: {},
          nearClient: {},
          touchConfirmManager: {},
        };

        const request = {
          requestId: 'r1',
          type: types.UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
          summary: {},
          payload: { nearAccountId: 'alice.testnet', publicKey: 'pk' },
        };

        const msgs: any[] = [];
        const worker = { postMessage: (m: any) => msgs.push(m) } as unknown as Worker;
        await handle(
          ctx,
          {
            type: types.UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
            data: request,
          },
          worker,
        );
        const resp = msgs[0]?.data;
        return {
          ok: !!resp?.confirmed,
          prf: resp?.prfOutput,
          cred: resp?.credential,
          wrapKeySeed: (resp as any).wrapKeySeed ?? (resp as any).wrapKeySeed,
          wrapKeySalt: (resp as any).wrapKeySalt ?? (resp as any).wrapKeySalt,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ok).toBe(true);
    // LocalOnly decrypt returns the credential; PRF outputs are handled after confirmation.
    expect(result.prf).toBeUndefined();
    expect(result.cred?.id).toBe('cred-id');
    // LocalOnly decrypt flows should not surface wrap key material on the main thread.
    expect(result.wrapKeySeed).toBeUndefined();
    expect(result.wrapKeySalt).toBeUndefined();
  });

  test('LocalOnly: decryptPrivateKeyWithPrf skips intermediate confirm UI in wallet-iframe host mode', async ({
    page,
  }) => {
    // Export Private Key UX in wallet-iframe host mode:
    // - For the initial DECRYPT_PRIVATE_KEY_WITH_PRF step, we should proceed directly to the
    //   TouchID/WebAuthn prompt (no "Confirm Decryption" UI that requires an extra click).
    //
    // Therefore the effective confirmation behavior in host mode must be:
    // - `uiMode: 'none'` (skip intermediate confirmer UI entirely)
    // - `behavior: 'skipClick'` (no click gating; go straight to TouchID prompt)
    //
    // If we ever regress to `uiMode: 'drawer'` + `behavior: 'requireClick'`, the user is forced
    // to click a redundant drawer before the TouchID prompt appears (the bug that prompted this test).
    const result = await page.evaluate(
      async ({ paths }) => {
        const types = await import(paths.types);
        const tags = await import(paths.litRegistry);
        const localOnly = await import(paths.localOnly);

        // Force wallet-iframe host behavior (test-only global override).
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (globalThis as any).__W3A_TEST_WALLET_IFRAME_HOST_MODE__ = true;

        // Detect any attempts to mount confirmation UI during this decrypt flow.
        const confirmTags = new Set(
          (tags.CONFIRM_UI_ELEMENT_SELECTORS as string[]).map((t) => String(t).toLowerCase()),
        );
        const originalCreateElement = document.createElement.bind(document);
        let createdConfirmUiElements = 0;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (document as any).createElement = (tagName: any, options?: any) => {
          if (confirmTags.has(String(tagName).toLowerCase())) {
            createdConfirmUiElements++;
          }
          return originalCreateElement(tagName, options);
        };

        try {
          let promptCalls = 0;
          const ctx: any = {
            touchIdPrompt: {
              getRpId: () => 'example.localhost',
              getAuthenticationCredentialsSerializedForChallengeB64u: async ({
                includeSecondPrfOutput,
              }: any) => {
                if (!includeSecondPrfOutput) {
                  throw new Error('Expected includeSecondPrfOutput for export/decrypt flow');
                }
                promptCalls++;
                return {
                  id: 'auth-cred',
                  rawId: 'CQ',
                  type: 'public-key',
                  response: {
                    clientDataJSON: 'AQ',
                    authenticatorData: 'Ag',
                    signature: 'Aw',
                    userHandle: undefined,
                  },
                  clientExtensionResults: {
                    prf: {
                      results: {
                        first: 'BQ',
                        second: 'Bg',
                      },
                    },
                  },
                } as any;
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
                }) => (globalThis as any).__buildTestNearProfileAccountContext({ chainIdKey, accountAddress }),
                listProfileAuthenticators: async () => [{ credentialId: 'test-passkey', transports: [] }],
                selectProfileAuthenticatorsForPrompt: async ({ authenticators }: any) => ({
                  authenticatorsForPrompt: authenticators,
                  wrongPasskeyError: undefined,
                }),
              },
            },
          };

          const request = {
            requestId: 'r-decrypt-host',
            type: types.UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
            summary: {},
            payload: { nearAccountId: 'alice.testnet', publicKey: 'pk' },
          } as any;

          // Simulate a config that would normally mount UI, and assert host-mode overrides it.
          const confirmationConfig: any = {
            uiMode: 'drawer',
            behavior: 'requireClick',
            autoProceedDelay: 0,
          };

          const msgs: any[] = [];
          const worker = { postMessage: (m: any) => msgs.push(m) } as unknown as Worker;

          await (localOnly.handleLocalOnlyFlow as Function)(ctx, request, worker, {
            confirmationConfig,
            transactionSummary: {},
            theme: 'dark',
          });

          const resp = msgs[0]?.data;
          return {
            confirmed: resp?.confirmed,
            error: resp?.error,
            credId: resp?.credential?.id,
            promptCalls,
            createdConfirmUiElements,
            finalUiMode: confirmationConfig.uiMode,
            finalBehavior: confirmationConfig.behavior,
          };
        } finally {
          // Restore globals for test isolation.
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (document as any).createElement = originalCreateElement as any;
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          try {
            delete (globalThis as any).__W3A_TEST_WALLET_IFRAME_HOST_MODE__;
          } catch {}
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.confirmed, result.error || 'unknown error').toBe(true);
    expect(result.credId).toBe('auth-cred');
    expect(result.promptCalls).toBe(1);
    expect(result.createdConfirmUiElements).toBe(0);
    expect(result.finalUiMode).toBe('none');
    expect(result.finalBehavior).toBe('skipClick');
  });

  test('Registration: collects registration credential without access-key nonce reservation', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.handle);
        const types = await import(paths.types);
        const handle = mod.handlePromptFromWorker as Function;

        let nonceReserved: string[] = [];
        let capturedChallengeB64u: string | null = null;
        let capturedIntendedUserName: string | null = null;
        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'none',
              behavior: 'skipClick',
              autoProceedDelay: 0,
            }),
          },
          nearContextFixture: {
            nearPublicKeyStr: 'pk',
            async getNonceBlockHashAndHeight(_nc: any, _opts?: any) {
              return {
                nearPublicKeyStr: 'pk',
                accessKeyInfo: { nonce: 100 },
                nextNonce: '101',
                txBlockHeight: '1000',
                txBlockHash: 'hash0',
              };
            },
            reserveNonces(n: number) {
              nonceReserved = Array.from({ length: n }, (_, i) => String(101 + i));
              return nonceReserved;
            },
            releaseNonce(_n: string) {},
          },
          nearClient: {
            async viewBlock() {
              return { header: { height: 1001, hash: 'hash1' } };
            },
          },
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            generateRegistrationCredentialsInternal: async (args: any) => {
              capturedChallengeB64u =
                typeof args?.challengeB64u === 'string' ? args.challengeB64u : null;
              capturedIntendedUserName =
                typeof args?.intendedUserName === 'string' ? args.intendedUserName : null;
              return {
                id: 'reg-cred',
                type: 'public-key',
                rawId: new Uint8Array([1, 2, 3]).buffer,
                response: {
                  clientDataJSON: new Uint8Array([1]).buffer,
                  attestationObject: new Uint8Array([4]).buffer,
                  getTransports: () => ['internal'],
                },
                getClientExtensionResults: () => ({
                  prf: {
                    results: {
                      first: new Uint8Array(32).fill(8),
                      second: new Uint8Array(32).fill(9),
                    },
                  },
                }),
              } as any;
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
              }) => (globalThis as any).__buildTestNearProfileAccountContext({ chainIdKey, accountAddress }),
              listProfileAuthenticators: async () => [{ credentialId: 'test-passkey', transports: [] }],
              selectProfileAuthenticatorsForPrompt: async ({ authenticators }: any) => ({
                authenticatorsForPrompt: authenticators,
                wrongPasskeyError: undefined,
              }),
            },
          },
        };
        await (globalThis as any).__attachTestNonceCoordinator(ctx);

        const request = {
          requestId: 'r2',
          type: types.UserConfirmationType.REGISTER_ACCOUNT,
          summary: {},
          payload: {
            nearAccountId: 'bob.testnet',
            signerSlot: 1,
            rpcCall: { method: 'create', argsJson: {} },
          },
          intentDigest: 'register:bob.testnet:1',
        };
        const msgs: any[] = [];
        const worker = { postMessage: (m: any) => msgs.push(m) } as unknown as Worker;
        await handle(
          ctx,
          {
            type: types.UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
            data: request,
          },
          worker,
        );
        const resp = msgs[0]?.data;
        return {
          confirmed: resp?.confirmed,
          prf: resp?.prfOutput,
          tx: resp?.transactionContext,
          reserved: nonceReserved,
          capturedChallengeB64u,
          capturedIntendedUserName,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.confirmed).toBe(true);
    const expectedChallengeB64u = createHash('sha256')
      .update('register:bob.testnet:1', 'utf8')
      .digest()
      .toString('base64url');
    expect(result.capturedChallengeB64u).toBe(expectedChallengeB64u);
    expect(result.capturedIntendedUserName).toBe('bob');
    expect(result.tx).toBeUndefined();
    expect(result.reserved).toEqual([]);
    // Registration responses should not contain PRF output in UserConfirm-driven design.
    expect(result.prf).toBeUndefined();
  });

  test('Signing: collects assertion credential, reserves nonces, emits tx context', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.handle);
        const types = await import(paths.types);
        const handle = mod.handlePromptFromWorker as Function;

        let reserved: string[] = [];
        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'none',
              behavior: 'skipClick',
              autoProceedDelay: 0,
            }),
          },
          nearContextFixture: {
            async getNonceBlockHashAndHeight(_nc: any, _opts?: any) {
              return {
                nearPublicKeyStr: 'pk',
                accessKeyInfo: { nonce: 200 },
                nextNonce: '201',
                txBlockHeight: '2000',
                txBlockHash: 'h0',
              };
            },
            reserveNonces(n: number) {
              reserved = Array.from({ length: n }, (_, i) => String(201 + i));
              return reserved;
            },
            releaseNonce(_n: string) {},
          },
          nearClient: {
            async viewBlock() {
              return { header: { height: 2001, hash: 'h1' } };
            },
          },
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            getAuthenticationCredentialsSerializedForChallengeB64u: async () =>
              ({
                id: 'auth-cred',
                rawId: 'CQ',
                type: 'public-key',
                response: {
                  clientDataJSON: 'AQ',
                  authenticatorData: 'Ag',
                  signature: 'Aw',
                  userHandle: undefined,
                },
                clientExtensionResults: {
                  prf: {
                    results: {
                      first: 'BQ',
                      second: undefined,
                    },
                  },
                },
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
              }) => (globalThis as any).__buildTestNearProfileAccountContext({ chainIdKey, accountAddress }),
              listProfileAuthenticators: async () => [{ credentialId: 'test-passkey', transports: [] }],
              selectProfileAuthenticatorsForPrompt: async ({ authenticators }: any) => ({
                authenticatorsForPrompt: authenticators,
                wrongPasskeyError: undefined,
              }),
              getLastUser: async () => ({ nearAccountId: 'carol.testnet', signerSlot: 1 }),
              getUserBySignerSlot: async () => ({ signerSlot: 1 }),
            },
            nearKeysDB: {
              getLocalKeyMaterial: async () => ({
                kind: 'local_near_sk_v3',
                nearAccountId: 'carol.testnet',
                signerSlot: 1,
                publicKey: 'ed25519:pk',
                encryptedSk: 'ciphertext-b64u',
                chacha20NonceB64u: 'nonce-b64u',
                wrapKeySalt: 'salt-sign',
                timestamp: Date.now(),
              }),
              getThresholdKeyMaterial: async () => null,
            },
          },
        };
        await (globalThis as any).__attachTestNonceCoordinator(ctx);

        const request = {
          requestId: 'r3',
          type: types.UserConfirmationType.SIGN_TRANSACTION,
          summary: {},
          payload: {
            intentDigest: 'intent-1',
            signingAuthPlan: { kind: 'passkeyReauth', method: 'passkey' },
            nearAccountId: 'carol.testnet',
            nearPublicKeyStr: 'pk',
            txSigningRequests: [{ receiverId: 'x', actions: [] }],
            rpcCall: {
              method: 'sign',
              argsJson: {},
              nearAccountId: 'carol.testnet',
              nearRpcUrl: 'https://rpc.testnet.near.org',
            },
          },
        } as any;
        const msgs: any[] = [];
        const worker = { postMessage: (m: any) => msgs.push(m) } as unknown as Worker;
        await handle(
          ctx,
          {
            type: types.UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
            data: request,
          },
          worker,
        );
        const resp = msgs[0]?.data;
        return {
          confirmed: resp?.confirmed,
          error: resp?.error,
          tx: resp?.transactionContext,
          reserved,
          prf: resp?.prfOutput,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.confirmed, result.error || 'unknown error').toBe(true);
    expect(result.tx?.nextNonce).toBe('201');
    expect(result.reserved).toEqual(['201']);
    // Signing responses must not expose PRF in UserConfirm-driven design.
    expect(result.prf).toBeUndefined();
  });

  test('NEP-413: collects assertion credential and returns tx context without PRF', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.handle);
        const types = await import(paths.types);
        const handle = mod.handlePromptFromWorker as Function;

        const reserved: string[] = [];
        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'none',
              behavior: 'skipClick',
              autoProceedDelay: 0,
            }),
          },
          nearContextFixture: {
            async getNonceBlockHashAndHeight(_nc: any, _opts?: any) {
              return {
                nearPublicKeyStr: 'pk-nep413',
                accessKeyInfo: { nonce: 10 },
                nextNonce: '11',
                txBlockHeight: '3000',
                txBlockHash: 'h-nep',
              };
            },
            reserveNonces(_n: number) {
              reserved.push('11');
              return ['11'];
            },
            releaseNonce(_n: string) {},
          },
          nearClient: {
            async viewBlock() {
              return { header: { height: 3001, hash: 'h-nep-1' } };
            },
          },
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            getAuthenticationCredentialsSerializedForChallengeB64u: async () =>
              ({
                id: 'nep-cred',
                rawId: 'Bw',
                type: 'public-key',
                response: {
                  clientDataJSON: 'AQ',
                  authenticatorData: 'Ag',
                  signature: 'Aw',
                  userHandle: undefined,
                },
                clientExtensionResults: {
                  prf: {
                    results: {
                      first: 'Bg',
                      second: undefined,
                    },
                  },
                },
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
              }) => (globalThis as any).__buildTestNearProfileAccountContext({ chainIdKey, accountAddress }),
              listProfileAuthenticators: async () => [{ credentialId: 'test-passkey', transports: [] }],
              selectProfileAuthenticatorsForPrompt: async ({ authenticators }: any) => ({
                authenticatorsForPrompt: authenticators,
                wrongPasskeyError: undefined,
              }),
              getLastUser: async () => ({ nearAccountId: 'nep.testnet', signerSlot: 1 }),
              getUserBySignerSlot: async () => ({ signerSlot: 1 }),
            },
            nearKeysDB: {
              getLocalKeyMaterial: async () => ({
                kind: 'local_near_sk_v3',
                nearAccountId: 'nep.testnet',
                signerSlot: 1,
                publicKey: 'ed25519:pk',
                encryptedSk: 'ciphertext-b64u',
                chacha20NonceB64u: 'nonce-b64u',
                wrapKeySalt: 'salt-nep',
                timestamp: Date.now(),
              }),
              getThresholdKeyMaterial: async () => null,
            },
          },
        };
        await (globalThis as any).__attachTestNonceCoordinator(ctx);

        const request = {
          requestId: 'r-nep',
          type: types.UserConfirmationType.SIGN_NEP413_MESSAGE,
          summary: {},
          payload: {
            signingAuthPlan: { kind: 'passkeyReauth', method: 'passkey' },
            nearAccountId: 'nep.testnet',
            nearPublicKeyStr: 'pk-nep413',
            message: 'hello-world',
            recipient: 'receiver.testnet',
            nearRpcUrl: 'https://rpc.custom.testnet',
          },
        } as any;

        const msgs: any[] = [];
        const worker = { postMessage: (m: any) => msgs.push(m) } as unknown as Worker;
        await handle(
          ctx,
          {
            type: types.UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
            data: request,
          },
          worker,
        );
        const resp = msgs[0]?.data;
        return {
          confirmed: resp?.confirmed,
          error: resp?.error,
          prf: resp?.prfOutput,
          tx: resp?.transactionContext,
          reserved,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.confirmed, result.error || 'unknown error').toBe(true);
    expect(result.tx?.nextNonce).toBe('11');
    expect(result.reserved).toEqual([]);
    // NEP-413 signing also must not expose PRF output.
    expect(result.prf).toBeUndefined();
  });
});

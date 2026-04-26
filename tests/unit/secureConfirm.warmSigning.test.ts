import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  handle: '/sdk/esm/core/signingEngine/touchConfirm/handlers/handlePromptFromWorker.js',
  types: '/sdk/esm/core/signingEngine/touchConfirm/shared/confirmTypes.js',
  nonceCoordinator: '/sdk/esm/core/signingEngine/nonce/NonceCoordinator.js',
} as const;

test.describe('UserConfirm – warm signing', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('SIGN_TRANSACTION warmSession skips TouchID and returns tx context', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.handle);
        const types = await import(paths.types);
        const handle = mod.handlePromptFromWorker as Function;

        const counts = { touchId: 0 };
        const reserved: string[] = [];

        const ctx: any = {
          userPreferencesManager: {
            getConfirmationConfig: () => ({
              uiMode: 'none',
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
            releaseNonce(_nonce: string) {},
          },
          nearClient: {
            async viewAccessKey() {
              const context = await ctx.nearContextFixture.getNonceBlockHashAndHeight();
              return context.accessKeyInfo;
            },
            async viewBlock() {
              const context = await ctx.nearContextFixture.getNonceBlockHashAndHeight();
              return {
                header: {
                  height: Number(context.txBlockHeight || 1),
                  hash: String(context.txBlockHash || 'h3000'),
                },
              };
            },
          },
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            async getAuthenticationCredentialsInternal() {
              counts.touchId++;
              throw new Error('TouchID prompt should not be called for warmSession');
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
              }) => ({
                profileId: `legacy-near:${String(accountAddress)}`,
                accountRef: { chainIdKey, accountAddress },
              }),
              listProfileAuthenticators: async () => [],
              selectProfileAuthenticatorsForPrompt: async ({ authenticators }: any) => ({
                authenticatorsForPrompt: authenticators,
                wrongPasskeyError: undefined,
              }),
            },
          },
        };
        const nonceCoordinatorMod = await import(paths.nonceCoordinator);
        ctx.nonceCoordinator = nonceCoordinatorMod.createNonceCoordinator({
          evmNonceBackend: {
            fetchChainNonce: async () => 0n,
          },
          nearClient: ctx.nearClient,
          onTrace: (event: any) => {
            if (event?.lease?.lane?.family !== 'near') return;
            if (event.event === 'nonce_lease_reserved') {
              ctx.nearContextFixture.reserveNonces(1);
            }
          },
        });
        ctx.nonceCoordinator.initializeNearAccessKey({
          accountId: 'alice.testnet',
          publicKey: 'pk',
        });

        const request = {
          requestId: 'sess-warm',
          type: types.UserConfirmationType.SIGN_TRANSACTION,
          summary: {},
          payload: {
            intentDigest: 'intent-warm',
            txSigningRequests: [
              { receiverId: 'x', actions: [] },
              { receiverId: 'y', actions: [] },
            ],
            rpcCall: {
              method: 'sign',
              argsJson: {},
              nearAccountId: 'alice.testnet',
              nearRpcUrl: 'https://rpc.testnet.near.org',
            },
            signingAuthPlan: {
              kind: 'warmSession',
              method: 'passkey',
              accountId: 'alice.testnet',
              intent: 'transaction_sign',
              curve: 'ed25519',
              sessionId: 'threshold-session-warm',
              retention: 'session',
              expiresAtMs: Date.now() + 60_000,
              remainingUses: 1,
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
        return { counts, reserved, response };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.counts.touchId).toBe(0);
    expect(result.response.confirmed).toBe(true);
    expect(result.response.transactionContext).toBeTruthy();
    expect(result.reserved.length).toBeGreaterThan(0);
  });
});

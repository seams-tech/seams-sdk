import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, sdkEsmPath } from '../setup';

const IMPORT_PATHS = {
  adapters: sdkEsmPath('core/signingEngine/uiConfirm/handlers/flows/adapters/adapters.js'),
} as const;

test.describe('touchConfirm confirm session onMounted lifecycle', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('promptUser exposes handle early enough for updateUI before decision resolution', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const adaptersMod = await import(paths.adapters);
        const handleUpdates: Array<Record<string, unknown>> = [];
        const closeCalls: boolean[] = [];

        const fakeHandle = {
          close: (confirmed: boolean) => {
            closeCalls.push(confirmed);
          },
          update: (props: Record<string, unknown>) => {
            handleUpdates.push(props);
          },
        };

        const adapters = {
          near: {
            releaseReservedNonces: (_nonces?: string[]) => {},
          },
          security: {
            getRpId: () => 'example.com',
          },
          webauthn: {
            collectAuthenticationCredentialWithPRF: async () => ({}),
            createRegistrationCredential: async () => ({}),
          },
          ui: {
            renderConfirmUI: async ({
              onMounted,
            }: {
              onMounted?: (handle: typeof fakeHandle) => void;
            }) => {
              onMounted?.(fakeHandle);
              await new Promise((resolve) => setTimeout(resolve, 25));
              return {
                confirmed: false as const,
                confirmHandle: fakeHandle,
                error: 'mock-cancelled',
              };
            },
            closeModalSafely: (confirmed: boolean, handle?: typeof fakeHandle) => {
              handle?.close(confirmed);
            },
          },
        } as any;

        const session = adaptersMod.createConfirmSession({
          adapters,
          worker: { postMessage: () => {} } as any,
          request: {
            requestId: 'req-1',
            type: 'signTransaction',
            summary: { intentDigest: 'intent-1' },
            payload: {
              txSigningRequests: [],
              intentDigest: 'intent-1',
              rpcCall: { nearAccountId: 'alice.testnet' },
            },
          } as any,
          confirmationConfig: {
            uiMode: 'modal',
            behavior: 'requireClick',
            autoProceedDelay: 0,
          } as any,
          transactionSummary: { intentDigest: 'intent-1' },
          theme: 'dark',
        });

        const decisionPromise = session.promptUser({
          securityContext: { rpId: 'example.com' },
          loading: true,
        });

        // Allow renderConfirmUI to mount and invoke onMounted callback.
        await new Promise((resolve) => setTimeout(resolve, 0));

        // This should hit fakeHandle.update before decisionPromise resolves.
        session.updateUI({
          loading: false,
          securityContext: {
            rpId: 'example.com',
            blockHeight: '123',
            blockHash: 'hash-123',
          },
        });

        const decision = await decisionPromise;

        return {
          decision,
          handleUpdates,
          closeCalls,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.decision.confirmed).toBe(false);
    expect(result.decision.error).toBe('mock-cancelled');
    expect(result.handleUpdates.length).toBe(1);
    expect(result.handleUpdates[0]?.loading).toBe(false);
    expect((result.handleUpdates[0]?.securityContext as any)?.blockHeight).toBe('123');
    expect(result.closeCalls.length).toBe(0);
  });
});

import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, SDK_ESM_PATHS } from '../setup';
import {
  buildWalletServiceHtml,
  captureOverlay,
  registerWalletServiceRoute,
  waitFor,
} from './harness';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';
const CAPTURE_OVERLAY_SOURCE = `(${captureOverlay.toString()})`;
const WAIT_FOR_SOURCE = `(${waitFor.toString()})`;

function unwrapFixture<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('invalid fixture value');
  return result.value;
}

const REGISTRATION_RP_ID = unwrapFixture(parseWebAuthnRpId('example.localhost'));

test.describe('WalletIframeRouter cancellation progress', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await registerWalletServiceRoute(page, buildWalletServiceHtml(), WALLET_SERVICE_ROUTE);
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  test('forwards v2 cancelled terminal events for core request flows', async ({ page }) => {
    const result = await page.evaluate(
      async ({
        routerPath,
        walletOrigin,
        registrationRpId,
        captureOverlaySource,
        waitForSource,
      }) => {
        const mod = await import(routerPath);
        const { WalletIframeRouter } =
          mod as typeof import('@/SeamsWeb/walletIframe/client/router');
        const capture = eval(captureOverlaySource) as typeof import('./harness').captureOverlay;
        const waitFor = eval(waitForSource) as typeof import('./harness').waitFor;

        const router = new WalletIframeRouter({
          walletOrigin,
          servicePath: '/wallet-service',
          connectTimeoutMs: 3000,
          requestTimeoutMs: 5000,
          debug: true,
          sdkBasePath: '/sdk',
        });
        await router.init();

        const events: Record<string, any[]> = {
          registration: [],
          unlock: [],
          signing: [],
        };
        const registrationSignerSet = {
          kind: 'signer_set' as const,
          signers: [
            {
              kind: 'near_ed25519' as const,
              accountProvisioning: {
                kind: 'implicit_account' as const,
                accountIdSource: 'ed25519_public_key' as const,
              },
              signerSlot: 1,
              participantIds: [1, 2],
              derivationVersion: 1,
            },
          ],
        };

        const runAndCancel = async (
          name: keyof typeof events,
          run: () => Promise<unknown>,
        ): Promise<{
          message: string;
          code?: string;
          overlayShown: boolean;
          overlayHidden: boolean;
        }> => {
          const pending = run().catch((error: any) => ({
            message: String(error?.message || error || ''),
            code: typeof error?.code === 'string' ? error.code : undefined,
          }));
          const overlayShown = await waitFor(() => {
            const state = capture();
            return !!(state.exists && state.visible);
          }, 3000);
          await router.cancelAll();
          const overlayHidden = await waitFor(() => {
            const state = capture();
            return !state.exists || !state.visible;
          }, 3000);
          const settled = (await pending) as { message: string; code?: string };
          return { ...settled, overlayShown, overlayHidden };
        };

        const registration = await runAndCancel('registration', () =>
          router.registerWallet({
            wallet: { kind: 'server_allocated' },
            authMethod: { kind: 'passkey', rpId: registrationRpId },
            signerSelection: registrationSignerSet,
            options: { onEvent: (event: any) => events.registration.push(event) },
          }),
        );
        const unlock = await runAndCancel('unlock', () =>
          router.unlock({
            kind: 'custom_options',
            walletId: 'alice.testnet',
            options: { onEvent: (event: any) => events.unlock.push(event) },
          }),
        );
        const signing = await runAndCancel('signing', () =>
          router.executeAction({
            walletId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            receiverId: 'w3a-v1.testnet',
            actionArgs: { type: 'Transfer', amount: '1' } as any,
            options: { onEvent: (event: any) => events.signing.push(event) },
          }),
        );

        return {
          registration,
          unlock,
          signing,
          events,
        };
      },
      {
        routerPath: SDK_ESM_PATHS.walletIframeRouter,
        walletOrigin: WALLET_ORIGIN,
        registrationRpId: REGISTRATION_RP_ID,
        captureOverlaySource: CAPTURE_OVERLAY_SOURCE,
        waitForSource: WAIT_FOR_SOURCE,
      },
    );

    expect(result.registration).toMatchObject({
      message: 'Request cancelled.',
      code: 'cancelled',
      overlayShown: true,
      overlayHidden: true,
    });
    expect(result.unlock).toMatchObject({
      message: 'Request cancelled.',
      code: 'cancelled',
      overlayShown: true,
      overlayHidden: true,
    });
    expect(result.signing).toMatchObject({
      message: 'Request cancelled.',
      code: 'cancelled',
      overlayShown: true,
      overlayHidden: true,
    });

    expect(result.events.registration.at(-1)).toMatchObject({
      version: 2,
      flow: 'registration',
      step: 0,
      phase: 'registration.cancelled',
      status: 'cancelled',
      message: 'Request cancelled.',
      error: { code: 'cancelled', message: 'Request cancelled.' },
      interaction: { kind: 'none', overlay: 'hide' },
    });
    expect(result.events.unlock.at(-1)).toMatchObject({
      version: 2,
      flow: 'unlock',
      step: 0,
      phase: 'unlock.cancelled',
      status: 'cancelled',
      message: 'Request cancelled.',
      error: { code: 'cancelled', message: 'Request cancelled.' },
      interaction: { kind: 'none', overlay: 'hide' },
    });
    expect(result.events.signing.at(-1)).toMatchObject({
      version: 2,
      flow: 'signing',
      step: 0,
      phase: 'signing.cancelled',
      status: 'cancelled',
      message: 'Request cancelled.',
      error: { code: 'cancelled', message: 'Request cancelled.' },
      interaction: { kind: 'none', overlay: 'hide' },
    });
  });
});

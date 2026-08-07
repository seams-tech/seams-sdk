import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest, handleInfrastructureErrors, SDK_ESM_PATHS } from '../setup';
import { buildWalletServiceHtml, registerWalletServiceRoute, waitFor } from './harness';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { buildMpcMaterialActivationRefFixture } from '../unit/helpers/ecdsaMaterialRef.fixtures';

/**
 * Key export ALWAYS presents as a bottom drawer. It deliberately does not
 * follow the Confirmer UI (modal|drawer|none) preference that the tx confirmer
 * uses — so these drive every setting and require the drawer regardless.
 *
 * Both halves are asserted together: the variant the parent stamps into the
 * outgoing payload (what the iframe reads back) AND the presentation the parent
 * dressed the dialog with. The two resolving independently is what once painted
 * a drawer into a compact modal box and lost the viewer entirely, so checking
 * only one would miss exactly that bug.
 */

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';
const WAIT_FOR_SOURCE = `(${waitFor.toString()})`;
const SUBJECT_ID = toWalletId('export-variant.testnet');
const EVM_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
  networkSlug: 'sepolia',
});
const ECDSA_KEY = buildEvmFamilyEcdsaKeyIdentity({
  walletId: SUBJECT_ID,
  evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
    walletId: SUBJECT_ID,
    signingRootId: 'signing-root-export-variant',
    signingRootVersion: 'root-v1',
  }),
  ecdsaThresholdKeyId: 'ecdsa-threshold-export-variant',
  signingRootId: 'signing-root-export-variant',
  signingRootVersion: 'root-v1',
  participantIds: [1, 2],
  thresholdOwnerAddress: '0x2222222222222222222222222222222222222222',
});
const EXPORT_LANE = exactEcdsaSigningLaneIdentity({
  signer: buildEvmFamilyEcdsaSignerBinding({
    walletId: SUBJECT_ID,
    chainTarget: EVM_TARGET,
    keyHandle: toEvmFamilyEcdsaKeyHandle('ecdsa-key-handle-export-variant'),
    key: ECDSA_KEY,
    materialActivation: buildMpcMaterialActivationRefFixture('export-variant', SUBJECT_ID),
  }),
  auth: {
    kind: 'passkey',
    rpId: toRpId('example.localhost'),
    credentialIdB64u: 'credential-export-variant',
  },
  thresholdSessionId: 'threshold-ecdsa-export-variant',
});

/**
 * Answers the two requests these tests drive, and records the export payload so
 * the test can read back the variant the parent stamped. The export request is
 * deliberately left open until the test releases it, so the dialog can be
 * inspected while the surface is still up.
 */
const RECORDING_STUB = String.raw`
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;
        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          const data = event.data || {};
          if (data && data.type === 'PM_SET_CONFIRMATION_CONFIG') {
            adoptedPort.postMessage({
              type: 'PM_RESULT',
              requestId: data.requestId,
              payload: { ok: true, result: undefined },
            });
            return;
          }
          if (data && data.type === 'PM_EXPORT_KEYPAIR_UI') {
            const options = (data.payload && data.payload.options) || {};
            window.parent.postMessage(
              {
                type: 'TEST_MARKER',
                marker: 'EXPORT_STARTED',
                variant: options.variant ?? null,
              },
              '*',
            );
            return;
          }
          originalHandler?.(event);
        };
      };
`;

/**
 * Reads the presentation the host actually dressed the dialog with. The
 * bootstrap leaves more than one overlay dialog in the document, so pick the
 * one framing the wallet-origin iframe, preferring an open one — the same
 * disambiguation captureOverlay does for iframes.
 */
const captureDialogPresentation = () => {
  const dialogs = Array.from(
    document.querySelectorAll('dialog.w3a-wallet-overlay-dialog'),
  ) as HTMLDialogElement[];
  const walletFramed = dialogs.filter((d) =>
    /wallet\.example\.localhost/.test(d.querySelector('iframe')?.getAttribute('src') || ''),
  );
  const pool = walletFramed.length ? walletFramed : dialogs;
  const dialog = pool.find((d) => d.open) ?? pool[pool.length - 1];
  if (!dialog) {
    return {
      exists: false,
      drawer: false,
      modal: false,
      open: false,
      dialogCount: dialogs.length,
      classes: '',
    };
  }
  return {
    exists: true,
    drawer: dialog.classList.contains('is-drawer'),
    modal: dialog.classList.contains('is-modal'),
    open: dialog.open,
    dialogCount: dialogs.length,
    classes: dialog.className,
  };
};
const CAPTURE_PRESENTATION_SOURCE = `(${captureDialogPresentation.toString()})`;

type UiMode = 'drawer' | 'modal' | 'none';

test.describe('wallet iframe export surface variant', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await page.waitForTimeout(200);
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  // The Confirmer UI setting must NOT reach the export surface.
  for (const uiMode of ['drawer', 'modal', 'none'] as UiMode[]) {
    const expected = 'drawer' as const;
    test(`export is a drawer regardless of Confirmer UI '${uiMode}'`, async ({ page }) => {
      await registerWalletServiceRoute(
        page,
        buildWalletServiceHtml({ extraScript: RECORDING_STUB }),
        WALLET_SERVICE_ROUTE,
      );

      const result = await page.evaluate(
        async ({
          walletOrigin,
          waitForSource,
          capturePresentationSource,
          routerPath,
          walletId,
          chainTarget,
          exportLaneIdentity,
          uiMode,
        }) => {
          const waitFor = eval(waitForSource) as typeof import('./harness').waitFor;
          const capturePresentation = eval(capturePresentationSource) as () => {
            exists: boolean;
            drawer: boolean;
            modal: boolean;
            open: boolean;
            dialogCount: number;
            classes: string;
          };
          try {
            const mod = await import(routerPath);
            const { WalletIframeRouter } =
              mod as typeof import('@/SeamsWeb/walletIframe/client/router');

            let exportStarted = false;
            let stampedVariant: string | null = null;
            window.addEventListener('message', (ev) => {
              const data = (ev.data || {}) as {
                type?: string;
                marker?: string;
                variant?: string | null;
              };
              if (data.type === 'TEST_MARKER' && data.marker === 'EXPORT_STARTED') {
                exportStarted = true;
                stampedVariant = data.variant ?? null;
              }
            });

            const router = new WalletIframeRouter({
              walletOrigin,
              servicePath: '/wallet-service',
              connectTimeoutMs: 3000,
              requestTimeoutMs: 5000,
              debug: false,
              sdkBasePath: '/sdk',
            });
            await router.init();

            // The Confirmer UI setting is the single source of truth here.
            await router.setConfirmationConfig({ uiMode: uiMode as 'drawer' | 'modal' | 'none' });

            // No caller variant: this is the account-menu path.
            const exportPromise = router
              .exportKeypairWithUI({
                kind: 'ecdsa',
                walletSession: { walletId, walletSessionUserId: 'export-variant.testnet' },
                chainTarget,
                laneIdentity: exportLaneIdentity,
                options: { theme: 'light' },
              })
              .catch(() => undefined);

            const started = await waitFor(() => exportStarted, 4000);
            // The surface opens on its own schedule; poll rather than sample.
            const surfaced = await waitFor(() => {
              const state = capturePresentation();
              return state.exists && state.open;
            }, 4000);
            const presentation = capturePresentation();

            void router.cancelAll();
            await Promise.race([exportPromise, new Promise((r) => setTimeout(r, 500))]);

            return { success: true, started, surfaced, presentation, stampedVariant } as const;
          } catch (error: any) {
            return { success: false, error: error?.message || String(error) } as const;
          }
        },
        {
          walletOrigin: WALLET_ORIGIN,
          waitForSource: WAIT_FOR_SOURCE,
          capturePresentationSource: CAPTURE_PRESENTATION_SOURCE,
          routerPath: SDK_ESM_PATHS.walletIframeRouter,
          walletId: SUBJECT_ID,
          chainTarget: EVM_TARGET,
          exportLaneIdentity: EXPORT_LANE,
          uiMode,
        },
      );

      if (!result.success) {
        if (handleInfrastructureErrors(result)) return;
        expect(result, result.error).toEqual(expect.objectContaining({ success: true }));
        return;
      }

      expect(result.started).toBe(true);
      expect(result.surfaced).toBe(true);
      expect(result.presentation.exists).toBe(true);
      expect(result.presentation.open).toBe(true);

      // Both halves of the agreement, for the same request.
      expect(result.stampedVariant).toBe(expected);
      expect(result.presentation.drawer).toBe(expected === 'drawer');
      expect(result.presentation.modal).toBe(expected === 'modal');
    });
  }
});

import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest, handleInfrastructureErrors, SDK_ESM_PATHS } from '../setup';
import {
  buildWalletServiceHtml,
  registerWalletServiceRoute,
  waitFor,
  captureOverlay,
} from './harness';
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

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';
const WAIT_FOR_SOURCE = `(${waitFor.toString()})`;
const CAPTURE_OVERLAY_SOURCE = `(${captureOverlay.toString()})`;
const EXPORT_FLOW_SUBJECT_ID = toWalletId('export-flow.testnet');
const EXPORT_FLOW_EVM_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
  networkSlug: 'sepolia',
});
const EXPORT_FLOW_ECDSA_KEY = buildEvmFamilyEcdsaKeyIdentity({
  walletId: EXPORT_FLOW_SUBJECT_ID,
  evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
    walletId: EXPORT_FLOW_SUBJECT_ID,
    signingRootId: 'signing-root-export-flow',
    signingRootVersion: 'root-v1',
  }),
  ecdsaThresholdKeyId: 'ecdsa-threshold-export-flow',
  signingRootId: 'signing-root-export-flow',
  signingRootVersion: 'root-v1',
  participantIds: [1, 2],
  thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
});
const EXPORT_FLOW_ECDSA_EXPORT_LANE = exactEcdsaSigningLaneIdentity({
  signer: buildEvmFamilyEcdsaSignerBinding({
    walletId: EXPORT_FLOW_SUBJECT_ID,
    chainTarget: EXPORT_FLOW_EVM_TARGET,
    keyHandle: toEvmFamilyEcdsaKeyHandle('ecdsa-key-handle-export-flow'),
    key: EXPORT_FLOW_ECDSA_KEY,
  }),
  auth: {
    kind: 'passkey',
    rpId: toRpId('example.test'),
    credentialIdB64u: 'credential-export-flow',
  },
  signingGrantId: 'grant-ecdsa-export-flow',
  thresholdSessionId: 'threshold-ecdsa-export-flow',
});

const staleGenericCloseAfterExportViewerScript = String.raw`
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;
        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object') return;
          if (data.type !== 'PM_EXPORT_KEYPAIR_UI' || typeof data.requestId !== 'string') return;

          setTimeout(() => {
            try {
              adoptedPort.postMessage({
                type: 'PROGRESS',
                requestId: data.requestId,
                payload: {
                  version: 2,
                  flow: 'key_export',
                  step: 2,
                  phase: 'key_export.auth.passkey.prompt.started',
                  status: 'waiting_for_user',
                  message: 'Confirm with passkey',
                  flowId: 'key_export:test:' + data.requestId,
                  requestId: data.requestId,
                  interaction: { kind: 'passkey_assert', overlay: 'show' },
                },
              });
            } catch (err) {
              console.error('Failed to post export PROGRESS', err);
            }
          }, 20);

          setTimeout(() => {
            pendingRequests.delete(data.requestId);
            try {
              adoptedPort.postMessage({
                type: 'PM_RESULT',
                requestId: data.requestId,
                payload: { ok: true, result: null },
              });
            } catch (err) {
              console.error('Failed to post export PM_RESULT', err);
            }
          }, 130);

          setTimeout(() => {
            try {
              adoptedPort.postMessage({
                type: 'PROGRESS',
                requestId: data.requestId,
                payload: {
                  version: 2,
                  flow: 'key_export',
                  step: 4,
                  phase: 'key_export.viewer.opened',
                  status: 'waiting_for_user',
                  message: 'Review private key',
                  flowId: 'key_export:test:' + data.requestId,
                  requestId: data.requestId,
                  interaction: { kind: 'key_export_viewer', overlay: 'show' },
                },
              });
              window.parent?.postMessage({ type: 'TEST_MARKER', marker: 'EXPORT_VIEWER_OPENED' }, '*');
            } catch (err) {
              console.error('Failed to post export viewer open marker', err);
            }
          }, 100);

          setTimeout(() => {
            try {
              window.parent?.postMessage({ type: 'WALLET_UI_CLOSED' }, '*');
              window.parent?.postMessage({ type: 'TEST_MARKER', marker: 'STALE_GENERIC_UI_CLOSED' }, '*');
            } catch (err) {
              console.error('Failed to post stale generic close marker', err);
            }
          }, 150);

          setTimeout(() => {
            try {
              adoptedPort.postMessage({
                type: 'PROGRESS',
                requestId: data.requestId,
                payload: {
                  version: 2,
                  flow: 'key_export',
                  step: 5,
                  phase: 'key_export.viewer.closed',
                  status: 'succeeded',
                  message: 'Key export closed',
                  flowId: 'key_export:test:' + data.requestId,
                  requestId: data.requestId,
                  interaction: { kind: 'key_export_viewer', overlay: 'hide' },
                },
              });
              window.parent?.postMessage({ type: 'TEST_MARKER', marker: 'EXPORT_UI_CLOSED' }, '*');
            } catch (err) {
              console.error('Failed to post export close marker', err);
            }
          }, 260);
        };
      };
`;

test.describe('wallet-origin export flow integration', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await page.waitForTimeout(200);
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  test('export viewer ignores stale generic WALLET_UI_CLOSED from previous wallet UI', async ({
    page,
  }) => {
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: staleGenericCloseAfterExportViewerScript }),
      WALLET_SERVICE_ROUTE,
    );

    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({
        walletOrigin,
        waitForSource,
        captureOverlaySource,
        routerPath,
        walletId,
        chainTarget,
        exportLaneIdentity,
      }) => {
        const waitFor = eval(waitForSource) as typeof import('./harness').waitFor;
        const capture = eval(captureOverlaySource) as typeof import('./harness').captureOverlay;
        try {
          const mod = await import(routerPath);
          const { WalletIframeRouter } =
            mod as typeof import('@/SeamsWeb/walletIframe/client/router');

          const marks: Record<string, boolean> = {};
          let visibleAtStaleGenericClose = false;
          window.addEventListener('message', (ev) => {
            const data = ev.data || {};
            if (!data || typeof data !== 'object') return;
            if ((data as any).type !== 'TEST_MARKER') return;
            const marker = String((data as any).marker || '');
            if (marker) marks[marker] = true;
            if (marker === 'STALE_GENERIC_UI_CLOSED') {
              const state = capture();
              visibleAtStaleGenericClose = state.exists && state.visible;
            }
          });

          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 1800,
            debug: true,
            sdkBasePath: '/sdk',
          });
          await router.init();

          const exportPromise = router.exportKeypairWithUI({
            kind: 'ecdsa',
            walletSession: {
              walletId,
              walletSessionUserId: 'export-flow.testnet',
            },
            chainTarget,
            laneIdentity: exportLaneIdentity,
            options: {
              variant: 'drawer',
              theme: 'light',
            },
          });

          const shown = await waitFor(() => {
            const state = capture();
            return state.exists && state.visible;
          }, 3000);

          await exportPromise;
          const viewerOpened = await waitFor(() => !!marks.EXPORT_VIEWER_OPENED, 3000);
          const visibleWhileExportSurfaceOwnsTheIframe = (() => {
            const state = capture();
            return state.exists && state.visible;
          })();
          const staleCloseMarker = await waitFor(() => !!marks.STALE_GENERIC_UI_CLOSED, 3000);

          const closeMarker = await waitFor(() => !!marks.EXPORT_UI_CLOSED, 3000);
          const hiddenAfterExportClose = await waitFor(() => {
            const state = capture();
            if (!state.exists) return true;
            return !state.visible;
          }, 3000);

          return {
            success: true,
            shown,
            viewerOpened,
            visibleWhileExportSurfaceOwnsTheIframe,
            staleCloseMarker,
            visibleAtStaleGenericClose,
            closeMarker,
            hiddenAfterExportClose,
          } as const;
        } catch (error: any) {
          return { success: false, error: error?.message || String(error) } as const;
        }
      },
      {
        walletOrigin: WALLET_ORIGIN,
        waitForSource: WAIT_FOR_SOURCE,
        captureOverlaySource: CAPTURE_OVERLAY_SOURCE,
        routerPath,
        walletId: toWalletId('export-flow.testnet'),
        chainTarget: EXPORT_FLOW_EVM_TARGET,
        exportLaneIdentity: EXPORT_FLOW_ECDSA_EXPORT_LANE,
      },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result, result.error).toEqual(expect.objectContaining({ success: true }));
      return;
    }

    expect(result.shown).toBe(true);
    expect(result.viewerOpened).toBe(true);
    expect(result.visibleWhileExportSurfaceOwnsTheIframe).toBe(true);
    expect(result.staleCloseMarker).toBe(true);
    expect(result.visibleAtStaleGenericClose).toBe(true);
    expect(result.closeMarker).toBe(true);
    expect(result.hiddenAfterExportClose).toBe(true);
  });

});

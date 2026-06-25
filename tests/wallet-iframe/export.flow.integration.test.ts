import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest, handleInfrastructureErrors, SDK_ESM_PATHS } from '../setup';
import {
  buildWalletServiceHtml,
  registerWalletServiceRoute,
  waitFor,
  captureOverlay,
} from './harness';
import {
  nearAccountRefFromAccountId,
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  exactEcdsaSigningLaneIdentity,
  exactEd25519SigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { ed25519KeyScopeIdFromString } from '@shared/utils/registrationIntent';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';
const WAIT_FOR_SOURCE = `(${waitFor.toString()})`;
const CAPTURE_OVERLAY_SOURCE = `(${captureOverlay.toString()})`;
const EXPORT_FLOW_NEAR_ACCOUNT = nearAccountRefFromAccountId('export-flow.testnet');
const ISOLATION_NEAR_ACCOUNT = nearAccountRefFromAccountId('isolation.testnet');
const EXPORT_FLOW_SUBJECT_ID = toWalletId('export-flow.testnet');
const EXPORT_FLOW_WALLET_SESSION = walletSessionRefFromSession({
  walletId: EXPORT_FLOW_SUBJECT_ID,
  walletSessionUserId: EXPORT_FLOW_SUBJECT_ID,
});
const EXPORT_FLOW_NEAR_EXPORT_LANE = exactEd25519SigningLaneIdentity({
  walletId: EXPORT_FLOW_SUBJECT_ID,
  nearAccountId: 'export-flow.testnet',
  ed25519KeyScopeId: ed25519KeyScopeIdFromString('export-flow.testnet'),
  auth: {
    kind: 'passkey',
    rpId: toRpId('example.test'),
    credentialIdB64u: 'credential-export-flow',
  },
  signingGrantId: 'grant-export-flow',
  thresholdSessionId: 'threshold-export-flow',
});
const ISOLATION_SUBJECT_ID = toWalletId('isolation.testnet');
const ISOLATION_WALLET_SESSION = walletSessionRefFromSession({
  walletId: ISOLATION_SUBJECT_ID,
  walletSessionUserId: ISOLATION_SUBJECT_ID,
});
const ISOLATION_NEAR_EXPORT_LANE = exactEd25519SigningLaneIdentity({
  walletId: ISOLATION_SUBJECT_ID,
  nearAccountId: 'isolation.testnet',
  ed25519KeyScopeId: ed25519KeyScopeIdFromString('isolation.testnet'),
  auth: {
    kind: 'passkey',
    rpId: toRpId('example.test'),
    credentialIdB64u: 'credential-isolation',
  },
  signingGrantId: 'grant-isolation-export',
  thresholdSessionId: 'threshold-isolation-export',
});
const EXPORT_FLOW_EVM_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
  networkSlug: 'sepolia',
});
const EXPORT_FLOW_ECDSA_KEY = buildEvmFamilyEcdsaKeyIdentity({
  walletId: EXPORT_FLOW_SUBJECT_ID,
  walletKeyId: 'wallet-key-export-flow',
  ecdsaThresholdKeyId: 'ecdsa-threshold-export-flow',
  signingRootId: 'signing-root-export-flow',
  signingRootVersion: 'root-v1',
  participantIds: [1, 2],
  thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
});
const EXPORT_FLOW_ECDSA_EXPORT_LANE = exactEcdsaSigningLaneIdentity({
  walletId: EXPORT_FLOW_SUBJECT_ID,
  chainTarget: EXPORT_FLOW_EVM_TARGET,
  keyHandle: toEvmFamilyEcdsaKeyHandle('ecdsa-key-handle-export-flow'),
  key: EXPORT_FLOW_ECDSA_KEY,
  auth: {
    kind: 'passkey',
    rpId: toRpId('example.test'),
    credentialIdB64u: 'credential-export-flow',
  },
  signingGrantId: 'grant-ecdsa-export-flow',
  thresholdSessionId: 'threshold-ecdsa-export-flow',
});

const exportFlowScript = String.raw`
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

          try {
            window.parent?.postMessage({
              type: 'TEST_MARKER',
              marker: 'EXPORT_REQUEST_CAPTURED',
              payload: data.payload || {},
              requestId: data.requestId,
            }, '*');
          } catch {}

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
          }, 80);

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
              console.error('Failed to post key export viewer opened progress', err);
            }
          }, 220);

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
              console.error('Failed to post key export viewer closed progress', err);
            }
          }, 260);
        };
      };
`;

const exportSigningIsolationScript = String.raw`
      const originalAdoptPort = adoptPort;
      adoptPort = function patchedAdoptPort(port) {
        originalAdoptPort(port);
        if (!adoptedPort) return;
        const originalHandler = adoptedPort.onmessage;
        adoptedPort.onmessage = (event) => {
          originalHandler?.(event);
          const data = event.data || {};
          if (!data || typeof data !== 'object' || typeof data.requestId !== 'string') return;

          if (data.type === 'PM_EXPORT_KEYPAIR_UI') {
            try {
              window.parent?.postMessage({
                type: 'TEST_MARKER',
                marker: 'EXPORT_REQUEST_CAPTURED',
                requestId: data.requestId,
              }, '*');
            } catch {}

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
            }, 100);

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
            }, 760);

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
            }, 900);
            return;
          }

          if (data.type === 'PM_EXECUTE_ACTION') {
            try {
              window.parent?.postMessage({
                type: 'TEST_MARKER',
                marker: 'SIGNING_REQUEST_CAPTURED',
                requestId: data.requestId,
              }, '*');
            } catch {}

            setTimeout(() => {
              try {
                adoptedPort.postMessage({
                  type: 'PROGRESS',
                  requestId: data.requestId,
                  payload: {
                    version: 2,
                    flow: 'signing',
                    step: 5,
                    phase: 'signing.confirmation.displayed',
                    status: 'waiting_for_user',
                    message: 'Review transaction',
                    flowId: 'signing:test:' + data.requestId,
                    requestId: data.requestId,
                    interaction: { kind: 'transaction_confirmation', overlay: 'show' },
                  },
                });
              } catch (err) {
                console.error('Failed to post signing PROGRESS', err);
              }
            }, 40);

            setTimeout(() => {
              pendingRequests.delete(data.requestId);
              try {
                adoptedPort.postMessage({
                  type: 'PM_RESULT',
                  requestId: data.requestId,
                  payload: { ok: true, result: { ok: true, source: 'signing' } },
                });
                window.parent?.postMessage({
                  type: 'TEST_MARKER',
                  marker: 'SIGNING_RESULT',
                  requestId: data.requestId,
                }, '*');
              } catch (err) {
                console.error('Failed to post signing PM_RESULT', err);
              }
            }, 180);
          }
        };
      };
`;

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

  test('export flow completes and overlay closes on key export progress', async ({
    page,
  }) => {
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: exportFlowScript }),
      WALLET_SERVICE_ROUTE,
    );

    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({
        walletOrigin,
        waitForSource,
        captureOverlaySource,
        routerPath,
        nearAccount,
        exportLaneIdentity,
        walletSession,
      }) => {
        const waitFor = eval(waitForSource) as typeof import('./harness').waitFor;
        const capture = eval(captureOverlaySource) as typeof import('./harness').captureOverlay;
        try {
          const mod = await import(routerPath);
          const { WalletIframeRouter } = mod as typeof import('@/SeamsWeb/walletIframe/client/router');

          const marks: Record<string, boolean> = {};
          let capturedPayload: Record<string, unknown> | null = null;
          window.addEventListener('message', (ev) => {
            const data = ev.data || {};
            if (!data || typeof data !== 'object') return;
            if ((data as any).type !== 'TEST_MARKER') return;
            const marker = String((data as any).marker || '');
            if (marker) marks[marker] = true;
            if (marker === 'EXPORT_REQUEST_CAPTURED') {
              capturedPayload = ((data as any).payload || null) as Record<string, unknown> | null;
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
            kind: 'near',
            walletSession,
            nearAccount,
            laneIdentity: exportLaneIdentity,
            options: {
              chain: 'near',
              variant: 'drawer',
              theme: 'light',
            },
          });

          const shown = await waitFor(() => {
            const state = capture();
            return state.exists && state.visible;
          }, 3000);

          await exportPromise;
          const visibleAfterExportPromise = (() => {
            const state = capture();
            return state.exists && state.visible;
          })();

          const closeMarker = await waitFor(() => !!marks.EXPORT_UI_CLOSED, 3000);
          const hiddenAfterClose = await waitFor(() => {
            const state = capture();
            if (!state.exists) return true;
            return !state.visible;
          }, 3000);

          return {
            success: true,
            shown,
            visibleAfterExportPromise,
            closeMarker,
            hiddenAfterClose,
            exportPayload: capturedPayload,
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
        nearAccount: EXPORT_FLOW_NEAR_ACCOUNT,
        exportLaneIdentity: EXPORT_FLOW_NEAR_EXPORT_LANE,
        walletSession: EXPORT_FLOW_WALLET_SESSION,
      },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.shown).toBe(true);
    expect(result.visibleAfterExportPromise).toBe(true);
    expect(result.closeMarker).toBe(true);
    expect(result.hiddenAfterClose).toBe(true);
    expect(result.exportPayload).toMatchObject({
      kind: 'near',
      walletSession: {
        walletId: 'export-flow.testnet',
        walletSessionUserId: 'export-flow.testnet',
      },
      nearAccount: {
        kind: 'named',
        accountId: 'export-flow.testnet',
      },
      laneIdentity: {
        kind: 'exact_ed25519_signing_lane_identity',
        signingGrantId: 'grant-export-flow',
        thresholdSessionId: 'threshold-export-flow',
      },
      options: {
        chain: 'near',
        variant: 'drawer',
        theme: 'light',
      },
    });
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
        subjectId,
        walletId,
        chainTarget,
        exportLaneIdentity,
      }) => {
        const waitFor = eval(waitForSource) as typeof import('./harness').waitFor;
        const capture = eval(captureOverlaySource) as typeof import('./harness').captureOverlay;
        try {
          const mod = await import(routerPath);
          const { WalletIframeRouter } = mod as typeof import('@/SeamsWeb/walletIframe/client/router');

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
          (router as any).hideFrameForActivation();
          const visibleAfterUnrelatedHideCall = (() => {
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
            visibleAfterUnrelatedHideCall,
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
        subjectId: EXPORT_FLOW_SUBJECT_ID,
        walletId: toWalletId('export-flow.testnet'),
        chainTarget: EXPORT_FLOW_EVM_TARGET,
        exportLaneIdentity: EXPORT_FLOW_ECDSA_EXPORT_LANE,
      },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.shown).toBe(true);
    expect(result.viewerOpened).toBe(true);
    expect(result.visibleAfterUnrelatedHideCall).toBe(true);
    expect(result.staleCloseMarker).toBe(true);
    expect(result.visibleAtStaleGenericClose).toBe(true);
    expect(result.closeMarker).toBe(true);
    expect(result.hiddenAfterExportClose).toBe(true);
  });

  test('concurrent export and signing remain isolated and do not cross-talk', async ({ page }) => {
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: exportSigningIsolationScript }),
      WALLET_SERVICE_ROUTE,
    );

    const routerPath = SDK_ESM_PATHS.walletIframeRouter;
    const result = await page.evaluate(
      async ({
        walletOrigin,
        waitForSource,
        captureOverlaySource,
        routerPath,
        nearAccount,
        exportLaneIdentity,
        walletSession,
      }) => {
        const waitFor = eval(waitForSource) as typeof import('./harness').waitFor;
        const capture = eval(captureOverlaySource) as typeof import('./harness').captureOverlay;
        try {
          const mod = await import(routerPath);
          const { WalletIframeRouter } = mod as typeof import('@/SeamsWeb/walletIframe/client/router');

          const marks: Record<string, boolean> = {};
          let exportRequestId = '';
          let signingRequestId = '';
          window.addEventListener('message', (ev) => {
            const data = ev.data || {};
            if (!data || typeof data !== 'object') return;
            if ((data as any).type !== 'TEST_MARKER') return;
            const marker = String((data as any).marker || '');
            if (marker) marks[marker] = true;
            if (marker === 'EXPORT_REQUEST_CAPTURED') {
              exportRequestId = String((data as any).requestId || '').trim();
            }
            if (marker === 'SIGNING_REQUEST_CAPTURED') {
              signingRequestId = String((data as any).requestId || '').trim();
            }
          });

          const router = new WalletIframeRouter({
            walletOrigin,
            servicePath: '/wallet-service',
            connectTimeoutMs: 3000,
            requestTimeoutMs: 2200,
            debug: true,
            sdkBasePath: '/sdk',
          });
          await router.init();

          const exportPromise = router.exportKeypairWithUI({
            kind: 'near',
            walletSession,
            nearAccount,
            laneIdentity: exportLaneIdentity,
            options: {
              chain: 'near',
              variant: 'drawer',
              theme: 'dark',
            },
          });
          const shown = await waitFor(() => {
            const state = capture();
            return state.exists && state.visible;
          }, 3000);

          const signPromise = router.executeAction({
            walletId: 'isolation.testnet',
            nearAccountId: 'isolation.testnet',
            receiverId: 'w3a-v1.testnet',
            actionArgs: { type: 'Transfer', amount: '1' } as any,
            options: {},
          });

          const visibleDuringSigning = await waitFor(() => {
            if (!marks.SIGNING_REQUEST_CAPTURED) return false;
            const state = capture();
            return state.exists && state.visible;
          }, 3000);
          const signingResultMarker = await waitFor(() => !!marks.SIGNING_RESULT, 3000);
          const [exportResult, signingResult] = await Promise.all([
            exportPromise.then(() => ({ ok: true })),
            signPromise,
          ]);

          const closeMarker = await waitFor(() => !!marks.EXPORT_UI_CLOSED, 3000);
          const hiddenAfterClose = await waitFor(() => {
            const state = capture();
            if (!state.exists) return true;
            return !state.visible;
          }, 3000);

          return {
            success: true,
            shown,
            visibleDuringSigning,
            signingResultMarker,
            exportResult,
            signingResult,
            closeMarker,
            hiddenAfterClose,
            exportRequestId,
            signingRequestId,
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
        nearAccount: ISOLATION_NEAR_ACCOUNT,
        exportLaneIdentity: ISOLATION_NEAR_EXPORT_LANE,
        walletSession: ISOLATION_WALLET_SESSION,
      },
    );

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success).toBe(true);
      return;
    }

    expect(result.shown).toBe(true);
    expect(result.visibleDuringSigning).toBe(true);
    expect(result.signingResultMarker).toBe(true);
    expect(result.exportResult).toEqual({ ok: true });
    expect(result.signingResult).toMatchObject({ ok: true, source: 'signing' });
    expect(result.closeMarker).toBe(true);
    expect(result.hiddenAfterClose).toBe(true);
    expect(result.exportRequestId).toBeTruthy();
    expect(result.signingRequestId).toBeTruthy();
    expect(result.exportRequestId).not.toBe(result.signingRequestId);
  });
});

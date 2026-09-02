import { expect, test, type Frame, type Page } from '@playwright/test';
import { encodeFunctionData, parseAbi } from 'viem';
import { setupBasicPasskeyTest } from '../setup';
import { injectImportMap } from '../setup/bootstrap';
import { buildTestBrowserImportMapHtml } from '../setup/importMap';
import { buildWalletServiceHtml, registerWalletServiceRoute } from './harness';

/**
 * Host-driven tree growth across the REAL wallet-iframe boundary.
 *
 * The parent router, the cross-origin wallet frame, the parent's resize ease,
 * and the real confirmer (wrapper → modal → content → tree) all take part; the
 * only stand-in is the wallet-service host runtime, whose stub hands the
 * signing request straight to `mountConfirmUI`. Same-process harnesses cannot
 * see what this boundary does — the parent forces a layout at the destination
 * geometry before its ease starts and the frame receives that size for one
 * frame — so the invariants below are asserted from inside the frame, per
 * animation frame, while the parent is genuinely easing:
 *
 * - the child posts exactly one measurement per toggle (the target), never a
 *   stream of intermediate sizes;
 * - the card never exceeds the box in any frame (nothing is clipped);
 * - the body reaches its final height only after the box has been seen at
 *   intermediate sizes (it does not land on the destination blip).
 */

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';
const CONTRACT = '0xbb442b6d9a4c1f0f3e2d3c4b5a6978695a4b3a48';
const SET_GREETING_ABI = [
  {
    type: 'function',
    name: 'setGreeting',
    inputs: [{ name: 'newGreeting', type: 'string' }],
    outputs: [],
    stateMutability: 'nonpayable',
  },
] as const;

const childScript = (calldata: string) => String.raw`
  const CALLDATA = '${calldata}';
  const ABI = ${JSON.stringify(SET_GREETING_ABI)};
  const originalAdoptPort = adoptPort;
  adoptPort = function patchedAdoptPort(port) {
    originalAdoptPort(port);
    if (!adoptedPort) return;
    const originalHandler = adoptedPort.onmessage;
    adoptedPort.onmessage = (event) => {
      originalHandler?.(event);
      const message = event.data || {};
      if (message.type !== 'PM_SIGN_TEMPO' || typeof message.requestId !== 'string') return;
      window.__mountReal(message.requestId).catch((e) => { window.__mountError = String((e && e.stack) || e); });
    };
  };
  window.__measurements = [];
  window.__mountReal = async (requestId) => {
    const confirmUi = await import('/_test-sdk/esm/core/signingEngine/uiConfirm/ui/confirm-ui.js');
    const evm = await import('/_test-sdk/esm/core/signingEngine/chains/evm/display/evmTx.js');
    const model = evm.buildEvmDisplayModel({ request: { chain: 'evm', kind: 'eip1559', senderSignatureAlgorithm: 'secp256k1',
      tx: { chainId: 42431, nonce: 1n, maxPriorityFeePerGas: 1500000000n, maxFeePerGas: 3000000000n, gasLimit: 200000n,
        to: '${CONTRACT}', value: 0n, data: CALLDATA, accessList: [], abi: ABI } } });
    const ctx = { userPreferencesManager: { getCurrentWalletId: () => 'alice.testnet' },
      surfaceMeasurementBinding: { kind: 'wallet_iframe', requestId,
        postMeasurement: (m) => { window.__measurements.push(m.heightCssPx); adoptedPort.postMessage({ type: 'SURFACE_MEASUREMENT', payload: m }); } } };
    await confirmUi.mountConfirmUI({ ctx, summary: { intentDigest: 'tree-growth' }, model,
      securityContext: { blockHeight: '1', blockHash: 'h' }, loading: false, theme: 'light', uiMode: 'modal', nearAccountIdOverride: 'alice.testnet' });
    window.__mounted = true;
  };
`;

type ToggleTrace = {
  begin: {
    open: boolean;
    delta: number;
    viewportPx: number;
    hostPx: number;
    surface: string | null;
  };
  measurements: number[];
  frames: Array<{ viewportPx: number; cardPx: number; bodyPx: number; pinned: boolean }>;
  open: boolean;
};

async function openRealModal(page: Page): Promise<Frame> {
  await page.goto('about:blank');
  await injectImportMap(page);
  const calldata = encodeFunctionData({
    abi: parseAbi(['function setGreeting(string newGreeting)']),
    functionName: 'setGreeting',
    args: ['Hello Tempo'],
  });
  // The stub document must reset the UA body margin exactly like the real
  // wallet-service document does (wallet-service.css): with an 8px margin the
  // host is 16px narrower than the frame, the parent eases the width down to
  // the host each round, and the two chase each other in width.
  const html = buildWalletServiceHtml({ extraScript: childScript(calldata) }).replace(
    '</head>',
    `<link rel="stylesheet" href="/sdk/wallet-service.css" />${buildTestBrowserImportMapHtml()}</head>`,
  );
  await registerWalletServiceRoute(page, html, WALLET_SERVICE_ROUTE);

  await page.evaluate(
    async ({ walletOrigin, calldata, contract }) => {
      const routerModule = (await import(
        /* @vite-ignore */ '/_test-sdk/esm/SeamsWeb/walletIframe/client/router.js' as string
      )) as typeof import('@/SeamsWeb/walletIframe/client/router');
      const router = new routerModule.WalletIframeRouter({
        walletOrigin,
        servicePath: '/wallet-service',
        sdkBasePath: '/sdk',
        relayer: { url: window.location.origin },
        registration: { projectEnvironmentId: 'proj_local:test', publishableKey: 'pk_local' },
        requestTimeoutMs: 60_000,
        testOptions: { ownerTag: 'tree-growth-integration' },
      });
      await router.init();
      (window as any).__treeGrowthRouter = router;
      void router
        .signTempo({
          walletSession: { walletId: 'alice.testnet', walletSessionUserId: 'u' } as any,
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 42431,
              nonce: 1n,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 200_000n,
              to: contract,
              value: 0n,
              data: calldata,
              accessList: [],
            },
          } as any,
          chainTarget: {
            kind: 'evm',
            namespace: 'eip155',
            chainId: 42431,
            networkSlug: 'tempo-testnet',
          } as any,
          options: { confirmationConfig: { uiMode: 'modal' } },
        })
        .catch(() => undefined);
    },
    { walletOrigin: WALLET_ORIGIN, calldata, contract: CONTRACT },
  );

  await page.waitForFunction(
    () => {
      const dialog = document.querySelector('dialog.w3a-wallet-overlay-dialog');
      return (
        !!dialog &&
        dialog.classList.contains('is-modal') &&
        !dialog.classList.contains('is-provisional')
      );
    },
    undefined,
    { timeout: 30_000 },
  );
  const frame = page.frames().find((candidate) => candidate.url().startsWith(WALLET_ORIGIN));
  if (!frame)
    throw new Error(
      `wallet frame missing: ${page
        .frames()
        .map((f) => f.url())
        .join(', ')}`,
    );
  await frame.waitForFunction(
    () =>
      (window as any).__mounted === true && !!document.querySelector('w3a-tx-tree details.folder'),
    undefined,
    { timeout: 30_000 },
  );
  // Let the confirmer's own settling (headings, halo) finish before measuring.
  await page.waitForTimeout(600);
  return frame;
}

async function toggleFolder(frame: Frame, expectOpen: boolean): Promise<ToggleTrace> {
  return frame.evaluate(async (expectOpen) => {
    const host = document.getElementById('w3a-confirm-portal')!.firstElementChild as HTMLElement;
    const card = host.querySelector('.modal-container-root') as HTMLElement;
    const details = document.querySelector(
      `w3a-tx-tree details.folder${expectOpen ? ':not([open])' : '[open]:not(:has(> .folder-children > details.folder[open]))'}`,
    ) as HTMLDetailsElement | null;
    if (!details) throw new Error('no folder in the expected state');
    const summary = details.querySelector(':scope > summary') as HTMLElement;
    const body = details.querySelector(':scope > .folder-children') as HTMLElement;
    let begin: ToggleTrace['begin'] | null = null;
    host.addEventListener(
      'lit-tree-resize-begin',
      (e: any) => {
        begin = {
          open: e.detail.open,
          delta: e.detail.deltaCssPx,
          viewportPx: document.documentElement.clientHeight,
          hostPx: host.getBoundingClientRect().height,
          surface: host.getAttribute('data-w3a-confirm-surface'),
        };
      },
      { capture: true, once: true },
    );
    const measurements: number[] = (window as any).__measurements;
    measurements.length = 0;
    const frames: ToggleTrace['frames'] = [];
    const sample = () => {
      frames.push({
        viewportPx: document.documentElement.clientHeight,
        cardPx: card.getBoundingClientRect().height,
        bodyPx: body.getBoundingClientRect().height,
        pinned: host.classList.contains('w3a-confirm-surface-pinned'),
      });
    };
    // ResizeObserver callbacks run after layout and after every animation-frame
    // callback, so each sample is what that frame paints; sampling from a
    // competing requestAnimationFrame would read the card one step stale.
    const observer = new ResizeObserver(sample);
    observer.observe(document.documentElement);
    observer.observe(card);
    observer.observe(body);
    sample();
    summary.click();
    await new Promise((resolve) => setTimeout(resolve, 1200));
    observer.disconnect();
    sample();
    if (!begin) throw new Error('the tree did not hand its motion to the host');
    return { begin, measurements: measurements.slice(), frames, open: details.open };
  }, expectOpen);
}

function assertToggleInvariants(trace: ToggleTrace, expectOpen: boolean): void {
  const { begin, measurements, frames } = trace;
  expect(begin.surface).toBe('wallet-iframe');
  expect(begin.open).toBe(expectOpen);
  expect(begin.delta).toBeGreaterThan(0);
  // The box hugs the host when the toggle starts.
  expect(Math.abs(begin.viewportPx - begin.hostPx)).toBeLessThanOrEqual(1);
  const closedPx = Math.round(expectOpen ? begin.hostPx : begin.hostPx - begin.delta);
  const targetPx = expectOpen ? closedPx + begin.delta : closedPx;
  // One measurement per toggle: the target, posted before the motion.
  expect(measurements[0]).toBe(targetPx);
  // The host releases its pin the moment the body lands (the closed body keeps
  // a stale layout box in Chrome, so the pin is the reliable landing marker).
  const firstPinned = frames.findIndex((f) => f.pinned);
  expect(firstPinned).toBeGreaterThanOrEqual(0);
  const landing = frames.findIndex((f, i) => i > firstPinned && !f.pinned);
  expect(landing).toBeGreaterThan(firstPinned);
  const untilLanding = frames.slice(0, landing + 1);
  if (expectOpen) expect(frames[landing].bodyPx).toBeGreaterThanOrEqual(begin.delta - 0.5);
  expect(measurements.filter((px) => px !== targetPx)).toEqual([]);
  // The card never exceeds the box while the toggle is in flight.
  for (const f of untilLanding) expect(f.cardPx).toBeLessThanOrEqual(f.viewportPx + 1);
  // The body only lands after the box has been seen at intermediate sizes.
  const intermediate = untilLanding.filter(
    (f) => f.pinned && f.bodyPx > 0.5 && f.bodyPx < begin.delta - 0.5,
  );
  expect(intermediate.length).toBeGreaterThanOrEqual(2);
  expect(trace.open).toBe(expectOpen);
  expect(frames.at(-1)?.pinned).toBe(false);
}

test.describe('wallet iframe host-driven tree growth', () => {
  test.beforeEach(async ({ page }) => {
    test.setTimeout(90_000);
    await setupBasicPasskeyTest(page, {
      skipSeamsWebInit: true,
      injectWalletServiceImportMap: true,
    });
  });

  test.afterEach(async ({ page }) => {
    await page.evaluate(() => {
      (window as any).__treeGrowthRouter?.dispose();
      delete (window as any).__treeGrowthRouter;
    });
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  test('the card fills the easing box on open and close, one measurement each', async ({
    page,
  }) => {
    const frame = await openRealModal(page);

    const opened = await toggleFolder(frame, true);
    assertToggleInvariants(opened, true);

    await page.waitForTimeout(400);
    const closed = await toggleFolder(frame, false);
    assertToggleInvariants(closed, false);
  });
});

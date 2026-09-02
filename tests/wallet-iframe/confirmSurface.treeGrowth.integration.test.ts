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

/** What a single interior height change looks like from inside the frame. */
type MotionTrace = {
  begin: {
    deltaCssPx: number;
    viewportPx: number;
    hostPx: number;
    surface: string | null;
  };
  measurements: number[];
  frames: Array<{ viewportPx: number; cardPx: number; pinned: boolean }>;
  /** Where the content actually ended up, once everything settled. */
  finalHostPx: number;
  /** Frames where the box claimed its target and then moved away again. */
  blipFrames: number;
};

/** The interior changes this surface can make, each through the same seam. */
type MotionAction =
  | { kind: 'folder'; open: boolean }
  | { kind: 'file-content-mode' }
  | { kind: 'error-banner'; message: string };

async function openRealModal(page: Page, options: { greeting?: string } = {}): Promise<Frame> {
  await page.goto('about:blank');
  await injectImportMap(page);
  const calldata = encodeFunctionData({
    abi: parseAbi(['function setGreeting(string newGreeting)']),
    functionName: 'setGreeting',
    args: [options.greeting ?? 'Hello Tempo'],
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

async function recordMotion(frame: Frame, action: MotionAction): Promise<MotionTrace> {
  return frame.evaluate(async (action) => {
    const host = document.getElementById('w3a-confirm-portal')!.firstElementChild as HTMLElement;
    const card = host.querySelector('.modal-container-root') as HTMLElement;
    let begin: MotionTrace['begin'] | null = null;
    host.addEventListener(
      'lit-surface-resize-begin',
      (e: any) => {
        begin = {
          deltaCssPx: e.detail.deltaCssPx,
          viewportPx: document.documentElement.clientHeight,
          hostPx: host.getBoundingClientRect().height,
          surface: host.getAttribute('data-w3a-confirm-surface'),
        };
      },
      { capture: true, once: true },
    );

    const measurements: number[] = (window as any).__measurements;
    measurements.length = 0;
    const frames: MotionTrace['frames'] = [];
    const sample = () => {
      frames.push({
        viewportPx: document.documentElement.clientHeight,
        cardPx: card.getBoundingClientRect().height,
        pinned: host.classList.contains('w3a-confirm-surface-pinned'),
      });
    };
    // ResizeObserver callbacks run after layout and after every animation-frame
    // callback, so each sample is what that frame paints; sampling from a
    // competing requestAnimationFrame would read the card one step stale.
    const observer = new ResizeObserver(sample);
    observer.observe(document.documentElement);
    observer.observe(card);
    sample();

    const click = (selector: string) => {
      const target = document.querySelector(selector) as HTMLElement | null;
      if (!target) throw new Error(`nothing to click for ${selector}`);
      target.click();
    };
    switch (action.kind) {
      case 'folder':
        click(
          action.open
            ? 'w3a-tx-tree details.folder:not([open]) > summary'
            : 'w3a-tx-tree details.folder[open]:not(:has(> .folder-children > details.folder[open])) > summary',
        );
        break;
      case 'file-content-mode':
        click('w3a-tx-tree .file-content-mode-toggle');
        break;
      case 'error-banner':
        (host as unknown as { errorMessage: string }).errorMessage = action.message;
        break;
    }

    await new Promise((resolve) => setTimeout(resolve, 1200));
    observer.disconnect();
    sample();
    if (!begin) throw new Error('the surface was never offered the height change');
    return {
      begin,
      measurements: measurements.slice(),
      frames,
      finalHostPx: host.getBoundingClientRect().height,
      blipFrames:
        (window as unknown as { __w3aSurfaceMotion?: { blipFrames: number } }).__w3aSurfaceMotion
          ?.blipFrames ?? 0,
    };
  }, action);
}

/**
 * The invariants of refactor 116, asserted from inside the frame while the
 * parent is genuinely easing: one measurement, a card that never exceeds its
 * box, and content that lands only after the box was seen part-way there.
 */
function assertMotionInvariants(trace: MotionTrace, expected: { sign?: 1 | -1 } = {}): void {
  const { begin, measurements, frames } = trace;
  expect(begin.surface).toBe('wallet-iframe');
  if (expected.sign) expect(Math.sign(begin.deltaCssPx)).toBe(expected.sign);
  expect(Math.abs(begin.deltaCssPx)).toBeGreaterThanOrEqual(1);
  // The box hugs the host when the change is announced, and the announcing
  // element is still clamped at its pre-change height.
  expect(Math.abs(begin.viewportPx - begin.hostPx)).toBeLessThanOrEqual(1);

  const originPx = Math.round(begin.hostPx);
  // Exactly one measurement per change, and it is where the content actually
  // ended up. A stream of intermediate sizes, and a box sent somewhere the
  // card then has to correct, are the two defects this guards.
  expect(measurements).toHaveLength(1);
  expect(Math.abs(measurements[0] - trace.finalHostPx)).toBeLessThanOrEqual(1);
  const targetPx = measurements[0];

  // The pin comes off when the content lands, so it is the landing marker: a
  // collapsed body keeps a stale layout box in Chrome and cannot be one.
  const firstPinned = frames.findIndex((f) => f.pinned);
  expect(firstPinned).toBeGreaterThanOrEqual(0);
  const landing = frames.findIndex((f, i) => i > firstPinned && !f.pinned);
  expect(landing).toBeGreaterThan(firstPinned);

  const untilLanding = frames.slice(0, landing + 1);
  for (const f of untilLanding) expect(f.cardPx).toBeLessThanOrEqual(f.viewportPx + 1);

  const progressOf = (viewportPx: number) => (viewportPx - originPx) / (targetPx - originPx);
  const intermediate = untilLanding.filter(
    (f) => f.pinned && progressOf(f.viewportPx) > 0.01 && progressOf(f.viewportPx) < 0.99,
  );
  expect(intermediate.length).toBeGreaterThanOrEqual(2);
  expect(frames.at(-1)?.pinned).toBe(false);
  // The parent held the iframe at the origin while it wrote the destination,
  // so the frame never saw the final size before the ease reached it.
  expect(trace.blipFrames).toBe(0);
}

test.describe('wallet iframe host-driven interior motion', () => {
  test.beforeEach(async ({ page }) => {
    test.setTimeout(120_000);
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

  test('a tree node fills the easing box on open and close, one measurement each', async ({
    page,
  }) => {
    const frame = await openRealModal(page);

    assertMotionInvariants(await recordMotion(frame, { kind: 'folder', open: true }), { sign: 1 });
    await page.waitForTimeout(400);
    assertMotionInvariants(await recordMotion(frame, { kind: 'folder', open: false }), {
      sign: -1,
    });
  });

  test('swapping decoded calldata for bytes moves the box, not the card', async ({ page }) => {
    // Long enough that the decoded JSON and the hex differ by more than a line.
    const frame = await openRealModal(page, { greeting: `Hello Tempo ${'x'.repeat(120)}` });
    await recordMotion(frame, { kind: 'folder', open: true });
    await page.waitForTimeout(400);

    assertMotionInvariants(await recordMotion(frame, { kind: 'file-content-mode' }));
  });

  test('an error banner arriving moves the box, not the card', async ({ page }) => {
    const frame = await openRealModal(page);
    assertMotionInvariants(
      await recordMotion(frame, { kind: 'error-banner', message: 'Signing failed. Try again.' }),
    );
  });

  test('content height does not depend on the box it is given', async ({ page }) => {
    // Long calldata so the block's height cap actually binds: a cap in viewport
    // units would then make the content a function of the box the parent gave
    // it, and the two would chase each other.
    const frame = await openRealModal(page, { greeting: `Hello Tempo ${'y'.repeat(600)}` });
    await recordMotion(frame, { kind: 'folder', open: true });
    await page.waitForTimeout(400);

    const hostHeight = () =>
      frame.evaluate(() =>
        Math.round(
          (
            document.getElementById('w3a-confirm-portal')!.firstElementChild as HTMLElement
          ).getBoundingClientRect().height,
        ),
      );
    // Grow only: a box smaller than its content would raise a classic
    // scrollbar, narrow the content, and re-wrap it for reasons of its own.
    const setBoxHeightCssPx = async (px: number | null) => {
      await page.evaluate((height) => {
        const iframe = document.querySelector(
          'dialog.w3a-wallet-overlay-dialog iframe',
        ) as HTMLIFrameElement;
        iframe.style.height = height === null ? '' : `${height}px`;
      }, px);
      await page.waitForTimeout(150);
    };

    const natural = await hostHeight();
    await setBoxHeightCssPx(natural + 320);
    const grown = await hostHeight();
    await setBoxHeightCssPx(null);
    expect(grown).toBe(natural);
  });
});

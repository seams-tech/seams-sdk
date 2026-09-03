import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, sdkEsmPath } from '../setup';

// Host-driven tree growth in the wallet-iframe modal surface
// (packages/wallet/src/core/signingEngine/uiConfirm/ui/confirm-surface-resize.ts).
//
// The parent window sizes the iframe to hug the confirmer and eases the box to
// each new measurement. These tests stand in for that parent with a scripted
// viewport height and assert the contract the child keeps regardless of the
// parent's easing: the host reports exactly one size per toggle, the tree body
// never exceeds the room the box has made, and the node lands in its final
// state once the box stops moving.

const IMPORT_PATHS = {
  txTree: sdkEsmPath('core/signingEngine/uiConfirm/ui/lit-components/TxTree/index.js'),
  choreographer: sdkEsmPath('core/signingEngine/uiConfirm/ui/confirm-surface-resize.js'),
} as const;

const NODE_ID = 'action-0';

type HarnessState = {
  hostHeights: number[];
  toggled: number;
  begins: Array<{ open: boolean; deltaCssPx: number }>;
  viewportPx: number;
};

declare global {
  interface Window {
    __w3aResizeHarness?: HarnessState & {
      host: HTMLElement;
      details: HTMLDetailsElement;
      body: HTMLElement;
      summary: HTMLElement;
      dispose: () => void;
    };
  }
}

async function mountTreeHost(
  page: import('@playwright/test').Page,
  opts: { surface: 'wallet-iframe' | 'standalone'; viewportOffsetPx?: number },
): Promise<{ closedPx: number; deltaHintPx: number }> {
  return await page.evaluate(
    async ({ paths, surface, viewportOffsetPx, nodeId }) => {
      await import(paths.txTree);
      const choreography = (await import(
        paths.choreographer
      )) as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-surface-resize');

      window.__w3aResizeHarness?.dispose();
      document.getElementById('w3a-resize-harness')?.remove();

      const host = document.createElement('div');
      host.id = 'w3a-resize-harness';
      host.setAttribute(choreography.CONFIRM_SURFACE_MODE_ATTR, surface);
      const tree = document.createElement('w3a-tx-tree') as HTMLElement & {
        node?: unknown;
        theme?: string;
        updateComplete?: Promise<unknown>;
      };
      tree.theme = 'dark';
      tree.node = {
        id: 'root',
        label: 'Transaction',
        type: 'folder',
        open: true,
        children: [
          {
            id: nodeId,
            label: 'Action 1: FunctionCall',
            type: 'folder',
            open: false,
            children: [
              { id: `${nodeId}-method`, label: 'method: set_greeting', type: 'file' },
              { id: `${nodeId}-gas`, label: 'gas: 30 Tgas', type: 'file' },
              { id: `${nodeId}-deposit`, label: 'deposit: 0', type: 'file' },
              { id: `${nodeId}-args`, label: 'args: {"greeting":"hi"}', type: 'file' },
            ],
          },
        ],
      };
      host.appendChild(tree);
      document.body.appendChild(host);
      await tree.updateComplete;

      // The tree's external stylesheet carries the .anim-h rules the motion
      // relies on; wait until it has actually loaded.
      const link = document.head.querySelector(
        'link[data-w3a-tx-tree-css]',
      ) as HTMLLinkElement | null;
      if (!link) throw new Error('tx-tree.css link missing');
      if (!link.sheet) {
        await new Promise<void>((resolve) => {
          link.addEventListener('load', () => resolve(), { once: true });
          link.addEventListener('error', () => resolve(), { once: true });
        });
      }

      const details = host.querySelector(
        `details[data-node-id="${nodeId}"]`,
      ) as HTMLDetailsElement | null;
      const summary = details?.querySelector(':scope > summary') as HTMLElement | null;
      if (!details || !summary) throw new Error('collapsible node missing');

      const state: HarnessState = {
        hostHeights: [],
        toggled: 0,
        begins: [],
        viewportPx: 0,
      };
      const closedPx = Math.round(host.getBoundingClientRect().height);
      state.viewportPx = closedPx + (viewportOffsetPx ?? 0);

      const observer = new ResizeObserver((entries) => {
        const last = entries[entries.length - 1];
        if (!last) return;
        state.hostHeights.push(Math.round(last.contentRect.height));
      });
      observer.observe(host);
      host.addEventListener('lit-tree-toggled', () => {
        state.toggled += 1;
      });
      host.addEventListener('lit-surface-resize-begin', (event) => {
        // The seam speaks a signed delta; for a tree node its sign is the
        // direction of the toggle, which is what these cases assert on.
        const detail = (event as CustomEvent<{ deltaCssPx: number }>).detail;
        state.begins.push({
          open: detail.deltaCssPx > 0,
          deltaCssPx: Math.abs(detail.deltaCssPx),
        });
      });

      const choreographer = choreography.attachConfirmSurfaceResizeChoreographer(host, {
        viewportHeightCssPx: () => state.viewportPx,
      });

      const bodyLookup = () =>
        details.querySelector(':scope > .folder-children') as HTMLElement | null;

      window.__w3aResizeHarness = Object.assign(state, {
        host,
        details,
        summary,
        get body() {
          const body = bodyLookup();
          if (!body) throw new Error('folder body missing');
          return body;
        },
        dispose: () => {
          choreographer.dispose();
          observer.disconnect();
          host.remove();
        },
      });
      return { closedPx, deltaHintPx: 0 };
    },
    {
      paths: IMPORT_PATHS,
      surface: opts.surface,
      viewportOffsetPx: opts.viewportOffsetPx,
      nodeId: NODE_ID,
    },
  );
}

async function frames(page: import('@playwright/test').Page, count: number): Promise<void> {
  await page.evaluate(async (n) => {
    for (let i = 0; i < n; i += 1) {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    }
  }, count);
}

async function snapshot(page: import('@playwright/test').Page) {
  return await page.evaluate(() => {
    const h = window.__w3aResizeHarness;
    if (!h) throw new Error('harness missing');
    const body = h.body;
    return {
      hostPx: Math.round(h.host.getBoundingClientRect().height),
      bodyPx: Math.round(body.getBoundingClientRect().height),
      pinned: h.host.classList.contains('w3a-confirm-surface-pinned'),
      driven: body.classList.contains('anim-h-driven'),
      animating: body.classList.contains('anim-h'),
      open: h.details.open,
      toggled: h.toggled,
      begins: h.begins.slice(),
      hostHeights: h.hostHeights.slice(),
      viewportPx: h.viewportPx,
    };
  });
}

async function setViewport(page: import('@playwright/test').Page, px: number): Promise<void> {
  await page.evaluate((value) => {
    const h = window.__w3aResizeHarness;
    if (!h) throw new Error('harness missing');
    h.viewportPx = value;
  }, px);
}

async function clickNode(page: import('@playwright/test').Page): Promise<void> {
  await page.evaluate(() => {
    window.__w3aResizeHarness?.summary.click();
  });
}

function distinct(values: number[]): number[] {
  return values.filter((value, index) => index === 0 || values[index - 1] !== value);
}

/**
 * Wait for the motion to land rather than counting frames: a box that jumps
 * straight to its target is deliberately held for a few frames before the
 * content follows it (LANDING_CONFIRM_FRAMES), so any fixed count here would
 * encode that constant into every case.
 */
async function waitForLanded(
  page: import('@playwright/test').Page,
  toggles: number,
): Promise<void> {
  await expect.poll(async () => (await snapshot(page)).toggled, { timeout: 2_000 }).toBe(toggles);
}

test.describe('wallet-iframe confirm surface resize choreography', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test.afterEach(async ({ page }) => {
    await page.evaluate(() => window.__w3aResizeHarness?.dispose());
  });

  test('opening grows the host first and fills the body from the box, one measurement', async ({
    page,
  }) => {
    const { closedPx } = await mountTreeHost(page, { surface: 'wallet-iframe' });

    await clickNode(page);
    // The tree measures on the next frame; the choreographer pins on that frame.
    await frames(page, 2);
    const pinned = await snapshot(page);
    expect(pinned.begins).toHaveLength(1);
    expect(pinned.begins[0].open).toBe(true);
    const deltaPx = pinned.begins[0].deltaCssPx;
    expect(deltaPx).toBeGreaterThan(0);
    expect(pinned.pinned).toBe(true);
    expect(pinned.driven).toBe(true);
    expect(pinned.open).toBe(true);
    expect(pinned.hostPx).toBe(closedPx + deltaPx);
    // The box has not moved yet, so the body still shows nothing.
    expect(pinned.bodyPx).toBe(0);
    expect(pinned.toggled).toBe(0);

    // Stand in for the parent's ease: the box grows in four steps.
    const steps = [0.25, 0.5, 0.75, 1];
    for (const fraction of steps.slice(0, -1)) {
      const viewportPx = closedPx + Math.round(deltaPx * fraction);
      await setViewport(page, viewportPx);
      await frames(page, 1);
      const mid = await snapshot(page);
      expect(mid.bodyPx).toBe(viewportPx - closedPx);
      expect(mid.pinned).toBe(true);
      expect(mid.hostPx).toBe(closedPx + deltaPx);
      expect(mid.toggled).toBe(0);
    }

    await setViewport(page, closedPx + deltaPx);
    await waitForLanded(page, 1);
    const settled = await snapshot(page);
    expect(settled.pinned).toBe(false);
    expect(settled.driven).toBe(false);
    expect(settled.animating).toBe(false);
    expect(settled.open).toBe(true);
    expect(settled.bodyPx).toBe(deltaPx);
    expect(settled.hostPx).toBe(closedPx + deltaPx);
    expect(settled.toggled).toBe(1);
    // What the reporter would have posted: one change, straight to the target.
    expect(distinct(settled.hostHeights).filter((px) => px !== closedPx)).toEqual([
      closedPx + deltaPx,
    ]);
  });

  test('closing pins the host to the closed size and drains the body as the box shrinks', async ({
    page,
  }) => {
    const { closedPx } = await mountTreeHost(page, { surface: 'wallet-iframe' });

    // Open first, letting the box follow instantly.
    await clickNode(page);
    await frames(page, 2);
    const opened = await snapshot(page);
    const deltaPx = opened.begins[0].deltaCssPx;
    await setViewport(page, closedPx + deltaPx);
    await waitForLanded(page, 1);

    await clickNode(page);
    await frames(page, 1);
    const pinned = await snapshot(page);
    expect(pinned.begins).toHaveLength(2);
    expect(pinned.begins[1]).toEqual({ open: false, deltaCssPx: deltaPx });
    expect(pinned.pinned).toBe(true);
    expect(pinned.driven).toBe(true);
    // Host already reports the closed size while the card is still fully open.
    expect(pinned.hostPx).toBe(closedPx);
    expect(pinned.bodyPx).toBe(deltaPx);
    expect(pinned.open).toBe(true);

    await setViewport(page, closedPx + Math.round(deltaPx / 2));
    await frames(page, 1);
    const mid = await snapshot(page);
    expect(mid.bodyPx).toBe(Math.round(deltaPx / 2));
    expect(mid.open).toBe(true);

    await setViewport(page, closedPx);
    await waitForLanded(page, 2);
    const settled = await snapshot(page);
    expect(settled.pinned).toBe(false);
    expect(settled.open).toBe(false);
    expect(settled.hostPx).toBe(closedPx);
    expect(settled.toggled).toBe(2);
    expect(distinct(settled.hostHeights).filter((px) => px !== closedPx)).toEqual([
      closedPx + deltaPx,
    ]);
  });

  test('does not land on the one-frame destination blip before the parent eases', async ({
    page,
  }) => {
    // The parent writes the destination geometry and forces a layout before
    // its ease starts, so a cross-origin iframe sees the final size for one
    // frame, then the origin again, then the ease. Landing on the blip would
    // finish the interior instantly while the box still has to travel.
    const { closedPx } = await mountTreeHost(page, { surface: 'wallet-iframe' });

    await clickNode(page);
    await frames(page, 2);
    const pinned = await snapshot(page);
    expect(pinned.pinned).toBe(true);
    const deltaPx = pinned.begins[0].deltaCssPx;

    await setViewport(page, closedPx + deltaPx);
    await frames(page, 1);
    const blip = await snapshot(page);
    expect(blip.pinned).toBe(true);
    expect(blip.bodyPx).toBe(0);
    expect(blip.toggled).toBe(0);

    await setViewport(page, closedPx);
    await frames(page, 1);
    const back = await snapshot(page);
    expect(back.pinned).toBe(true);
    expect(back.bodyPx).toBe(0);

    for (const fraction of [0.3, 0.6]) {
      const viewportPx = closedPx + Math.round(deltaPx * fraction);
      await setViewport(page, viewportPx);
      await frames(page, 1);
      expect((await snapshot(page)).bodyPx).toBe(viewportPx - closedPx);
    }
    await setViewport(page, closedPx + deltaPx);
    await waitForLanded(page, 1);
    const settled = await snapshot(page);
    expect(settled.pinned).toBe(false);
    expect(settled.bodyPx).toBe(deltaPx);
    expect(distinct(settled.hostHeights).filter((px) => px !== closedPx)).toEqual([
      closedPx + deltaPx,
    ]);
  });

  test('lands on a box that jumps to the target and stays there', async ({ page }) => {
    const { closedPx } = await mountTreeHost(page, { surface: 'wallet-iframe' });
    await clickNode(page);
    await frames(page, 2);
    const deltaPx = (await snapshot(page)).begins[0].deltaCssPx;
    await setViewport(page, closedPx + deltaPx);
    await waitForLanded(page, 1);
    const settled = await snapshot(page);
    expect(settled.pinned).toBe(false);
    expect(settled.open).toBe(true);
    expect(settled.bodyPx).toBe(deltaPx);
  });

  test('a box that does not hug the host leaves the tree to its own transition', async ({
    page,
  }) => {
    await mountTreeHost(page, { surface: 'wallet-iframe', viewportOffsetPx: 40 });

    await clickNode(page);
    await frames(page, 2);
    const during = await snapshot(page);
    expect(during.begins).toHaveLength(1);
    expect(during.pinned).toBe(false);
    expect(during.driven).toBe(false);
    expect(during.open).toBe(true);

    await expect.poll(async () => (await snapshot(page)).toggled, { timeout: 2_000 }).toBe(1);
    const settled = await snapshot(page);
    expect(settled.animating).toBe(false);
    expect(settled.bodyPx).toBe(during.begins[0].deltaCssPx);
  });

  test('an unclaimed surface still animates the node itself', async ({ page }) => {
    // The drawer's box never hugs its content, so nobody claims the motion and
    // the tree runs its own height transition. Offering the change must hand
    // the node back exactly as it was found: a body left unclipped animates
    // nothing and the node snaps open a safety-timeout later.
    await mountTreeHost(page, { surface: 'standalone' });

    const heights = await page.evaluate(async () => {
      const harness = window.__w3aResizeHarness;
      if (!harness) throw new Error('harness missing');
      const body = () => harness.body;
      const samples: Array<{ px: number; clipped: boolean }> = [];
      const startedAt = performance.now();
      const done = new Promise<void>((resolve) => {
        const tick = () => {
          const element = body();
          samples.push({
            px: element.getBoundingClientRect().height,
            clipped: element.classList.contains('anim-h'),
          });
          if (performance.now() - startedAt < 400) requestAnimationFrame(tick);
          else resolve();
        };
        requestAnimationFrame(tick);
      });
      harness.summary.click();
      await done;
      return samples;
    });

    const finalPx = heights.at(-1)?.px ?? 0;
    expect(finalPx).toBeGreaterThan(0);
    // The body was clipped while it grew, and passed through the middle.
    const midway = heights.filter((s) => s.clipped && s.px > 0.5 && s.px < finalPx - 0.5);
    expect(midway.length).toBeGreaterThanOrEqual(1);
    expect((await snapshot(page)).open).toBe(true);
  });

  test('a standalone surface never pins', async ({ page }) => {
    await mountTreeHost(page, { surface: 'standalone' });

    await clickNode(page);
    await frames(page, 2);
    expect((await snapshot(page)).pinned).toBe(false);
    await expect.poll(async () => (await snapshot(page)).toggled, { timeout: 2_000 }).toBe(1);
  });

  test('a parent that never moves the box still lands the node', async ({ page }) => {
    const { closedPx } = await mountTreeHost(page, { surface: 'wallet-iframe' });

    await clickNode(page);
    await frames(page, 2);
    const pinned = await snapshot(page);
    expect(pinned.pinned).toBe(true);
    const deltaPx = pinned.begins[0].deltaCssPx;

    await expect.poll(async () => (await snapshot(page)).toggled, { timeout: 2_000 }).toBe(1);
    const settled = await snapshot(page);
    expect(settled.pinned).toBe(false);
    expect(settled.open).toBe(true);
    expect(settled.bodyPx).toBe(deltaPx);
    expect(settled.hostPx).toBe(closedPx + deltaPx);
  });
});

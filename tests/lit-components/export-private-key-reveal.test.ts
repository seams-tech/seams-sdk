import { expect, test, type Page } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { ensureComponentModule, mountComponent } from './harness';

const EXPORT_VIEWER_MODULE = '/sdk/export-private-key-viewer.js';
const EXPORT_VIEWER_TAG = 'w3a-export-key-viewer';
const PRIVATE_KEY = `0x${'1'.repeat(64)}`;

type ViewerSnapshot = {
  accentColor: string;
  copyDisabled: boolean;
  hasRippleTarget: boolean;
  innerHtml: string;
  rippleTargetText: string;
  tileAnimationName: string;
  tileColor: string;
  rippleTiles: number;
  text: string;
};

async function viewerSnapshot(page: Page): Promise<ViewerSnapshot> {
  return await page.evaluate(async (tagName) => {
    const viewer = document.querySelector(tagName) as HTMLElement & {
      updateComplete?: Promise<void>;
    };
    if (!viewer) throw new Error('export viewer not found');
    await viewer.updateComplete;
    const root = viewer.shadowRoot || viewer;
    const privateKeyField = Array.from(root.querySelectorAll('.field')).find(
      (field) => field.querySelector('.field-label')?.textContent?.trim() === 'Private Key',
    );
    if (!privateKeyField) throw new Error('private key field not found');
    const copyButton = privateKeyField.matches('button')
      ? (privateKeyField as HTMLButtonElement)
      : (privateKeyField.querySelector('button') as HTMLButtonElement | null);
    const rippleTarget = privateKeyField.querySelector('.private-key-ripple-target');
    const firstTile = privateKeyField.querySelector('.ripple-tile');
    const tileStyle = firstTile ? getComputedStyle(firstTile) : null;
    const accentProbe = document.createElement('span');
    accentProbe.style.backgroundColor = 'var(--w3a-colors-accent)';
    privateKeyField.append(accentProbe);
    const accentColor = getComputedStyle(accentProbe).backgroundColor;
    accentProbe.remove();
    return {
      accentColor,
      copyDisabled: copyButton?.disabled ?? true,
      hasRippleTarget: rippleTarget !== null,
      innerHtml: privateKeyField.innerHTML,
      rippleTargetText: rippleTarget?.textContent ?? '',
      rippleTiles: privateKeyField.querySelectorAll('.ripple-tile').length,
      tileAnimationName: tileStyle?.animationName ?? '',
      tileColor: tileStyle?.backgroundColor ?? '',
      text: privateKeyField.textContent ?? '',
    };
  }, EXPORT_VIEWER_TAG);
}

async function updateViewerToReady(page: Page): Promise<void> {
  await page.evaluate(
    async ({ tagName, privateKey }) => {
      const viewer = document.querySelector(tagName) as HTMLElement & {
        keys: Array<{
          scheme: 'secp256k1';
          label: string;
          publicKey: string;
          privateKey: string;
          address: string;
        }>;
        loading: boolean;
        updateComplete?: Promise<void>;
      };
      viewer.keys = [
        {
          scheme: 'secp256k1',
          label: 'EVM',
          publicKey: '0x02abcd',
          privateKey,
          address: '0x1234',
        },
      ];
      viewer.loading = false;
      await viewer.updateComplete;
    },
    { tagName: EXPORT_VIEWER_TAG, privateKey: PRIVATE_KEY },
  );
}

async function waitForPrivateKeyField(page: Page): Promise<void> {
  await page.waitForFunction((tagName) => {
    const viewer = document.querySelector(tagName);
    const root = viewer?.shadowRoot || viewer;
    return Array.from(root?.querySelectorAll('.field-label') ?? []).some(
      (label) => label.textContent?.trim() === 'Private Key',
    );
  }, EXPORT_VIEWER_TAG);
}

async function mountLoadingViewer(page: Page): Promise<void> {
  await mountComponent(page, {
    tagName: EXPORT_VIEWER_TAG,
    props: {
      theme: 'dark',
      variant: 'drawer',
      accountId: 'wallet-1',
      loading: true,
      keys: [
        {
          scheme: 'secp256k1',
          label: 'EVM',
          publicKey: '0x02abcd',
          privateKey: '',
          address: '0x1234',
        },
      ],
    },
  });
  await waitForPrivateKeyField(page);
}

async function mountReadyViewer(page: Page): Promise<void> {
  await mountComponent(page, {
    tagName: EXPORT_VIEWER_TAG,
    props: {
      theme: 'dark',
      variant: 'drawer',
      accountId: 'wallet-1',
      loading: false,
      keys: [
        {
          scheme: 'secp256k1',
          label: 'EVM',
          publicKey: '0x02abcd',
          privateKey: PRIVATE_KEY,
          address: '0x1234',
        },
      ],
    },
  });
  await waitForPrivateKeyField(page);
}

test.describe('Export private key tile reveal', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await ensureComponentModule(page, {
      modulePath: EXPORT_VIEWER_MODULE,
      tagName: EXPORT_VIEWER_TAG,
    });
  });

  test('ripples a tile field and settles before enabling Copy', async ({ page }) => {
    await mountLoadingViewer(page);

    const loading = await viewerSnapshot(page);
    expect(loading.text).not.toContain('Decrypting…');
    expect(loading.rippleTiles).toBe(128);
    expect(loading.hasRippleTarget).toBe(false);
    expect(loading.tileAnimationName).toBe('private-key-tile-ripple');
    expect(loading.tileColor).toBe(loading.accentColor);
    expect(loading.copyDisabled).toBe(true);

    await updateViewerToReady(page);

    const settling = await viewerSnapshot(page);
    expect(settling.rippleTiles).toBe(128);
    expect(settling.hasRippleTarget).toBe(true);
    expect(settling.rippleTargetText).toBe(`0x${'1'.repeat(20)}${'x'.repeat(24)}${'1'.repeat(20)}`);
    expect(settling.copyDisabled).toBe(true);
    expect(settling.innerHtml).not.toContain(PRIVATE_KEY);

    await expect
      .poll(async () => (await viewerSnapshot(page)).copyDisabled, {
        intervals: [25],
        timeout: 2_000,
      })
      .toBe(false);
    await expect.poll(async () => (await viewerSnapshot(page)).rippleTiles).toBe(0);
    const settled = await viewerSnapshot(page);
    expect(settled.copyDisabled).toBe(false);
    expect(settled.text).toContain(`0x${'1'.repeat(20)}${'x'.repeat(24)}${'1'.repeat(20)}`);
    expect(settled.innerHtml).not.toContain(PRIVATE_KEY);
  });

  test('uses a stable scaffold and settles immediately with reduced motion', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await mountLoadingViewer(page);

    const firstLoading = await viewerSnapshot(page);
    await page.waitForTimeout(150);
    const secondLoading = await viewerSnapshot(page);
    expect(firstLoading.innerHtml).toBe(secondLoading.innerHtml);
    expect(firstLoading.rippleTiles).toBe(128);
    expect(firstLoading.copyDisabled).toBe(true);

    await updateViewerToReady(page);

    const ready = await viewerSnapshot(page);
    expect(ready.rippleTiles).toBe(0);
    expect(ready.copyDisabled).toBe(false);
    expect(ready.innerHtml).not.toContain(PRIVATE_KEY);
  });

  test('cancels loading on error and leaves ready-on-mount keys static', async ({ page }) => {
    await mountLoadingViewer(page);
    await page.evaluate(async (tagName) => {
      const viewer = document.querySelector(tagName) as HTMLElement & {
        errorMessage: string;
        updateComplete?: Promise<void>;
      };
      viewer.errorMessage = 'Key preparation failed';
      await viewer.updateComplete;
    }, EXPORT_VIEWER_TAG);

    const failed = await viewerSnapshot(page);
    expect(failed.rippleTiles).toBe(0);
    expect(failed.copyDisabled).toBe(true);

    await mountReadyViewer(page);

    const ready = await viewerSnapshot(page);
    expect(ready.rippleTiles).toBe(0);
    expect(ready.copyDisabled).toBe(false);
    expect(ready.innerHtml).not.toContain(PRIVATE_KEY);
  });

  test('copies from the full key field and transitions the copy icon to a check', async ({
    page,
  }) => {
    await mountReadyViewer(page);
    await page.evaluate(() => {
      Object.defineProperty(navigator, 'clipboard', {
        configurable: true,
        value: { writeText: async () => undefined },
      });
    });

    const state = await page.evaluate(async (tagName) => {
      const viewer = document.querySelector(tagName) as HTMLElement & {
        updateComplete?: Promise<void>;
      };
      const root = viewer.shadowRoot || viewer;
      const privateKeyField = Array.from(root.querySelectorAll('.field')).find(
        (field) => field.querySelector('.field-label')?.textContent?.trim() === 'Private Key',
      ) as HTMLButtonElement | undefined;
      if (!privateKeyField) throw new Error('private key field not found');

      const copied = new Promise<void>((resolve) => {
        viewer.addEventListener('lit-copy', () => resolve(), { once: true });
      });
      privateKeyField.click();
      await copied;
      await viewer.updateComplete;
      return {
        ariaLabel: privateKeyField.getAttribute('aria-label'),
        copied: privateKeyField.classList.contains('copied'),
        hasCheckIcon: privateKeyField.querySelector('.copy-icon-check') !== null,
        hasCopyIcon: privateKeyField.querySelector('.copy-icon-copy') !== null,
        isWholeFieldButton: privateKeyField.matches('button.copy-field'),
      };
    }, EXPORT_VIEWER_TAG);

    expect(state).toEqual({
      ariaLabel: 'Private key copied',
      copied: true,
      hasCheckIcon: true,
      hasCopyIcon: true,
      isWholeFieldButton: true,
    });
  });
});

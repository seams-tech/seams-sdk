import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

test.describe('export viewer host cleanup', () => {
  test('removeExportViewerHostIfPresent removes a mounted export viewer host', async ({ page }) => {
    await setupBasicPasskeyTest(page);

    const result = await page.evaluate(async () => {
      const mod = await import(
        new URL(
          '/_test-sdk/esm/react/core/signingEngine/uiConfirm/ui/export-viewer-host.js',
          window.location.origin,
        ).toString()
      );

      const staleHost = document.createElement('w3a-export-viewer-iframe');
      document.body.appendChild(staleHost);

      const before = !!document.querySelector('w3a-export-viewer-iframe');
      mod.removeExportViewerHostIfPresent();
      const after = !!document.querySelector('w3a-export-viewer-iframe');

      return { before, after };
    });

    expect(result.before).toBe(true);
    expect(result.after).toBe(false);
  });

  test('export viewer session state clears after host removal', async ({ page }) => {
    await setupBasicPasskeyTest(page);

    const result = await page.evaluate(async () => {
      const mod = await import(
        new URL(
          '/_test-sdk/esm/react/core/signingEngine/uiConfirm/ui/export-viewer-host.js',
          window.location.origin,
        ).toString()
      );

      const sessionId = 'near-ed25519-export-session-test';
      await mod.upsertExportViewerHost({
        theme: 'dark',
        variant: 'modal',
        accountId: 'alice.testnet',
        sessionId,
        publicKey: 'ed25519:test-public-key',
        keys: [
          {
            scheme: 'ed25519',
            label: 'NEAR private key',
            publicKey: 'ed25519:test-public-key',
            privateKey: '',
          },
        ],
        loading: true,
        surfaceMeasurementBinding: { kind: 'disabled' },
      });

      const before = mod.isExportViewerSessionOpen(sessionId);
      const host = document.querySelector('w3a-export-viewer-iframe');
      const standaloneSurface = host?.getAttribute('data-w3a-export-surface');
      await mod.upsertExportViewerHost({
        theme: 'dark',
        variant: 'drawer',
        accountId: 'alice.testnet',
        sessionId,
        loading: true,
        surfaceMeasurementBinding: {
          kind: 'wallet_iframe',
          requestId: 'request-a',
          postMeasurement: () => undefined,
        },
      });
      const walletDrawerSurface = host?.getAttribute('data-w3a-export-surface');
      await mod.upsertExportViewerHost({
        theme: 'dark',
        variant: 'modal',
        accountId: 'alice.testnet',
        sessionId,
        loading: true,
        surfaceMeasurementBinding: {
          kind: 'wallet_iframe',
          requestId: 'request-b',
          postMeasurement: () => undefined,
        },
      });
      const walletModalSurface = host?.getAttribute('data-w3a-export-surface');
      mod.removeExportViewerHostIfPresent();
      const after = mod.isExportViewerSessionOpen(sessionId);
      const hostExists = !!document.querySelector('w3a-export-viewer-iframe');

      return {
        before,
        after,
        hostExists,
        standaloneSurface,
        walletDrawerSurface,
        walletModalSurface,
      };
    });

    expect(result.before).toBe(true);
    expect(result.after).toBe(false);
    expect(result.hostExists).toBe(false);
    expect(result.standaloneSurface).toBe('standalone');
    expect(result.walletDrawerSurface).toBe('standalone');
    expect(result.walletModalSurface).toBe('wallet-iframe');
  });

  test('export drawer keeps a fixed sheet width while content and open state change', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page);

    const result = await page.evaluate(async () => {
      const mod = await import(
        new URL(
          '/_test-sdk/esm/react/core/signingEngine/uiConfirm/ui/export-viewer-host.js',
          window.location.origin,
        ).toString()
      );

      await mod.upsertExportViewerHost({
        theme: 'light',
        variant: 'drawer',
        accountId: 'alice.testnet',
        publicKey: 'ed25519:test-public-key',
        keys: [
          {
            scheme: 'ed25519',
            label: 'NEAR private key',
            publicKey: 'ed25519:test-public-key',
            privateKey: 'ed25519:test-private-key',
          },
        ],
        surfaceMeasurementBinding: {
          kind: 'wallet_iframe',
          requestId: 'export-drawer-request',
          postMeasurement: () => undefined,
        },
      });

      await new Promise<void>((resolve, reject) => {
        const startedAt = performance.now();
        const check = () => {
          const host = document.querySelector('w3a-export-viewer-iframe');
          const iframe = host?.shadowRoot?.querySelector('iframe') as HTMLIFrameElement | null;
          const drawer = iframe?.contentDocument?.querySelector('w3a-drawer');
          const innerDrawer = drawer?.querySelector('.drawer');
          if (drawer && innerDrawer) {
            resolve();
            return;
          }
          if (performance.now() - startedAt > 3_000) {
            reject(new Error('export drawer did not mount inside iframe'));
            return;
          }
          setTimeout(check, 20);
        };
        check();
      });

      const host = document.querySelector('w3a-export-viewer-iframe');
      const iframe = host?.shadowRoot?.querySelector('iframe') as HTMLIFrameElement | null;
      const iframeDocument = iframe.contentDocument;
      const drawer = iframeDocument?.querySelector('w3a-drawer');
      const innerDrawer = drawer?.querySelector('.drawer') as HTMLElement | null;
      if (!iframeDocument || !drawer || !innerDrawer) {
        throw new Error('export drawer DOM is incomplete');
      }

      const viewport = { width: window.innerWidth, height: window.innerHeight };
      const hostRect = (host as HTMLElement).getBoundingClientRect();
      const iframeRect = iframe.getBoundingClientRect();

      const widthWhileOpen = innerDrawer.getBoundingClientRect().width;
      drawer.open = false;
      await new Promise((resolve) => setTimeout(resolve, 300));
      const widthWhileClosed = innerDrawer.getBoundingClientRect().width;
      drawer.open = true;
      await new Promise((resolve) => setTimeout(resolve, 300));
      const widthAfterReopen = innerDrawer.getBoundingClientRect().width;

      await mod.upsertExportViewerHost({
        theme: 'light',
        variant: 'drawer',
        accountId: 'alice.testnet',
        publicKey: 'ed25519:test-public-key',
        keys: [
          {
            scheme: 'ed25519',
            label: 'NEAR private key',
            publicKey: 'ed25519:test-public-key',
            privateKey: 'ed25519:test-private-key',
          },
          {
            scheme: 'ed25519',
            label: 'Second NEAR private key',
            publicKey: 'ed25519:second-test-public-key',
            privateKey: 'ed25519:second-test-private-key',
          },
        ],
        surfaceMeasurementBinding: {
          kind: 'wallet_iframe',
          requestId: 'export-drawer-content-update',
          postMeasurement: () => undefined,
        },
      });
      await new Promise((resolve) => setTimeout(resolve, 300));
      const widthAfterContentUpdate = innerDrawer.getBoundingClientRect().width;

      return {
        hostSurface: (host as HTMLElement).getAttribute('data-w3a-export-surface'),
        surface: drawer.getAttribute('data-w3a-export-surface'),
        open: drawer.hasAttribute('open'),
        widthWhileOpen,
        widthWhileClosed,
        widthAfterReopen,
        widthAfterContentUpdate,
        viewport,
        hostRect: {
          width: hostRect.width,
          height: hostRect.height,
          top: hostRect.top,
          left: hostRect.left,
        },
        iframeRect: {
          width: iframeRect.width,
          height: iframeRect.height,
          top: iframeRect.top,
          left: iframeRect.left,
        },
      };
    });

    expect(result.hostSurface).toBe('standalone');
    expect(result.surface).toBe('standalone');
    expect(result.open).toBe(true);
    expect(result.hostRect.width).toBeCloseTo(result.viewport.width, 0);
    expect(result.hostRect.height).toBeCloseTo(result.viewport.height, 0);
    expect(result.hostRect.top).toBeCloseTo(0, 0);
    expect(result.hostRect.left).toBeCloseTo(0, 0);
    expect(result.iframeRect.width).toBeCloseTo(result.viewport.width, 0);
    expect(result.iframeRect.height).toBeCloseTo(result.viewport.height, 0);
    expect(result.iframeRect.top).toBeCloseTo(0, 0);
    expect(result.iframeRect.left).toBeCloseTo(0, 0);
    expect(result.widthWhileOpen).toBeGreaterThan(0);
    expect(result.widthWhileClosed).toBeCloseTo(result.widthWhileOpen, 0);
    expect(result.widthAfterReopen).toBeCloseTo(result.widthWhileOpen, 0);
    expect(result.widthAfterContentUpdate).toBeCloseTo(result.widthWhileOpen, 0);
  });

  test('export drawer handle drag moves the nested sheet', async ({ page }) => {
    await setupBasicPasskeyTest(page);

    const result = await page.evaluate(async () => {
      const mod = await import(
        new URL(
          '/_test-sdk/esm/react/core/signingEngine/uiConfirm/ui/export-viewer-host.js',
          window.location.origin,
        ).toString()
      );
      await mod.upsertExportViewerHost({
        theme: 'light',
        variant: 'drawer',
        accountId: 'alice.testnet',
        publicKey: 'ed25519:test-public-key',
        keys: [
          {
            scheme: 'ed25519',
            label: 'NEAR private key',
            publicKey: 'ed25519:test-public-key',
            privateKey: 'ed25519:test-private-key',
          },
        ],
        surfaceMeasurementBinding: {
          kind: 'wallet_iframe',
          requestId: 'export-drawer-drag',
          postMeasurement: () => undefined,
        },
      });

      const startedAt = performance.now();
      let drawer: HTMLElement | null = null;
      let handle: HTMLElement | null = null;
      let sheet: HTMLElement | null = null;
      while (performance.now() - startedAt < 3_000) {
        const iframe = document
          .querySelector('w3a-export-viewer-iframe')
          ?.shadowRoot?.querySelector('iframe') as HTMLIFrameElement | null;
        drawer = iframe?.contentDocument?.querySelector('w3a-drawer') as HTMLElement | null;
        handle = drawer?.querySelector('.handle') as HTMLElement | null;
        sheet = drawer?.querySelector('.drawer') as HTMLElement | null;
        const viewportHeight = iframe?.contentDocument?.documentElement.clientHeight ?? 0;
        const handleRect = handle?.getBoundingClientRect();
        if (
          drawer?.hasAttribute('open') &&
          handle &&
          sheet &&
          viewportHeight > 0 &&
          !!handleRect &&
          handleRect.top >= 0 &&
          handleRect.bottom <= viewportHeight
        ) {
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      if (!drawer || !handle || !sheet) throw new Error('export drawer did not mount');
      await new Promise((resolve) => setTimeout(resolve, 300));

      const iframe = document
        .querySelector('w3a-export-viewer-iframe')
        ?.shadowRoot?.querySelector('iframe') as HTMLIFrameElement | null;
      if (!iframe) throw new Error('export drawer iframe did not mount');
      const rect = handle.getBoundingClientRect();
      const before = getComputedStyle(sheet).transform;
      const iframeRect = iframe.getBoundingClientRect();
      return {
        before,
        point: {
          x: iframeRect.left + rect.left + rect.width / 2,
          y: iframeRect.top + rect.top + rect.height / 2,
        },
      };
    });

    await page.mouse.move(result.point.x, result.point.y);
    await page.mouse.down();
    await page.mouse.move(result.point.x, result.point.y + 80, { steps: 2 });
    const during = await page.evaluate(() => {
      const iframe = document
        .querySelector('w3a-export-viewer-iframe')
        ?.shadowRoot?.querySelector('iframe') as HTMLIFrameElement | null;
      const drawer = iframe?.contentDocument?.querySelector('w3a-drawer') as HTMLElement | null;
      const sheet = iframe?.contentDocument?.querySelector('.drawer') as HTMLElement | null;
      if (!drawer || !sheet) return null;
      const sheetStyle = getComputedStyle(sheet);
      return {
        transform: sheetStyle.transform,
        open: drawer.hasAttribute('open'),
        loading: Boolean((drawer as any).loading),
        dragging: sheet.classList.contains('dragging'),
        dragTranslate: sheetStyle.getPropertyValue('--w3a-drawer__drag-translate').trim(),
      };
    });
    await page.mouse.up();
    expect(during).not.toBeNull();
    expect(during?.open).toBe(true);
    expect(during?.loading).not.toBe('true');
    expect(during?.dragging).toBe(true);
    expect(during?.dragTranslate).not.toBe('');
    expect(during?.transform).not.toBe(result.before);
  });
});

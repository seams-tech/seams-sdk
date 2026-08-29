import { test, expect } from '@playwright/test';
import { buildWalletServiceHtml as buildWalletHostServiceHtml } from '@/plugins/plugin-utils';
import { injectImportMap } from '../setup/bootstrap';
import { buildWalletServiceHtml, initRouter, registerWalletServiceRoute } from './harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service';

function buildHostPortCloseProbeHtml(): string {
  return buildWalletHostServiceHtml('/_test-sdk/esm/sdk').replace(
    '</body>',
    `<script>
      (() => {
        const close = MessagePort.prototype.close;
        MessagePort.prototype.close = function () {
          window.parent.postMessage({ type: 'TEST_HOST_PORT_CLOSED' }, '*');
          return close.call(this);
        };
      })();
    </script></body>`,
  );
}

test.describe('Wallet iframe handshake', () => {
  test.beforeEach(async ({ page }) => {
    page.on('console', (msg) => {
      console.log(`[browser] ${msg.type().toUpperCase()}: ${msg.text()}`);
    });
    const configured = String(process.env.W3A_TEST_FRONTEND_URL || '').trim();
    const url =
      configured ||
      (process.env.NO_CADDY === '1' || process.env.CI === '1'
        ? 'http://localhost:4004'
        : 'https://example.localhost');
    await page.goto(url);
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  // verifies the CONNECT→READY handshake succeeds and exposes a ready router
  test('resolves when the wallet host replies with READY', async ({ page }) => {
    await registerWalletServiceRoute(page, buildWalletServiceHtml(), WALLET_SERVICE_ROUTE);
    await initRouter(page, { walletOrigin: WALLET_ORIGIN });

    const readyState = await page.evaluate(async () => {
      const router = (window as any).__walletRouter;
      await router.init();
      return router.isReady();
    });

    expect(readyState).toBe(true);

    const iframeAttributes = await page.evaluate(() => {
      const iframeEl =
        document.querySelector('iframe[data-w3a-owner="tests"]') ||
        document.querySelector('iframe');
      if (!iframeEl) return null;
      const cs = window.getComputedStyle(iframeEl as HTMLIFrameElement);
      return {
        src: iframeEl.getAttribute('src'),
        allow: iframeEl.getAttribute('allow'),
        sandbox: iframeEl.getAttribute('sandbox'),
        pointerEvents: cs.pointerEvents,
        opacity: cs.opacity,
      };
    });

    expect(iframeAttributes?.src).toBe(new URL('/wallet-service', WALLET_ORIGIN).toString());
    expect(iframeAttributes?.allow).toContain('publickey-credentials-get');
    expect(iframeAttributes?.sandbox).toBeNull();
    expect(iframeAttributes?.pointerEvents).toBe('none');
    expect(iframeAttributes?.opacity).toBe('0');
  });

  // asserts init() times out if the wallet host never acknowledges READY
  test('rejects when READY never arrives within the timeout budget', async ({ page }) => {
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ respondReady: false }),
      WALLET_SERVICE_ROUTE,
    );
    await initRouter(page, { walletOrigin: WALLET_ORIGIN, connectTimeoutMs: 200 });

    const result = await page.evaluate(async () => {
      const router = (window as any).__walletRouter;
      try {
        await router.init();
        return { ok: true };
      } catch (err: any) {
        return { ok: false, message: err?.message };
      }
    });

    expect(result.ok).toBe(false);
    expect(result.message).toMatch(
      /^\[IframeTransport\] Wallet iframe READY timed out after \d+ms$/,
    );

    const readyState = await page.evaluate(() => {
      const router = (window as any).__walletRouter;
      return router.isReady();
    });

    expect(readyState).toBe(false);
  });

  test('rejects when READY advertises a mismatched protocol version', async ({ page }) => {
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({
        protocolVersion: '1.0.0',
        expectedConnectProtocolVersion: null,
      }),
      WALLET_SERVICE_ROUTE,
    );
    await initRouter(page, { walletOrigin: WALLET_ORIGIN, connectTimeoutMs: 1000 });

    const result = await page.evaluate(async () => {
      const router = (window as any).__walletRouter;
      try {
        await router.init();
        return { ok: true };
      } catch (err: any) {
        return { ok: false, code: err?.code, name: err?.name, message: err?.message };
      }
    });

    expect(result.ok).toBe(false);
    expect(result.code).toBe('WALLET_IFRAME_PROTOCOL_VERSION_MISMATCH');
    expect(result.name).toBe('WalletIframeProtocolVersionMismatchError');
    expect(result.message).toContain('expected 2.0.0, received 1.0.0');

    const readyState = await page.evaluate(() => {
      const router = (window as any).__walletRouter;
      return router.isReady();
    });

    expect(readyState).toBe(false);
  });

  test('rejects when CONNECT advertises an older host SDK protocol version', async ({ page }) => {
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ expectedConnectProtocolVersion: '3.0.0' }),
      WALLET_SERVICE_ROUTE,
    );
    await initRouter(page, { walletOrigin: WALLET_ORIGIN, connectTimeoutMs: 1000 });

    const result = await page.evaluate(async () => {
      const router = (window as any).__walletRouter;
      try {
        await router.init();
        return { ok: true };
      } catch (err: any) {
        return {
          ok: false,
          code: err?.code,
          name: err?.name,
          message: err?.message,
          receivedProtocolVersion: err?.receivedProtocolVersion,
        };
      }
    });

    expect(result.ok).toBe(false);
    expect(result.code).toBe('WALLET_IFRAME_PROTOCOL_VERSION_MISMATCH');
    expect(result.name).toBe('WalletIframeProtocolVersionMismatchError');
    expect(result.message).toContain('expected 2.0.0, received 2.0.0');
    expect(result.receivedProtocolVersion).toBe('2.0.0');

    const readyState = await page.evaluate(() => {
      const router = (window as any).__walletRouter;
      return router.isReady();
    });

    expect(readyState).toBe(false);
  });

  test('closes the transferred port after rejecting a mismatched CONNECT', async ({ page }) => {
    await injectImportMap(page);
    await registerWalletServiceRoute(page, buildHostPortCloseProbeHtml(), WALLET_SERVICE_ROUTE);

    const portClosed = await page.evaluate(
      async ({ walletOrigin }) => {
        const iframe = document.createElement('iframe');
        iframe.src = `${walletOrigin}/wallet-service`;
        iframe.style.display = 'none';
        document.body.appendChild(iframe);
        await new Promise<void>((resolve) => {
          iframe.addEventListener('load', () => resolve(), { once: true });
        });

        const result = await new Promise<boolean>((resolve) => {
          let timeout: number | undefined;
          const onMessage = (event: MessageEvent): void => {
            if (
              event.source !== iframe.contentWindow ||
              event.data?.type !== 'TEST_HOST_PORT_CLOSED'
            ) {
              return;
            }
            if (timeout !== undefined) window.clearTimeout(timeout);
            window.removeEventListener('message', onMessage);
            resolve(true);
          };
          window.addEventListener('message', onMessage);
          timeout = window.setTimeout(() => {
            window.removeEventListener('message', onMessage);
            resolve(false);
          }, 3_000);

          const channel = new MessageChannel();
          channel.port1.start();
          iframe.contentWindow?.postMessage(
            { type: 'CONNECT', payload: { protocolVersion: '1.0.0' } },
            walletOrigin,
            [channel.port2],
          );
        });
        iframe.remove();
        return result;
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    expect(portClosed).toBe(true);
  });
});

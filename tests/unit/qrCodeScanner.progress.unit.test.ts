import { expect, test, type Page } from '@playwright/test';
import path from 'node:path';
import { injectImportMap } from '../setup/bootstrap';

const SCANNER_PATH = '/_test-sdk/esm/react/components/QRCodeScanner.js';
const CONTEXT_PATH = '/_test-sdk/esm/react/context/index.js';
const CAMERA_PATH = '/_test-sdk/esm/react/hooks/useQRCamera.js';
const SCANNER_CSS_PATH = path.resolve(
  process.cwd(),
  '../packages/wallet/dist/esm/react/components/QRCodeScanner.css',
);

const MOCK_CONTEXT_MODULE = `
export function useSeams() {
  const harness = globalThis.__qrScannerHarness;
  return {
    cancelDeviceLinking: () => harness.cancelDeviceLinking(),
    seams: {
      devices: {
        scanAndLinkDevice: (...args) => harness.scanAndLinkDevice(...args),
      },
    },
  };
}
`;

const MOCK_CAMERA_MODULE = `
import { useCallback, useEffect, useRef, useState } from 'react';

export const QRScanMode = { CAMERA: 'camera', FILE: 'file', AUTO: 'auto' };

export function useQRCamera(options) {
  const optionsRef = useRef(options);
  optionsRef.current = options;
  const [isScanning, setIsScanning] = useState(Boolean(options.isOpen));
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const stopScanning = useCallback(() => {
    globalThis.__qrScannerHarness.stopCalls += 1;
    setIsScanning(false);
  }, []);

  useEffect(() => {
    const harness = globalThis.__qrScannerHarness;
    harness.detect = (payload) => optionsRef.current.onQRDetected?.(payload);
    return () => {
      if (harness.detect) harness.detect = null;
    };
  }, []);

  useEffect(() => {
    setIsScanning(Boolean(options.isOpen));
  }, [options.isOpen]);

  return {
    isScanning,
    isProcessing: isScanning,
    error: null,
    cameras: [],
    selectedCamera: '',
    scanMode: QRScanMode.CAMERA,
    isFrontCamera: false,
    scanDurationMs: 0,
    videoRef,
    canvasRef,
    startScanning: async () => undefined,
    stopScanning,
    handleCameraChange: () => undefined,
    setScanMode: () => undefined,
    setError: () => undefined,
    getOptimalFacingMode: () => 'environment',
  };
}
`;

type HarnessState = {
  cancelCalls: number;
  closeCalls: number;
  detect: ((payload: unknown) => unknown) | null;
  cancelDeviceLinking: () => Promise<void>;
  scanAndLinkDevice: (
    payload: unknown,
    options: { onEvent?: (event: unknown) => void },
  ) => Promise<void>;
  resolveScan?: () => void;
  rejectScan?: (reason?: unknown) => void;
  scanCalls: number;
  scanOptions: { onEvent?: (event: unknown) => void } | null;
  stopCalls: number;
};

declare global {
  var __qrScannerHarness: HarnessState;
}

async function installScannerMocks(page: Page): Promise<void> {
  await page.route(`**${CONTEXT_PATH}`, (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/javascript',
      body: MOCK_CONTEXT_MODULE,
    }),
  );
  await page.route(`**${CAMERA_PATH}`, (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/javascript',
      body: MOCK_CAMERA_MODULE,
    }),
  );
}

async function createHarness(page: Page): Promise<void> {
  await page.evaluate(() => {
    const harness: HarnessState = {
      cancelCalls: 0,
      closeCalls: 0,
      detect: null,
      scanCalls: 0,
      scanOptions: null,
      stopCalls: 0,
      cancelDeviceLinking: async () => undefined,
      scanAndLinkDevice: async () => undefined,
    };
    harness.scanAndLinkDevice = (
      _payload: unknown,
      options: { onEvent?: (event: unknown) => void },
    ) => {
      harness.scanCalls += 1;
      harness.scanOptions = options;
      return new Promise<void>((resolve, reject) => {
        harness.resolveScan = resolve;
        harness.rejectScan = reject;
      });
    };
    harness.cancelDeviceLinking = () => {
      harness.cancelCalls += 1;
      return Promise.resolve();
    };
    globalThis.__qrScannerHarness = harness;
  });
}

async function mountScanner(page: Page): Promise<void> {
  await page.evaluate(async (scannerPath) => {
    const React = await import('react');
    const ReactDOMClient = await import('react-dom/client');
    const ReactDOM = await import('react-dom');
    const scannerModule = await import(scannerPath);
    const Scanner = scannerModule.default;
    const mount = document.createElement('div');
    mount.id = 'qr-scanner-progress-test';
    document.body.appendChild(mount);

    const opener = document.createElement('button');
    opener.id = 'qr-scanner-opener';
    opener.type = 'button';
    opener.textContent = 'Open scanner';
    document.body.insertBefore(opener, mount);
    opener.focus();

    const App = () => {
      const [isOpen, setIsOpen] = React.useState(true);
      return React.createElement(
        React.Fragment,
        null,
        React.createElement(Scanner, {
          isOpen,
          onClose: () => {
            globalThis.__qrScannerHarness.closeCalls += 1;
            setIsOpen(false);
          },
        }),
      );
    };

    const root = ReactDOMClient.createRoot(mount);
    ReactDOM.flushSync(() => {
      root.render(React.createElement(App, null));
    });
  }, SCANNER_PATH);
}

async function detectValidQr(page: Page): Promise<void> {
  await page.evaluate(() => {
    void globalThis.__qrScannerHarness.detect?.({
      linkSessionId: 'session-1',
      purpose: 'link_device',
      issuedAtMs: 1,
      expiresAtMs: 2,
      ownerWalletId: 'wallet-1',
    });
  });
  await expect.poll(() => page.evaluate(() => globalThis.__qrScannerHarness.scanCalls)).toBe(1);
}

test.describe('QRCodeScanner progress state', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('about:blank');
    await injectImportMap(page);
    await installScannerMocks(page);
    await createHarness(page);
    await page.addStyleTag({ path: SCANNER_CSS_PATH });
    await mountScanner(page);
    await expect(page.locator('.qr-scanner-modal')).toBeVisible();
  });

  test('morphs into a focused progress card after scanning', async ({ page }) => {
    await detectValidQr(page);

    await expect(page.getByRole('status')).toHaveText('Continue linking on your other device.');
    await expect(page.getByRole('button', { name: 'Cancel linking' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Minimize' })).toHaveCount(0);
    await expect(page.locator('.qr-scanner-progress-dots span')).toHaveCount(3);
    await expect(page.locator('video')).toHaveCount(0);
    await expect(page.locator('.qr-scanner-modal')).toHaveAttribute('role', 'region');
    await expect(page.locator('#qr-scanner-progress-title')).toBeFocused();

    const stopCalls = await page.evaluate(() => globalThis.__qrScannerHarness.stopCalls);
    expect(stopCalls).toBeGreaterThan(0);
  });

  test('cancel linking invokes owner abort and returns focus to the opener', async ({ page }) => {
    await page.evaluate(() => {
      document.documentElement.style.setProperty('--w3a-wallet-overlay-z', '100');
      const walletIframeOverlay = document.createElement('div');
      walletIframeOverlay.id = 'wallet-iframe-overlay-test-double';
      Object.assign(walletIframeOverlay.style, {
        position: 'fixed',
        inset: '0',
        zIndex: '100',
      });
      document.body.appendChild(walletIframeOverlay);
    });
    await detectValidQr(page);
    const cancelButton = page.getByRole('button', { name: 'Cancel linking' });
    await expect(cancelButton).toBeVisible();

    const cancelButtonReceivesPointerInput = await cancelButton.evaluate((button) => {
      const bounds = button.getBoundingClientRect();
      const hit = document.elementFromPoint(
        bounds.left + bounds.width / 2,
        bounds.top + bounds.height / 2,
      );
      return hit === button || button.contains(hit);
    });
    expect(cancelButtonReceivesPointerInput).toBe(true);

    await cancelButton.click();
    await expect(page.locator('.qr-scanner-modal')).toHaveCount(0);
    await expect(page.locator('#qr-scanner-opener')).toBeFocused();

    const state = await page.evaluate(() => ({
      cancelCalls: globalThis.__qrScannerHarness.cancelCalls,
      closeCalls: globalThis.__qrScannerHarness.closeCalls,
    }));
    expect(state.cancelCalls).toBe(1);
    expect(state.closeCalls).toBe(1);
  });

  test('completion settles the scanner and returns focus to the opener', async ({ page }) => {
    await detectValidQr(page);
    await expect(page.getByText('Continue linking on your other device.')).toBeVisible();

    await page.evaluate(() => {
      const harness = globalThis.__qrScannerHarness;
      harness.scanOptions?.onEvent?.({
        version: 2,
        flow: 'link_device',
        step: 2,
        phase: 'link_device.qr.scan.started',
        status: 'succeeded',
        message: 'Device linked',
        flowId: 'flow-1',
        walletId: 'wallet-1',
        data: { enrollmentId: 'enrollment-1' },
      });
      harness.resolveScan?.();
    });

    await expect(page.locator('.qr-scanner-modal')).toHaveCount(0);
    await expect(page.locator('#qr-scanner-opener')).toBeFocused();
    await expect.poll(() => page.evaluate(() => globalThis.__qrScannerHarness.closeCalls)).toBe(1);
  });

  test('linking errors settle the scanner and return focus to the opener', async ({ page }) => {
    await detectValidQr(page);
    await expect(page.getByText('Continue linking on your other device.')).toBeVisible();

    await page.evaluate(() => {
      globalThis.__qrScannerHarness.rejectScan?.(new Error('Linking failed'));
    });

    await expect(page.locator('.qr-scanner-modal')).toHaveCount(0);
    await expect(page.locator('#qr-scanner-opener')).toBeFocused();
    await expect.poll(() => page.evaluate(() => globalThis.__qrScannerHarness.closeCalls)).toBe(1);
  });

  test('an expired session stays visible and can restart scanning', async ({ page }) => {
    await detectValidQr(page);

    await page.evaluate(() => {
      globalThis.__qrScannerHarness.scanOptions?.onEvent?.({
        version: 2,
        flow: 'link_device',
        step: 0,
        phase: 'link_device.failed',
        status: 'failed',
        message: 'Device-link session expired',
        flowId: 'flow-1',
        error: {
          code: 'SESSION_EXPIRED',
          message: 'Device-link session expired',
          retryable: false,
        },
      });
      globalThis.__qrScannerHarness.resolveScan?.();
    });

    await expect(page.getByRole('heading', { name: 'Linking expired' })).toBeVisible();
    await expect(
      page.getByText('This linking request expired. Scan the QR code again to retry.'),
    ).toBeVisible();
    await expect(page.locator('.qr-scanner-modal')).toBeVisible();
    await expect.poll(() => page.evaluate(() => globalThis.__qrScannerHarness.closeCalls)).toBe(0);

    await page.getByRole('button', { name: 'Try again' }).click();
    await expect(page.getByText('Position the QR code within the frame')).toBeVisible();
  });
});

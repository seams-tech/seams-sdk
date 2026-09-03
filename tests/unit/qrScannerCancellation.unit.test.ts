import { test, expect, type Page } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';

/**
 * Closing the Link Device scanner tears the video element down under the
 * pending `play()`, so the browser rejects it with an AbortError whose message
 * is about the media element ("The play() request was interrupted by a new load
 * request. https://goo.gl/LdLk22"). That is the user's own cancellation and
 * must not reach them as a device-linking failure.
 */
const QR_SCANNER_PATH = '/_test-sdk/esm/react/utils/qrScanner.js';

type ScannerProbeResult = {
  readonly errors: readonly string[];
  readonly state: string;
  readonly stoppedTracks: number;
};

/**
 * `srcObject` rejects anything that is not a real MediaStream, and `play()`
 * needs decoded media, so both are replaced with harness-controlled stand-ins.
 * The camera is represented by its only observable behaviour here: tracks that
 * record being stopped.
 */
async function installCameraHarness(page: Page): Promise<void> {
  await page.evaluate(() => {
    const harness = {
      stoppedTracks: 0,
      rejectPlay: (_reason: unknown) => {},
      resolveCamera: () => {},
      getUserMediaError: null as unknown,
      holdCamera: false,
    };
    (globalThis as any).__qrCameraHarness = harness;

    Object.defineProperty(HTMLMediaElement.prototype, 'srcObject', {
      configurable: true,
      writable: true,
      value: null,
    });
    HTMLMediaElement.prototype.play = () =>
      new Promise<void>((_resolve, reject) => {
        harness.rejectPlay = reject;
      });

    const track = () => ({
      stop: () => {
        harness.stoppedTracks += 1;
      },
    });
    (navigator as any).mediaDevices = {
      enumerateDevices: async () => [],
      getUserMedia: async () => {
        if (harness.getUserMediaError) throw harness.getUserMediaError;
        if (harness.holdCamera) {
          await new Promise<void>((resolve) => {
            harness.resolveCamera = resolve;
          });
        }
        return { getTracks: () => [track()] };
      },
    };
  });
}

test.describe('QR scanner cancellation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('about:blank');
    await injectImportMap(page);
    await installCameraHarness(page);
  });

  test('closing the scanner while the camera starts reports no error', async ({ page }) => {
    const result = await page.evaluate<ScannerProbeResult, string>(async (modulePath) => {
      const harness = (globalThis as any).__qrCameraHarness;
      const { ScanQRCodeFlow } = (await import(modulePath)) as any;

      const errors: string[] = [];
      const flow = new ScanQRCodeFlow({ timeout: 0 }, { onError: (e: Error) => errors.push(e.message) });

      const started = flow.startQRScanner();
      await new Promise((resolve) => setTimeout(resolve, 0));

      // The user closes the scanner while play() is still pending.
      flow.stop();
      harness.rejectPlay(
        new DOMException(
          'The play() request was interrupted by a new load request. https://goo.gl/LdLk22',
          'AbortError',
        ),
      );
      await started;

      return { errors, state: flow.getState().state, stoppedTracks: harness.stoppedTracks };
    }, QR_SCANNER_PATH);

    expect(result.errors).toEqual([]);
    expect(result.state).toBe('cancelled');
    expect(result.stoppedTracks).toBeGreaterThan(0);
  });

  test('cancelling before the camera resolves still releases the stream', async ({ page }) => {
    const result = await page.evaluate<ScannerProbeResult, string>(async (modulePath) => {
      const harness = (globalThis as any).__qrCameraHarness;
      harness.holdCamera = true;
      const { ScanQRCodeFlow } = (await import(modulePath)) as any;

      const errors: string[] = [];
      const flow = new ScanQRCodeFlow({ timeout: 0 }, { onError: (e: Error) => errors.push(e.message) });

      const started = flow.startQRScanner();
      void started.catch(() => {});
      await new Promise((resolve) => setTimeout(resolve, 0));

      // Closed while the permission prompt is still up: the stream arrives with
      // nobody waiting for it and must not leave the camera light on.
      flow.stop();
      harness.resolveCamera();
      // A start that keeps going here parks on the stubbed play() forever, so
      // bound the wait and let the assertions report what actually happened.
      await Promise.race([started, new Promise((resolve) => setTimeout(resolve, 250))]);

      return { errors, state: flow.getState().state, stoppedTracks: harness.stoppedTracks };
    }, QR_SCANNER_PATH);

    expect(result.errors).toEqual([]);
    expect(result.state).toBe('cancelled');
    expect(result.stoppedTracks).toBe(1);
  });

  test('a denied camera reports a human sentence, not browser debugging text', async ({ page }) => {
    const result = await page.evaluate<ScannerProbeResult, string>(async (modulePath) => {
      const harness = (globalThis as any).__qrCameraHarness;
      harness.getUserMediaError = new DOMException('Permission denied', 'NotAllowedError');
      const { ScanQRCodeFlow } = (await import(modulePath)) as any;

      const errors: string[] = [];
      const flow = new ScanQRCodeFlow({ timeout: 0 }, { onError: (e: Error) => errors.push(e.message) });
      await flow.startQRScanner();

      return { errors, state: flow.getState().state, stoppedTracks: harness.stoppedTracks };
    }, QR_SCANNER_PATH);

    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toBe(
      'Camera access was blocked. Allow camera access in your browser, then scan again.',
    );
    expect(result.errors[0]).not.toContain('goo.gl');
    expect(result.errors[0]).not.toContain('play()');
    expect(result.state).toBe('error');
  });
});

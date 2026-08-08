import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const REPORTER_PATH =
  '/_test-sdk/esm/SeamsWeb/walletIframe/host/lit-ui/surface-measurement-reporter.js';

test.describe('wallet iframe surface measurement reporter', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('keeps sequence numbers monotonic across root remounts', async ({ page }) => {
    const result = await page.evaluate(async (path) => {
      const reporterModule = await import(path);
      const originalResizeObserver = window.ResizeObserver;
      Object.defineProperty(window, 'ResizeObserver', {
        configurable: true,
        value: undefined,
      });

      try {
        const createElement = () => {
          const element = document.createElement('div');
          Object.defineProperty(element, 'getBoundingClientRect', {
            configurable: true,
            value: () => ({ width: 320, height: 240 }),
          });
          document.body.appendChild(element);
          return element;
        };

        const firstMeasurements: unknown[] = [];
        const firstElement = createElement();
        const firstReporter = reporterModule.createWalletIframeSurfaceMeasurementReporter({
          kind: 'request_surface',
          element: firstElement,
          requestId: 'request-a',
          postMeasurement: (measurement: unknown) => firstMeasurements.push(measurement),
        });
        firstReporter.disconnect();
        firstElement.remove();

        const secondMeasurements: unknown[] = [];
        const secondElement = createElement();
        const secondReporter = reporterModule.createWalletIframeSurfaceMeasurementReporter({
          kind: 'request_surface',
          element: secondElement,
          requestId: 'request-a',
          postMeasurement: (measurement: unknown) => secondMeasurements.push(measurement),
        });
        secondReporter.disconnect();
        secondElement.remove();

        return {
          firstSequence: (firstMeasurements[0] as { sequence?: unknown })?.sequence,
          secondSequence: (secondMeasurements[0] as { sequence?: unknown })?.sequence,
        };
      } finally {
        Object.defineProperty(window, 'ResizeObserver', {
          configurable: true,
          value: originalResizeObserver,
        });
      }
    }, REPORTER_PATH);

    expect(result.firstSequence).toBe(1);
    expect(result.secondSequence).toBe(2);
  });

  test('coalesces ResizeObserver updates, dedupes rounded sizes, and stops after disconnect', async ({
    page,
  }) => {
    const result = await page.evaluate(async (path) => {
      const reporterModule = await import(path);
      const originalResizeObserver = window.ResizeObserver;
      const originalRequestAnimationFrame = window.requestAnimationFrame;
      const originalCancelAnimationFrame = window.cancelAnimationFrame;
      let nextFrameId = 1;
      const frameCallbacks = new Map<number, (timestamp: number) => void>();

      class FakeResizeObserver {
        static latest: FakeResizeObserver | null = null;
        private readonly callback: (entries: unknown[]) => void;
        disconnected = false;

        constructor(callback: (entries: unknown[]) => void) {
          this.callback = callback;
          FakeResizeObserver.latest = this;
        }

        observe(): void {}

        disconnect(): void {
          this.disconnected = true;
        }

        trigger(width: number, height: number): void {
          this.callback([{ contentRect: { width, height } }]);
        }
      }

      const requestAnimationFrame = (callback: (timestamp: number) => void): number => {
        const frameId = nextFrameId;
        nextFrameId += 1;
        frameCallbacks.set(frameId, callback);
        return frameId;
      };
      const cancelAnimationFrame = (frameId: number): void => {
        frameCallbacks.delete(frameId);
      };
      const flushAnimationFrames = (): void => {
        const callbacks = [...frameCallbacks.values()];
        frameCallbacks.clear();
        for (const callback of callbacks) callback(0);
      };

      Object.defineProperty(window, 'ResizeObserver', {
        configurable: true,
        value: FakeResizeObserver,
      });
      Object.defineProperty(window, 'requestAnimationFrame', {
        configurable: true,
        value: requestAnimationFrame,
      });
      Object.defineProperty(window, 'cancelAnimationFrame', {
        configurable: true,
        value: cancelAnimationFrame,
      });

      try {
        const element = document.createElement('div');
        document.body.appendChild(element);
        const measurements: unknown[] = [];
        const reporter = reporterModule.createWalletIframeSurfaceMeasurementReporter({
          kind: 'request_surface',
          element,
          requestId: 'request-resize',
          postMeasurement: (measurement: unknown) => measurements.push(measurement),
        });
        const observer = FakeResizeObserver.latest;
        if (!observer) throw new Error('fake ResizeObserver was not constructed');

        observer.trigger(320.2, 240.2);
        observer.trigger(320.4, 240.4);
        const queuedAfterCoalescing = frameCallbacks.size;
        flushAnimationFrames();

        observer.trigger(320.49, 240.49);
        flushAnimationFrames();
        const countAfterRoundedDuplicate = measurements.length;

        observer.trigger(321.2, 241.2);
        flushAnimationFrames();

        observer.trigger(322.2, 242.2);
        const lateFrame = [...frameCallbacks.values()][0];
        const queuedBeforeDisconnect = frameCallbacks.size;
        reporter.disconnect();
        const queuedAfterDisconnect = frameCallbacks.size;
        lateFrame?.(0);
        observer.trigger(323.2, 243.2);
        flushAnimationFrames();

        const result = {
          measurements,
          queuedAfterCoalescing,
          countAfterRoundedDuplicate,
          queuedBeforeDisconnect,
          queuedAfterDisconnect,
          observerDisconnected: observer.disconnected,
        };
        element.remove();
        return result;
      } finally {
        Object.defineProperty(window, 'ResizeObserver', {
          configurable: true,
          value: originalResizeObserver,
        });
        Object.defineProperty(window, 'requestAnimationFrame', {
          configurable: true,
          value: originalRequestAnimationFrame,
        });
        Object.defineProperty(window, 'cancelAnimationFrame', {
          configurable: true,
          value: originalCancelAnimationFrame,
        });
      }
    }, REPORTER_PATH);

    expect(result.queuedAfterCoalescing).toBe(1);
    expect(result.countAfterRoundedDuplicate).toBe(1);
    expect(result.queuedBeforeDisconnect).toBe(1);
    expect(result.queuedAfterDisconnect).toBe(0);
    expect(result.observerDisconnected).toBe(true);
    expect(result.measurements).toEqual([
      {
        kind: 'measured_v1',
        requestId: 'request-resize',
        sequence: 1,
        widthCssPx: 320,
        heightCssPx: 240,
      },
      {
        kind: 'measured_v1',
        requestId: 'request-resize',
        sequence: 2,
        widthCssPx: 321,
        heightCssPx: 241,
      },
    ]);
  });
});

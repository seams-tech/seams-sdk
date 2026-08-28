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

  test('reports the current size before ResizeObserver delivers its first callback', async ({
    page,
  }) => {
    const result = await page.evaluate(async (path) => {
      const reporterModule = await import(path);
      const originalResizeObserver = window.ResizeObserver;

      class FakeResizeObserver {
        disconnected = false;

        constructor(_callback: (entries: unknown[]) => void) {}

        observe(): void {}

        disconnect(): void {
          this.disconnected = true;
        }
      }

      Object.defineProperty(window, 'ResizeObserver', {
        configurable: true,
        value: FakeResizeObserver,
      });

      try {
        const element = document.createElement('div');
        Object.defineProperty(element, 'getBoundingClientRect', {
          configurable: true,
          value: () => ({ width: 420, height: 360 }),
        });
        document.body.appendChild(element);
        const measurements: unknown[] = [];
        const reporter = reporterModule.createWalletIframeSurfaceMeasurementReporter({
          kind: 'request_surface',
          element,
          requestId: 'request-initial-size',
          postMeasurement: (measurement: unknown) => measurements.push(measurement),
        });
        reporter.disconnect();
        element.remove();
        return measurements;
      } finally {
        Object.defineProperty(window, 'ResizeObserver', {
          configurable: true,
          value: originalResizeObserver,
        });
      }
    }, REPORTER_PATH);

    expect(result).toEqual([
      {
        kind: 'measured_v1',
        requestId: 'request-initial-size',
        sequence: 1,
        widthCssPx: 420,
        heightCssPx: 360,
      },
    ]);
  });

  test('dedupes rounded ResizeObserver sizes and stops after disconnect', async ({ page }) => {
    const result = await page.evaluate(async (path) => {
      const reporterModule = await import(path);
      const originalResizeObserver = window.ResizeObserver;

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

      Object.defineProperty(window, 'ResizeObserver', {
        configurable: true,
        value: FakeResizeObserver,
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
        const countAfterRoundedDuplicate = measurements.length;
        observer.trigger(321.2, 241.2);
        reporter.disconnect();
        observer.trigger(322.2, 242.2);

        element.remove();
        return {
          measurements,
          countAfterRoundedDuplicate,
          observerDisconnected: observer.disconnected,
        };
      } finally {
        Object.defineProperty(window, 'ResizeObserver', {
          configurable: true,
          value: originalResizeObserver,
        });
      }
    }, REPORTER_PATH);

    expect(result.countAfterRoundedDuplicate).toBe(1);
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

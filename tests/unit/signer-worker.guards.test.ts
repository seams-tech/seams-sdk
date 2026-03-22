import { test, expect } from '@playwright/test';

test.describe('signer worker JS guards – PRF rejection', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/', { waitUntil: 'domcontentloaded' });
  });

  test('rejects payloads containing prfOutput', async ({ page }) => {
    const res = await page.evaluate(async () => {
      try {
        // Load the signer worker as a module and create a Worker instance
        const workerUrl = new URL(
          '/sdk/workers/near-signer.worker.js',
          window.location.origin,
        ).toString();
        const worker = new Worker(workerUrl, { type: 'module', name: 'GuardTestSignerWorker' });

        const messages: any[] = [];
        const errors: any[] = [];
        const requestId = 'guard-prf-output';

        worker.onmessage = (ev: MessageEvent) => messages.push(ev.data);
        worker.onerror = (ev: ErrorEvent) => errors.push(ev.message || ev.error);

        const waitFor = async (
          predicate: () => boolean,
          timeoutMs: number = 5000,
        ): Promise<void> => {
          const start = Date.now();
          while (Date.now() - start < timeoutMs) {
            if (predicate()) return;
            await new Promise((resolve) => setTimeout(resolve, 20));
          }
        };

        await waitFor(() => messages.some((m: any) => m?.type === 'WORKER_READY'), 5000);
        worker.postMessage({
          id: requestId,
          type: 5, // WorkerRequestType.DeriveThresholdEd25519ClientVerifyingShare (numeric)
          payload: {
            prfOutput: 'leaked-prf',
          },
        });
        await waitFor(
          () => messages.some((m: any) => m?.id === requestId && m?.ok === false),
          5000,
        );
        const response = messages.find((m: any) => m?.id === requestId && m?.ok === false) || null;
        worker.terminate();

        return { messages, errors, response };
      } catch (err: any) {
        return { messages: [], errors: [err?.message || String(err)] };
      }
    });

    const combined = [...res.errors, ...res.messages.map((m: any) => JSON.stringify(m))].join(' ');
    const errorText = String((res as any)?.response?.error || combined);
    expect(errorText).toContain('Forbidden secret field');
  });

  test('rejects payloads containing prfFirst', async ({ page }) => {
    const res = await page.evaluate(async () => {
      try {
        const workerUrl = new URL(
          '/sdk/workers/near-signer.worker.js',
          window.location.origin,
        ).toString();
        const worker = new Worker(workerUrl, {
          type: 'module',
          name: 'GuardTestSignerWorkerSecureConfirm',
        });

        const messages: any[] = [];
        const errors: any[] = [];
        const requestId = 'guard-prf-first';

        worker.onmessage = (ev: MessageEvent) => messages.push(ev.data);
        worker.onerror = (ev: ErrorEvent) => errors.push(ev.message || ev.error);

        const waitFor = async (
          predicate: () => boolean,
          timeoutMs: number = 5000,
        ): Promise<void> => {
          const start = Date.now();
          while (Date.now() - start < timeoutMs) {
            if (predicate()) return;
            await new Promise((resolve) => setTimeout(resolve, 20));
          }
        };

        await waitFor(() => messages.some((m: any) => m?.type === 'WORKER_READY'), 5000);
        worker.postMessage({
          id: requestId,
          type: 0, // WorkerRequestType.SignTransactionsWithActions (numeric)
          payload: {
            prfFirst: 'leaked-prf-first',
          },
        });
        await waitFor(
          () => messages.some((m: any) => m?.id === requestId && m?.ok === false),
          5000,
        );
        const response = messages.find((m: any) => m?.id === requestId && m?.ok === false) || null;
        worker.terminate();

        return { messages, errors, response };
      } catch (err: any) {
        return { messages: [], errors: [err?.message || String(err)] };
      }
    });

    const combined = [...res.errors, ...res.messages.map((m: any) => JSON.stringify(m))].join(' ');
    const errorText = String((res as any)?.response?.error || combined);
    expect(errorText).toContain('Forbidden secret field');
  });
});

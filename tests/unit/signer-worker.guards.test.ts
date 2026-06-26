import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function sourceBetween(source: string, start: string, end: string): string {
  const startIndex = source.indexOf(start);
  expect(startIndex, `Missing source marker ${start}`).toBeGreaterThanOrEqual(0);
  const endIndex = source.indexOf(end, startIndex + start.length);
  expect(endIndex, `Missing source marker ${end}`).toBeGreaterThan(startIndex);
  return source.slice(startIndex, endIndex);
}

test.describe('signer worker JS guards – PRF rejection', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/', { waitUntil: 'domcontentloaded' });
  });

  test('rejects payloads containing prfOutput', async ({ page }) => {
    const res = await page.evaluate(async () => {
      try {
        // Load the signer worker as a module and create a Worker instance
        const workerUrl = new URL(
          '/sdk/workers/hss-client.worker.js',
          window.location.origin,
        ).toString();
        const worker = new Worker(workerUrl, { type: 'module', name: 'GuardTestHssClientWorker' });

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

test('HSS client worker allows prfFirstB64u only for Ed25519 HSS client-input derivation', () => {
  const source = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/workerManager/workers/hss-client.worker.ts',
  );
  const fieldPolicy = sourceBetween(
    source,
    'function forbiddenSecretFieldsForHssWorkerRequest',
    'function assertNoPrfSecretsInSignerPayload',
  );
  const derivationCase = sourceBetween(
    fieldPolicy,
    'case WorkerRequestType.DeriveThresholdEd25519HssClientInputs:',
    'default:',
  );

  expect(derivationCase).toContain("field !== secretB64uField('prfFirst')");
  expect(fieldPolicy).toContain("'prfOutput'");
  expect(fieldPolicy).toContain("secretB64uField('prfFirst')");
});

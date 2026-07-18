import { expect, test } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const TEST_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(TEST_DIRECTORY, '../..');
const DERIVATION_WORKER_PATH = path.join(
  REPOSITORY_ROOT,
  'packages/sdk-web/dist/workers/ecdsa-derivation-client.worker.js',
);
const REGISTRATION_WASM_PATH = path.join(
  REPOSITORY_ROOT,
  'packages/sdk-web/dist/workers/ecdsa_registration_client_bg.wasm',
);
const PAGE_URL = 'https://wallet.example.localhost/__ecdsa-registration-waterfall.html';
const DERIVATION_WORKER_URL =
  'https://wallet.example.localhost/sdk/workers/ecdsa-derivation-client.worker.js';
const REGISTRATION_WASM_URL =
  'https://wallet.example.localhost/sdk/workers/ecdsa_registration_client_bg.wasm';
const DEFERRED_EXPORT_WASM_URL =
  'https://wallet.example.localhost/sdk/workers/router_ab_ecdsa_derivation_client_bg.wasm';

type RegistrationWaterfallResult = {
  readonly responseType: number;
  readonly observedRequests: readonly string[];
  readonly deferredExportWasmRequested: boolean;
};

test.describe('Router A/B ECDSA registration browser waterfall', () => {
  test('prepare loads the registration Wasm and leaves export Wasm deferred', async ({ page }) => {
    await page.route(PAGE_URL, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: '<!doctype html><meta charset="utf-8"><title>ECDSA registration</title>',
      });
    });
    await page.route(DERIVATION_WORKER_URL, async (route) => {
      await route.fulfill({ path: DERIVATION_WORKER_PATH, contentType: 'application/javascript' });
    });
    await page.route(REGISTRATION_WASM_URL, async (route) => {
      await route.fulfill({ path: REGISTRATION_WASM_PATH, contentType: 'application/wasm' });
    });

    const observedRequests: string[] = [];
    page.on('request', (request) => {
      observedRequests.push(request.url());
    });

    await page.goto(PAGE_URL, { waitUntil: 'domcontentloaded' });
    const responseType = await page.evaluate(
      async ({ workerUrl }): Promise<number> => {
        const worker = new Worker(workerUrl, { type: 'module' });
        try {
          await new Promise<void>((resolve, reject) => {
            const timeout = window.setTimeout(
              () => reject(new Error('ECDSA registration worker ready timeout')),
              10_000,
            );
            const onMessage = (event: MessageEvent): void => {
              const value = event.data as { type?: unknown; ready?: unknown };
              if (value.type !== 'WORKER_READY' && value.ready !== true) return;
              window.clearTimeout(timeout);
              worker.removeEventListener('message', onMessage);
              resolve();
            };
            worker.addEventListener('message', onMessage);
            worker.addEventListener(
              'error',
              (event) => {
                window.clearTimeout(timeout);
                reject(new Error(event.message || 'ECDSA registration worker load failed'));
              },
              { once: true },
            );
          });

          const response = await new Promise<{ readonly type: number }>((resolve, reject) => {
            const requestId = 'registration-waterfall-prepare';
            const timeout = window.setTimeout(
              () => reject(new Error('ECDSA registration prepare timeout')),
              20_000,
            );
            const onMessage = (event: MessageEvent): void => {
              const value = event.data as {
                readonly id?: string;
                readonly ok?: boolean;
                readonly error?: string;
                readonly result?: { readonly type: number };
              };
              if (value.id !== requestId) return;
              window.clearTimeout(timeout);
              worker.removeEventListener('message', onMessage);
              if (!value.ok || !value.result) {
                reject(new Error(value.error || 'ECDSA registration prepare failed'));
                return;
              }
              resolve(value.result);
            };
            worker.addEventListener('message', onMessage);
            worker.postMessage({
              id: requestId,
              type: 70_000,
              payload: {
                kind: 'prepare_ecdsa_client_bootstrap_v1',
                algorithm: 'router_ab_ecdsa_derivation_secp256k1_role_local_v1',
                context: {
                  applicationBindingDigestB64u: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE',
                },
                participants: {
                  clientParticipantId: 1,
                  relayerParticipantId: 2,
                  participantIds: [1, 2],
                },
                secretSource: {
                  kind: 'webauthn_prf_first',
                  prfFirstB64u: 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI',
                  rpId: 'wallet.example.localhost',
                  credentialIdB64u: 'Aw',
                },
              },
            });
          });
          return response.type;
        } finally {
          worker.terminate();
        }
      },
      { workerUrl: DERIVATION_WORKER_URL },
    );

    const result: RegistrationWaterfallResult = {
      responseType,
      observedRequests,
      deferredExportWasmRequested: observedRequests.includes(DEFERRED_EXPORT_WASM_URL),
    };
    expect(result.responseType).toBe(70_100);
    expect(result.observedRequests).toContain(DERIVATION_WORKER_URL);
    expect(result.observedRequests).toContain(REGISTRATION_WASM_URL);
    expect(result.deferredExportWasmRequested).toBe(false);
  });
});

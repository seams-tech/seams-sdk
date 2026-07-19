import { expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { statSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const TEST_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(TEST_DIRECTORY, '../..');
const STORE_SOURCE = path.join(
  REPOSITORY_ROOT,
  'packages/sdk-web/src/core/indexedDB/seamsWalletDB/ecdsaPresignMaterialStore.ts',
);
const STORE_BUNDLE_PATH = path.join(tmpdir(), `seams-ecdsa-pool-hit-store-${process.pid}.mjs`);
const ONLINE_WORKER_PATH = path.join(
  REPOSITORY_ROOT,
  'packages/sdk-web/dist/workers/ecdsa-online-client.worker.js',
);
const ONLINE_WASM_PATH = path.join(
  REPOSITORY_ROOT,
  'packages/sdk-web/dist/workers/router_ab_ecdsa_online_client_bg.wasm',
);
const PAGE_URL = 'https://wallet.example.localhost/__ecdsa-pool-hit-waterfall.html';
const STORE_MODULE_URL = 'https://wallet.example.localhost/__ecdsa-pool-hit-store.mjs';
const ONLINE_WORKER_URL =
  'https://wallet.example.localhost/sdk/workers/ecdsa-online-client.worker.js';
const ONLINE_WASM_URL =
  'https://wallet.example.localhost/sdk/workers/router_ab_ecdsa_online_client_bg.wasm';
const PRESIGN_ASSET_MARKERS = [
  'ecdsa-presign-client.worker',
  'router_ab_ecdsa_presign_client',
] as const;
const DERIVER_ROUTE_MARKERS = ['/router-ab/deriver-a', '/router-ab/deriver-b'] as const;

const GROUP_PUBLIC_KEY_33 = [
  2, 254, 141, 30, 177, 188, 179, 67, 43, 29, 181, 131, 63, 245, 242, 34, 109, 156, 181, 230, 92,
  238, 67, 5, 88, 193, 142, 211, 163, 200, 108, 225, 175,
] as const;
const BIG_R_33 = [
  3, 237, 150, 72, 69, 132, 153, 242, 148, 195, 128, 215, 84, 235, 17, 17, 182, 76, 107, 254, 74,
  146, 36, 62, 241, 41, 198, 185, 22, 109, 37, 77, 101,
] as const;
const CLIENT_K_32 = [
  197, 87, 37, 100, 201, 71, 119, 15, 251, 24, 175, 179, 76, 165, 241, 88, 226, 144, 113, 32, 42,
  139, 246, 79, 67, 44, 131, 217, 172, 59, 26, 168,
] as const;
const CLIENT_SIGMA_32 = [
  41, 80, 108, 245, 183, 251, 136, 226, 31, 123, 65, 156, 75, 13, 173, 79, 47, 134, 41, 97, 244,
  228, 59, 120, 19, 22, 222, 236, 92, 19, 78, 7,
] as const;
const EXPECTED_CLIENT_SHARE_32 = [
  8, 46, 156, 40, 245, 90, 89, 122, 17, 195, 125, 69, 237, 224, 21, 99, 97, 131, 12, 51, 124, 227,
  87, 88, 198, 192, 41, 38, 207, 186, 26, 74,
] as const;

type PoolHitResult = {
  readonly responseType: number;
  readonly signatureShare32: number[];
  readonly retiredCount: number;
  readonly retirementReason: string;
};

type WaterfallEvidence = {
  readonly operation: 'router_ab_ecdsa_pool_hit_online_client_v1';
  readonly topologyApplicability: readonly ['same_account_development', 'independent_accounts'];
  readonly observedRequests: readonly string[];
  readonly observedWorkers: readonly string[];
  readonly onlineBytes: number;
  readonly presignBytes: 0;
  readonly browserDeriverCalls: 0;
};

function containsAnyMarker(value: string, markers: readonly string[]): boolean {
  return markers.some((marker) => value.includes(marker));
}

test.describe('Router A/B ECDSA pool-hit browser waterfall', () => {
  test.beforeAll(() => {
    execFileSync(
      'bun',
      ['build', STORE_SOURCE, '--target=browser', '--format=esm', `--outfile=${STORE_BUNDLE_PATH}`],
      { cwd: REPOSITORY_ROOT, stdio: 'pipe' },
    );
  });

  test.afterAll(() => {
    try {
      unlinkSync(STORE_BUNDLE_PATH);
    } catch {}
  });

  test('a committed pool hit fetches only the online worker and online Wasm', async ({
    page,
  }, testInfo) => {
    await page.route(PAGE_URL, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: '<!doctype html><meta charset="utf-8"><title>ECDSA pool hit</title>',
      });
    });
    await page.route(STORE_MODULE_URL, async (route) => {
      await route.fulfill({ path: STORE_BUNDLE_PATH, contentType: 'application/javascript' });
    });
    await page.route(ONLINE_WORKER_URL, async (route) => {
      await route.fulfill({ path: ONLINE_WORKER_PATH, contentType: 'application/javascript' });
    });
    await page.route(ONLINE_WASM_URL, async (route) => {
      await route.fulfill({ path: ONLINE_WASM_PATH, contentType: 'application/wasm' });
    });

    const observedRequests: string[] = [];
    const observedWorkers: string[] = [];
    let observePoolHit = false;
    page.on('request', (request) => {
      if (observePoolHit) observedRequests.push(request.url());
    });
    page.on('worker', (worker) => {
      if (observePoolHit) observedWorkers.push(worker.url());
    });

    await page.goto(PAGE_URL, { waitUntil: 'domcontentloaded' });
    await page.evaluate(
      async ({ storeModuleUrl, fixture }) => {
        const { IndexedDbClientPresignMaterialStore } = await import(storeModuleUrl);
        const store = new IndexedDbClientPresignMaterialStore();
        await store.deleteDatabaseForTests();
        const createdAtMs = Date.now();
        const expiresAtMs = createdAtMs + 60_000;
        const presignatureId = await store.putPendingAdmission({
          materialHandle: fixture.materialHandle,
          presignSessionId: fixture.presignSessionId,
          poolIdentity: fixture.poolIdentity,
          groupPublicKey33: new Uint8Array(fixture.groupPublicKey33),
          bigR33: new Uint8Array(fixture.bigR33),
          kShare32: new Uint8Array(fixture.kShare32),
          sigmaShare32: new Uint8Array(fixture.sigmaShare32),
          createdAtMs,
          expiresAtMs,
        });
        const retirementPresignatureId = await store.putPendingAdmission({
          materialHandle: fixture.retirementMaterialHandle,
          presignSessionId: `${fixture.presignSessionId}-retirement`,
          poolIdentity: fixture.poolIdentity,
          groupPublicKey33: new Uint8Array(fixture.groupPublicKey33),
          bigR33: new Uint8Array(fixture.bigR33),
          kShare32: new Uint8Array(fixture.kShare32),
          sigmaShare32: new Uint8Array(fixture.sigmaShare32),
          createdAtMs,
          expiresAtMs,
        });
        const admission = await store.admit({
          materialHandle: fixture.materialHandle,
          expectedPresignatureId: presignatureId,
          poolIdentity: fixture.poolIdentity,
          nowMs: createdAtMs + 1,
        });
        if (!admission.ok) throw new Error(`fixture admission failed: ${admission.code}`);
        const retirementAdmission = await store.admit({
          materialHandle: fixture.retirementMaterialHandle,
          expectedPresignatureId: retirementPresignatureId,
          poolIdentity: fixture.poolIdentity,
          nowMs: createdAtMs + 1,
        });
        if (!retirementAdmission.ok) {
          throw new Error(`retirement fixture admission failed: ${retirementAdmission.code}`);
        }
        const reservation = await store.reserve({
          materialHandle: fixture.materialHandle,
          poolIdentity: fixture.poolIdentity,
          requestBinding: fixture.requestBinding,
          reservationId: fixture.reservationId,
          nowMs: createdAtMs + 2,
          leaseExpiresAtMs: createdAtMs + 30_000,
        });
        if (!reservation.ok) throw new Error(`fixture reservation failed: ${reservation.code}`);
        const committed = await store.commit({
          materialHandle: fixture.materialHandle,
          poolIdentity: fixture.poolIdentity,
          requestBinding: fixture.requestBinding,
          reservationId: fixture.reservationId,
          nowMs: createdAtMs + 3,
        });
        if (!committed.ok) throw new Error(`fixture commit failed: ${committed.code}`);
        store.close();
      },
      {
        storeModuleUrl: STORE_MODULE_URL,
        fixture: poolHitFixture(),
      },
    );

    observePoolHit = true;
    const result = await page.evaluate(
      async ({ workerUrl, fixture }): Promise<PoolHitResult> => {
        const worker = new Worker(workerUrl, { type: 'module' });
        try {
          await new Promise<void>((resolve, reject) => {
            const timeout = window.setTimeout(
              () => reject(new Error('online worker ready timeout')),
              10_000,
            );
            const onMessage = (event: MessageEvent): void => {
              const value = event.data as { type?: unknown; ready?: unknown };
              if (value.type !== 'WORKER_READY' && value.ready !== true) return;
              clearTimeout(timeout);
              worker.removeEventListener('message', onMessage);
              resolve();
            };
            worker.addEventListener('message', onMessage);
            worker.addEventListener(
              'error',
              (event) => {
                clearTimeout(timeout);
                reject(new Error(event.message || 'online worker load failed'));
              },
              { once: true },
            );
          });

          const groupPublicKey33 = new Uint8Array(fixture.groupPublicKey33);
          const expectedPresignBigR33 = new Uint8Array(fixture.bigR33);
          const digest32 = new Uint8Array(32).fill(0x42);
          const clientRerandomizationContribution32 = new Uint8Array(32).fill(0x20);
          const signingWorkerRerandomizationContribution32 = new Uint8Array(32).fill(0x04);
          const response = await new Promise<{
            readonly type: number;
            readonly payload: ArrayBuffer;
          }>((resolve, reject) => {
            const requestId = 'pool-hit-waterfall-request';
            const timeout = window.setTimeout(
              () => reject(new Error('online signature-share timeout')),
              20_000,
            );
            const onMessage = (event: MessageEvent): void => {
              const value = event.data as {
                readonly id?: string;
                readonly ok?: boolean;
                readonly error?: string;
                readonly result?: { readonly type: number; readonly payload: ArrayBuffer };
              };
              if (value.id !== requestId) return;
              clearTimeout(timeout);
              worker.removeEventListener('message', onMessage);
              if (!value.ok || !value.result) {
                reject(new Error(value.error || 'online signature-share failed'));
                return;
              }
              resolve(value.result);
            };
            worker.addEventListener('message', onMessage);
            worker.postMessage(
              {
                id: requestId,
                type: 72_000,
                payload: {
                  materialHandle: fixture.materialHandle,
                  poolIdentity: fixture.poolIdentity,
                  requestBinding: fixture.requestBinding,
                  reservationId: fixture.reservationId,
                  groupPublicKey33: groupPublicKey33.buffer,
                  expectedPresignBigR33: expectedPresignBigR33.buffer,
                  digest32: digest32.buffer,
                  clientRerandomizationContribution32:
                    clientRerandomizationContribution32.buffer,
                  signingWorkerRerandomizationContribution32:
                    signingWorkerRerandomizationContribution32.buffer,
                },
              },
              [
                groupPublicKey33.buffer,
                expectedPresignBigR33.buffer,
                digest32.buffer,
                clientRerandomizationContribution32.buffer,
                signingWorkerRerandomizationContribution32.buffer,
              ],
            );
          });
          const retirement = await new Promise<{
            readonly type: number;
            readonly payload: {
              readonly kind: string;
              readonly reason: string;
              readonly retiredCount: number;
            };
          }>((resolve, reject) => {
            const requestId = 'pool-hit-retirement-request';
            const timeout = window.setTimeout(
              () => reject(new Error('online pool-retirement timeout')),
              20_000,
            );
            const onMessage = (event: MessageEvent): void => {
              const value = event.data as {
                readonly id?: string;
                readonly ok?: boolean;
                readonly error?: string;
                readonly result?: {
                  readonly type: number;
                  readonly payload: {
                    readonly kind: string;
                    readonly reason: string;
                    readonly retiredCount: number;
                  };
                };
              };
              if (value.id !== requestId) return;
              clearTimeout(timeout);
              worker.removeEventListener('message', onMessage);
              if (!value.ok || !value.result) {
                reject(new Error(value.error || 'online pool retirement failed'));
                return;
              }
              resolve(value.result);
            };
            worker.addEventListener('message', onMessage);
            worker.postMessage({
              id: requestId,
              type: 72_001,
              payload: {
                poolIdentity: fixture.poolIdentity,
                reason: 'activation_epoch_retired',
              },
            });
          });
          if (
            retirement.type !== 72_101 ||
            retirement.payload.kind !== 'ecdsa_client_presignature_pool_retired_v1'
          ) {
            throw new Error('online pool retirement returned an invalid receipt');
          }
          return {
            responseType: response.type,
            signatureShare32: Array.from(new Uint8Array(response.payload)),
            retiredCount: retirement.payload.retiredCount,
            retirementReason: retirement.payload.reason,
          };
        } finally {
          worker.terminate();
          const { IndexedDbClientPresignMaterialStore } = await import(fixture.storeModuleUrl);
          const store = new IndexedDbClientPresignMaterialStore();
          await store.deleteDatabaseForTests();
        }
      },
      {
        workerUrl: ONLINE_WORKER_URL,
        fixture: { ...poolHitFixture(), storeModuleUrl: STORE_MODULE_URL },
      },
    );
    observePoolHit = false;

    expect(result.responseType).toBe(72_100);
    expect(result.signatureShare32).toEqual(EXPECTED_CLIENT_SHARE_32);
    expect(result.retiredCount).toBe(1);
    expect(result.retirementReason).toBe('activation_epoch_retired');
    expect(observedWorkers).toEqual([ONLINE_WORKER_URL]);
    expect(observedRequests).toEqual([ONLINE_WORKER_URL, ONLINE_WASM_URL]);
    expect(observedRequests.some((url) => containsAnyMarker(url, PRESIGN_ASSET_MARKERS))).toBe(
      false,
    );
    expect(observedRequests.some((url) => containsAnyMarker(url, DERIVER_ROUTE_MARKERS))).toBe(
      false,
    );

    const evidence: WaterfallEvidence = {
      operation: 'router_ab_ecdsa_pool_hit_online_client_v1',
      topologyApplicability: ['same_account_development', 'independent_accounts'],
      observedRequests,
      observedWorkers,
      onlineBytes: statSync(ONLINE_WORKER_PATH).size + statSync(ONLINE_WASM_PATH).size,
      presignBytes: 0,
      browserDeriverCalls: 0,
    };
    await testInfo.attach('router-ab-ecdsa-pool-hit-waterfall.json', {
      body: Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`),
      contentType: 'application/json',
    });
  });
});

function poolHitFixture() {
  return {
    materialHandle: 'pool-hit-material-1',
    retirementMaterialHandle: 'pool-hit-retirement-material-1',
    presignSessionId: 'pool-hit-session-1',
    requestBinding: 'pool-hit-request-binding-1',
    reservationId: 'pool-hit-reservation-1',
    poolIdentity: {
      poolKey: 'pool-hit-key-1',
      walletKeyId: 'wallet-key-1',
      walletId: 'wallet-1',
      signingScopeB64u: 'scope-1',
      pairRole: 'client' as const,
      keyEpoch: 'signing-worker-key-epoch-1',
      activationEpoch: 'activation-epoch-1',
      protocolId: 'seams/router-ab-ecdsa-presign/fixed-2of2/v1' as const,
    },
    groupPublicKey33: [...GROUP_PUBLIC_KEY_33],
    bigR33: [...BIG_R_33],
    kShare32: [...CLIENT_K_32],
    sigmaShare32: [...CLIENT_SIGMA_32],
  };
}

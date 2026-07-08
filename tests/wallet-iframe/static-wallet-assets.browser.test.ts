import { expect, test } from '@playwright/test';
import * as fs from 'node:fs/promises';
import * as http from 'node:http';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AddressInfo } from 'node:net';

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(TEST_DIR, '../..');
const PUBLIC_ROOT = path.join(REPO_ROOT, 'packages/sdk-web/dist/public');
const ASSETS_MANIFEST_PATH = path.join(PUBLIC_ROOT, 'wallet-assets.manifest.json');

type StaticAsset = {
  route: string;
  sourceFile: string;
  contentType: string;
  cachePolicy: string;
  requiredHeaders?: Array<{ name: string; value: string }>;
};

type WorkerLoadResult = {
  route: string;
  ok: boolean;
  message: string;
};

type WasmLoadResult = {
  route: string;
  ok: boolean;
  contentType: string | null;
  message: string;
};

function assetMapByRoute(assets: readonly StaticAsset[]): Map<string, StaticAsset> {
  return new Map(assets.map((asset) => [asset.route, asset]));
}

function normalizeRoute(pathname: string): string {
  if (pathname === '/wallet-service/') return '/wallet-service';
  return pathname;
}

function workerRoutesFromAssets(assets: readonly StaticAsset[]): string[] {
  return assets
    .map((asset) => asset.route)
    .filter((route) => route.startsWith('/sdk/workers/') && route.endsWith('.worker.js'))
    .sort();
}

function workerWasmRoutesFromAssets(assets: readonly StaticAsset[]): string[] {
  return assets
    .map((asset) => asset.route)
    .filter((route) => route.startsWith('/sdk/workers/') && route.endsWith('.wasm'))
    .sort();
}

async function readAssetsManifest(): Promise<{ assets: StaticAsset[] }> {
  const raw = await fs.readFile(ASSETS_MANIFEST_PATH, 'utf8');
  return JSON.parse(raw) as { assets: StaticAsset[] };
}

async function respondWithAsset(response: http.ServerResponse, asset: StaticAsset): Promise<void> {
  const filePath = path.join(PUBLIC_ROOT, asset.sourceFile);
  const content = await fs.readFile(filePath);
  response.statusCode = 200;
  response.setHeader('Content-Type', asset.contentType);
  response.setHeader('Cache-Control', asset.cachePolicy);
  for (const header of asset.requiredHeaders || []) {
    response.setHeader(header.name, header.value);
  }
  response.end(content);
}

function respondNotFound(response: http.ServerResponse): void {
  response.statusCode = 404;
  response.end('not found');
}

function createStaticWalletServer(assetsByRoute: ReadonlyMap<string, StaticAsset>): http.Server {
  return http.createServer((request, response) => {
    const url = new URL(request.url || '/', 'http://127.0.0.1');
    const route = normalizeRoute(url.pathname);
    const asset = assetsByRoute.get(route);
    if (!asset) {
      respondNotFound(response);
      return;
    }
    respondWithAsset(response, asset).catch((error) => {
      response.statusCode = 500;
      response.end(String(error?.message || error));
    });
  });
}

function listen(server: http.Server): Promise<AddressInfo> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      resolve(server.address() as AddressInfo);
    });
  });
}

function close(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

async function createWalletServerFixture(): Promise<{
  server: http.Server;
  baseUrl: string;
  assets: StaticAsset[];
}> {
  const manifest = await readAssetsManifest();
  const server = createStaticWalletServer(assetMapByRoute(manifest.assets));
  const address = await listen(server);
  return {
    server,
    baseUrl: `http://${address.address}:${address.port}`,
    assets: manifest.assets,
  };
}

test('static wallet-service loads workers and worker WASM from dist/public', async ({ page }) => {
  const { server, baseUrl, assets } = await createWalletServerFixture();
  try {
    const response = await page.goto(`${baseUrl}/wallet-service`, { waitUntil: 'domcontentloaded' });
    expect(response?.ok()).toBe(true);

    const workerRoutes = workerRoutesFromAssets(assets);
    const wasmRoutes = workerWasmRoutesFromAssets(assets);
    expect(workerRoutes.length).toBeGreaterThan(0);
    expect(wasmRoutes.length).toBeGreaterThan(0);

    const results = await page.evaluate(
      async ({ workerRoutes, wasmRoutes }) => {
        function workerLoadResult(route: string): Promise<WorkerLoadResult> {
          return new Promise((resolve) => {
            let settled = false;
            let timeout: number | undefined;
            let worker: Worker | undefined;
            const finish = (result: WorkerLoadResult) => {
              if (settled) return;
              settled = true;
              if (timeout !== undefined) clearTimeout(timeout);
              if (worker) worker.terminate();
              resolve(result);
            };
            try {
              worker = new Worker(route, { type: 'module' });
            } catch (error) {
              finish({
                route,
                ok: false,
                message: String(error instanceof Error ? error.message : error),
              });
              return;
            }
            timeout = window.setTimeout(() => {
              finish({ route, ok: true, message: 'module worker loaded' });
            }, 750);
            worker.addEventListener('message', () => {
              finish({ route, ok: true, message: 'worker posted ready message' });
            });
            worker.addEventListener('error', (event) => {
              finish({ route, ok: false, message: event.message || 'worker error' });
            });
          });
        }

        async function wasmLoadResult(route: string): Promise<WasmLoadResult> {
          try {
            const response = await fetch(route);
            const contentType = response.headers.get('content-type');
            if (!response.ok) {
              return { route, ok: false, contentType, message: `HTTP ${response.status}` };
            }
            const bytes = await response.arrayBuffer();
            await WebAssembly.compile(bytes);
            return { route, ok: true, contentType, message: 'compiled' };
          } catch (error) {
            return {
              route,
              ok: false,
              contentType: null,
              message: String(error instanceof Error ? error.message : error),
            };
          }
        }

        const workerResults = [];
        for (const route of workerRoutes) {
          workerResults.push(await workerLoadResult(route));
        }
        const wasmResults = [];
        for (const route of wasmRoutes) {
          wasmResults.push(await wasmLoadResult(route));
        }
        return { workerResults, wasmResults };
      },
      { workerRoutes, wasmRoutes },
    );

    expect(results.workerResults.filter((result) => !result.ok)).toEqual([]);
    expect(results.wasmResults.filter((result) => !result.ok)).toEqual([]);
    for (const result of results.wasmResults) {
      expect(result.contentType).toBe('application/wasm');
    }
  } finally {
    await close(server);
  }
});

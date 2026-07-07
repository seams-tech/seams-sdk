#!/usr/bin/env node

import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const SDK_ROOT = path.resolve(SCRIPT_DIR, '../..');
const PUBLIC_ROOT = path.join(SDK_ROOT, 'dist/public');
const ASSETS_MANIFEST_PATH = path.join(PUBLIC_ROOT, 'wallet-assets.manifest.json');

const APP_ORIGIN_404_PATHS = [
  '/sdk/wallet-iframe-host-runtime.js',
  '/sdk/workers/near-signer.worker.js',
  '/wallet-service',
  '/export-viewer',
];

const WALLET_ORIGIN_200_PATHS = [
  { path: '/wallet-service', contentType: 'text/html; charset=utf-8' },
  { path: '/export-viewer', contentType: 'text/html; charset=utf-8' },
  { path: '/sdk/workers/near-signer.worker.js', contentType: 'text/javascript; charset=utf-8' },
  { path: '/sdk/workers/wasm_signer_worker_bg.wasm', contentType: 'application/wasm' },
  { path: '/sdk/workers/eth_signer_bg.wasm', contentType: 'application/wasm' },
  { path: '/sdk/workers/tempo_signer_bg.wasm', contentType: 'application/wasm' },
  { path: '/wallet-assets.manifest.json', contentType: 'application/json; charset=utf-8' },
  { path: '/headers.manifest.json', contentType: 'application/json; charset=utf-8' },
];

function isAppWalletAssetPath(pathname) {
  return (
    pathname.startsWith('/sdk/') ||
    pathname === '/wallet-service' ||
    pathname.startsWith('/wallet-service/') ||
    pathname === '/export-viewer' ||
    pathname.startsWith('/export-viewer/')
  );
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function readAssetsManifest() {
  return JSON.parse(await fs.readFile(ASSETS_MANIFEST_PATH, 'utf-8'));
}

function assetMapByRoute(assets) {
  return new Map(assets.map((asset) => [asset.route, asset]));
}

function normalizeWalletRoute(pathname) {
  if (pathname === '/wallet-service/') return '/wallet-service';
  if (pathname === '/export-viewer/') return '/export-viewer';
  return pathname;
}

async function respondWithFile(response, asset) {
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

function respondNotFound(response) {
  response.statusCode = 404;
  response.end('not found');
}

function respondOk(response) {
  response.statusCode = 200;
  response.setHeader('Content-Type', 'text/plain; charset=utf-8');
  response.end('app origin');
}

function createAppServer() {
  return http.createServer((request, response) => {
    const url = new URL(request.url || '/', 'http://127.0.0.1');
    if (isAppWalletAssetPath(url.pathname)) {
      respondNotFound(response);
      return;
    }
    respondOk(response);
  });
}

function createWalletServer(assetsByRoute) {
  return http.createServer((request, response) => {
    const url = new URL(request.url || '/', 'http://127.0.0.1');
    const route = normalizeWalletRoute(url.pathname);
    const asset = assetsByRoute.get(route);
    if (!asset) {
      respondNotFound(response);
      return;
    }
    respondWithFile(response, asset).catch((error) => {
      response.statusCode = 500;
      response.end(String(error?.message || error));
    });
  });
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      resolve(server.address());
    });
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

async function fetchSmoke(url) {
  const response = await fetch(url);
  await response.arrayBuffer();
  return response;
}

async function assertStatus(url, expectedStatus) {
  const response = await fetchSmoke(url);
  assert(response.status === expectedStatus, `${url} returned ${response.status}, expected ${expectedStatus}`);
  return response;
}

async function assertContentType(url, expectedContentType) {
  const response = await assertStatus(url, 200);
  const actualContentType = response.headers.get('content-type');
  assert(
    actualContentType === expectedContentType,
    `${url} returned Content-Type ${actualContentType}, expected ${expectedContentType}`,
  );
}

async function assertAppOrigin(appBaseUrl) {
  await assertStatus(`${appBaseUrl}/`, 200);
  for (const pathname of APP_ORIGIN_404_PATHS) {
    await assertStatus(`${appBaseUrl}${pathname}`, 404);
  }
}

async function assertWalletOrigin(walletBaseUrl) {
  for (const route of WALLET_ORIGIN_200_PATHS) {
    await assertContentType(`${walletBaseUrl}${route.path}`, route.contentType);
  }
}

function assertRequiredSmokeRoutesExist(assetsByRoute) {
  for (const route of WALLET_ORIGIN_200_PATHS) {
    const normalizedRoute = normalizeWalletRoute(route.path);
    assert(assetsByRoute.has(normalizedRoute), `Missing static wallet smoke route ${normalizedRoute}`);
  }
}

async function smokeStaticWalletOrigin() {
  const assetsManifest = await readAssetsManifest();
  const assetsByRoute = assetMapByRoute(assetsManifest.assets || []);
  assertRequiredSmokeRoutesExist(assetsByRoute);

  const appServer = createAppServer();
  const walletServer = createWalletServer(assetsByRoute);
  const appAddress = await listen(appServer);
  const walletAddress = await listen(walletServer);
  const appBaseUrl = `http://${appAddress.address}:${appAddress.port}`;
  const walletBaseUrl = `http://${walletAddress.address}:${walletAddress.port}`;

  try {
    await assertAppOrigin(appBaseUrl);
    await assertWalletOrigin(walletBaseUrl);
  } finally {
    await close(appServer);
    await close(walletServer);
  }

  console.log(`Static wallet origin smoke OK (${walletBaseUrl})`);
}

await smokeStaticWalletOrigin();

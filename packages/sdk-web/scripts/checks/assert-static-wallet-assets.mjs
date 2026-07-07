#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const SDK_ROOT = path.resolve(SCRIPT_DIR, '../..');
const PUBLIC_ROOT = path.join(SDK_ROOT, 'dist/public');
const PUBLIC_SDK = path.join(PUBLIC_ROOT, 'sdk');
const ASSETS_MANIFEST_PATH = path.join(PUBLIC_ROOT, 'wallet-assets.manifest.json');
const HEADERS_MANIFEST_PATH = path.join(PUBLIC_ROOT, 'headers.manifest.json');
const WALLET_STATIC_ASSETS_ROOT = path.join(SDK_ROOT, 'src/static/wallet-assets');

const REQUIRED_ROUTES = [
  '/wallet-service',
  '/export-viewer',
  '/headers.manifest.json',
  '/wallet-assets.manifest.json',
  '/sdk/wallet-shims.js',
  '/sdk/wallet-service.css',
  '/sdk/wallet-iframe-host-runtime.js',
  '/sdk/wallet-iframe-host-near.js',
  '/sdk/wallet-iframe-host-ecdsa.js',
  '/sdk/wallet-iframe-host-full.js',
  '/sdk/export-private-key-viewer.js',
  '/sdk/iframe-export-bootstrap.js',
  '/sdk/workers/near-signer.worker.js',
  '/sdk/workers/hss-client.worker.js',
  '/sdk/workers/passkey-confirm.worker.js',
  '/sdk/workers/email-otp.worker.js',
  '/sdk/workers/eth-signer.worker.js',
  '/sdk/workers/tempo-signer.worker.js',
  '/sdk/workers/wasm_signer_worker_bg.wasm',
  '/sdk/workers/hss_client_signer_bg.wasm',
  '/sdk/workers/eth_signer.wasm',
  '/sdk/workers/eth_signer_bg.wasm',
  '/sdk/workers/tempo_signer.wasm',
  '/sdk/workers/tempo_signer_bg.wasm',
  '/sdk/workers/email_otp_runtime_bg.wasm',
];

const WORKER_WASM_COMPANIONS = [
  {
    worker: '/sdk/workers/near-signer.worker.js',
    companions: ['/sdk/workers/wasm_signer_worker_bg.wasm', '/sdk/workers/near_signer.wasm'],
  },
  {
    worker: '/sdk/workers/hss-client.worker.js',
    companions: ['/sdk/workers/hss_client_signer_bg.wasm'],
  },
  {
    worker: '/sdk/workers/email-otp.worker.js',
    companions: ['/sdk/workers/email_otp_runtime.js', '/sdk/workers/email_otp_runtime_bg.wasm'],
  },
  {
    worker: '/sdk/workers/shamir3pass.worker.js',
    companions: ['/sdk/workers/shamir3pass_runtime.js', '/sdk/workers/shamir3pass_runtime_bg.wasm'],
  },
  {
    worker: '/sdk/workers/eth-signer.worker.js',
    companions: ['/sdk/workers/eth_signer.wasm', '/sdk/workers/eth_signer_bg.wasm'],
  },
  {
    worker: '/sdk/workers/tempo-signer.worker.js',
    companions: ['/sdk/workers/tempo_signer.wasm', '/sdk/workers/tempo_signer_bg.wasm'],
  },
];

const EXPECTED_CONTENT_TYPES = [
  { suffix: '.wasm', contentType: 'application/wasm' },
  { suffix: '.js', contentType: 'text/javascript; charset=utf-8' },
  { suffix: '.css', contentType: 'text/css; charset=utf-8' },
  { suffix: '.html', contentType: 'text/html; charset=utf-8' },
  { suffix: '.json', contentType: 'application/json; charset=utf-8' },
  { suffix: '.map', contentType: 'application/json; charset=utf-8' },
];

const REQUIRED_HEADER_ROUTE_CLASSES = [
  '/sdk/*.js',
  '/sdk/*.css',
  '/sdk/workers/*.js',
  '/sdk/workers/*.wasm',
  '/wallet-service',
  '/export-viewer',
  '/*.manifest.json',
];

const CANONICAL_WALLET_STATIC_ASSETS = ['wallet-shims.js', 'wallet-service.css'];

const REFERENCED_ROUTE_CLASSES = new Set(['javascript', 'css', 'htmlDocument']);
const JS_REFERENCE_PATTERNS = [
  /\bimport\s+(?:[^'"]+\s+from\s+)?["']([^"']+)["']/g,
  /\bexport\s+[^'"]+\s+from\s+["']([^"']+)["']/g,
  /\bimport\(\s*["']([^"']+)["']\s*\)/g,
  /\bnew URL\(\s*["']([^"']+)["']\s*,\s*import\.meta\.url\s*\)/g,
];
const HTML_REFERENCE_PATTERN = /\b(?:href|src)="([^"]+)"/g;
const CSS_URL_PATTERN = /\burl\(\s*(['"]?)([^'")]+)\1\s*\)/g;
const SOURCE_MAPPING_URL_PATTERN = /(?:\/\/|\/\*)# sourceMappingURL=([^\s*]+)/g;

function routeToFilePath(route) {
  if (route === '/wallet-service') return path.join(PUBLIC_ROOT, 'wallet-service/index.html');
  if (route === '/export-viewer') return path.join(PUBLIC_ROOT, 'export-viewer/index.html');
  return path.join(PUBLIC_ROOT, route.slice(1));
}

function sourceFileToFilePath(sourceFile) {
  return path.join(PUBLIC_ROOT, sourceFile);
}

function expectedContentTypeForSourceFile(sourceFile) {
  const match = EXPECTED_CONTENT_TYPES.find((entry) => sourceFile.endsWith(entry.suffix));
  return match?.contentType || 'application/octet-stream';
}

function assetByRoute(assets) {
  return new Map(assets.map((asset) => [asset.route, asset]));
}

function isReferencedRouteAsset(asset) {
  return REFERENCED_ROUTE_CLASSES.has(asset.routeClass);
}

function isIgnoredReference(specifier) {
  const trimmed = String(specifier || '').trim();
  if (!trimmed) return true;
  if (trimmed.startsWith('#')) return true;
  if (trimmed.startsWith('data:')) return true;
  if (trimmed.startsWith('blob:')) return true;
  if (trimmed.startsWith('http:')) return true;
  if (trimmed.startsWith('https:')) return true;
  if (trimmed.startsWith('mailto:')) return true;
  return false;
}

function referencedRouteForSpecifier(sourceRoute, specifier) {
  const cleanSpecifier = specifier.split('#')[0].split('?')[0];
  if (isIgnoredReference(cleanSpecifier)) return undefined;
  const sourceUrl = new URL(sourceRoute, 'https://wallet.static.local');
  const referencedRoute = new URL(cleanSpecifier, sourceUrl).pathname;
  if (referencedRoute.endsWith('/')) return undefined;
  return referencedRoute;
}

function addPatternReferences(references, content, pattern) {
  pattern.lastIndex = 0;
  let match = pattern.exec(content);
  while (match) {
    references.add(match[1]);
    match = pattern.exec(content);
  }
}

function addCssUrlReferences(references, content) {
  CSS_URL_PATTERN.lastIndex = 0;
  let match = CSS_URL_PATTERN.exec(content);
  while (match) {
    references.add(match[2]);
    match = CSS_URL_PATTERN.exec(content);
  }
}

function referencesForAsset(asset, content) {
  const references = new Set();
  if (asset.routeClass === 'htmlDocument') {
    addPatternReferences(references, content, HTML_REFERENCE_PATTERN);
  }
  if (asset.routeClass === 'javascript') {
    for (const pattern of JS_REFERENCE_PATTERNS) {
      addPatternReferences(references, content, pattern);
    }
    addPatternReferences(references, content, SOURCE_MAPPING_URL_PATTERN);
  }
  if (asset.routeClass === 'css') {
    addCssUrlReferences(references, content);
    addPatternReferences(references, content, SOURCE_MAPPING_URL_PATTERN);
  }
  return references;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, 'utf-8'));
}

async function assertFileExists(filePath, label) {
  try {
    const stat = await fs.stat(filePath);
    assert(stat.isFile(), `${label} is not a file: ${filePath}`);
  } catch (error) {
    if (error && error.code === 'ENOENT') throw new Error(`${label} is missing: ${filePath}`);
    throw error;
  }
}

function assertUniqueAssets(assets) {
  const routes = new Set();
  const sourceFiles = new Set();
  for (const asset of assets) {
    assert(!routes.has(asset.route), `Duplicate wallet asset route: ${asset.route}`);
    assert(!sourceFiles.has(asset.sourceFile), `Duplicate wallet asset source: ${asset.sourceFile}`);
    routes.add(asset.route);
    sourceFiles.add(asset.sourceFile);
  }
}

async function assertManifestFilesExist(assets) {
  for (const asset of assets) {
    await assertFileExists(sourceFileToFilePath(asset.sourceFile), `Asset ${asset.route}`);
  }
}

function assertRequiredRoutes(routes) {
  for (const route of REQUIRED_ROUTES) {
    assert(routes.has(route), `Missing required wallet static route: ${route}`);
  }
}

async function assertCanonicalWalletStaticAssets() {
  for (const fileName of CANONICAL_WALLET_STATIC_ASSETS) {
    const sourcePath = path.join(WALLET_STATIC_ASSETS_ROOT, fileName);
    const publicPath = path.join(PUBLIC_SDK, fileName);
    const source = await fs.readFile(sourcePath, 'utf-8');
    const published = await fs.readFile(publicPath, 'utf-8');
    assert(published === source, `${publicPath} must match ${sourcePath}`);
  }
}

function assertContentTypes(assets) {
  for (const asset of assets) {
    const expected = expectedContentTypeForSourceFile(asset.sourceFile);
    assert(
      asset.contentType === expected,
      `Unexpected content type for ${asset.sourceFile}: ${asset.contentType} !== ${expected}`,
    );
  }
}

function assertRequiredHeaders(assets) {
  for (const asset of assets) {
    const contentTypeHeader = asset.requiredHeaders?.find((header) => {
      return header.name === 'Content-Type';
    });
    assert(contentTypeHeader, `Missing Content-Type header metadata for ${asset.route}`);
    assert(
      contentTypeHeader.value === asset.contentType,
      `Content-Type header does not match contentType for ${asset.route}`,
    );
  }
}

async function assertAssetReferencesResolve(assets, routes) {
  for (const asset of assets.filter(isReferencedRouteAsset)) {
    const content = await fs.readFile(sourceFileToFilePath(asset.sourceFile), 'utf-8');
    const references = referencesForAsset(asset, content);
    for (const reference of references) {
      const referencedRoute = referencedRouteForSpecifier(asset.route, reference);
      if (!referencedRoute) continue;
      assert(
        routes.has(referencedRoute),
        `${asset.route} references missing static asset ${referencedRoute}`,
      );
    }
  }
}

function assertWorkerCompanions(routes) {
  for (const pair of WORKER_WASM_COMPANIONS) {
    assert(routes.has(pair.worker), `Missing worker route: ${pair.worker}`);
    for (const companion of pair.companions) {
      assert(routes.has(companion), `Missing companion for ${pair.worker}: ${companion}`);
    }
  }
}

function assertHeaderManifest(headersManifest) {
  assert(headersManifest.schemaVersion === 1, 'headers.manifest.json schemaVersion must be 1');
  const classes = new Set(headersManifest.routeClasses?.map((entry) => entry.routePattern) || []);
  for (const routeClass of REQUIRED_HEADER_ROUTE_CLASSES) {
    assert(classes.has(routeClass), `headers.manifest.json missing route class ${routeClass}`);
  }
}

function assertVersionSkewContract(versionSkewContract) {
  assert(versionSkewContract, 'wallet-assets.manifest.json missing versionSkewContract');
  assert(
    versionSkewContract.kind === 'wallet_iframe_protocol_handshake',
    'versionSkewContract.kind must be wallet_iframe_protocol_handshake',
  );
  assert(
    typeof versionSkewContract.protocolVersion === 'string' &&
      versionSkewContract.protocolVersion.length > 0,
    'versionSkewContract.protocolVersion must be a non-empty string',
  );
  assert(
    versionSkewContract.readyPayloadField === 'protocolVersion',
    'versionSkewContract.readyPayloadField must be protocolVersion',
  );
  assert(
    versionSkewContract.failureMode === 'typed_error',
    'versionSkewContract.failureMode must be typed_error',
  );
  assert(
    versionSkewContract.errorCode === 'WALLET_IFRAME_PROTOCOL_VERSION_MISMATCH',
    'versionSkewContract.errorCode must be WALLET_IFRAME_PROTOCOL_VERSION_MISMATCH',
  );
}

function assertManifestShape(assetsManifest, headersManifest) {
  assert(assetsManifest.schemaVersion === 1, 'wallet-assets.manifest.json schemaVersion must be 1');
  assert(headersManifest.schemaVersion === 1, 'headers.manifest.json schemaVersion must be 1');
  assert(Array.isArray(assetsManifest.assets), 'wallet-assets.manifest.json must contain assets[]');
  assert(assetsManifest.headersManifest === 'headers.manifest.json', 'assets manifest must point at headers.manifest.json');
  assertVersionSkewContract(assetsManifest.versionSkewContract);
}

async function assertStaticWalletAssets() {
  await assertFileExists(ASSETS_MANIFEST_PATH, 'wallet-assets.manifest.json');
  await assertFileExists(HEADERS_MANIFEST_PATH, 'headers.manifest.json');
  const assetsManifest = await readJson(ASSETS_MANIFEST_PATH);
  const headersManifest = await readJson(HEADERS_MANIFEST_PATH);
  assertManifestShape(assetsManifest, headersManifest);
  assertHeaderManifest(headersManifest);
  const assets = assetsManifest.assets;
  assertUniqueAssets(assets);
  await assertManifestFilesExist(assets);
  assertContentTypes(assets);
  assertRequiredHeaders(assets);
  const routes = assetByRoute(assets);
  assertRequiredRoutes(routes);
  await assertCanonicalWalletStaticAssets();
  await assertAssetReferencesResolve(assets, routes);
  assertWorkerCompanions(routes);
  console.log(`Static wallet asset manifest OK (${assets.length} assets)`);
}

await assertStaticWalletAssets();

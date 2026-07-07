#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const SDK_ROOT = path.resolve(SCRIPT_DIR, '../..');
const DIST_ROOT = path.join(SDK_ROOT, 'dist');
const DIST_ESM_SDK = path.join(DIST_ROOT, 'esm/sdk');
const DIST_WORKERS = path.join(DIST_ROOT, 'workers');
const DIST_PUBLIC = path.join(DIST_ROOT, 'public');
const PUBLIC_SDK = path.join(DIST_PUBLIC, 'sdk');
const PUBLIC_WORKERS = path.join(PUBLIC_SDK, 'workers');
const WALLET_SERVICE_HTML = path.join(DIST_PUBLIC, 'wallet-service/index.html');
const EXPORT_VIEWER_HTML = path.join(DIST_PUBLIC, 'export-viewer/index.html');
const HEADERS_MANIFEST = path.join(DIST_PUBLIC, 'headers.manifest.json');
const ASSETS_MANIFEST = path.join(DIST_PUBLIC, 'wallet-assets.manifest.json');
const DIST_WALLET_MESSAGES = path.join(
  DIST_ROOT,
  'esm/SeamsWeb/walletIframe/shared/messages.js',
);

const PACKAGE_JSON = JSON.parse(await fs.readFile(path.join(SDK_ROOT, 'package.json'), 'utf-8'));

const HEADER_NAMES = {
  cacheControl: 'Cache-Control',
  contentSecurityPolicy: 'Content-Security-Policy',
  contentType: 'Content-Type',
};

const FORBIDDEN_DEFAULT_ASSET_HEADERS = [
  'Content-Security-Policy',
  'Cross-Origin-Embedder-Policy',
  'Cross-Origin-Opener-Policy',
  'Cross-Origin-Resource-Policy',
  'Permissions-Policy',
];

const ROUTE_CLASS_HEADERS = {
  javascript: {
    cachePolicy: 'public, max-age=300, must-revalidate',
    contentType: 'text/javascript; charset=utf-8',
  },
  css: {
    cachePolicy: 'public, max-age=300, must-revalidate',
    contentType: 'text/css; charset=utf-8',
  },
  wasm: {
    cachePolicy: 'public, max-age=300, must-revalidate',
    contentType: 'application/wasm',
  },
  htmlDocument: {
    cachePolicy: 'no-store',
    contentType: 'text/html; charset=utf-8',
    frameAncestors: "frame-ancestors 'self' http://localhost:* https://localhost:*",
  },
  json: {
    cachePolicy: 'no-store',
    contentType: 'application/json; charset=utf-8',
  },
};

function toPosixPath(input) {
  return input.split(path.sep).join('/');
}

function compareBySourceFile(left, right) {
  return left.sourceFile.localeCompare(right.sourceFile);
}

function isNotGeneratedAssetsManifest(sourceFile) {
  return sourceFile !== 'wallet-assets.manifest.json';
}

function routeForSourceFile(sourceFile) {
  if (sourceFile === 'wallet-service/index.html') return '/wallet-service';
  if (sourceFile === 'export-viewer/index.html') return '/export-viewer';
  return `/${sourceFile}`;
}

function routeClassForSourceFile(sourceFile) {
  if (sourceFile.endsWith('.wasm')) return 'wasm';
  if (sourceFile.endsWith('.js')) return 'javascript';
  if (sourceFile.endsWith('.css')) return 'css';
  if (sourceFile.endsWith('.html')) return 'htmlDocument';
  if (sourceFile.endsWith('.json')) return 'json';
  if (sourceFile.endsWith('.map')) return 'json';
  return 'binary';
}

function ownerForSourceFile(sourceFile) {
  if (sourceFile === 'wallet-service/index.html') return 'wallet_service_document';
  if (sourceFile === 'export-viewer/index.html') return 'export_viewer_document';
  if (sourceFile.startsWith('sdk/workers/')) return 'wallet_worker_runtime';
  if (sourceFile.startsWith('sdk/')) return 'wallet_sdk_asset';
  if (sourceFile.endsWith('.manifest.json')) return 'wallet_asset_manifest';
  return 'wallet_static_asset';
}

function requiredHeadersForRouteClass(routeClass) {
  const headers = ROUTE_CLASS_HEADERS[routeClass];
  if (!headers) return [];
  const required = [
    { name: HEADER_NAMES.contentType, value: headers.contentType },
    { name: HEADER_NAMES.cacheControl, value: headers.cachePolicy },
  ];
  if (routeClass === 'htmlDocument') {
    required.push({
      name: HEADER_NAMES.contentSecurityPolicy,
      value: headers.frameAncestors,
      purpose: 'embedding_control',
      stage: 'local_dev_default',
    });
  }
  return required;
}

function cachePolicyForRouteClass(routeClass) {
  return ROUTE_CLASS_HEADERS[routeClass]?.cachePolicy || 'public, max-age=300, must-revalidate';
}

function contentTypeForRouteClass(routeClass) {
  return ROUTE_CLASS_HEADERS[routeClass]?.contentType || 'application/octet-stream';
}

function manifestEntryForSourceFile(sourceFile) {
  const routeClass = routeClassForSourceFile(sourceFile);
  return {
    route: routeForSourceFile(sourceFile),
    sourceFile,
    owner: ownerForSourceFile(sourceFile),
    routeClass,
    contentType: contentTypeForRouteClass(routeClass),
    cachePolicy: cachePolicyForRouteClass(routeClass),
    requiredHeaders: requiredHeadersForRouteClass(routeClass),
  };
}

async function assertDirectoryExists(directory, label) {
  try {
    const stat = await fs.stat(directory);
    if (stat.isDirectory()) return;
  } catch {}
  throw new Error(`${label} is missing: ${directory}`);
}

async function copyDirectory(source, destination) {
  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.cp(source, destination, { recursive: true });
}

async function readPluginUtils() {
  const pluginUtilsPath = path.join(DIST_ROOT, 'esm/plugins/plugin-utils.js');
  try {
    await fs.access(pluginUtilsPath);
  } catch {
    throw new Error(`Missing built plugin utils: ${pluginUtilsPath}`);
  }
  return await import(pathToFileURL(pluginUtilsPath).href);
}

async function readWalletProtocolVersion() {
  try {
    await fs.access(DIST_WALLET_MESSAGES);
  } catch {
    throw new Error(`Missing built wallet protocol messages: ${DIST_WALLET_MESSAGES}`);
  }
  const module = await import(pathToFileURL(DIST_WALLET_MESSAGES).href);
  if (typeof module.WALLET_PROTOCOL_VERSION === 'string' && module.WALLET_PROTOCOL_VERSION) {
    return module.WALLET_PROTOCOL_VERSION;
  }
  throw new Error(`Built wallet protocol messages must export WALLET_PROTOCOL_VERSION`);
}

async function writeHtmlDocuments() {
  const { buildWalletServiceHtml, buildExportViewerHtml } = await readPluginUtils();
  await fs.mkdir(path.dirname(WALLET_SERVICE_HTML), { recursive: true });
  await fs.mkdir(path.dirname(EXPORT_VIEWER_HTML), { recursive: true });
  await fs.writeFile(WALLET_SERVICE_HTML, buildWalletServiceHtml('/sdk', undefined, 'runtime'));
  await fs.writeFile(EXPORT_VIEWER_HTML, buildExportViewerHtml('/sdk'));
}

async function collectFiles(directory) {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await collectFiles(fullPath)));
      continue;
    }
    if (entry.isFile()) files.push(fullPath);
  }
  return files;
}

function sourceFileForPublicFile(filePath) {
  return toPosixPath(path.relative(DIST_PUBLIC, filePath));
}

async function buildAssetEntries() {
  const files = await collectFiles(DIST_PUBLIC);
  const sourceFiles = files.map(sourceFileForPublicFile).filter(isNotGeneratedAssetsManifest);
  sourceFiles.push('wallet-assets.manifest.json');
  return sourceFiles.map(manifestEntryForSourceFile).sort(compareBySourceFile);
}

function buildHeadersManifest() {
  return {
    schemaVersion: 1,
    packageName: PACKAGE_JSON.name,
    packageVersion: PACKAGE_JSON.version,
    assetRoot: 'dist/public',
    routeClasses: [
      {
        routePattern: '/sdk/*.js',
        routeClass: 'javascript',
        owner: 'wallet_sdk_asset',
        requiredHeaders: requiredHeadersForRouteClass('javascript'),
        forbiddenDefaultHeaders: FORBIDDEN_DEFAULT_ASSET_HEADERS,
      },
      {
        routePattern: '/sdk/*.css',
        routeClass: 'css',
        owner: 'wallet_sdk_asset',
        requiredHeaders: requiredHeadersForRouteClass('css'),
        forbiddenDefaultHeaders: FORBIDDEN_DEFAULT_ASSET_HEADERS,
      },
      {
        routePattern: '/sdk/workers/*.js',
        routeClass: 'javascript',
        owner: 'wallet_worker_runtime',
        requiredHeaders: requiredHeadersForRouteClass('javascript'),
        forbiddenDefaultHeaders: FORBIDDEN_DEFAULT_ASSET_HEADERS,
      },
      {
        routePattern: '/sdk/workers/*.wasm',
        routeClass: 'wasm',
        owner: 'wallet_worker_runtime',
        requiredHeaders: requiredHeadersForRouteClass('wasm'),
        forbiddenDefaultHeaders: FORBIDDEN_DEFAULT_ASSET_HEADERS,
      },
      {
        routePattern: '/wallet-service',
        routeClass: 'htmlDocument',
        owner: 'wallet_service_document',
        requiredHeaders: requiredHeadersForRouteClass('htmlDocument'),
        forbiddenDefaultHeaders: [
          'Cross-Origin-Embedder-Policy',
          'Cross-Origin-Opener-Policy',
          'Cross-Origin-Resource-Policy',
          'Permissions-Policy',
        ],
      },
      {
        routePattern: '/export-viewer',
        routeClass: 'htmlDocument',
        owner: 'export_viewer_document',
        requiredHeaders: requiredHeadersForRouteClass('htmlDocument'),
        forbiddenDefaultHeaders: [
          'Cross-Origin-Embedder-Policy',
          'Cross-Origin-Opener-Policy',
          'Cross-Origin-Resource-Policy',
          'Permissions-Policy',
        ],
      },
      {
        routePattern: '/*.manifest.json',
        routeClass: 'json',
        owner: 'wallet_asset_manifest',
        requiredHeaders: requiredHeadersForRouteClass('json'),
      },
    ],
  };
}

function buildAssetsManifest(assets, walletProtocolVersion) {
  return {
    schemaVersion: 1,
    packageName: PACKAGE_JSON.name,
    packageVersion: PACKAGE_JSON.version,
    assetRoot: 'dist/public',
    sdkBasePath: '/sdk',
    walletServicePath: '/wallet-service',
    exportViewerPath: '/export-viewer',
    headersManifest: 'headers.manifest.json',
    versionSkewContract: {
      kind: 'wallet_iframe_protocol_handshake',
      packageVersion: PACKAGE_JSON.version,
      protocolVersion: walletProtocolVersion,
      readyPayloadField: 'protocolVersion',
      failureMode: 'typed_error',
      errorCode: 'WALLET_IFRAME_PROTOCOL_VERSION_MISMATCH',
    },
    assets,
  };
}

async function emitStaticWalletAssets() {
  await assertDirectoryExists(DIST_ESM_SDK, 'SDK browser asset output');
  await assertDirectoryExists(DIST_WORKERS, 'SDK worker output');
  await fs.rm(DIST_PUBLIC, { recursive: true, force: true });
  await copyDirectory(DIST_ESM_SDK, PUBLIC_SDK);
  await copyDirectory(DIST_WORKERS, PUBLIC_WORKERS);
  await writeHtmlDocuments();
  await fs.writeFile(HEADERS_MANIFEST, `${JSON.stringify(buildHeadersManifest(), null, 2)}\n`);
  const walletProtocolVersion = await readWalletProtocolVersion();
  const assets = await buildAssetEntries();
  await fs.writeFile(
    ASSETS_MANIFEST,
    `${JSON.stringify(buildAssetsManifest(assets, walletProtocolVersion), null, 2)}\n`,
  );
  console.log(`Emitted hosted wallet static assets at ${path.relative(SDK_ROOT, DIST_PUBLIC)}`);
}

await emitStaticWalletAssets();

#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');

const runtimeForbiddenPatterns = [
  /\bWalletIframe\b/,
  /\bSeamsWeb\b/,
  /from\s+['"][^'"]*react[^'"]*['"]/,
  /\bwindow\b/,
  /\bdocument\b/,
  /\bnavigator\b/,
  /\bDOMException\b/,
  /\bIndexedDBManager\b/,
  /\bUnifiedIndexedDBManager\b/,
  /\bcreateBrowserPlatformRuntime\b/,
  /\bgetBrowserPlatformIndexedDB\b/,
  /platform\/browser/,
  /from\s+['"]@simplewebauthn\/server['"]/,
  /import\s*\(\s*['"]@simplewebauthn\/server['"]\s*\)/,
  /from\s+['"]pg['"]/,
  /import\s*\(\s*['"]pg['"]\s*\)/,
];

const getBrowserPlatformIndexedDBAllowList = guardBoundaryEntries([
  {
    file: 'packages/sdk-web/src/core/platform/index.ts',
    owner: 'platform browser adapter barrel',
    reason: 'exports the browser IndexedDB adapter for web assembly consumers',
  },
  {
    file: 'packages/sdk-web/src/core/platform/browser/createBrowserPlatformRuntime.ts',
    owner: 'browser platform adapter',
    reason: 'defines the browser IndexedDB accessor until browser store adapters replace it',
  },
]);

const browserRuntimeConstructionAllowList = guardBoundaryEntries([
  {
    file: 'packages/sdk-web/src/core/platform/index.ts',
    owner: 'platform browser adapter barrel',
    reason: 'exports the browser platform runtime for web assembly consumers',
  },
  {
    file: 'packages/sdk-web/src/core/platform/browser/createBrowserPlatformRuntime.ts',
    owner: 'browser platform adapter',
    reason: 'defines current browser platform runtime',
  },
  {
    file: 'packages/sdk-web/src/SeamsWeb/assembly/createBrowserSigningRuntime.ts',
    owner: 'browser runtime assembly',
    reason: 'browser web assembly constructs the browser platform runtime for SeamsWeb',
  },
]);

const walletIframeCoreImportAllowList = guardBoundaryEntries([
  {
    file: 'packages/sdk-web/src/core/config/configBuilder.ts',
    owner: 'runtime/web config split',
    reason: 'current resolved SDK config still normalizes iframe wallet fields in core config',
  },
  {
    file: 'packages/sdk-web/src/core/types/seams.ts',
    owner: 'runtime/web config split',
    reason: 'current shared config types still include iframe wallet fields',
  },
  {
    file: 'packages/sdk-web/src/core/rpcClients/relayer/sealedRefreshCapabilities.ts',
    owner: 'web sealed-refresh boundary',
    reason: 'current sealed-refresh exchange types still carry wallet iframe expected-origin data',
  },
  {
    file: 'packages/sdk-web/src/core/browser/walletIframe/events.ts',
    owner: 'browser wallet iframe primitive',
    reason: 'shared browser-platform event constants stay outside wallet iframe implementation',
  },
  {
    file: 'packages/sdk-web/src/core/browser/walletIframe/host-mode.ts',
    owner: 'browser wallet iframe primitive',
    reason: 'shared browser-platform host-mode state stays outside wallet iframe implementation',
  },
  {
    prefix: 'packages/sdk-web/src/SeamsWeb/',
    owner: 'browser web facade',
    reason: 'current browser facade owns wallet iframe routing',
  },
  {
    prefix: 'packages/sdk-web/src/SeamsWeb/walletIframe/',
    owner: 'browser wallet iframe implementation',
    reason: 'current wallet iframe implementation imports within its own browser-only tree',
  },
  {
    prefix: 'packages/sdk-web/src/react/',
    owner: 'browser React entrypoint',
    reason: 'current React hooks coordinate wallet iframe readiness and assets',
  },
  {
    prefix: 'packages/sdk-web/src/plugins/',
    owner: 'browser plugin entrypoints',
    reason: 'current browser plugins import wallet iframe host variants',
  },
  {
    prefix: 'packages/sdk-web/src/core/signingEngine/uiConfirm/',
    owner: 'browser confirmation UI',
    reason: 'current confirmation UI modules include iframe-hosted browser UI surfaces',
  },
]);

const nativeAndEmbeddedRoots = [
  'packages/sdk-web/src/core/platform/ios',
  'packages/sdk-web/src/core/platform/embedded',
];

const nativeAndEmbeddedForbiddenPatterns = [
  /\bWalletIframe\b/,
  /core\/WalletIframe/,
  /from\s+['"][^'"]*react[^'"]*['"]/,
  /\bwindow\b/,
  /\bdocument\b/,
  /\bnavigator\b/,
  /\bDOMException\b/,
  /\bIndexedDBManager\b/,
  /\bUnifiedIndexedDBManager\b/,
  /platform\/browser/,
  /SeamsWeb/,
];

const useCaseIndexedDBForbiddenPatterns = [
  /\bIndexedDBManager\b/,
  /\bUnifiedIndexedDBManager\b/,
  /core\/indexedDB/,
  /\/indexedDB(?:\/|['"])/,
];

const forbiddenNativeFacadePaths = [
  'packages/sdk-web/src/ios',
  'packages/sdk-web/src/embedded',
  'packages/sdk-web/src/ios.ts',
  'packages/sdk-web/src/embedded.ts',
];

const chainSignerFiles = [
  'packages/sdk-web/src/SeamsWeb/operations/near/index.ts',
  'packages/sdk-web/src/SeamsWeb/operations/tempo/index.ts',
  'packages/sdk-web/src/SeamsWeb/operations/evm/index.ts',
];

const chainSignerForbiddenPatterns = [
  /\brouteWalletIframeOrLocal\b/,
  /\bWalletIframeRouteDeps\b/,
  /\bWalletIframeCoordinator\b/,
  /\bWalletIframeRouter\b/,
  /\bwalletIframe\b/,
];

function absolutePath(relativePath) {
  return path.join(repoRoot, relativePath);
}

function pathExists(relativePath) {
  return fs.existsSync(absolutePath(relativePath));
}

function readRepoFile(relativePath) {
  return fs.readFileSync(absolutePath(relativePath), 'utf8');
}

function isTypeScriptFileName(fileName) {
  return /\.tsx?$/.test(fileName);
}

function guardBoundaryEntries(entries) {
  const seen = new Set();
  for (const entry of entries) {
    const key = entry.file ? `file:${entry.file}` : `prefix:${entry.prefix}`;
    if (!entry.file && !entry.prefix) {
      throw new Error('Guard boundary entry requires file or prefix');
    }
    if (seen.has(key)) {
      throw new Error(`Duplicate guard boundary entry: ${key}`);
    }
    seen.add(key);
    if (!entry.owner.trim() || !entry.reason.trim()) {
      throw new Error(`Incomplete guard boundary entry: ${key}`);
    }
  }
  return entries;
}

function entryMatchesFile(entry, file) {
  if (entry.file) {
    return entry.file === file;
  }
  return Boolean(entry.prefix && file.startsWith(entry.prefix));
}

function isAllowed(file, entries) {
  for (const entry of entries) {
    if (entryMatchesFile(entry, file)) {
      return true;
    }
  }
  return false;
}

function listFiles(relativeDir, files) {
  const absoluteDir = absolutePath(relativeDir);
  if (!fs.existsSync(absoluteDir)) {
    return;
  }

  const entries = fs.readdirSync(absoluteDir, { withFileTypes: true });
  for (const entry of entries) {
    const relativePath = path.join(relativeDir, entry.name).split(path.sep).join('/');
    if (entry.isDirectory()) {
      listFiles(relativePath, files);
      continue;
    }
    if (entry.isFile() && isTypeScriptFileName(entry.name)) {
      files.push(relativePath);
    }
  }
}

function listTypeScriptFiles(relativeDir) {
  const files = [];
  listFiles(relativeDir, files);
  return files;
}

function listTypeScriptFilesInRoots(relativeRoots) {
  const files = new Set();
  for (const relativeRoot of relativeRoots) {
    const absoluteRoot = absolutePath(relativeRoot);
    if (!fs.existsSync(absoluteRoot)) {
      continue;
    }

    const stat = fs.statSync(absoluteRoot);
    if (stat.isDirectory()) {
      const rootFiles = listTypeScriptFiles(relativeRoot);
      for (const file of rootFiles) {
        files.add(file);
      }
      continue;
    }
    if (stat.isFile() && isTypeScriptFileName(relativeRoot)) {
      files.add(relativeRoot);
    }
  }
  return [...files].sort();
}

function collectPatternViolations(files, patterns, suffix) {
  const violations = [];
  for (const file of files) {
    const source = readRepoFile(file);
    for (const pattern of patterns) {
      if (pattern.test(source)) {
        violations.push(`${file}: ${suffix}: ${pattern}`);
      }
    }
  }
  return violations;
}

function collectRuntimeViolations() {
  return collectPatternViolations(
    listTypeScriptFiles('packages/sdk-web/src/core/runtime'),
    runtimeForbiddenPatterns,
    'core runtime import/platform leak',
  );
}

function collectSigningWarmupViolations() {
  const violations = [];
  const source = readRepoFile('packages/sdk-web/src/core/signingEngine/assembly/warmup.ts');

  if (!source.includes('shouldPrewarmWorkers')) {
    violations.push('warmup.ts missing shouldPrewarmWorkers');
  }
  for (const forbidden of ['window', 'document', 'navigator']) {
    if (source.includes(forbidden)) {
      violations.push(`warmup.ts contains browser global ${forbidden}`);
    }
  }

  return violations;
}

function collectUseCaseIndexedDBViolations() {
  return collectPatternViolations(
    listTypeScriptFiles('packages/sdk-web/src/core/signingEngine/useCases'),
    useCaseIndexedDBForbiddenPatterns,
    'use case imports IndexedDB persistence implementation',
  );
}

function collectBrowserIndexedDBAccessorViolations() {
  const violations = [];
  const files = listTypeScriptFilesInRoots(['packages/sdk-web/src']);

  for (const file of files) {
    const source = readRepoFile(file);
    if (!/\bgetBrowserPlatformIndexedDB\b/.test(source)) {
      continue;
    }
    if (isAllowed(file, getBrowserPlatformIndexedDBAllowList)) {
      continue;
    }
    violations.push(`${file}: getBrowserPlatformIndexedDB outside owned boundary`);
  }

  return violations;
}

function collectBrowserRuntimeConstructionViolations() {
  const violations = [];
  const files = listTypeScriptFilesInRoots(['packages/sdk-web/src']);

  for (const file of files) {
    const source = readRepoFile(file);
    if (!/\bcreateBrowserPlatformRuntime\b/.test(source)) {
      continue;
    }
    if (isAllowed(file, browserRuntimeConstructionAllowList)) {
      continue;
    }
    violations.push(`${file}: createBrowserPlatformRuntime outside browser assembly boundary`);
  }

  return violations;
}

function collectNativeAndEmbeddedViolations() {
  return collectPatternViolations(
    listTypeScriptFilesInRoots(nativeAndEmbeddedRoots),
    nativeAndEmbeddedForbiddenPatterns,
    'native or embedded SDK imports browser surface',
  );
}

function collectNativeFacadeViolations() {
  const violations = [];
  for (const relativePath of forbiddenNativeFacadePaths) {
    if (pathExists(relativePath)) {
      violations.push(`${relativePath}: TypeScript native facade exists`);
    }
  }

  const forbiddenNamePattern = /(?:SeamsIOS|IoSSigningSurface|SeamsEmbedded|EmbeddedSigningSurface)/;
  const files = listTypeScriptFilesInRoots(['packages/sdk-web/src']);
  for (const file of files) {
    if (forbiddenNamePattern.test(file)) {
      violations.push(`${file}: TypeScript native facade name exists`);
    }
  }

  return violations;
}

function collectWalletIframeCoreImportViolations() {
  const violations = [];
  const files = listTypeScriptFilesInRoots(['packages/sdk-web/src']);

  for (const file of files) {
    const source = readRepoFile(file);
    if (!/WalletIframe|core\/WalletIframe/.test(source)) {
      continue;
    }
    if (isAllowed(file, walletIframeCoreImportAllowList)) {
      continue;
    }
    violations.push(`${file}: WalletIframe import outside web-owned boundary`);
  }

  return violations;
}

function collectChainSignerRoutingViolations() {
  const violations = [];
  for (const file of chainSignerFiles) {
    const source = readRepoFile(file);
    for (const pattern of chainSignerForbiddenPatterns) {
      if (pattern.test(source)) {
        violations.push(`${file}: chain signer contains iframe routing: ${pattern}`);
      }
    }
  }

  if (pathExists('packages/sdk-web/src/SeamsWeb/walletIframeRoute.ts')) {
    violations.push('packages/sdk-web/src/SeamsWeb/walletIframeRoute.ts exists');
  }

  return violations;
}

function main() {
  const violations = [
    ...collectRuntimeViolations(),
    ...collectSigningWarmupViolations(),
    ...collectUseCaseIndexedDBViolations(),
    ...collectBrowserIndexedDBAccessorViolations(),
    ...collectBrowserRuntimeConstructionViolations(),
    ...collectNativeAndEmbeddedViolations(),
    ...collectNativeFacadeViolations(),
    ...collectWalletIframeCoreImportViolations(),
    ...collectChainSignerRoutingViolations(),
  ];

  if (violations.length > 0) {
    console.error('[check-platform-runtime-boundaries] failed');
    for (const violation of violations) {
      console.error(`- ${violation}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log('[check-platform-runtime-boundaries] passed');
}

main();

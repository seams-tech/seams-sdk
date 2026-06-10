import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

type GuardBoundaryEntry = {
  file?: string;
  prefix?: string;
  owner: string;
  reason: string;
};

function guardBoundaryEntries(entries: readonly GuardBoundaryEntry[]): readonly GuardBoundaryEntry[] {
  const seen = new Set<string>();
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

function entryMatchesFile(entry: GuardBoundaryEntry, file: string): boolean {
  if (entry.file) return entry.file === file;
  return Boolean(entry.prefix && file.startsWith(entry.prefix));
}

function isAllowed(file: string, entries: readonly GuardBoundaryEntry[]): boolean {
  return entries.some((entry) => entryMatchesFile(entry, file));
}

function listFiles(relativeDir: string, predicate: (fileName: string) => boolean): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  if (!fs.existsSync(absoluteDir)) return [];
  const entries = fs.readdirSync(absoluteDir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listFiles(relativePath, predicate));
      continue;
    }
    if (entry.isFile() && predicate(entry.name)) {
      files.push(relativePath);
    }
  }
  return files;
}

function listTypeScriptFiles(relativeDir: string): string[] {
  return listFiles(relativeDir, (fileName) => /\.tsx?$/.test(fileName));
}

function listTypeScriptFilesInRoots(relativeRoots: readonly string[]): string[] {
  const files = new Set<string>();
  for (const relativeRoot of relativeRoots) {
    const absoluteRoot = path.join(repoRoot, relativeRoot);
    if (!fs.existsSync(absoluteRoot)) continue;
    const stat = fs.statSync(absoluteRoot);
    if (stat.isDirectory()) {
      for (const file of listTypeScriptFiles(relativeRoot)) {
        files.add(file);
      }
      continue;
    }
    if (stat.isFile() && /\.tsx?$/.test(relativeRoot)) {
      files.add(relativeRoot);
    }
  }
  return [...files].sort();
}

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

const runtimeForbiddenPatterns = [
  /\bWalletIframe\b/,
  /\bSeamsWeb\b/,
  /from\s+['"][^'"]*react[^'"]*['"]/,
  /\bwindow\b/,
  /\bdocument\b/,
  /\bnavigator\b/,
  /\bIndexedDBManager\b/,
  /\bUnifiedIndexedDBManager\b/,
  /\bcreateBrowserPlatformRuntime\b/,
  /\bgetBrowserPlatformIndexedDB\b/,
  /platform\/browser/,
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

test.describe('refactor 51b platform boundary guards', () => {
  test('keeps core runtime free of browser, DOM, React, iframe, and IndexedDB imports', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFiles('packages/sdk-runtime-ts/src/runtime')) {
      const source = readRepoFile(file);
      for (const pattern of runtimeForbiddenPatterns) {
        if (pattern.test(source)) {
          violations.push(`${file}: ${pattern}`);
        }
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps shared signing warmup free of browser worker globals', () => {
    const source = readRepoFile('packages/sdk-web/src/core/signingEngine/assembly/warmup.ts');

    expect(source).toContain('shouldPrewarmWorkers');
    expect(source).not.toContain('window');
    expect(source).not.toContain('document');
    expect(source).not.toContain('navigator');
  });

  test('keeps signing use cases free of IndexedDB persistence implementations', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFiles('packages/sdk-web/src/core/signingEngine/useCases')) {
      const source = readRepoFile(file);
      for (const pattern of useCaseIndexedDBForbiddenPatterns) {
        if (pattern.test(source)) {
          violations.push(`${file}: ${pattern}`);
        }
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps getBrowserPlatformIndexedDB confined to owned Phase 3 boundaries', () => {
    const roots = ['packages/sdk-web/src'];
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots(roots)) {
      const source = readRepoFile(file);
      if (!/\bgetBrowserPlatformIndexedDB\b/.test(source)) continue;
      if (isAllowed(file, getBrowserPlatformIndexedDBAllowList)) continue;
      violations.push(file);
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps createBrowserPlatformRuntime confined to owned browser assembly boundaries', () => {
    const roots = ['packages/sdk-web/src'];
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots(roots)) {
      const source = readRepoFile(file);
      if (!/\bcreateBrowserPlatformRuntime\b/.test(source)) continue;
      if (isAllowed(file, browserRuntimeConstructionAllowList)) continue;
      violations.push(file);
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps native SDK notes free of browser surfaces', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots(nativeAndEmbeddedRoots)) {
      const source = readRepoFile(file);
      for (const pattern of nativeAndEmbeddedForbiddenPatterns) {
        if (pattern.test(source)) {
          violations.push(`${file}: ${pattern}`);
        }
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('does not grow TypeScript native SDK facades', () => {
    const forbiddenPaths = [
      'packages/sdk-web/src/ios',
      'packages/sdk-web/src/embedded',
      'packages/sdk-web/src/ios.ts',
      'packages/sdk-web/src/embedded.ts',
    ];
    const existing = forbiddenPaths.filter((relativePath) =>
      fs.existsSync(path.join(repoRoot, relativePath)),
    );

    const forbiddenNamePattern =
      /(?:SeamsIOS|IoSSigningSurface|SeamsEmbedded|EmbeddedSigningSurface)/;
    const namedOffenders = listTypeScriptFilesInRoots(['packages/sdk-web/src']).filter((file) =>
      forbiddenNamePattern.test(file),
    );

    expect([...existing, ...namedOffenders]).toEqual([]);
  });

  test('tracks current core WalletIframe imports as web-owned Phase 4 work', () => {
    const roots = ['packages/sdk-web/src'];
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots(roots)) {
      const source = readRepoFile(file);
      if (!/WalletIframe|core\/WalletIframe/.test(source)) continue;
      if (isAllowed(file, walletIframeCoreImportAllowList)) continue;
      violations.push(file);
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps chain signer modules local-only after SeamsWeb owns iframe routing', () => {
    const signerFiles = [
      'packages/sdk-web/src/SeamsWeb/operations/near/index.ts',
      'packages/sdk-web/src/SeamsWeb/operations/tempo/index.ts',
      'packages/sdk-web/src/SeamsWeb/operations/evm/index.ts',
    ];
    const violations: string[] = [];
    for (const file of signerFiles) {
      const source = readRepoFile(file);
      for (const pattern of [
        /\brouteWalletIframeOrLocal\b/,
        /\bWalletIframeRouteDeps\b/,
        /\bWalletIframeCoordinator\b/,
        /\bWalletIframeRouter\b/,
        /\bwalletIframe\b/,
      ]) {
        if (pattern.test(source)) {
          violations.push(`${file}: ${pattern}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
    expect(fs.existsSync(path.join(repoRoot, 'packages/sdk-web/src/SeamsWeb/walletIframeRoute.ts'))).toBe(
      false,
    );
  });
});

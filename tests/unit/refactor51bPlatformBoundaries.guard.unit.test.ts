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
    file: 'client/src/core/platform/index.ts',
    owner: 'platform browser adapter barrel',
    reason: 'exports the browser IndexedDB adapter for web assembly consumers',
  },
  {
    file: 'client/src/core/platform/browser/createBrowserPlatformRuntime.ts',
    owner: 'browser platform adapter',
    reason: 'defines the browser IndexedDB accessor until browser store adapters replace it',
  },
]);

const browserRuntimeConstructionAllowList = guardBoundaryEntries([
  {
    file: 'client/src/core/platform/index.ts',
    owner: 'platform browser adapter barrel',
    reason: 'exports the browser platform runtime for web assembly consumers',
  },
  {
    file: 'client/src/core/platform/browser/createBrowserPlatformRuntime.ts',
    owner: 'browser platform adapter',
    reason: 'defines current browser platform runtime',
  },
  {
    file: 'client/src/web/SeamsWeb/assembly/createBrowserSigningRuntime.ts',
    owner: 'browser runtime assembly',
    reason: 'browser web assembly constructs the browser platform runtime for SeamsWeb',
  },
]);

const walletIframeCoreImportAllowList = guardBoundaryEntries([
  {
    file: 'client/src/core/config/configBuilder.ts',
    owner: 'runtime/web config split',
    reason: 'current resolved SDK config still normalizes iframe wallet fields in core config',
  },
  {
    file: 'client/src/core/types/seams.ts',
    owner: 'runtime/web config split',
    reason: 'current shared config types still include iframe wallet fields',
  },
  {
    file: 'client/src/core/rpcClients/relayer/sealedRefreshCapabilities.ts',
    owner: 'web sealed-refresh boundary',
    reason: 'current sealed-refresh exchange types still carry wallet iframe expected-origin data',
  },
  {
    prefix: 'client/src/web/SeamsWeb/',
    owner: 'browser web facade',
    reason: 'current browser facade owns wallet iframe routing',
  },
  {
    prefix: 'client/src/core/WalletIframe/',
    owner: 'browser wallet iframe implementation',
    reason: 'current wallet iframe implementation imports within its own browser-only tree',
  },
  {
    prefix: 'client/src/react/',
    owner: 'browser React entrypoint',
    reason: 'current React hooks coordinate wallet iframe readiness and assets',
  },
  {
    prefix: 'client/src/plugins/',
    owner: 'browser plugin entrypoints',
    reason: 'current browser plugins import wallet iframe host variants',
  },
  {
    prefix: 'client/src/core/signingEngine/uiConfirm/',
    owner: 'browser confirmation UI',
    reason: 'current confirmation UI modules include iframe-hosted browser UI surfaces',
  },
]);

const nativeAndEmbeddedRoots = [
  'client/src/core/platform/ios',
  'client/src/core/platform/embedded',
  'client/src/ios',
  'client/src/embedded',
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
  /web\/SeamsWeb/,
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
    for (const file of listTypeScriptFiles('client/src/core/runtime')) {
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
    const source = readRepoFile('client/src/core/signingEngine/assembly/warmup.ts');

    expect(source).toContain('shouldPrewarmWorkers');
    expect(source).not.toContain('window');
    expect(source).not.toContain('document');
    expect(source).not.toContain('navigator');
  });

  test('keeps signing use cases free of IndexedDB persistence implementations', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFiles('client/src/core/signingEngine/useCases')) {
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
    const roots = ['client/src'];
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
    const roots = ['client/src'];
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots(roots)) {
      const source = readRepoFile(file);
      if (!/\bcreateBrowserPlatformRuntime\b/.test(source)) continue;
      if (isAllowed(file, browserRuntimeConstructionAllowList)) continue;
      violations.push(file);
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps future native and embedded roots free of browser surfaces', () => {
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

  test('tracks current core WalletIframe imports as web-owned Phase 4 work', () => {
    const roots = ['client/src'];
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
      'client/src/web/SeamsWeb/near/index.ts',
      'client/src/web/SeamsWeb/tempo/index.ts',
      'client/src/web/SeamsWeb/evm/index.ts',
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
    expect(fs.existsSync(path.join(repoRoot, 'client/src/web/SeamsWeb/walletIframeRoute.ts'))).toBe(
      false,
    );
  });
});

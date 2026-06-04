import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readJson(relativePath: string): Record<string, any> {
  return JSON.parse(fs.readFileSync(path.join(repoRoot, relativePath), 'utf8'));
}

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

const browserSurfacePatterns = [
  /\bWalletIframe\b/,
  /web\/SeamsWeb/,
  /from\s+['"][^'"]*react[^'"]*['"]/,
  /\bwindow\b/,
  /\bdocument\b/,
  /\bnavigator\b/,
  /\bIndexedDBManager\b/,
  /\bUnifiedIndexedDBManager\b/,
  /platform\/browser/,
];

test.describe('refactor 51b package exports', () => {
  test('maps public roots to current web, runtime, server, and native-facing entries', () => {
    const packageJson = readJson('sdk/package.json');
    const exportsMap = packageJson.exports;

    expect(exportsMap['.']?.import).toBe('./dist/esm/index.js');
    expect(readRepoFile('client/src/index.ts')).toContain('export { SeamsWeb }');
    expect(exportsMap['./react']?.import).toBe('./dist/esm/react/index.js');
    expect(readRepoFile('client/src/react/index.ts')).toContain('SeamsWebProvider');

    expect(exportsMap['./runtime']).toEqual({
      import: './dist/esm/runtime.js',
      default: './dist/esm/runtime.js',
      types: './dist/types/client/src/runtime.d.ts',
    });
    expect(exportsMap['./ios']).toEqual({
      import: './dist/esm/ios.js',
      default: './dist/esm/ios.js',
      types: './dist/types/client/src/ios.d.ts',
    });
    expect(exportsMap['./embedded']).toEqual({
      import: './dist/esm/embedded.js',
      default: './dist/esm/embedded.js',
      types: './dist/types/client/src/embedded.d.ts',
    });
  });

  test('keeps native-facing and runtime source entries free of browser surfaces', () => {
    const violations: string[] = [];
    for (const file of ['client/src/runtime.ts', 'client/src/ios.ts', 'client/src/embedded.ts']) {
      const source = readRepoFile(file);
      for (const pattern of browserSurfacePatterns) {
        if (pattern.test(source)) violations.push(`${file}: ${pattern}`);
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps WalletIframe HTML under a web-owned package export', () => {
    const packageJson = readJson('sdk/package.json');
    const exportsMap = packageJson.exports;

    expect(exportsMap['./WalletIframe/client/html']).toBeUndefined();
    expect(exportsMap['./components/modal']).toBeUndefined();
    expect(exportsMap['./components/embedded']).toBeUndefined();
    expect(exportsMap['./web/wallet-iframe-client-html']).toEqual({
      import: './dist/esm/core/WalletIframe/client/html.js',
      default: './dist/esm/core/WalletIframe/client/html.js',
      types: './dist/types/client/src/core/WalletIframe/client/html.d.ts',
    });
  });

  test('describes package surfaces without stale embedded-only positioning', () => {
    const packageJson = readJson('sdk/package.json');
    expect(packageJson.description).toContain('web');
    expect(packageJson.description).toContain('runtime');
    expect(packageJson.description).toContain('server');
    expect(packageJson.description).toContain('native-facing');
    expect(packageJson.keywords).toEqual(
      expect.arrayContaining(['browser', 'signing-runtime', 'server', 'native', 'embedded']),
    );
  });
});

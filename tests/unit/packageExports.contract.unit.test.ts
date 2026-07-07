import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readJson(relativePath: string): Record<string, any> {
  return JSON.parse(fs.readFileSync(path.join(repoRoot, relativePath), 'utf8'));
}

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function resolveSdkWebPath(packagePath: string): string {
  const normalized = packagePath.replace(/^\.\//, '');
  return path.join(repoRoot, 'packages/sdk-web', normalized);
}

function resolveSdkServerPath(packagePath: string): string {
  const normalized = packagePath.replace(/^\.\//, '');
  return path.join(repoRoot, 'packages/sdk-server-ts', normalized);
}

function isExperimentalExportKey(key: string): boolean {
  return key === './experimental' || key.startsWith('./experimental/');
}

function isPasskeyAuthMenuCompatExportKey(key: string): boolean {
  return key.includes('passkey-auth-menu-compat') || key.includes('passkeyAuthMenuCompat');
}

const browserSurfacePatterns = [
  /\bWalletIframe\b/,
  /SeamsWeb/,
  /from\s+['"][^'"]*react[^'"]*['"]/,
  /\bwindow\b/,
  /\bdocument\b/,
  /\bnavigator\b/,
  /\bIndexedDBManager\b/,
  /\bUnifiedIndexedDBManager\b/,
  /platform\/browser/,
];

test.describe('package export contracts', () => {
  test('maps public roots to current web and runtime entries', () => {
    const packageJson = readJson('packages/sdk-web/package.json');
    const exportsMap = packageJson.exports;

    expect(exportsMap['.']?.import).toBe('./dist/esm/index.js');
    expect(readRepoFile('packages/sdk-web/src/index.ts')).toContain('export { SeamsWeb }');
    expect(exportsMap['./react']?.import).toBe('./dist/esm/react/index.js');
    expect(readRepoFile('packages/sdk-web/src/react/index.ts')).toContain('SeamsWebProvider');

    expect(exportsMap['./runtime']).toEqual({
      import: './dist/esm/runtime.js',
      default: './dist/esm/runtime.js',
      types: './dist/types/sdk-web/src/runtime.d.ts',
    });
    expect(fs.existsSync(resolveSdkWebPath(exportsMap['./runtime'].types))).toBe(true);

    expect(exportsMap['./server']).toBeUndefined();
    expect(exportsMap['./server/router/express']).toBeUndefined();
    expect(exportsMap['./server/router/cloudflare']).toBeUndefined();
    expect(exportsMap['./server/router/ror']).toBeUndefined();
    expect(exportsMap['./server/storage/postgres']).toBeUndefined();
    expect(exportsMap['./server/wasm/signer']).toBeUndefined();
    expect(exportsMap['./ios']).toBeUndefined();
    expect(exportsMap['./embedded']).toBeUndefined();
  });

  test('keeps experimental and signing internals out of stable web exports', () => {
    const packageJson = readJson('packages/sdk-web/package.json');
    const rootSource = readRepoFile('packages/sdk-web/src/index.ts');
    const exportKeys = Object.keys(packageJson.exports ?? {});

    expect(rootSource).not.toMatch(/^\s*export\s+.*from\s+['"]\.\/core\/signingEngine\//m);
    expect(rootSource).not.toMatch(/^\s*export\s+.*from\s+['"]\.\/utils\/intentDigest/m);
    expect(rootSource).not.toMatch(/^\s*export\s+.*from\s+['"]\.\/threshold['"]/m);
    expect(fs.existsSync(path.join(repoRoot, 'packages/sdk-web/src/experimental'))).toBe(false);
    expect(exportKeys.filter(isExperimentalExportKey)).toEqual([]);
  });

  test('maps PasskeyAuthMenu public subpath to the SSR-safe entry', () => {
    const packageJson = readJson('packages/sdk-web/package.json');
    const exportsMap = packageJson.exports;
    const exportKeys = Object.keys(exportsMap ?? {});

    expect(exportsMap['./react/passkey-auth-menu']).toEqual({
      import: './dist/esm/react/components/PasskeyAuthMenu/public.js',
      default: './dist/esm/react/components/PasskeyAuthMenu/public.js',
      types: './dist/types/sdk-web/src/react/components/PasskeyAuthMenu/public.d.ts',
    });
    expect(fs.existsSync(resolveSdkWebPath(exportsMap['./react/passkey-auth-menu'].types))).toBe(
      true,
    );
    expect(exportKeys.filter(isPasskeyAuthMenuCompatExportKey)).toEqual([]);
    expect(readRepoFile('packages/sdk-web/src/react/index.ts')).toContain(
      "export { PasskeyAuthMenu, PasskeyAuthMenuSkeleton } from './components/PasskeyAuthMenu/public';",
    );
  });

  test('maps server roots to @seams/sdk-server entries', () => {
    const packageJson = readJson('packages/sdk-server-ts/package.json');
    const exportsMap = packageJson.exports;

    expect(packageJson.name).toBe('@seams/sdk-server');
    expect(packageJson.private).toBeUndefined();
    expect(exportsMap['.']).toEqual({
      import: './dist/esm/index.js',
      default: './dist/esm/index.js',
      types: './dist/types/sdk-server-ts/src/index.d.ts',
    });
    expect(exportsMap['./router/express']).toEqual({
      import: './dist/esm/router/express.js',
      default: './dist/esm/router/express.js',
      types: './dist/types/sdk-server-ts/src/router/express-adaptor.d.ts',
    });
    expect(exportsMap['./router/cloudflare']).toEqual({
      import: './dist/esm/router/cloudflare.js',
      default: './dist/esm/router/cloudflare.js',
      types: './dist/types/sdk-server-ts/src/router/cloudflare-adaptor.d.ts',
    });
    expect(exportsMap['./router/ror']).toEqual({
      import: './dist/esm/router/ror.js',
      default: './dist/esm/router/ror.js',
      types: './dist/types/sdk-server-ts/src/router/ror-adaptor.d.ts',
    });
    expect(exportsMap['./console']).toEqual({
      import: './dist/esm/console/index.js',
      default: './dist/esm/console/index.js',
      types: './dist/types/sdk-server-ts/src/console/index.d.ts',
    });
    const cloudflareTypes = readRepoFile(
      'packages/sdk-server-ts/src/router/cloudflare/cloudflare.types.ts',
    );
    expect(cloudflareTypes).toContain('RouterApiCloudflareSignerWorkerEnv');
    expect(cloudflareTypes).toContain('RouterApiCloudflareConsoleWorkerEnv');
    expect(cloudflareTypes).toContain('SeamsD1SignerTenantStorageWorkerEnv');
    expect(cloudflareTypes).toContain('SeamsD1ConsoleTenantStorageWorkerEnv');
    expect(cloudflareTypes).not.toContain('interface RouterApiCloudflareWorkerEnv');
    expect(cloudflareTypes).not.toContain('interface SeamsD1DoTenantStorageWorkerEnv');
    expect(exportsMap['./storage/postgres']).toBeUndefined();
    expect(exportsMap['./wasm/signer']).toEqual({
      import: './dist/esm/wasm/signer.js',
      default: './dist/esm/wasm/signer.js',
      types: './dist/types/sdk-server-ts/src/wasm/signer.d.ts',
    });
    expect(readRepoFile('packages/sdk-server-ts/src/index.ts')).toContain('export { AuthService }');
    expect(readRepoFile('packages/sdk-server-ts/src/index.ts')).not.toContain(
      "export * from './console/",
    );
    expect(resolveSdkServerPath(exportsMap['.'].import)).toContain('packages/sdk-server-ts');
    expect(fs.existsSync(resolveSdkServerPath(exportsMap['./console'].types))).toBe(true);
  });

  test('public runtime package export exposes runtime value constructors', async () => {
    const packageJson = readJson('packages/sdk-web/package.json');
    const runtimeExport = packageJson.exports['./runtime'];
    const runtimeModule = await import(pathToFileURL(resolveSdkWebPath(runtimeExport.import)).href);

    expect(typeof runtimeModule.createSigningRuntime).toBe('function');
    expect(typeof runtimeModule.createSigningRuntimeStatePorts).toBe('function');

    const runtimeTypes = readRepoFile('packages/sdk-web/src/runtime.ts');
    expect(runtimeTypes).toContain('createSigningRuntime');
    expect(runtimeTypes).toContain('createSigningRuntimeStatePorts');
  });

  test('react provider subpath exposes named and default provider exports', async () => {
    const packageJson = readJson('packages/sdk-web/package.json');
    const providerExport = packageJson.exports['./react/provider'];
    const providerModule = await import(pathToFileURL(resolveSdkWebPath(providerExport.import)).href);

    expect(typeof providerModule.SeamsWebProvider).toBe('function');
    expect(providerModule.default).toBe(providerModule.SeamsWebProvider);
  });

  test('keeps runtime source entry free of browser surfaces', () => {
    const violations: string[] = [];
    for (const file of ['packages/sdk-web/src/runtime.ts']) {
      const source = readRepoFile(file);
      for (const pattern of browserSurfacePatterns) {
        if (pattern.test(source)) violations.push(`${file}: ${pattern}`);
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
    expect(fs.existsSync(path.join(repoRoot, 'packages/sdk-web/src/ios.ts'))).toBe(false);
    expect(fs.existsSync(path.join(repoRoot, 'packages/sdk-web/src/embedded.ts'))).toBe(false);
  });

  test('keeps WalletIframe HTML under a web-owned package export', () => {
    const packageJson = readJson('packages/sdk-web/package.json');
    const exportsMap = packageJson.exports;

    expect(exportsMap['./WalletIframe/client/html']).toBeUndefined();
    expect(exportsMap['./components/modal']).toBeUndefined();
    expect(exportsMap['./components/embedded']).toBeUndefined();
    expect(exportsMap['./web/wallet-iframe-client-html']).toEqual({
      import: './dist/esm/SeamsWeb/walletIframe/client/html.js',
      default: './dist/esm/SeamsWeb/walletIframe/client/html.js',
      types: './dist/types/sdk-web/src/SeamsWeb/walletIframe/client/html.d.ts',
    });
    expect(
      fs.existsSync(resolveSdkWebPath(exportsMap['./web/wallet-iframe-client-html'].types)),
    ).toBe(true);
  });

  test('describes package surfaces without stale embedded-only positioning', () => {
    const packageJson = readJson('packages/sdk-web/package.json');
    expect(packageJson.description).toContain('web');
    expect(packageJson.description).toContain('runtime');
    expect(packageJson.description).toContain('TypeScript');
    expect(packageJson.description).not.toContain('server');
    expect(packageJson.description).not.toContain('native-facing');
    expect(packageJson.keywords).toEqual(expect.arrayContaining(['browser', 'signing-runtime']));
    expect(packageJson.keywords).not.toContain('server');
    expect(packageJson.keywords).not.toContain('native');
    expect(packageJson.keywords).not.toContain('embedded');
  });

  test('keeps server-only packages out of hard browser installs', () => {
    const packageJson = readJson('packages/sdk-web/package.json');
    const serverOnlyPackages = ['pg', '@simplewebauthn/server', 'express'];

    for (const packageName of serverOnlyPackages) {
      expect(packageJson.dependencies?.[packageName]).toBeUndefined();
      expect(packageJson.peerDependencies?.[packageName]).toBeUndefined();
      expect(packageJson.peerDependenciesMeta?.[packageName]).toBeUndefined();
    }

    const rolldownConfig = readRepoFile('packages/sdk-web/rolldown.config.ts');
    for (const packageName of serverOnlyPackages) {
      expect(rolldownConfig).not.toContain(`'${packageName}'`);
    }
  });

  test('keeps server runtime dependencies on @seams/sdk-server', () => {
    const packageJson = readJson('packages/sdk-server-ts/package.json');
    const serverPackages = ['@simplewebauthn/server', 'express', 'bs58'];

    for (const packageName of serverPackages) {
      expect(packageJson.dependencies?.[packageName]).toBeTruthy();
    }

    const rolldownConfig = readRepoFile('packages/sdk-server-ts/rolldown.config.ts');
    for (const packageName of serverPackages) {
      expect(rolldownConfig).toContain(`'${packageName}'`);
    }
  });
});

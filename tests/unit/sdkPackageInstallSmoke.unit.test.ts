import { expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sdkWebRoot = path.join(repoRoot, 'packages/wallet');
const sdkServerRoot = path.join(repoRoot, 'packages/wallet-server');

function run(command: string, args: readonly string[], cwd: string): string {
  try {
    return execFileSync(command, [...args], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    const err = error as { stdout?: string; stderr?: string; message?: string };
    throw new Error(
      [
        `${command} ${args.join(' ')} failed`,
        err.message || '',
        err.stdout ? `stdout:\n${err.stdout}` : '',
        err.stderr ? `stderr:\n${err.stderr}` : '',
      ]
        .filter(Boolean)
        .join('\n'),
    );
  }
}

function hasPnpmPackage(nodeModulesDir: string, packageName: string): boolean {
  const pnpmDir = path.join(nodeModulesDir, '.pnpm');
  if (!fs.existsSync(pnpmDir)) return false;
  const encodedName = packageName.replace('/', '+');
  return fs.readdirSync(pnpmDir).some((entry) => entry.startsWith(`${encodedName}@`));
}

function packSdkWeb(tmpRoot: string): string {
  const packDir = path.join(tmpRoot, 'pack');
  fs.mkdirSync(packDir);
  run('pnpm', ['-C', sdkWebRoot, 'pack', '--pack-destination', packDir], repoRoot);
  const tarball = fs
    .readdirSync(packDir)
    .filter((name) => name.endsWith('.tgz'))
    .map((name) => path.join(packDir, name))[0];
  expect(tarball).toBeTruthy();
  return tarball;
}

function packSdkServer(tmpRoot: string): string {
  const packDir = path.join(tmpRoot, 'pack-server');
  fs.mkdirSync(packDir);
  run('pnpm', ['-C', sdkServerRoot, 'build'], repoRoot);
  run('pnpm', ['-C', sdkServerRoot, 'pack', '--pack-destination', packDir], repoRoot);
  const tarball = fs
    .readdirSync(packDir)
    .filter((name) => name.endsWith('.tgz'))
    .map((name) => path.join(packDir, name))[0];
  expect(tarball).toBeTruthy();
  return tarball;
}

test.describe('SDK package install smoke', () => {
  test('browser/runtime package install does not pull server-only peers', () => {
    test.setTimeout(90_000);

    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'seams-sdk-browser-install-'));
    try {
      const tarball = packSdkWeb(tmpRoot);

      fs.writeFileSync(
        path.join(tmpRoot, 'package.json'),
        JSON.stringify({
          name: 'seams-sdk-browser-install-smoke',
          private: true,
          type: 'module',
          dependencies: {
            '@seams/wallet': `file:${tarball}`,
          },
        }),
      );
      run('pnpm', ['install', '--ignore-scripts', '--prod'], tmpRoot);

      const nodeModulesDir = path.join(tmpRoot, 'node_modules');
      for (const packageName of ['pg', '@simplewebauthn/server', 'express']) {
        expect(fs.existsSync(path.join(nodeModulesDir, packageName))).toBe(false);
        expect(hasPnpmPackage(nodeModulesDir, packageName)).toBe(false);
      }

      fs.writeFileSync(
        path.join(tmpRoot, 'import-browser-subpaths.mjs'),
        `
          function expectMissingSubpath(specifier) {
            try {
              import.meta.resolve(specifier);
            } catch (error) {
              if (error && error.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED') return;
              throw error;
            }
            throw new Error(specifier + ' still resolves');
          }

          const runtime = await import('@seams/wallet/runtime');
          if (typeof runtime.createSigningRuntime !== 'function') {
            throw new Error('missing createSigningRuntime');
          }
          if (typeof runtime.createSigningRuntimeStatePorts !== 'function') {
            throw new Error('missing createSigningRuntimeStatePorts');
          }
          const root = await import('@seams/wallet');
          if (typeof root.SeamsWeb !== 'function') {
            throw new Error('missing SeamsWeb export');
          }
          expectMissingSubpath('@seams/wallet/server');
          expectMissingSubpath('@seams/wallet/worker');
          expectMissingSubpath('@seams/wallet/wasm');
          expectMissingSubpath('@seams/wallet/wasm-js');
        `,
      );
      run(process.execPath, ['import-browser-subpaths.mjs'], tmpRoot);
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  test('server package install resolves server dependencies and adapters', () => {
    test.setTimeout(120_000);

    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'seams-sdk-server-install-'));
    try {
      const tarball = packSdkServer(tmpRoot);

      fs.writeFileSync(
        path.join(tmpRoot, 'package.json'),
        JSON.stringify({
          name: 'seams-sdk-server-install-smoke',
          private: true,
          type: 'module',
          dependencies: {
            '@seams/wallet-server': `file:${tarball}`,
          },
        }),
      );
      run('pnpm', ['install', '--ignore-scripts', '--prod'], tmpRoot);

      const nodeModulesDir = path.join(tmpRoot, 'node_modules');
      for (const packageName of ['@simplewebauthn/server', 'express']) {
        expect(hasPnpmPackage(nodeModulesDir, packageName)).toBe(true);
      }

      fs.writeFileSync(
        path.join(tmpRoot, 'import-server-subpaths.mjs'),
        `
          const server = await import('@seams/wallet-server');
          if (typeof server.AuthService !== 'function') {
            throw new Error('missing AuthService export');
          }
          if (typeof server.createRouterApiModule !== 'function') {
            throw new Error('missing createRouterApiModule export');
          }
          if (typeof server.createInMemoryConsoleSponsoredCallService !== 'undefined') {
            throw new Error('unexpected root console sponsored-call export');
          }

          try {
            import.meta.resolve('@seams/wallet-server/console');
            throw new Error('server console subpath still resolves');
          } catch (error) {
            if (!error || error.code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED') throw error;
          }
          try {
            import.meta.resolve('@seams/wallet-server/internal/storage/tenantRoute');
            throw new Error('server internal wildcard subpath still resolves');
          } catch (error) {
            if (!error || error.code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED') throw error;
          }

          const expressRouter = await import('@seams/wallet-server/router/express');
          if (typeof expressRouter.createRouterApiRouter !== 'function') {
            throw new Error('missing createRouterApiRouter export');
          }
          if (typeof expressRouter.createConsoleRouter !== 'undefined') {
            throw new Error('unexpected createConsoleRouter export');
          }

          const cloudflareRouter = await import('@seams/wallet-server/router/cloudflare');
          if (typeof cloudflareRouter.createCloudflareRouter !== 'function') {
            throw new Error('missing createCloudflareRouter export');
          }
          if (typeof cloudflareRouter.createCloudflareConsoleRouter !== 'undefined') {
            throw new Error('unexpected createCloudflareConsoleRouter export');
          }

          const tenantStorage = await import('@seams/wallet-server/storage/tenant-route');
          if (typeof tenantStorage.createConsoleD1StorageTarget !== 'undefined') {
            throw new Error('unexpected public console storage target export');
          }
        `,
      );
      run(process.execPath, ['import-server-subpaths.mjs'], tmpRoot);
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });
});

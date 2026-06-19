import { expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sdkWebRoot = path.join(repoRoot, 'packages/sdk-web');
const serverPeerDeps = {
  '@simplewebauthn/server': '^13.2.2',
  express: '^4.21.2',
  pg: '^8.17.2',
};

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

test.describe('refactor 51b package install smoke', () => {
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
            '@seams/sdk': `file:${tarball}`,
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
          const runtime = await import('@seams/sdk/runtime');
          if (typeof runtime.createSigningRuntime !== 'function') {
            throw new Error('missing createSigningRuntime');
          }
          if (typeof runtime.createSigningRuntimeStatePorts !== 'function') {
            throw new Error('missing createSigningRuntimeStatePorts');
          }
          const root = await import('@seams/sdk');
          if (typeof root.SeamsWeb !== 'function') {
            throw new Error('missing SeamsWeb export');
          }
        `,
      );
      run(process.execPath, ['import-browser-subpaths.mjs'], tmpRoot);
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  test('server subpath package install resolves server peers and adapters', () => {
    test.setTimeout(120_000);

    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'seams-sdk-server-install-'));
    try {
      const tarball = packSdkWeb(tmpRoot);

      fs.writeFileSync(
        path.join(tmpRoot, 'package.json'),
        JSON.stringify({
          name: 'seams-sdk-server-install-smoke',
          private: true,
          type: 'module',
          dependencies: {
            '@seams/sdk': `file:${tarball}`,
            ...serverPeerDeps,
          },
        }),
      );
      run('pnpm', ['install', '--ignore-scripts', '--prod'], tmpRoot);

      const nodeModulesDir = path.join(tmpRoot, 'node_modules');
      for (const packageName of Object.keys(serverPeerDeps)) {
        expect(fs.existsSync(path.join(nodeModulesDir, packageName))).toBe(true);
        expect(hasPnpmPackage(nodeModulesDir, packageName)).toBe(true);
      }

      fs.writeFileSync(
        path.join(tmpRoot, 'import-server-subpaths.mjs'),
        `
          const server = await import('@seams/sdk/server');
          if (typeof server.AuthService !== 'function') {
            throw new Error('missing AuthService export');
          }
          if (typeof server.createRelayRouterModule !== 'function') {
            throw new Error('missing createRelayRouterModule export');
          }

          const expressRouter = await import('@seams/sdk/server/router/express');
          if (typeof expressRouter.createRelayRouter !== 'function') {
            throw new Error('missing createRelayRouter export');
          }
          if (typeof expressRouter.createConsoleRouter !== 'function') {
            throw new Error('missing createConsoleRouter export');
          }
          if (typeof expressRouter.createPostgresConsoleBootstrapTokenService !== 'function') {
            throw new Error('missing Express Postgres service export');
          }

          const cloudflareRouter = await import('@seams/sdk/server/router/cloudflare');
          if (typeof cloudflareRouter.createCloudflareRouter !== 'function') {
            throw new Error('missing createCloudflareRouter export');
          }
          if (typeof cloudflareRouter.createCloudflareConsoleRouter !== 'function') {
            throw new Error('missing createCloudflareConsoleRouter export');
          }
          if (typeof cloudflareRouter.createPostgresConsoleBootstrapTokenService !== 'function') {
            throw new Error('missing Cloudflare Postgres service export');
          }
        `,
      );
      run(process.execPath, ['import-server-subpaths.mjs'], tmpRoot);
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });
});

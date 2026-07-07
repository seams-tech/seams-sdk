import { test, expect } from '@playwright/test';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { seamsBuildHeaders, seamsWalletService } from '@/plugins/vite';
import { buildWalletServiceHtml } from '@/plugins/plugin-utils';

type Middleware = (req: any, res: any, next: () => void) => void;

type WalletServiceResult = {
  headers: Record<string, string>;
  body: string;
  ended: boolean;
};

function collectWalletServiceMiddlewares(plugin: ReturnType<typeof seamsWalletService>): Middleware[] {
  const middlewares: Middleware[] = [];
  plugin.configureServer?.({
    middlewares: {
      use(fn: Middleware) {
        middlewares.push(fn);
      },
    },
  });
  return middlewares;
}

function runWalletServiceMiddlewares(middlewares: readonly Middleware[]): WalletServiceResult {
  const headers: Record<string, string> = {};
  const result: WalletServiceResult = { headers, body: '', ended: false };
  const req = { url: '/wallet-service' };
  const res = {
    statusCode: 0,
    setHeader(key: string, value: string) {
      headers[key.toLowerCase()] = value;
    },
    end(value?: string) {
      result.body = String(value || '');
      result.ended = true;
    },
  };

  let index = 0;
  function next() {
    const middleware = middlewares[index++];
    if (middleware) middleware(req, res, next);
  }
  next();
  return result;
}

function runWalletServicePlugin(plugin: ReturnType<typeof seamsWalletService>): WalletServiceResult {
  return runWalletServiceMiddlewares(collectWalletServiceMiddlewares(plugin));
}

test.describe('plugins/vite hosted wallet helper headers', () => {
  test('dev wallet-service emits no legacy isolation or CSP headers by default', async () => {
    const plugin = seamsWalletService({
      walletServicePath: '/wallet-service',
      sdkBasePath: '/sdk',
      coepMode: 'off',
    });

    const { headers, ended } = runWalletServicePlugin(plugin);

    expect(ended).toBe(true);
    expect(headers['cross-origin-resource-policy']).toBeUndefined();
    expect(headers['cross-origin-embedder-policy']).toBeUndefined();
    expect(headers['cross-origin-opener-policy']).toBeUndefined();
    expect(headers['content-security-policy']).toBeUndefined();
    expect(headers['permissions-policy']).toBeUndefined();
  });

  test('dev wallet-service emits strict isolation only when requested', async () => {
    const plugin = seamsWalletService({
      walletServicePath: '/wallet-service',
      sdkBasePath: '/sdk',
      coepMode: 'strict',
    });

    const { headers } = runWalletServicePlugin(plugin);

    expect(headers['cross-origin-embedder-policy']).toBe('require-corp');
    expect(headers['cross-origin-resource-policy']).toBe('cross-origin');
    expect(headers['cross-origin-opener-policy']).toBeUndefined();
    expect(headers['content-security-policy']).toBeUndefined();
    expect(headers['permissions-policy']).toBeUndefined();
  });

  test('wallet-service HTML can select product-specific host builds', async () => {
    expect(buildWalletServiceHtml('/sdk', undefined, 'near')).toContain(
      '/sdk/wallet-iframe-host-near.js',
    );
    expect(buildWalletServiceHtml('/sdk', undefined, 'ecdsa')).toContain(
      '/sdk/wallet-iframe-host-ecdsa.js',
    );
    expect(buildWalletServiceHtml('/sdk')).toContain('/sdk/wallet-iframe-host-runtime.js');
  });

  test('dev wallet-service serves the selected host variant', async () => {
    const plugin = seamsWalletService({
      walletServicePath: '/wallet-service',
      sdkBasePath: '/sdk',
      walletHostVariant: 'ecdsa',
      coepMode: 'off',
    });

    const { body } = runWalletServicePlugin(plugin);

    expect(body).toContain('/sdk/wallet-iframe-host-ecdsa.js');
    expect(body).not.toContain('/sdk/wallet-iframe-host-runtime.js');
  });

  test('build _headers omits legacy defaults when COEP is off', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'seams-headers-'));
    const outDir = path.join(tmp, 'dist');

    const plugin = seamsBuildHeaders({
      coepMode: 'off',
      cors: { accessControlAllowOrigin: 'https://wallet.example.localhost' },
    });

    (plugin as any).configResolved?.({ build: { outDir } });
    (plugin as any).generateBundle?.();

    const content = fs.readFileSync(path.join(outDir, '_headers'), 'utf-8');
    expect(content).toContain('/sdk/*');
    expect(content).toContain('Access-Control-Allow-Origin: https://wallet.example.localhost');
    expect(content).not.toContain('Cross-Origin-Resource-Policy');
    expect(content).not.toContain('Cross-Origin-Embedder-Policy');
    expect(content).not.toContain('Cross-Origin-Opener-Policy');
    expect(content).not.toContain('Content-Security-Policy');
    expect(content).not.toContain('Permissions-Policy');
  });

  test('build _headers emits strict isolation only when requested', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'seams-headers-'));
    const outDir = path.join(tmp, 'dist');

    const plugin = seamsBuildHeaders({
      coepMode: 'strict',
    });

    (plugin as any).configResolved?.({ build: { outDir } });
    (plugin as any).generateBundle?.();

    const content = fs.readFileSync(path.join(outDir, '_headers'), 'utf-8');
    expect(content).toContain('Cross-Origin-Embedder-Policy: require-corp');
    expect(content).toContain('Cross-Origin-Resource-Policy: cross-origin');
    expect(content).not.toContain('Cross-Origin-Opener-Policy');
    expect(content).not.toContain('Content-Security-Policy');
    expect(content).not.toContain('Permissions-Policy');
  });
});

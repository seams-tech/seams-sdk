import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATH = '/_test-sdk/esm/core/rpcClients/relayer/sealedRefreshCapabilities.js' as const;

type TestConfig = {
  network: { relayer: { url: string } };
  signing: {
    sessionPersistenceMode: 'none' | 'sealed_refresh_v1';
    sessionSeal:
      | { mode: 'none' }
      | {
          mode: 'sealed_refresh_v1';
          protocol: { algorithm: 'shamir3pass-v2'; groupId: 'rfc2409-group2' };
        };
  };
  wallet: { mode: 'direct' | 'iframe' };
};

function buildConfig(input: {
  relayerUrl: string;
  mode?: 'none' | 'sealed_refresh_v1';
  walletMode?: 'direct' | 'iframe';
}): TestConfig {
  const mode = input.mode ?? 'sealed_refresh_v1';
  return {
    network: { relayer: { url: input.relayerUrl } },
    signing: {
      sessionPersistenceMode: mode,
      sessionSeal:
        mode === 'sealed_refresh_v1'
          ? {
              mode,
              protocol: { algorithm: 'shamir3pass-v2', groupId: 'rfc2409-group2' },
            }
          : { mode: 'none' },
    },
    wallet: { mode: input.walletMode ?? 'direct' },
  };
}

test.describe('sealed refresh startup parity', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('accepts the supported public protocol and server-owned key version', async ({ page }) => {
    const config = buildConfig({ relayerUrl: 'https://relay.example' });
    const result = await page.evaluate(
      async ({ importPath, config }) => {
        const mod = await import(importPath);
        let fetchCalls = 0;
        const fetchImpl = async (): Promise<Response> => {
          fetchCalls += 1;
          return new Response(
            JSON.stringify({
              origins: [],
              capabilities: {
                signingSessionSeal: {
                  mode: 'sealed_refresh_v1',
                  protocol: { algorithm: 'shamir3pass-v2', groupId: 'rfc2409-group2' },
                  currentKeyVersion: 'server-rotated-r9',
                },
              },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        };
        await mod.verifySealedRefreshStartupParity({
          configs: config,
          fetchImpl,
          timeoutMs: 2_000,
        });
        return { fetchCalls };
      },
      { importPath: IMPORT_PATH, config },
    );

    expect(result.fetchCalls).toBe(1);
  });

  test('does not cache transient well-known failures', async ({ page }) => {
    const config = buildConfig({ relayerUrl: 'https://relay-transient.example' });
    const result = await page.evaluate(
      async ({ importPath, config }) => {
        const mod = await import(importPath);
        let fetchCalls = 0;
        const fetchImpl = async (): Promise<Response> => {
          fetchCalls += 1;
          if (fetchCalls === 1) return new Response('bad gateway', { status: 502 });
          return new Response(
            JSON.stringify({
              origins: [],
              capabilities: {
                signingSessionSeal: {
                  mode: 'sealed_refresh_v1',
                  protocol: { algorithm: 'shamir3pass-v2', groupId: 'rfc2409-group2' },
                  currentKeyVersion: 'server-r2',
                },
              },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        };
        let firstCode = '';
        try {
          await mod.verifySealedRefreshStartupParity({
            configs: config,
            fetchImpl,
            timeoutMs: 2_000,
          });
        } catch (error: unknown) {
          firstCode = String((error as { code?: unknown })?.code || '');
        }
        await mod.verifySealedRefreshStartupParity({
          configs: config,
          fetchImpl,
          timeoutMs: 2_000,
        });
        return { fetchCalls, firstCode };
      },
      { importPath: IMPORT_PATH, config },
    );

    expect(result.fetchCalls).toBe(2);
    expect(result.firstCode).toBe('sealed_refresh_parity_http_error');
  });

  test('fails closed when the server advertises an unsupported protocol', async ({ page }) => {
    const config = buildConfig({ relayerUrl: 'https://relay-unsupported.example' });
    const result = await page.evaluate(
      async ({ importPath, config }) => {
        const mod = await import(importPath);
        const fetchImpl = async (): Promise<Response> =>
          new Response(
            JSON.stringify({
              origins: [],
              capabilities: {
                signingSessionSeal: {
                  mode: 'sealed_refresh_v1',
                  protocol: { algorithm: 'shamir3pass-v2', groupId: 'unsupported-group' },
                  currentKeyVersion: 'server-r2',
                },
              },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        try {
          await mod.verifySealedRefreshStartupParity({
            configs: config,
            fetchImpl,
            timeoutMs: 2_000,
          });
          return { ok: true, code: '', message: '' };
        } catch (error: unknown) {
          return {
            ok: false,
            code: String((error as { code?: unknown })?.code || ''),
            message: error instanceof Error ? error.message : String(error),
          };
        }
      },
      { importPath: IMPORT_PATH, config },
    );

    expect(result.ok).toBe(false);
    expect(result.code).toBe('sealed_refresh_parity_mismatch');
    expect(result.message).toContain('mode');
  });

  test('treats missing capabilities as a mode mismatch', async ({ page }) => {
    const config = buildConfig({ relayerUrl: 'https://relay-missing.example' });
    const result = await page.evaluate(
      async ({ importPath, config }) => {
        const mod = await import(importPath);
        const fetchImpl = async (): Promise<Response> =>
          new Response(JSON.stringify({ origins: [] }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        try {
          await mod.verifySealedRefreshStartupParity({
            configs: config,
            fetchImpl,
            timeoutMs: 2_000,
          });
          return { ok: true, code: '', message: '' };
        } catch (error: unknown) {
          return {
            ok: false,
            code: String((error as { code?: unknown })?.code || ''),
            message: error instanceof Error ? error.message : String(error),
          };
        }
      },
      { importPath: IMPORT_PATH, config },
    );

    expect(result.ok).toBe(false);
    expect(result.code).toBe('sealed_refresh_parity_mismatch');
    expect(result.message).toContain('mode');
  });

  test('skips the relayer fetch in app-origin wallet iframe mode', async ({ page }) => {
    const config = buildConfig({
      relayerUrl: 'https://relay-iframe.example',
      walletMode: 'iframe',
    });
    const result = await page.evaluate(
      async ({ importPath, config }) => {
        const mod = await import(importPath);
        let fetchCalls = 0;
        const fetchImpl = async (): Promise<Response> => {
          fetchCalls += 1;
          return new Response(JSON.stringify({}), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        };
        await mod.verifySealedRefreshStartupParity({
          configs: config,
          fetchImpl,
          timeoutMs: 2_000,
        });
        return { fetchCalls };
      },
      { importPath: IMPORT_PATH, config },
    );

    expect(result.fetchCalls).toBe(0);
  });
});

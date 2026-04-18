import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATH = '/sdk/esm/core/rpcClients/relayer/sealedRefreshCapabilities.js' as const;

type TestConfig = {
  network: {
    relayer: {
      url: string;
    };
  };
  signing: {
    sessionPersistenceMode: 'none' | 'sealed_refresh_v1';
    sessionSeal: {
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };
  };
  wallet: {
    mode: 'direct' | 'iframe';
  };
};

function buildConfig(input: {
  relayerUrl: string;
  mode?: 'none' | 'sealed_refresh_v1';
  keyVersion?: string;
  shamirPrimeB64u?: string;
  walletMode?: 'direct' | 'iframe';
}): TestConfig {
  return {
    network: {
      relayer: {
        url: input.relayerUrl,
      },
    },
    signing: {
      sessionPersistenceMode: input.mode || 'sealed_refresh_v1',
      sessionSeal: {
        ...(input.keyVersion ? { keyVersion: input.keyVersion } : {}),
        ...(input.shamirPrimeB64u ? { shamirPrimeB64u: input.shamirPrimeB64u } : {}),
      },
    },
    wallet: {
      mode: input.walletMode || 'direct',
    },
  };
}

test.describe('sealed refresh startup parity', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('passes when relayer well-known capabilities match client config', async ({ page }) => {
    const config = buildConfig({
      relayerUrl: 'https://relay.example',
      keyVersion: 'kek-s-2026-02',
      shamirPrimeB64u: 'AQAB',
    });
    const result = await page.evaluate(async ({ importPath, config }) => {
      const mod = await import(importPath);

      const originalFetch = window.fetch.bind(window);
      let fetchCalls = 0;
      window.fetch = (async (_input: RequestInfo | URL): Promise<Response> => {
        fetchCalls += 1;
        return new Response(
          JSON.stringify({
            origins: [],
            capabilities: {
              signingSessionSeal: {
                mode: 'sealed_refresh_v1',
                keyVersion: 'kek-s-2026-02',
                shamirPrimeB64u: 'AQAB',
              },
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }) as typeof fetch;

      try {
        await mod.verifySealedRefreshStartupParity({
          configs: config,
          timeoutMs: 2_000,
        });
        return { ok: true, fetchCalls };
      } catch (error: unknown) {
        return {
          ok: false,
          fetchCalls,
          message: error instanceof Error ? error.message : String(error),
          code: String((error as { code?: unknown })?.code || ''),
        };
      } finally {
        window.fetch = originalFetch;
      }
    }, { importPath: IMPORT_PATH, config });

    expect(result.ok).toBe(true);
    expect(result.fetchCalls).toBe(1);
  });

  test('does not cache transient well-known failures', async ({ page }) => {
    const config = buildConfig({
      relayerUrl: 'https://relay-transient.example',
      keyVersion: 'kek-s-2026-02',
      shamirPrimeB64u: 'AQAB',
    });
    const result = await page.evaluate(async ({ importPath, config }) => {
      const mod = await import(importPath);

      const originalFetch = window.fetch.bind(window);
      let fetchCalls = 0;
      window.fetch = (async (_input: RequestInfo | URL): Promise<Response> => {
        fetchCalls += 1;
        if (fetchCalls === 1) {
          return new Response('bad gateway', { status: 502 });
        }
        return new Response(
          JSON.stringify({
            origins: [],
            capabilities: {
              signingSessionSeal: {
                mode: 'sealed_refresh_v1',
                keyVersion: 'kek-s-2026-02',
                shamirPrimeB64u: 'AQAB',
              },
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }) as typeof fetch;

      try {
        let firstCode = '';
        try {
          await mod.verifySealedRefreshStartupParity({
            configs: config,
            timeoutMs: 2_000,
          });
        } catch (error: unknown) {
          firstCode = String((error as { code?: unknown })?.code || '');
        }
        await mod.verifySealedRefreshStartupParity({
          configs: config,
          timeoutMs: 2_000,
        });
        return { ok: true, fetchCalls, firstCode };
      } catch (error: unknown) {
        return {
          ok: false,
          fetchCalls,
          message: error instanceof Error ? error.message : String(error),
          code: String((error as { code?: unknown })?.code || ''),
        };
      } finally {
        window.fetch = originalFetch;
      }
    }, { importPath: IMPORT_PATH, config });

    expect(result.ok).toBe(true);
    expect(result.fetchCalls).toBe(2);
    expect(result.firstCode).toBe('sealed_refresh_parity_http_error');
  });

  test('fails closed with field-level mismatch diagnostics', async ({ page }) => {
    const config = buildConfig({
      relayerUrl: 'https://relay.example',
      keyVersion: 'client-key',
      shamirPrimeB64u: 'AQAB',
    });
    const result = await page.evaluate(async ({ importPath, config }) => {
      const mod = await import(importPath);

      const originalFetch = window.fetch.bind(window);
      window.fetch = (async (_input: RequestInfo | URL): Promise<Response> => {
        return new Response(
          JSON.stringify({
            origins: [],
            capabilities: {
              signingSessionSeal: {
                mode: 'sealed_refresh_v1',
                keyVersion: 'server-key',
                shamirPrimeB64u: 'AQAB',
              },
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }) as typeof fetch;

      try {
        await mod.verifySealedRefreshStartupParity({
          configs: config,
          timeoutMs: 2_000,
        });
        return { ok: true };
      } catch (error: unknown) {
        return {
          ok: false,
          message: error instanceof Error ? error.message : String(error),
          code: String((error as { code?: unknown })?.code || ''),
        };
      } finally {
        window.fetch = originalFetch;
      }
    }, { importPath: IMPORT_PATH, config });

    expect(result.ok).toBe(false);
    expect(result.code).toBe('sealed_refresh_parity_mismatch');
    expect(result.message).toContain('keyVersion');
  });

  test('treats missing capabilities payload as mode mismatch and fails closed', async ({ page }) => {
    const config = buildConfig({
      relayerUrl: 'https://relay.example',
      keyVersion: 'kek-s-2026-02',
      shamirPrimeB64u: 'AQAB',
    });
    const result = await page.evaluate(async ({ importPath, config }) => {
      const mod = await import(importPath);

      const originalFetch = window.fetch.bind(window);
      window.fetch = (async (_input: RequestInfo | URL): Promise<Response> => {
        return new Response(JSON.stringify({ origins: [] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }) as typeof fetch;

      try {
        await mod.verifySealedRefreshStartupParity({
          configs: config,
          timeoutMs: 2_000,
        });
        return { ok: true };
      } catch (error: unknown) {
        return {
          ok: false,
          message: error instanceof Error ? error.message : String(error),
          code: String((error as { code?: unknown })?.code || ''),
        };
      } finally {
        window.fetch = originalFetch;
      }
    }, { importPath: IMPORT_PATH, config });

    expect(result.ok).toBe(false);
    expect(result.code).toBe('sealed_refresh_parity_mismatch');
    expect(result.message).toContain('mode');
  });

  test('skips relayer fetch in app-origin wallet iframe mode', async ({ page }) => {
    const config = buildConfig({
      relayerUrl: 'https://relay.example',
      keyVersion: 'kek-s-2026-02',
      shamirPrimeB64u: 'AQAB',
      walletMode: 'iframe',
    });
    const result = await page.evaluate(async ({ importPath, config }) => {
      const mod = await import(importPath);

      const originalFetch = window.fetch.bind(window);
      let fetchCalls = 0;
      window.fetch = (async (_input: RequestInfo | URL): Promise<Response> => {
        fetchCalls += 1;
        return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
      }) as typeof fetch;

      try {
        await mod.verifySealedRefreshStartupParity({
          configs: config,
          timeoutMs: 2_000,
        });
        return { ok: true, fetchCalls };
      } catch (error: unknown) {
        return {
          ok: false,
          fetchCalls,
          message: error instanceof Error ? error.message : String(error),
          code: String((error as { code?: unknown })?.code || ''),
        };
      } finally {
        window.fetch = originalFetch;
      }
    }, { importPath: IMPORT_PATH, config });

    expect(result.ok).toBe(true);
    expect(result.fetchCalls).toBe(0);
  });
});

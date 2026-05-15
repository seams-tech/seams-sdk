import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const IMPORT_PATHS = {
  signingSessionState: '/sdk/esm/core/signingEngine/session/passkey/prfCache.js',
} as const;

test.describe('signing session PRF cache utilities', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('cache and clear helpers operate only on PRF claim state', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.signingSessionState);

        const putCalls: Array<{
          sessionId: string;
          prfFirstB64u: string;
          expiresAtMs: number;
          remainingUses: number;
        }> = [];
        const clearCalls: string[] = [];

        await mod.cacheSigningSessionPrfFirst(
          {
            putWarmSessionMaterial: async (args: {
              sessionId: string;
              prfFirstB64u: string;
              expiresAtMs: number;
              remainingUses: number;
            }) => {
              putCalls.push(args);
            },
          },
          {
            sessionId: 'session-hydrated',
            prfFirstB64u: 'AQ',
            expiresAtMs: 123_456,
            remainingUses: 2,
          },
        );

        await mod.clearSigningSessionPrfFirstBestEffort(
          {
            clearWarmSessionMaterial: async ({ sessionId }: { sessionId: string }) => {
              clearCalls.push(sessionId);
            },
          },
          'session-hydrated',
        );
        await mod.clearSigningSessionPrfFirstBestEffort(
          {
            clearWarmSessionMaterial: async ({ sessionId }: { sessionId: string }) => {
              clearCalls.push(`unexpected:${sessionId}`);
            },
          },
          '',
        );

        return { putCalls, clearCalls };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.putCalls).toEqual([
      {
        sessionId: 'session-hydrated',
        prfFirstB64u: 'AQ',
        expiresAtMs: 123_456,
        remainingUses: 2,
      },
    ]);
    expect(result.clearCalls).toEqual(['session-hydrated']);
  });

  test('generateSessionId falls back when crypto.randomUUID is unavailable', async ({ page }) => {
    const sessionId = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.signingSessionState);
      const originalCrypto = globalThis.crypto;
      Object.defineProperty(globalThis, 'crypto', {
        configurable: true,
        value: {},
      });
      try {
        return mod.generateSessionId('threshold-ed25519');
      } finally {
        Object.defineProperty(globalThis, 'crypto', {
          configurable: true,
          value: originalCrypto,
        });
      }
    }, { paths: IMPORT_PATHS });

    expect(sessionId).toContain('threshold-ed25519-');
  });

  test('threshold warm-session bootstrap uses hydrate seam without active-pointer flags', () => {
    const source = fs.readFileSync(
      path.resolve(process.cwd(), '../client/src/core/SeamsPasskey/thresholdWarmSessionBootstrap.ts'),
      'utf8',
    );

    expect(source).toContain('signingEngine.hydrateSigningSession({');
    expect(source).not.toContain('setActiveSigningSessionId');
    expect(source).not.toContain('signingEngine.setActiveSigningSessionId(');
    expect(source).not.toContain('signingEngine.putWarmSessionMaterial(');
  });

  test('signing engine global clear path wipes all worker PRF cache entries', () => {
    const source = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../client/src/core/signingEngine/session/warmCapabilities/clearWarmSigningSessions.ts',
      ),
      'utf8',
    );

    expect(source).toContain(
      'if (nearAccountId == null && hasWarmSessionMaterialClearAll(deps.touchConfirm))',
    );
    expect(source).toContain('clearAllWarmSessionMaterial');
  });
});

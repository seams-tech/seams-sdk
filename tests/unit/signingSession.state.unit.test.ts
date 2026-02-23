import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const IMPORT_PATHS = {
  signingSessionState:
    '/sdk/esm/core/signingEngine/api/session/signingSessionState.js',
} as const;

test.describe('signing session state', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('hydrates signing session and supports clear semantics', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.signingSessionState);

      let createCounter = 0;
      const putCalls: Array<{
        sessionId: string;
        prfFirstB64u: string;
        expiresAtMs: number;
        remainingUses: number;
      }> = [];

      const deps = {
        activeSigningSessionIds: new Map<string, string>(),
        touchConfirm: {
          peekPrfFirstForThresholdSession: async () => ({ ok: false, code: 'not_found', message: 'na' }),
          putPrfFirstForThresholdSession: async (args: {
            sessionId: string;
            prfFirstB64u: string;
            expiresAtMs: number;
            remainingUses: number;
          }) => {
            putCalls.push(args);
          },
        },
        createSessionId: (prefix: string) => `${prefix}-${++createCounter}`,
        signingSessionDefaults: { ttlMs: 1_000, remainingUses: 3 },
      };

      await mod.hydrateSigningSession(deps as any, {
        nearAccountId: 'alice.testnet',
        sessionId: 'session-hydrated',
        prfFirstB64u: 'AQ',
        expiresAtMs: 123_456,
        remainingUses: 2,
      });

      const reused = mod.getOrCreateActiveSigningSessionId(deps as any, 'alice.testnet');
      const cleared = mod.clearActiveSigningSessionId(deps as any, 'alice.testnet');
      const createdAfterClear = mod.getOrCreateActiveSigningSessionId(deps as any, 'alice.testnet');
      const clearedAll = mod.clearAllActiveSigningSessionIds(deps as any);

      return {
        putCalls,
        reused,
        cleared,
        createdAfterClear,
        clearedAll,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.putCalls).toEqual([{
      sessionId: 'session-hydrated',
      prfFirstB64u: 'AQ',
      expiresAtMs: 123_456,
      remainingUses: 2,
    }]);
    expect(result.reused).toBe('session-hydrated');
    expect(result.cleared).toBe('session-hydrated');
    expect(result.createdAfterClear).toBe('signing-session-1');
    expect(result.clearedAll).toEqual(['signing-session-1']);
  });

  test('hydrate can skip active session pointer mutation', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.signingSessionState);

      let createCounter = 0;
      const deps = {
        activeSigningSessionIds: new Map<string, string>(),
        touchConfirm: {
          peekPrfFirstForThresholdSession: async () => ({ ok: false, code: 'not_found', message: 'na' }),
          putPrfFirstForThresholdSession: async () => undefined,
        },
        createSessionId: (prefix: string) => `${prefix}-${++createCounter}`,
        signingSessionDefaults: { ttlMs: 1_000, remainingUses: 3 },
      };

      await mod.hydrateSigningSession(deps as any, {
        nearAccountId: 'alice.testnet',
        sessionId: 'session-not-active',
        prfFirstB64u: 'AQ',
        expiresAtMs: 123_456,
        remainingUses: 2,
        setActiveSigningSessionId: false,
      });

      return {
        created: mod.getOrCreateActiveSigningSessionId(deps as any, 'alice.testnet'),
      };
    }, { paths: IMPORT_PATHS });

    expect(result.created).toBe('signing-session-1');
  });

  test('status resolves active and terminal states', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.signingSessionState);

      const deps = {
        activeSigningSessionIds: new Map<string, string>([['alice.testnet', 'session-1']]),
        touchConfirm: {
          peekPrfFirstForThresholdSession: async ({ sessionId }: { sessionId: string }) => {
            if (sessionId === 'session-active') {
              return { ok: true, remainingUses: 5, expiresAtMs: 999_999 };
            }
            if (sessionId === 'session-expired') {
              return { ok: false, code: 'expired', message: 'expired' };
            }
            if (sessionId === 'session-exhausted') {
              return { ok: false, code: 'exhausted', message: 'exhausted' };
            }
            return { ok: false, code: 'not_found', message: 'missing' };
          },
          putPrfFirstForThresholdSession: async () => undefined,
        },
        createSessionId: () => 'new-session',
        signingSessionDefaults: { ttlMs: 1_000, remainingUses: 3 },
      };

      deps.activeSigningSessionIds.set('alice.testnet', 'session-active');
      const active = await mod.getWarmSigningSessionStatus(deps as any, 'alice.testnet');

      deps.activeSigningSessionIds.set('alice.testnet', 'session-expired');
      const expired = await mod.getWarmSigningSessionStatus(deps as any, 'alice.testnet');

      deps.activeSigningSessionIds.set('alice.testnet', 'session-exhausted');
      const exhausted = await mod.getWarmSigningSessionStatus(deps as any, 'alice.testnet');

      deps.activeSigningSessionIds.set('alice.testnet', 'session-missing');
      const notFound = await mod.getWarmSigningSessionStatus(deps as any, 'alice.testnet');

      deps.activeSigningSessionIds.clear();
      const absent = await mod.getWarmSigningSessionStatus(deps as any, 'alice.testnet');

      return { active, expired, exhausted, notFound, absent };
    }, { paths: IMPORT_PATHS });

    expect(result.active).toEqual({
      sessionId: 'session-active',
      status: 'active',
      remainingUses: 5,
      expiresAtMs: 999_999,
    });
    expect(result.expired).toEqual({
      sessionId: 'session-expired',
      status: 'expired',
    });
    expect(result.exhausted).toEqual({
      sessionId: 'session-exhausted',
      status: 'exhausted',
    });
    expect(result.notFound).toEqual({
      sessionId: 'session-missing',
      status: 'not_found',
    });
    expect(result.absent).toBeNull();
  });

  test('registration uses high-level signing session hydrate API', () => {
    const source = fs.readFileSync(
      path.resolve(process.cwd(), '../client/src/core/TatchiPasskey/registration.ts'),
      'utf8',
    );

    expect(source).toContain('signingEngine.hydrateSigningSession(');
    expect(source).toContain('setActiveSigningSessionId: true');
    expect(source).toContain('setActiveSigningSessionId: false');
    expect(source).not.toContain('signingEngine.setActiveSigningSessionId(');
    expect(source).not.toContain('signingEngine.putPrfFirstForThresholdSession(');
  });
});

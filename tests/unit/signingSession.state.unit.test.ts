import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const IMPORT_PATHS = {
  signingSessionState: '/sdk/esm/core/signingEngine/api/session/signingSessionState.js',
} as const;

test.describe('signing session state', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('hydrates signing session and supports clear semantics', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
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
            peekPrfFirstForThresholdSession: async () => ({
              ok: false,
              code: 'not_found',
              message: 'na',
            }),
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
          signerKind: 'threshold-ed25519',
          sessionId: 'session-hydrated',
          prfFirstB64u: 'AQ',
          expiresAtMs: 123_456,
          remainingUses: 2,
        });

        const reused = mod.getOrCreateActiveSigningSessionIdForKind(deps as any, {
          nearAccountId: 'alice.testnet',
          signerKind: 'threshold-ed25519',
        });
        const cleared = mod.clearAllActiveSigningSessionIdsForAccount(
          deps as any,
          'alice.testnet',
        );
        const createdAfterClear = mod.getOrCreateActiveSigningSessionIdForKind(deps as any, {
          nearAccountId: 'alice.testnet',
          signerKind: 'threshold-ed25519',
        });
        const clearedAll = mod.clearAllActiveSigningSessionIds(deps as any);

        return {
          putCalls,
          reused,
          cleared,
          createdAfterClear,
          clearedAll,
        };
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
    expect(result.reused).toBe('session-hydrated');
    expect(result.cleared).toEqual(['session-hydrated']);
    expect(result.createdAfterClear).toBe('threshold-ed25519-1');
    expect(result.clearedAll).toEqual(['threshold-ed25519-1']);
  });

  test('hydrate can skip active session pointer mutation', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.signingSessionState);

        let createCounter = 0;
        const deps = {
          activeSigningSessionIds: new Map<string, string>(),
          touchConfirm: {
            peekPrfFirstForThresholdSession: async () => ({
              ok: false,
              code: 'not_found',
              message: 'na',
            }),
            putPrfFirstForThresholdSession: async () => undefined,
          },
          createSessionId: (prefix: string) => `${prefix}-${++createCounter}`,
          signingSessionDefaults: { ttlMs: 1_000, remainingUses: 3 },
        };

        await mod.hydrateSigningSession(deps as any, {
          nearAccountId: 'alice.testnet',
          signerKind: 'threshold-ed25519',
          sessionId: 'session-not-active',
          prfFirstB64u: 'AQ',
          expiresAtMs: 123_456,
          remainingUses: 2,
          setActiveSigningSessionId: false,
        });

        return {
          created: mod.getOrCreateActiveSigningSessionIdForKind(deps as any, {
            nearAccountId: 'alice.testnet',
            signerKind: 'threshold-ed25519',
          }),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.created).toBe('threshold-ed25519-1');
  });

  test('status resolves active and terminal states', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.signingSessionState);

        let canonicalSessionId: string | null = null;
        const deps = {
          activeSigningSessionIds: new Map<string, string>([
            ['alice.testnet|threshold-ed25519', 'session-1'],
          ]),
          resolveCanonicalSigningSessionIdForKind: ({
            signerKind,
          }: {
            nearAccountId: string;
            signerKind: string;
          }) => (signerKind === 'threshold-ed25519' ? canonicalSessionId : null),
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

        deps.activeSigningSessionIds.set('alice.testnet|threshold-ed25519', 'session-active');
        const active = await mod.getWarmSigningSessionStatusForKind(deps as any, {
          nearAccountId: 'alice.testnet',
          signerKind: 'threshold-ed25519',
        });

        deps.activeSigningSessionIds.set('alice.testnet|threshold-ed25519', 'session-expired');
        const expired = await mod.getWarmSigningSessionStatusForKind(deps as any, {
          nearAccountId: 'alice.testnet',
          signerKind: 'threshold-ed25519',
        });

        deps.activeSigningSessionIds.set('alice.testnet|threshold-ed25519', 'session-exhausted');
        const exhausted = await mod.getWarmSigningSessionStatusForKind(deps as any, {
          nearAccountId: 'alice.testnet',
          signerKind: 'threshold-ed25519',
        });

        deps.activeSigningSessionIds.set('alice.testnet|threshold-ed25519', 'session-missing');
        const notFound = await mod.getWarmSigningSessionStatusForKind(deps as any, {
          nearAccountId: 'alice.testnet',
          signerKind: 'threshold-ed25519',
        });

        deps.activeSigningSessionIds.clear();
        const absent = await mod.getWarmSigningSessionStatusForKind(deps as any, {
          nearAccountId: 'alice.testnet',
          signerKind: 'threshold-ed25519',
        });

        canonicalSessionId = 'session-active';
        const restored = await mod.getWarmSigningSessionStatusForKind(deps as any, {
          nearAccountId: 'alice.testnet',
          signerKind: 'threshold-ed25519',
        });
        const restoredPointer =
          deps.activeSigningSessionIds.get('alice.testnet|threshold-ed25519') || null;

        return { active, expired, exhausted, notFound, absent, restored, restoredPointer };
      },
      { paths: IMPORT_PATHS },
    );

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
    expect(result.restored).toEqual({
      sessionId: 'session-active',
      status: 'active',
      remainingUses: 5,
      expiresAtMs: 999_999,
    });
    expect(result.restoredPointer).toBe('session-active');
  });

  test('session keys stay isolated across signer kinds', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.signingSessionState);

        const deps = {
          activeSigningSessionIds: new Map<string, string>(),
          touchConfirm: {
            peekPrfFirstForThresholdSession: async ({ sessionId }: { sessionId: string }) => {
              if (sessionId === 'ed25519-session') {
                return { ok: true, remainingUses: 4, expiresAtMs: 222_222 };
              }
              if (sessionId === 'tempo-session') {
                return { ok: true, remainingUses: 7, expiresAtMs: 333_333 };
              }
              return { ok: false, code: 'not_found', message: 'missing' };
            },
            putPrfFirstForThresholdSession: async () => undefined,
          },
          createSessionId: (prefix: string) => `${prefix}-generated`,
          signingSessionDefaults: { ttlMs: 1_000, remainingUses: 3 },
        };

        mod.setActiveSigningSessionIdForKind(deps as any, {
          nearAccountId: 'alice.testnet',
          signerKind: 'threshold-ed25519',
          sessionId: 'ed25519-session',
        });
        mod.setActiveSigningSessionIdForKind(deps as any, {
          nearAccountId: 'alice.testnet',
          signerKind: 'threshold-ecdsa-tempo',
          sessionId: 'tempo-session',
        });

        const ed25519Status = await mod.getWarmSigningSessionStatusForKind(deps as any, {
          nearAccountId: 'alice.testnet',
          signerKind: 'threshold-ed25519',
        });
        const tempoStatus = await mod.getWarmSigningSessionStatusForKind(deps as any, {
          nearAccountId: 'alice.testnet',
          signerKind: 'threshold-ecdsa-tempo',
        });
        const clearedEd25519 = mod.clearAllActiveSigningSessionIdsForAccount(
          {
            ...deps,
            activeSigningSessionIds: new Map<string, string>([
              ['alice.testnet|threshold-ed25519', 'ed25519-session'],
              ['alice.testnet|threshold-ecdsa-tempo', 'tempo-session'],
              ['bob.testnet|threshold-ed25519', 'bob-ed25519-session'],
            ]),
          } as any,
          'alice.testnet',
        );

        return {
          activeKeys: Array.from(deps.activeSigningSessionIds.keys()).sort(),
          ed25519Status,
          tempoStatus,
          clearedEd25519,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.activeKeys).toEqual([
      'alice.testnet|threshold-ecdsa-tempo',
      'alice.testnet|threshold-ed25519',
    ]);
    expect(result.ed25519Status).toEqual({
      sessionId: 'ed25519-session',
      status: 'active',
      remainingUses: 4,
      expiresAtMs: 222_222,
    });
    expect(result.tempoStatus).toEqual({
      sessionId: 'tempo-session',
      status: 'active',
      remainingUses: 7,
      expiresAtMs: 333_333,
    });
    expect(result.clearedEd25519).toEqual(['ed25519-session', 'tempo-session']);
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

  test('signing engine global clear path wipes all worker PRF cache entries', () => {
    const source = fs.readFileSync(
      path.resolve(process.cwd(), '../client/src/core/signingEngine/SigningEngine.ts'),
      'utf8',
    );

    expect(source).toContain(
      'if (nearAccountId == null && hasThresholdPrfFirstCacheClearAllPort(this.touchConfirm))',
    );
    expect(source).toContain('clearAllPrfFirstForThresholdSessions');
  });
});

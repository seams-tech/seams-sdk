import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  secp256k1: '/sdk/esm/core/signingEngine/signers/algorithms/secp256k1.js',
  thresholdSessionStore:
    '/sdk/esm/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.js',
} as const;

test.describe('secp256k1 Email OTP signing-session policy', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('does not let a stale consumed per-operation record block a newer session-mode record', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { Secp256k1Engine } = await import(paths.secp256k1);
        const storeMod = await import(paths.thresholdSessionStore);
        const deps = { recordsByLane: new Map<string, unknown>(), now: () => Date.now() };
        const accountId = 'alice.testnet';
        const now = Date.now();

        storeMod.clearAllThresholdEcdsaSessionRecords(deps);
        storeMod.upsertThresholdEcdsaSessionFromBootstrap(deps, {
          nearAccountId: accountId,
          chain: 'evm',
          source: 'email_otp',
          emailOtpAuthContext: {
            policy: 'per_operation',
            retention: 'single_use',
            reason: 'sign',
            authMethod: 'email_otp',
            consumedAtMs: now - 1_000,
          },
          bootstrap: {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: accountId,
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: 'stale-single-use-key',
              backendBinding: {
                relayerKeyId: 'rk-stale',
                clientVerifyingShareB64u: 'AQ',
                clientAdditiveShareHandle: {
                  kind: 'email_otp_worker_session',
                  sessionId: 'stale-single-use-session',
                },
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'stale-single-use-session',
              thresholdSessionJwt: 'jwt-stale-single-use',
            },
            keygen: {
              ok: true,
              keygenSessionId: 'kg-stale',
              rpId: 'example.localhost',
              clientVerifyingShareB64u: 'AQ',
              relayerKeyId: 'rk-stale',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'stale-single-use-session',
              jwt: 'jwt-stale-single-use',
              expiresAtMs: now + 60_000,
              remainingUses: 0,
            },
          },
        });

        deps.now = () => now + 1;
        storeMod.upsertThresholdEcdsaSessionFromBootstrap(deps, {
          nearAccountId: accountId,
          chain: 'evm',
          source: 'email_otp',
          emailOtpAuthContext: {
            policy: 'session',
            retention: 'session',
            reason: 'login',
            authMethod: 'email_otp',
          },
          bootstrap: {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: accountId,
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: 'active-session-key',
              backendBinding: {
                relayerKeyId: 'rk-active',
                clientVerifyingShareB64u: 'AQ',
                clientAdditiveShareHandle: {
                  kind: 'email_otp_worker_session',
                  sessionId: 'active-session',
                },
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'active-session',
              thresholdSessionJwt: 'jwt-active-session',
            },
            keygen: {
              ok: true,
              keygenSessionId: 'kg-active',
              rpId: 'example.localhost',
              clientVerifyingShareB64u: 'AQ',
              relayerKeyId: 'rk-active',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'active-session',
              jwt: 'jwt-active-session',
              expiresAtMs: now + 60_000,
              remainingUses: 9,
            },
          },
        });

        const keyRef = storeMod.getThresholdEcdsaKeyRefForSigning(deps, {
          nearAccountId: accountId,
          chain: 'evm',
        });
        const originalFetch = globalThis.fetch;
        let authorizeCalls = 0;
        globalThis.fetch = (async () => {
          authorizeCalls += 1;
          return new Response(
            JSON.stringify({
              ok: false,
              code: 'forced_authorize_stop',
              message: 'forced authorize stop',
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }) as typeof fetch;
        try {
          const engine = new Secp256k1Engine({
            getRpId: () => 'example.localhost',
            workerCtx: {
              requestWorkerOperation: async () => {
                throw new Error('worker should not be called before authorize succeeds');
              },
            },
          });
          await engine.sign(
            {
              kind: 'digest',
              algorithm: 'secp256k1',
              digest32: new Uint8Array(32),
              label: 'evm:test',
            },
            keyRef,
          );
          return { ok: true, authorizeCalls, message: '' };
        } catch (error) {
          return {
            ok: false,
            authorizeCalls,
            message: error instanceof Error ? error.message : String(error || ''),
          };
        } finally {
          globalThis.fetch = originalFetch;
          storeMod.clearAllThresholdEcdsaSessionRecords(deps);
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ok).toBe(false);
    expect(result.authorizeCalls, JSON.stringify(result)).toBe(1);
    expect(result.message).toBe('forced authorize stop');
    expect(result.message).not.toContain('requires fresh Email OTP verification');
  });
});

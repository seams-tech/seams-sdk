import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  thresholdSessionStore:
    '/sdk/esm/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.js',
} as const;

test.describe('threshold ECDSA canonical auth material', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('resolves JWT from canonical ECDSA record, then falls back to Ed25519 record', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const deps = { recordsByLane: new Map<string, unknown>() };
        const now = Date.now();

        const upsertEcdsaRecord = (args: {
          nearAccountId: string;
          thresholdSessionId: string;
          thresholdSessionKind: 'jwt' | 'cookie';
          thresholdSessionJwt?: string;
        }) => {
          storeMod.upsertThresholdEcdsaSessionFromBootstrap(deps, {
            nearAccountId: args.nearAccountId,
            chain: 'tempo',
            source: 'login',
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: args.nearAccountId,
                relayerUrl: 'https://relay.example',
                ecdsaThresholdKeyId: `ek-${args.thresholdSessionId}`,
                participantIds: [1, 2],
                backendBinding: {
                  relayerKeyId: `rk-${args.thresholdSessionId}`,
                  clientVerifyingShareB64u: `cvs-${args.thresholdSessionId}`,
                },
                thresholdSessionKind: args.thresholdSessionKind,
                thresholdSessionId: args.thresholdSessionId,
                ...(args.thresholdSessionJwt
                  ? { thresholdSessionJwt: args.thresholdSessionJwt }
                  : {}),
              },
              keygen: {
                ok: true,
                keygenSessionId: `kg-${args.thresholdSessionId}`,
                rpId: 'example.localhost',
                clientVerifyingShareB64u: `cvs-${args.thresholdSessionId}`,
                relayerKeyId: `rk-${args.thresholdSessionId}`,
                participantIds: [1, 2],
              },
              session: {
                ok: true,
                sessionId: args.thresholdSessionId,
                expiresAtMs: now + 120_000,
                remainingUses: 9,
                ...(args.thresholdSessionJwt ? { jwt: args.thresholdSessionJwt } : {}),
              },
            },
          });
        };

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        storeMod.clearAllThresholdEcdsaSessionRecords(deps);

        storeMod.upsertStoredThresholdEd25519SessionRecord({
          nearAccountId: 'fallback.testnet',
          rpId: 'example.localhost',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-ed25519',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'sess-ed25519',
          thresholdSessionJwt: 'jwt-ed25519-fallback',
          expiresAtMs: now + 120_000,
          remainingUses: 7,
          source: 'login',
        });

        upsertEcdsaRecord({
          nearAccountId: 'primary.testnet',
          thresholdSessionId: 'sess-ecdsa-jwt',
          thresholdSessionKind: 'jwt',
          thresholdSessionJwt: 'jwt-ecdsa-primary',
        });
        upsertEcdsaRecord({
          nearAccountId: 'fallback.testnet',
          thresholdSessionId: 'sess-ecdsa-cookie',
          thresholdSessionKind: 'cookie',
        });
        upsertEcdsaRecord({
          nearAccountId: 'nofallback.testnet',
          thresholdSessionId: 'sess-ecdsa-cookie-no-fallback',
          thresholdSessionKind: 'cookie',
        });

        const resolvedPrimary =
          storeMod.resolveThresholdEcdsaSessionAuthMaterialByThresholdSessionId({
            thresholdSessionId: 'sess-ecdsa-jwt',
          });
        const resolvedFallback =
          storeMod.resolveThresholdEcdsaSessionAuthMaterialByThresholdSessionId({
            thresholdSessionId: 'sess-ecdsa-cookie',
          });
        const resolvedNoFallback =
          storeMod.resolveThresholdEcdsaSessionAuthMaterialByThresholdSessionId({
            thresholdSessionId: 'sess-ecdsa-cookie-no-fallback',
          });
        const resolvedMissing =
          storeMod.resolveThresholdEcdsaSessionAuthMaterialByThresholdSessionId({
            thresholdSessionId: 'sess-missing',
          });
        const transportFromEcdsa =
          storeMod.resolveThresholdSessionSealTransportByThresholdSessionId({
            thresholdSessionId: 'sess-ecdsa-jwt',
          });
        const transportFromEd25519 =
          storeMod.resolveThresholdSessionSealTransportByThresholdSessionId({
            thresholdSessionId: 'sess-ed25519',
          });

        return {
          primary: resolvedPrimary
            ? {
                source: resolvedPrimary.thresholdSessionJwtSource,
                jwt: resolvedPrimary.thresholdSessionJwt || null,
              }
            : null,
          fallback: resolvedFallback
            ? {
                source: resolvedFallback.thresholdSessionJwtSource,
                jwt: resolvedFallback.thresholdSessionJwt || null,
              }
            : null,
          noFallback: resolvedNoFallback
            ? {
                source: resolvedNoFallback.thresholdSessionJwtSource,
                jwt: resolvedNoFallback.thresholdSessionJwt || null,
              }
            : null,
          missing: resolvedMissing,
          transportFromEcdsa: transportFromEcdsa
            ? {
                curve: transportFromEcdsa.curve,
                relayerUrl: transportFromEcdsa.relayerUrl,
                source: transportFromEcdsa.thresholdSessionJwtSource,
                jwt: transportFromEcdsa.thresholdSessionJwt || null,
              }
            : null,
          transportFromEd25519: transportFromEd25519
            ? {
                curve: transportFromEd25519.curve,
                relayerUrl: transportFromEd25519.relayerUrl,
                source: transportFromEd25519.thresholdSessionJwtSource,
                jwt: transportFromEd25519.thresholdSessionJwt || null,
              }
            : null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.primary).toEqual({
      source: 'ecdsa',
      jwt: 'jwt-ecdsa-primary',
    });
    expect(result.fallback).toEqual({
      source: 'ed25519',
      jwt: 'jwt-ed25519-fallback',
    });
    expect(result.noFallback).toEqual({
      source: 'none',
      jwt: null,
    });
    expect(result.missing).toBeNull();
    expect(result.transportFromEcdsa).toEqual({
      curve: 'ecdsa',
      relayerUrl: 'https://relay.example',
      source: 'ecdsa',
      jwt: 'jwt-ecdsa-primary',
    });
    expect(result.transportFromEd25519).toEqual({
      curve: 'ed25519',
      relayerUrl: 'https://relay.example',
      source: 'ed25519',
      jwt: 'jwt-ed25519-fallback',
    });
  });
});

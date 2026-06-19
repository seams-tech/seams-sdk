import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  thresholdSessionStore:
    '/sdk/esm/core/signingEngine/session/persistence/records.js',
  warmSessionCapabilityReader:
    '/sdk/esm/core/signingEngine/session/warmCapabilities/capabilityReader.js',
  ecdsaRoleLocalRecords:
    '/sdk/esm/core/signingEngine/session/persistence/ecdsaRoleLocalRecords.js',
} as const;

test.describe('threshold ECDSA warm-session auth material', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

test('resolves JWT only from explicit canonical ECDSA ownership', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const capabilityReaderMod = await import(paths.warmSessionCapabilityReader);
        const ecdsaRoleLocalMod = await import(paths.ecdsaRoleLocalRecords);
        const deps = {
          recordsByLane: new Map<string, unknown>(),
          exportArtifactsByLane: new Map<string, unknown>(),
        };
        const now = Date.now();

        const upsertEcdsaRecord = (args: {
          walletId: string;
          thresholdSessionId: string;
          thresholdSessionKind: 'jwt' | 'cookie';
          walletSessionJwt?: string;
        }) => {
          const chainTarget = {
            kind: 'tempo',
            chainId: 42431,
            networkSlug: 'tempo-42431',
          };
          const signingGrantId = `wallet-${args.thresholdSessionId}`;
          const ecdsaThresholdKeyId = `ek-${args.walletId}`;
          const keyHandle = `key-handle-${args.thresholdSessionId}`;
          const ecdsaRoleLocalReadyRecord = ecdsaRoleLocalMod.buildEcdsaRoleLocalReadyRecord({
            stateBlob: {
              kind: 'ecdsa_role_local_state_blob_v1',
              curve: 'secp256k1',
              encoding: 'base64url',
              producer: 'signer_core',
              stateBlobB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            },
            publicFacts: ecdsaRoleLocalMod.buildEcdsaRoleLocalPublicFacts({
              walletId: args.walletId,
              rpId: 'example.localhost',
              chainTarget,
              keyHandle,
              ecdsaThresholdKeyId,
              signingRootId: 'proj-a:env-a',
              signingRootVersion: 'default',
              clientParticipantId: 1,
              relayerParticipantId: 2,
              participantIds: [1, 2],
              contextBinding32B64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              hssClientSharePublicKey33B64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              relayerPublicKey33B64u: 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              groupPublicKey33B64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              ethereumAddress: `0x${'11'.repeat(20)}`,
            }),
            authMethod: ecdsaRoleLocalMod.buildEcdsaRoleLocalPasskeyAuthMethod({
              credentialIdB64u: `credential-${args.thresholdSessionId}`,
              rpId: 'example.localhost',
            }),
          });
          storeMod.upsertStoredThresholdEcdsaSessionRecord(deps, {
            walletId: args.walletId,
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            chainTarget,
            keyHandle,
            ecdsaThresholdKeyId,
            signingRootId: 'proj-a:env-a',
            signingRootVersion: 'default',
            relayerKeyId: `rk-${args.thresholdSessionId}`,
            clientVerifyingShareB64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            ecdsaRoleLocalReadyRecord,
            participantIds: [1, 2],
            thresholdSessionKind: args.thresholdSessionKind,
            thresholdSessionId: args.thresholdSessionId,
            signingGrantId,
            ...(args.walletSessionJwt
              ? { walletSessionJwt: args.walletSessionJwt }
              : {}),
            expiresAtMs: now + 120_000,
            remainingUses: 9,
            thresholdEcdsaPublicKeyB64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            ethereumAddress: `0x${'11'.repeat(20)}`,
            updatedAtMs: now,
            source: 'login',
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
          signingGrantId: 'wallet-sess-ed25519',
          walletSessionJwt: 'jwt-ed25519-fallback',
          expiresAtMs: now + 120_000,
          remainingUses: 7,
          source: 'login',
        });

        upsertEcdsaRecord({
          walletId: 'primary.testnet',
          thresholdSessionId: 'sess-ecdsa-jwt',
          thresholdSessionKind: 'jwt',
          walletSessionJwt: 'jwt-ecdsa-primary',
        });
        upsertEcdsaRecord({
          walletId: 'fallback.testnet',
          thresholdSessionId: 'sess-ecdsa-cookie',
          thresholdSessionKind: 'cookie',
        });
        upsertEcdsaRecord({
          walletId: 'nofallback.testnet',
          thresholdSessionId: 'sess-ecdsa-cookie-no-fallback',
          thresholdSessionKind: 'cookie',
        });

        const capabilityReader = capabilityReaderMod.createWarmSessionCapabilityReader();
        const resolvedPrimary =
          capabilityReader.resolveEcdsaAuthByThresholdSessionId('sess-ecdsa-jwt');
        const resolvedFallback =
          capabilityReader.resolveEcdsaAuthByThresholdSessionId('sess-ecdsa-cookie');
        const resolvedNoFallback =
          capabilityReader.resolveEcdsaAuthByThresholdSessionId(
            'sess-ecdsa-cookie-no-fallback',
          );
        const resolvedMissing =
          capabilityReader.resolveEcdsaAuthByThresholdSessionId('sess-missing');
        const transportFromEcdsa =
          capabilityReader.resolveEcdsaSealTransportByThresholdSessionId({
            thresholdSessionId: 'sess-ecdsa-jwt',
            chainTarget: {
              kind: 'tempo',
              chainId: 42431,
              networkSlug: 'tempo-42431',
            },
          });

        return {
          primary: resolvedPrimary
            ? {
                source: resolvedPrimary.walletSessionJwtSource,
                jwt: resolvedPrimary.walletSessionJwt || null,
              }
            : null,
          fallback: resolvedFallback
            ? {
                source: resolvedFallback.walletSessionJwtSource,
                jwt: resolvedFallback.walletSessionJwt || null,
              }
            : null,
          noFallback: resolvedNoFallback
            ? {
                source: resolvedNoFallback.walletSessionJwtSource,
                jwt: resolvedNoFallback.walletSessionJwt || null,
              }
            : null,
          missing: resolvedMissing,
          transportFromEcdsa: transportFromEcdsa
            ? {
                curve: transportFromEcdsa.curve,
                relayerUrl: transportFromEcdsa.relayerUrl,
                source: transportFromEcdsa.walletSessionJwtSource,
                jwt: transportFromEcdsa.walletSessionJwt || null,
              }
            : null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.primary).toEqual({
      source: 'ecdsa_record',
      jwt: 'jwt-ecdsa-primary',
    });
    expect(result.fallback).toEqual({
      source: 'none',
      jwt: null,
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
  });
});

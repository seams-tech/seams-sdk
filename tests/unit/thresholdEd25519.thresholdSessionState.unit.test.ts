import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  thresholdSessionAuth:
    '/sdk/esm/core/signingEngine/orchestration/near/shared/thresholdSessionAuth.js',
  warmSessionManager: '/sdk/esm/core/signingEngine/session/WarmSessionManager.js',
  thresholdSessionStore:
    '/sdk/esm/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.js',
} as const;

test.describe('threshold Ed25519 threshold-session state', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('resolves canonical threshold session state from the warm-session record', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const helperMod = await import(paths.thresholdSessionAuth);
        const managerMod = await import(paths.warmSessionManager);
        const storeMod = await import(paths.thresholdSessionStore);

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        storeMod.upsertStoredThresholdEd25519SessionRecord({
          nearAccountId: 'alice.testnet',
          rpId: 'example.localhost',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-1',
          participantIds: [1, 2],
          runtimeSnapshotScope: {
            orgId: 'org-a',
            environmentId: 'env-a',
          },
          xClientBaseB64u: 'x-client-base',
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'canonical-threshold-session',
          thresholdSessionJwt: 'jwt-canonical',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
          source: 'registration',
        });

        try {
          const warmSessionManager = managerMod.createWarmSessionManager();
          const resolved = helperMod.requireResolvedThresholdEd25519SessionState({
            warmSessionManager,
            thresholdSessionId: 'canonical-threshold-session',
          });
          return {
            sessionKind: resolved.sessionKind,
            thresholdSessionJwt: resolved.thresholdSessionJwt || null,
            thresholdSessionId: resolved.record.thresholdSessionId,
            xClientBaseB64u: resolved.xClientBaseB64u || null,
            relayerUrl: resolved.relayerUrl,
          };
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      sessionKind: 'jwt',
      thresholdSessionJwt: 'jwt-canonical',
      thresholdSessionId: 'canonical-threshold-session',
      xClientBaseB64u: 'x-client-base',
      relayerUrl: 'https://relay.example',
    });
  });

  test('prefers the Ed25519 record when ECDSA shares the same threshold session id', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const helperMod = await import(paths.thresholdSessionAuth);
        const managerMod = await import(paths.warmSessionManager);
        const storeMod = await import(paths.thresholdSessionStore);
        const ecdsaStoreDeps = {
          recordsByLane: new Map(),
          exportArtifactsByLane: new Map(),
        };

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        storeMod.clearAllThresholdEcdsaSessionRecords(ecdsaStoreDeps);

        storeMod.upsertStoredThresholdEd25519SessionRecord({
          nearAccountId: 'alice.testnet',
          rpId: 'example.localhost',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-ed25519',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'shared-session-id',
          thresholdSessionJwt: 'jwt-ed25519',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
          updatedAtMs: Date.now(),
          source: 'login',
        });

        storeMod.upsertThresholdEcdsaSessionFromBootstrap(ecdsaStoreDeps, {
          nearAccountId: 'alice.testnet',
          chain: 'evm',
          bootstrap: {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: 'ecdsa-key-id',
              backendBinding: {
                relayerKeyId: 'rk-ecdsa',
                clientVerifyingShareB64u: 'client-verifying-share',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'shared-session-id',
              thresholdSessionJwt: 'jwt-ecdsa',
            } as any,
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: 'ecdsa-key-id',
              relayerKeyId: 'rk-ecdsa',
              clientVerifyingShareB64u: 'client-verifying-share',
              participantIds: [1, 2],
            } as any,
            session: {
              ok: true,
              sessionId: 'shared-session-id',
              jwt: 'jwt-ecdsa',
              expiresAtMs: Date.now() + 60_000,
              remainingUses: 3,
              clientVerifyingShareB64u: 'client-verifying-share',
            } as any,
          },
          source: 'login',
        });

        try {
          const warmSessionManager = managerMod.createWarmSessionManager();
          const directEd25519 = storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
            'shared-session-id',
          );
          const directScoped =
            warmSessionManager.resolveEd25519RecordByThresholdSessionId('shared-session-id');
          const resolved = helperMod.requireResolvedThresholdEd25519SessionState({
            warmSessionManager,
            thresholdSessionId: 'shared-session-id',
          });
          return {
            directEd25519RelayerKeyId: String(directEd25519?.relayerKeyId || ''),
            directScopedRelayerKeyId: String(directScoped?.relayerKeyId || ''),
            relayerKeyId: resolved.record.relayerKeyId,
            thresholdSessionJwt: resolved.thresholdSessionJwt || null,
            thresholdSessionId: resolved.record.thresholdSessionId,
          };
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
          storeMod.clearAllThresholdEcdsaSessionRecords(ecdsaStoreDeps);
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      directEd25519RelayerKeyId: 'rk-ed25519',
      directScopedRelayerKeyId: 'rk-ed25519',
      relayerKeyId: 'rk-ed25519',
      thresholdSessionJwt: 'jwt-ed25519',
      thresholdSessionId: 'shared-session-id',
    });
  });
});

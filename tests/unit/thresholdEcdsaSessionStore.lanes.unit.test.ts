import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  thresholdSessionStore:
    '/sdk/esm/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.js',
} as const;

test.describe('threshold ECDSA lane-scoped session store', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('canonical lane key encoding round-trips and malformed lane keys are ignored', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const storeMod = await import(paths.thresholdSessionStore);
      const deps = { recordsByLane: new Map<string, unknown>() };
      storeMod.clearAllThresholdEcdsaSessionRecords(deps);
      const now = Date.now();
      const relayerKeyId = 'rk:tempo/1 with spaces';
      const ecdsaThresholdKeyId = 'ek:tempo/1 with spaces';
      storeMod.upsertThresholdEcdsaSessionFromBootstrap(deps, {
        nearAccountId: 'alice.testnet',
        chain: 'tempo',
        source: 'login',
        bootstrap: {
          thresholdEcdsaKeyRef: {
            type: 'threshold-ecdsa-secp256k1',
            userId: 'alice.testnet',
            relayerUrl: 'https://relay.example',
            ecdsaThresholdKeyId,
            backendBinding: {
              relayerKeyId,
              clientVerifyingShareB64u: 'AQ',
            },
            participantIds: [1, 2],
            thresholdSessionKind: 'jwt',
            thresholdSessionId: 'session-tempo-encode-1',
            thresholdSessionJwt: 'jwt-tempo-encode-1',
          },
          keygen: {
            ok: true,
            keygenSessionId: 'kg-tempo-encode-1',
            rpId: 'example.localhost',
            clientVerifyingShareB64u: 'AQ',
            relayerKeyId,
            participantIds: [1, 2],
          },
          session: {
            ok: true,
            sessionId: 'session-tempo-encode-1',
            jwt: 'jwt-tempo-encode-1',
            expiresAtMs: now + 120_000,
            remainingUses: 9,
          },
        },
      });

      const v2Prefix = 'tatchi:threshold-ecdsa-session:v2';
      const laneIndex = JSON.parse(sessionStorage.getItem(`${v2Prefix}:index`) || '[]');
      const canonicalLaneKey = Array.isArray(laneIndex) ? String(laneIndex[0] || '') : '';
      const canonicalDecoded = canonicalLaneKey
        .split('|')
        .map((token) => decodeURIComponent(String(token || '').trim()));

      sessionStorage.clear();
      sessionStorage.setItem(`${v2Prefix}:index`, JSON.stringify(['alice|not-a-chain|rk']));
      sessionStorage.setItem(
        `${v2Prefix}:alice|not-a-chain|rk`,
        JSON.stringify({
          v: 1,
          record: {
            nearAccountId: 'alice.testnet',
            chain: 'tempo',
            relayerUrl: 'https://relay.example',
            relayerKeyId: 'rk-tempo',
            clientVerifyingShareB64u: 'AQ',
            participantIds: [1, 2],
            thresholdSessionKind: 'jwt',
            thresholdSessionId: 'invalid-lane-key-record',
            thresholdSessionJwt: 'jwt-invalid',
            expiresAtMs: now + 120_000,
            remainingUses: 1,
            updatedAtMs: now,
            source: 'login',
          },
        }),
      );
      deps.recordsByLane.clear();

      let malformedLaneKeyError = '';
      try {
        storeMod.getThresholdEcdsaSessionRecordForSigning(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'tempo',
        });
      } catch (error) {
        malformedLaneKeyError = error instanceof Error ? error.message : String(error || '');
      }

      return {
        canonicalLaneKey,
        canonicalDecoded,
        malformedLaneKeyError,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.canonicalLaneKey).toContain('|');
    expect(result.canonicalDecoded).toEqual(['alice.testnet', 'tempo', 'ek:tempo/1 with spaces']);
    expect(result.malformedLaneKeyError).toContain('missing canonical threshold ECDSA session');
  });

  test('persists deterministic lane keys in canonical storage index', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const deps = { recordsByLane: new Map<string, unknown>() };
        storeMod.clearAllThresholdEcdsaSessionRecords(deps);
        const now = Date.now();
        storeMod.upsertThresholdEcdsaSessionFromBootstrap(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'tempo',
          source: 'login',
          bootstrap: {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: 'ek-tempo',
              backendBinding: {
                relayerKeyId: 'rk-tempo',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-tempo-1',
              thresholdSessionJwt: 'jwt-tempo-1',
            },
            keygen: {
              ok: true,
              keygenSessionId: 'kg-tempo-1',
              rpId: 'example.localhost',
              clientVerifyingShareB64u: 'AQ',
              relayerKeyId: 'rk-tempo',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'session-tempo-1',
              jwt: 'jwt-tempo-1',
              expiresAtMs: now + 120_000,
              remainingUses: 9,
            },
          },
        });
        const v2Prefix = 'tatchi:threshold-ecdsa-session:v2';
        const index = JSON.parse(sessionStorage.getItem(`${v2Prefix}:index`) || '[]');
        const laneKey = Array.isArray(index) ? String(index[0] || '') : '';
        const parsed = laneKey
          .split('|')
          .map((token) => decodeURIComponent(String(token || '').trim()))
          .filter(Boolean);
        return {
          laneKey,
          parsed,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.laneKey).toContain('|');
    expect(result.parsed).toEqual(['alice.testnet', 'tempo', 'ek-tempo']);
  });

  test('resolves Tempo/EVM records independently for the same account', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const deps = {
          recordsByLane: new Map<string, unknown>(),
          exportArtifactsByLane: new Map<string, unknown>(),
        };
        const now = Date.now();

        const upsert = (
          chain: 'tempo' | 'evm',
          sessionId: string,
          relayerKeyId: string,
          ecdsaThresholdKeyId: string,
        ) =>
          storeMod.upsertThresholdEcdsaSessionFromBootstrap(deps, {
            nearAccountId: 'alice.testnet',
            chain,
            source: 'login',
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relay.example',
                ecdsaThresholdKeyId,
                backendBinding: {
                  relayerKeyId,
                  clientVerifyingShareB64u: `cvs-${chain}`,
                },
                participantIds: [1, 2],
                thresholdSessionKind: 'jwt',
                thresholdSessionId: sessionId,
                thresholdSessionJwt: `jwt-${chain}`,
              },
              keygen: {
                ok: true,
                keygenSessionId: `kg-${chain}`,
                rpId: 'example.localhost',
                clientVerifyingShareB64u: `cvs-${chain}`,
                relayerKeyId,
                participantIds: [1, 2],
              },
              session: {
                ok: true,
                sessionId,
                jwt: `jwt-${chain}`,
                expiresAtMs: now + 120_000,
                remainingUses: 9,
              },
            },
          });

        storeMod.clearAllThresholdEcdsaSessionRecords(deps);
        upsert('tempo', 'session-tempo-1', 'rk-tempo', 'ek-tempo');
        upsert('evm', 'session-evm-1', 'rk-evm', 'ek-evm');

        const tempoRecord = storeMod.getThresholdEcdsaSessionRecordForSigning(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'tempo',
        });
        const evmRecord = storeMod.getThresholdEcdsaSessionRecordForSigning(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'evm',
        });
        return {
          tempo: {
            chain: tempoRecord.chain,
            sessionId: tempoRecord.thresholdSessionId,
            relayerKeyId: tempoRecord.relayerKeyId,
          },
          evm: {
            chain: evmRecord.chain,
            sessionId: evmRecord.thresholdSessionId,
            relayerKeyId: evmRecord.relayerKeyId,
          },
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.tempo).toEqual({
      chain: 'tempo',
      sessionId: 'session-tempo-1',
      relayerKeyId: 'rk-tempo',
    });
    expect(result.evm).toEqual({
      chain: 'evm',
      sessionId: 'session-evm-1',
      relayerKeyId: 'rk-evm',
    });
  });

  test('persists canonical threshold ECDSA records and loads legacy records without model metadata', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const deps = { recordsByLane: new Map<string, unknown>() };
        const now = Date.now();

        storeMod.clearAllThresholdEcdsaSessionRecords(deps);
        storeMod.upsertThresholdEcdsaSessionFromBootstrap(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'evm',
          source: 'registration',
          bootstrap: {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: 'ek-evm-hss',
              backendBinding: {
                relayerKeyId: 'rk-evm-hss',
                clientVerifyingShareB64u: 'AQ',
              },
              ecdsaHssExportArtifact: {
                artifactKind: 'ecdsa-hss-secp256k1-key-v1',
                chain: 'evm',
                publicKeyHex: `0x${'02'}${'11'.repeat(32)}`,
                privateKeyHex: `0x${'22'.repeat(32)}`,
                ethereumAddress: `0x${'33'.repeat(20)}`,
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-evm-hss-1',
              thresholdSessionJwt: 'jwt-evm-hss-1',
            },
            keygen: {
              ok: true,
              keygenSessionId: 'kg-evm-hss-1',
              rpId: 'example.localhost',
              clientVerifyingShareB64u: 'AQ',
              relayerKeyId: 'rk-evm-hss',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'session-evm-hss-1',
              jwt: 'jwt-evm-hss-1',
              expiresAtMs: now + 120_000,
              remainingUses: 9,
            },
          },
        });

        const explicitRecord = storeMod.getThresholdEcdsaSessionRecordForSigning(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'evm',
        });
        const explicitKeyRef = storeMod.getThresholdEcdsaKeyRefForSigning(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'evm',
        });
        const explicitStoragePrefix = 'tatchi:threshold-ecdsa-session:v2';
        const explicitLaneIndex = JSON.parse(
          sessionStorage.getItem(`${explicitStoragePrefix}:index`) || '[]',
        );
        const explicitLaneKey = Array.isArray(explicitLaneIndex) ? String(explicitLaneIndex[0] || '') : '';
        const explicitStoredRaw = explicitLaneKey
          ? sessionStorage.getItem(`${explicitStoragePrefix}:${explicitLaneKey}`) || ''
          : '';

        sessionStorage.clear();
        const legacyPrefix = 'tatchi:threshold-ecdsa-session:v2';
        const legacyLaneKey =
          encodeURIComponent('bob.testnet') + '|evm|' + encodeURIComponent('ek-legacy');
        sessionStorage.setItem(`${legacyPrefix}:index`, JSON.stringify([legacyLaneKey]));
        sessionStorage.setItem(
          `${legacyPrefix}:${legacyLaneKey}`,
          JSON.stringify({
            v: 1,
            record: {
              nearAccountId: 'bob.testnet',
              chain: 'evm',
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: 'ek-legacy',
              relayerKeyId: 'rk-legacy',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-legacy-1',
              thresholdSessionJwt: 'jwt-legacy-1',
              expiresAtMs: now + 120_000,
              remainingUses: 9,
              updatedAtMs: now,
              source: 'login',
            },
          }),
        );
        deps.recordsByLane.clear();

        const legacyRecord = storeMod.getThresholdEcdsaSessionRecordForSigning(deps, {
          nearAccountId: 'bob.testnet',
          chain: 'evm',
        });
        const legacyKeyRef = storeMod.getThresholdEcdsaKeyRefForSigning(deps, {
          nearAccountId: 'bob.testnet',
          chain: 'evm',
        });

        return {
          explicitRecordHasThresholdKeyId: String(explicitRecord.ecdsaThresholdKeyId || '').trim(),
          explicitKeyRefHasThresholdKeyId: String(explicitKeyRef.ecdsaThresholdKeyId || '').trim(),
          explicitStoredHasPrivateKeyHex: explicitStoredRaw.includes('privateKeyHex'),
          legacyRecordHasThresholdKeyId: String(legacyRecord.ecdsaThresholdKeyId || '').trim(),
          legacyKeyRefHasThresholdKeyId: String(legacyKeyRef.ecdsaThresholdKeyId || '').trim(),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      explicitRecordHasThresholdKeyId: 'ek-evm-hss',
      explicitKeyRefHasThresholdKeyId: 'ek-evm-hss',
      explicitStoredHasPrivateKeyHex: false,
      legacyRecordHasThresholdKeyId: 'ek-legacy',
      legacyKeyRefHasThresholdKeyId: 'ek-legacy',
    });
  });

  test('fails chain-strict lookup when requested lane is missing', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const deps = { recordsByLane: new Map<string, unknown>() };
        const now = Date.now();

        storeMod.clearAllThresholdEcdsaSessionRecords(deps);
        storeMod.upsertThresholdEcdsaSessionFromBootstrap(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'tempo',
          source: 'login',
          bootstrap: {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: 'ek-tempo-only',
              backendBinding: {
                relayerKeyId: 'rk-tempo-only',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-tempo-only',
              thresholdSessionJwt: 'jwt-tempo-only',
            },
            keygen: {
              ok: true,
              keygenSessionId: 'kg-tempo-only',
              rpId: 'example.localhost',
              clientVerifyingShareB64u: 'AQ',
              relayerKeyId: 'rk-tempo-only',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'session-tempo-only',
              jwt: 'jwt-tempo-only',
              expiresAtMs: now + 120_000,
              remainingUses: 9,
            },
          },
        });

        let errorMessage = '';
        try {
          storeMod.getThresholdEcdsaSessionRecordForSigning(deps, {
            nearAccountId: 'alice.testnet',
            chain: 'evm',
          });
        } catch (error) {
          errorMessage = error instanceof Error ? error.message : String(error || '');
        }

        return { errorMessage };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.errorMessage).toContain('missing canonical threshold ECDSA session');
  });

  test('migrates legacy account-scoped v1 storage into canonical lane keys', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const deps = { recordsByLane: new Map<string, unknown>() };
        const now = Date.now();
        const legacyPrefix = 'tatchi:threshold-ecdsa-session:v1';
        const legacyRecordKey = `${legacyPrefix}:alice.testnet`;

        sessionStorage.clear();
        sessionStorage.setItem(`${legacyPrefix}:index`, JSON.stringify(['alice.testnet']));
        sessionStorage.setItem(
          legacyRecordKey,
          JSON.stringify({
            v: 1,
            record: {
              nearAccountId: 'alice.testnet',
              chain: 'tempo',
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: 'ek-legacy',
              relayerKeyId: 'rk-legacy',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'legacy-session-1',
              thresholdSessionJwt: 'legacy-jwt-1',
              expiresAtMs: now + 120_000,
              remainingUses: 9,
              updatedAtMs: now,
              source: 'login',
            },
          }),
        );

        const record = storeMod.getThresholdEcdsaSessionRecordForSigning(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'tempo',
        });
        const laneKey = ['alice.testnet', 'tempo', 'ek-legacy']
          .map((part) => encodeURIComponent(part))
          .join('|');
        const v2Prefix = 'tatchi:threshold-ecdsa-session:v2';
        const v2Index = JSON.parse(sessionStorage.getItem(`${v2Prefix}:index`) || '[]');
        return {
          sessionId: record.thresholdSessionId,
          relayerKeyId: record.relayerKeyId,
          v1RecordRemoved: sessionStorage.getItem(legacyRecordKey) === null,
          v1IndexRemoved: sessionStorage.getItem(`${legacyPrefix}:index`) === null,
          v2IndexHasLaneKey: Array.isArray(v2Index) && v2Index.includes(laneKey),
          v2LaneRecordExists: !!sessionStorage.getItem(`${v2Prefix}:${laneKey}`),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.sessionId).toBe('legacy-session-1');
    expect(result.relayerKeyId).toBe('rk-legacy');
    expect(result.v1RecordRemoved).toBe(true);
    expect(result.v1IndexRemoved).toBe(true);
    expect(result.v2IndexHasLaneKey).toBe(true);
    expect(result.v2LaneRecordExists).toBe(true);
  });
});

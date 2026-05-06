import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  thresholdSessionAuth:
    '/sdk/esm/core/signingEngine/orchestration/near/shared/thresholdSessionAuth.js',
  warmSessionCapabilityReader:
    '/sdk/esm/core/signingEngine/session/warmSigning/capabilityReader.js',
  thresholdSessionStore:
    '/sdk/esm/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.js',
} as const;

test.describe('threshold Ed25519 threshold-session state', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('publishing a fresh Ed25519 runtime lane replaces stale account runtime lanes', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const nearAccountId = 'alice.testnet';
        const common = {
          nearAccountId,
          rpId: 'example.localhost',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-ed25519',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt' as const,
          expiresAtMs: Date.now() + 60_000,
        };

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        try {
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            ...common,
            thresholdSessionId: 'old-passkey-session',
            walletSigningSessionId: 'old-passkey-wallet-session',
            thresholdSessionJwt: 'jwt-old-passkey',
            remainingUses: 0,
            updatedAtMs: 1,
            source: 'login',
          });
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            ...common,
            thresholdSessionId: 'old-otp-session',
            walletSigningSessionId: 'old-otp-wallet-session',
            thresholdSessionJwt: 'jwt-old-otp',
            remainingUses: 0,
            updatedAtMs: 2,
            emailOtpAuthContext: {
              policy: 'per_operation',
              retention: 'single_use',
              reason: 'sign',
              authMethod: 'email_otp',
            },
            source: 'email_otp',
          });
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            ...common,
            thresholdSessionId: 'fresh-otp-session',
            walletSigningSessionId: 'fresh-otp-wallet-session',
            thresholdSessionJwt: 'jwt-fresh-otp',
            remainingUses: 1,
            updatedAtMs: 3,
            emailOtpAuthContext: {
              policy: 'per_operation',
              retention: 'single_use',
              reason: 'sign',
              authMethod: 'email_otp',
            },
            source: 'email_otp',
          });

          const records = storeMod.listStoredThresholdEd25519SessionRecordsForAccount(nearAccountId);
          return {
            records: records.map(
              (record: {
                source: string;
                thresholdSessionId: string;
                walletSigningSessionId?: string;
                remainingUses: number;
              }) => ({
                source: record.source,
                thresholdSessionId: record.thresholdSessionId,
                walletSigningSessionId: record.walletSigningSessionId,
                remainingUses: record.remainingUses,
              }),
            ),
            oldPasskeyLanePresent: Boolean(
              storeMod.getStoredThresholdEd25519SessionRecordForLane({
                nearAccountId,
                authMethod: 'passkey',
                walletSigningSessionId: 'old-passkey-wallet-session',
                thresholdSessionId: 'old-passkey-session',
              }),
            ),
            oldOtpLanePresent: Boolean(
              storeMod.getStoredThresholdEd25519SessionRecordForLane({
                nearAccountId,
                authMethod: 'email_otp',
                walletSigningSessionId: 'old-otp-wallet-session',
                thresholdSessionId: 'old-otp-session',
              }),
            ),
            freshOtpLanePresent: Boolean(
              storeMod.getStoredThresholdEd25519SessionRecordForLane({
                nearAccountId,
                authMethod: 'email_otp',
                walletSigningSessionId: 'fresh-otp-wallet-session',
                thresholdSessionId: 'fresh-otp-session',
              }),
            ),
          };
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      records: [
        {
          source: 'email_otp',
          thresholdSessionId: 'fresh-otp-session',
          walletSigningSessionId: 'fresh-otp-wallet-session',
          remainingUses: 1,
        },
      ],
      oldPasskeyLanePresent: false,
      oldOtpLanePresent: false,
      freshOtpLanePresent: true,
    });
  });

  test('resolves canonical threshold session state from the warm-session record', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const helperMod = await import(paths.thresholdSessionAuth);
        const capabilityReaderMod = await import(paths.warmSessionCapabilityReader);
        const storeMod = await import(paths.thresholdSessionStore);

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        storeMod.upsertStoredThresholdEd25519SessionRecord({
          nearAccountId: 'alice.testnet',
          rpId: 'example.localhost',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-1',
          participantIds: [1, 2],
          runtimePolicyScope: {
            orgId: 'org-a',
            projectId: 'proj-a',
            envId: 'env-a',
            signingRootVersion: 'default',
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
          const signingSessionCoordinator = capabilityReaderMod.createWarmSessionCapabilityReader();
          const resolved = helperMod.requireResolvedThresholdEd25519SessionState({
            signingSessionCoordinator,
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
        const capabilityReaderMod = await import(paths.warmSessionCapabilityReader);
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
              signingRootId: 'proj-a:env-a',
              signingRootVersion: 'default',
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
          const signingSessionCoordinator = capabilityReaderMod.createWarmSessionCapabilityReader();
          const directEd25519 = storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
            'shared-session-id',
          );
          const directScoped =
            signingSessionCoordinator.resolveEd25519RecordByThresholdSessionId('shared-session-id');
          const resolved = helperMod.requireResolvedThresholdEd25519SessionState({
            signingSessionCoordinator,
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

  test('rejects stale threshold session records with runtimeSnapshotScope or environmentId', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);

        const baseRecord = {
          nearAccountId: 'alice.testnet',
          rpId: 'example.localhost',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-1',
          participantIds: [1, 2],
          xClientBaseB64u: 'x-client-base',
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'stale-threshold-session',
          thresholdSessionJwt: 'jwt-stale',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
          source: 'registration',
        };

        const attempts: string[] = [];
        try {
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            ...baseRecord,
            runtimePolicyScope: {
              orgId: 'org-a',
              projectId: 'proj-a',
              envId: 'env-a',
              environmentId: 'env-a',
            },
          });
          attempts.push('accepted');
        } catch (error) {
          attempts.push(error instanceof Error ? error.message : String(error));
        }

        const staleRecord = {
          ...baseRecord,
          runtimeSnapshotScope: {
            orgId: 'org-a',
            projectId: 'proj-a',
            envId: 'env-a',
          },
        };
        sessionStorage.setItem(
          'seams:threshold-ed25519-session:v1:alice.testnet',
          JSON.stringify({ v: 1, record: staleRecord }),
        );
        sessionStorage.setItem(
          'seams:threshold-ed25519-session:v1:session-index',
          JSON.stringify({ 'stale-threshold-session': 'alice.testnet' }),
        );
        try {
          attempts.push(
            storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
              'stale-threshold-session',
            ) === null
              ? 'stale-record-dropped'
              : 'accepted',
          );
        } catch (error) {
          const err = error as { name?: string; reason?: string };
          attempts.push(
            err?.name === 'ThresholdSessionStoreInvalidRecordError'
              ? `stale-record-invalid:${String(err.reason || '')}`
              : String(error || ''),
          );
        }

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        return attempts;
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual([
      'Invalid threshold session record: stale runtimePolicyScope',
      'stale-record-invalid:invalid_shape',
    ]);
  });

  test('rejects malformed canonical Ed25519 session records at the store boundary', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);

        const makeBaseRecord = (thresholdSessionId: string): Record<string, unknown> => ({
          nearAccountId: `${thresholdSessionId}.testnet`,
          rpId: 'example.localhost',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-1',
          participantIds: [1, 2],
          xClientBaseB64u: 'x-client-base',
          thresholdSessionKind: 'jwt',
          thresholdSessionId,
          thresholdSessionJwt: `jwt-${thresholdSessionId}`,
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
          source: 'email_otp',
          emailOtpAuthContext: {
            policy: 'session',
            retention: 'session',
            reason: 'login',
            authMethod: 'email_otp',
          },
        });

        const writeRawRecord = (record: Record<string, unknown>) => {
          const nearAccountId = String(record.nearAccountId || '');
          const thresholdSessionId = String(record.thresholdSessionId || '');
          sessionStorage.setItem(
            `seams:threshold-ed25519-session:v1:${nearAccountId}`,
            JSON.stringify({ v: 1, record }),
          );
          sessionStorage.setItem(
            'seams:threshold-ed25519-session:v1:session-index',
            JSON.stringify({ [thresholdSessionId]: nearAccountId }),
          );
        };

        const malformedCases: Array<{
          name: string;
          record: Record<string, unknown>;
        }> = [
          {
            name: 'missing-remainingUses',
            record: ((record) => {
              delete record.remainingUses;
              return record;
            })(makeBaseRecord('missing-remaining-uses')),
          },
          {
            name: 'negative-remainingUses',
            record: {
              ...makeBaseRecord('negative-remaining-uses'),
              remainingUses: -1,
            },
          },
          {
            name: 'missing-expiresAtMs',
            record: ((record) => {
              delete record.expiresAtMs;
              return record;
            })(makeBaseRecord('missing-expires-at-ms')),
          },
          {
            name: 'invalid-expiresAtMs',
            record: {
              ...makeBaseRecord('invalid-expires-at-ms'),
              expiresAtMs: 0,
            },
          },
          {
            name: 'missing-jwt-for-jwt-session',
            record: ((record) => {
              delete record.thresholdSessionJwt;
              return record;
            })(makeBaseRecord('missing-jwt')),
          },
          {
            name: 'missing-email-otp-context',
            record: ((record) => {
              delete record.emailOtpAuthContext;
              return record;
            })(makeBaseRecord('missing-email-otp-context')),
          },
          {
            name: 'invalid-email-otp-retention',
            record: {
              ...makeBaseRecord('invalid-email-otp-retention'),
              emailOtpAuthContext: {
                policy: 'per_operation',
                retention: 'session',
                reason: 'sign',
                authMethod: 'email_otp',
              },
            },
          },
        ];

        const readErrorCode = (error: unknown) => {
          const err = error as { name?: string; reason?: string; code?: string };
          if (err?.name === 'ThresholdSessionStoreInvalidRecordError') {
            return `invalid:${String(err.reason || err.code || '')}`;
          }
          return 'missing';
        };

        const attempts: string[] = [];
        try {
          for (const attempt of malformedCases) {
            storeMod.clearAllStoredThresholdEd25519SessionRecords();
            writeRawRecord(attempt.record);
            try {
              const stored = storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
                String(attempt.record.thresholdSessionId || ''),
              );
              attempts.push(`${attempt.name}:${stored === null ? 'rejected' : 'accepted'}`);
            } catch (error) {
              attempts.push(`${attempt.name}:${readErrorCode(error)}`);
            }
          }

          storeMod.clearAllStoredThresholdEd25519SessionRecords();
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            ...makeBaseRecord('cookie-without-jwt'),
            thresholdSessionKind: 'cookie',
            thresholdSessionJwt: undefined,
          });
          const cookieRecord = storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
            'cookie-without-jwt',
          );
          attempts.push(`cookie-without-jwt:${cookieRecord ? 'accepted' : 'rejected'}`);
          return attempts;
        } finally {
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual([
      'missing-remainingUses:invalid:invalid_shape',
      'negative-remainingUses:invalid:invalid_shape',
      'missing-expiresAtMs:invalid:invalid_shape',
      'invalid-expiresAtMs:invalid:invalid_shape',
      'missing-jwt-for-jwt-session:invalid:invalid_shape',
      'missing-email-otp-context:invalid:invalid_shape',
      'invalid-email-otp-retention:invalid:invalid_shape',
      'cookie-without-jwt:accepted',
    ]);
  });
});

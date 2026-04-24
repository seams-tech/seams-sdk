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

  test('signing key ref carries wallet signing-session id for shared budget routing', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const deps = { recordsByLane: new Map<string, unknown>() };
        const now = Date.now();
        storeMod.upsertThresholdEcdsaSessionFromBootstrap(deps, {
          nearAccountId: 'budget-lane.testnet',
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
              userId: 'budget-lane.testnet',
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: 'ecdsa-budget-lane',
              signingRootId: 'proj_test:dev',
              backendBinding: {
                relayerKeyId: 'relayer-budget-lane',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'ecdsa-budget-lane-session',
              thresholdSessionJwt: 'jwt:ecdsa-budget-lane-session',
            },
            keygen: {
              ok: true,
              keygenSessionId: 'kg-budget-lane',
              rpId: 'example.localhost',
              clientVerifyingShareB64u: 'AQ',
              relayerKeyId: 'relayer-budget-lane',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'ecdsa-budget-lane-session',
              jwt: 'jwt:ecdsa-budget-lane-session',
              walletSigningSessionId: 'wallet-budget-lane-session',
              expiresAtMs: now + 120_000,
              remainingUses: 3,
            },
          },
        });

        return storeMod.getThresholdEcdsaKeyRefForLookup(deps, {
          nearAccountId: 'budget-lane.testnet',
          chain: 'evm',
          source: 'email_otp',
        });
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.walletSigningSessionId).toBe('wallet-budget-lane-session');
  });

  test('source-filtered signing lookup can select Email OTP lane over newer passkey lane', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const deps = { recordsByLane: new Map<string, unknown>(), now: () => 1_000 };
        const accountId = 'source-filter.testnet';
        const makeBootstrap = (args: {
          keyId: string;
          sessionId: string;
          jwt: string;
          relayerKeyId: string;
          workerSessionId?: string;
        }) => ({
          thresholdEcdsaKeyRef: {
            type: 'threshold-ecdsa-secp256k1',
            userId: accountId,
            relayerUrl: 'https://relay.example',
            ecdsaThresholdKeyId: args.keyId,
            signingRootId: 'proj_test:dev',
            backendBinding: {
              relayerKeyId: args.relayerKeyId,
              clientVerifyingShareB64u: 'AQ',
              ...(args.workerSessionId
                ? {
                    clientAdditiveShareHandle: {
                      kind: 'email_otp_worker_session',
                      sessionId: args.workerSessionId,
                    },
                  }
                : {}),
            },
            participantIds: [1, 2],
            thresholdSessionKind: 'jwt',
            thresholdSessionId: args.sessionId,
            thresholdSessionJwt: args.jwt,
          },
          keygen: {
            ok: true,
            keygenSessionId: `kg:${args.sessionId}`,
            rpId: 'example.localhost',
            clientVerifyingShareB64u: 'AQ',
            relayerKeyId: args.relayerKeyId,
            participantIds: [1, 2],
          },
          session: {
            ok: true,
            sessionId: args.sessionId,
            jwt: args.jwt,
            expiresAtMs: Date.now() + 120_000,
            remainingUses: 5,
          },
        });

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
          bootstrap: makeBootstrap({
            keyId: 'email-otp-key',
            sessionId: 'email-otp-session',
            jwt: 'jwt:email-otp-session',
            relayerKeyId: 'rk-email',
            workerSessionId: 'email-worker-session',
          }),
        });

        deps.now = () => 2_000;
        storeMod.upsertThresholdEcdsaSessionFromBootstrap(deps, {
          nearAccountId: accountId,
          chain: 'evm',
          source: 'login',
          bootstrap: makeBootstrap({
            keyId: 'passkey-key',
            sessionId: 'passkey-session',
            jwt: 'jwt:passkey-session',
            relayerKeyId: 'rk-passkey',
          }),
        });

        return {
          passkeySessionId: storeMod.getThresholdEcdsaKeyRefForLookup(deps, {
            nearAccountId: accountId,
            chain: 'evm',
            source: 'login',
          }).thresholdSessionId,
          emailOtpSessionId: storeMod.getThresholdEcdsaKeyRefForLookup(deps, {
            nearAccountId: accountId,
            chain: 'evm',
            source: 'email_otp',
          }).thresholdSessionId,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.passkeySessionId).toBe('passkey-session');
    expect(result.emailOtpSessionId).toBe('email-otp-session');
  });

  test('source-scoped lane clearing does not erase the Email OTP routing anchor', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const deps = { recordsByLane: new Map<string, unknown>(), now: () => 1_000 };
        const accountId = 'source-clear.testnet';
        const now = Date.now();
        const makeBootstrap = (args: {
          keyId: string;
          sessionId: string;
          jwt: string;
          relayerKeyId: string;
          workerSessionId?: string;
        }) => ({
          thresholdEcdsaKeyRef: {
            type: 'threshold-ecdsa-secp256k1',
            userId: accountId,
            relayerUrl: 'https://relay.example',
            ecdsaThresholdKeyId: args.keyId,
            signingRootId: 'proj_test:dev',
            backendBinding: {
              relayerKeyId: args.relayerKeyId,
              clientVerifyingShareB64u: 'AQ',
              ...(args.workerSessionId
                ? {
                    clientAdditiveShareHandle: {
                      kind: 'email_otp_worker_session',
                      sessionId: args.workerSessionId,
                    },
                  }
                : {}),
            },
            participantIds: [1, 2],
            thresholdSessionKind: 'jwt',
            thresholdSessionId: args.sessionId,
            thresholdSessionJwt: args.jwt,
          },
          keygen: {
            ok: true,
            keygenSessionId: `kg:${args.sessionId}`,
            rpId: 'example.localhost',
            clientVerifyingShareB64u: 'AQ',
            relayerKeyId: args.relayerKeyId,
            participantIds: [1, 2],
          },
          session: {
            ok: true,
            sessionId: args.sessionId,
            jwt: args.jwt,
            expiresAtMs: now + 120_000,
            remainingUses: 1,
          },
        });

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
          },
          bootstrap: makeBootstrap({
            keyId: 'email-otp-key',
            sessionId: 'email-otp-session',
            jwt: 'jwt:email-otp-session',
            relayerKeyId: 'rk-email',
            workerSessionId: 'email-worker-session',
          }),
        });

        deps.now = () => 2_000;
        storeMod.upsertThresholdEcdsaSessionFromBootstrap(deps, {
          nearAccountId: accountId,
          chain: 'evm',
          source: 'login',
          bootstrap: makeBootstrap({
            keyId: 'passkey-key',
            sessionId: 'passkey-session',
            jwt: 'jwt:passkey-session',
            relayerKeyId: 'rk-passkey',
          }),
        });

        storeMod.clearThresholdEcdsaSessionRecordForLane(deps, {
          nearAccountId: accountId,
          chain: 'evm',
          source: 'login',
        });

        const emailAfterPasskeyClear = storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
          nearAccountId: accountId,
          chain: 'evm',
          source: 'email_otp',
        });
        const defaultAfterPasskeyClear = storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
          nearAccountId: accountId,
          chain: 'evm',
          source: 'email_otp',
        });

        deps.now = () => 3_000;
        storeMod.upsertThresholdEcdsaSessionFromBootstrap(deps, {
          nearAccountId: accountId,
          chain: 'evm',
          source: 'login',
          bootstrap: makeBootstrap({
            keyId: 'passkey-key-2',
            sessionId: 'passkey-session-2',
            jwt: 'jwt:passkey-session-2',
            relayerKeyId: 'rk-passkey-2',
          }),
        });
        storeMod.clearThresholdEcdsaSessionRecordForLane(deps, {
          nearAccountId: accountId,
          chain: 'evm',
          source: 'email_otp',
        });

        let emailLookupAfterEmailClear = '';
        try {
          storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
            nearAccountId: accountId,
            chain: 'evm',
            source: 'email_otp',
          });
        } catch (error) {
          emailLookupAfterEmailClear = error instanceof Error ? error.message : String(error || '');
        }
        const defaultAfterEmailClear = storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
          nearAccountId: accountId,
          chain: 'evm',
          source: 'login',
        });

        return {
          emailAfterPasskeyClear: emailAfterPasskeyClear.thresholdSessionId,
          defaultAfterPasskeyClear: defaultAfterPasskeyClear.thresholdSessionId,
          emailLookupAfterEmailClear,
          defaultAfterEmailClear: defaultAfterEmailClear.thresholdSessionId,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.emailAfterPasskeyClear).toBe('email-otp-session');
    expect(result.defaultAfterPasskeyClear).toBe('email-otp-session');
    expect(result.emailLookupAfterEmailClear).toContain('missing canonical threshold ECDSA session');
    expect(result.defaultAfterEmailClear).toBe('passkey-session-2');
  });

  test('canonical lane key encoding round-trips and malformed lane keys are ignored', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
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
              signingRootId: 'proj_test:dev',
              signingRootVersion: 'v1',
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

        const v3Prefix = 'tatchi:threshold-ecdsa-session:v3';
        const laneIndex = JSON.parse(sessionStorage.getItem(`${v3Prefix}:index`) || '[]');
        const canonicalLaneKey = Array.isArray(laneIndex) ? String(laneIndex[0] || '') : '';
        const canonicalDecoded = canonicalLaneKey
          .split('|')
          .map((token) => decodeURIComponent(String(token || '').trim()));

        sessionStorage.clear();
        sessionStorage.setItem(`${v3Prefix}:index`, JSON.stringify(['alice|not-a-chain|rk']));
        sessionStorage.setItem(
          `${v3Prefix}:alice|not-a-chain|rk`,
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
          storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
            nearAccountId: 'alice.testnet',
            chain: 'tempo',
            source: 'login',
          });
        } catch (error) {
          malformedLaneKeyError = error instanceof Error ? error.message : String(error || '');
        }

        return {
          canonicalLaneKey,
          canonicalDecoded,
          malformedLaneKeyError,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.canonicalLaneKey).toContain('|');
    expect(result.canonicalDecoded).toEqual([
      'alice.testnet',
      'tempo',
      'login',
      'ek:tempo/1 with spaces',
      'proj_test:dev',
      'v1',
    ]);
    expect(result.malformedLaneKeyError).toContain('missing canonical threshold ECDSA session');
  });

  test('rejects malformed and lane-mismatched persisted ECDSA records at the store boundary', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const deps = { recordsByLane: new Map<string, unknown>() };
        const prefix = 'tatchi:threshold-ecdsa-session:v3';
        const now = Date.now();

        const lane = {
          nearAccountId: 'alice.testnet',
          chain: 'evm',
          source: 'login',
          ecdsaThresholdKeyId: 'ek-boundary',
          signingRootId: 'proj_test:dev',
          signingRootVersion: 'v1',
        };
        const laneKey = [
          lane.nearAccountId,
          lane.chain,
          lane.source,
          lane.ecdsaThresholdKeyId,
          lane.signingRootId,
          lane.signingRootVersion,
        ]
          .map((part) => encodeURIComponent(part))
          .join('|');
        const makeBaseRecord = (sessionId: string): Record<string, unknown> => ({
          nearAccountId: lane.nearAccountId,
          chain: lane.chain,
          relayerUrl: 'https://relay.example',
          ecdsaThresholdKeyId: lane.ecdsaThresholdKeyId,
          signingRootId: lane.signingRootId,
          signingRootVersion: lane.signingRootVersion,
          relayerKeyId: 'rk-boundary',
          clientVerifyingShareB64u: 'AQ',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: sessionId,
          thresholdSessionJwt: `jwt-${sessionId}`,
          expiresAtMs: now + 120_000,
          remainingUses: 3,
          updatedAtMs: now,
          source: lane.source,
        });
        const writeRawRecord = (record: Record<string, unknown>) => {
          sessionStorage.setItem(`${prefix}:index`, JSON.stringify([laneKey]));
          sessionStorage.setItem(`${prefix}:${laneKey}`, JSON.stringify({ v: 1, record }));
          sessionStorage.setItem(
            `${prefix}:session-index`,
            JSON.stringify({ [String(record.thresholdSessionId || '')]: laneKey }),
          );
        };

        const cases: Array<{ name: string; record: Record<string, unknown> }> = [
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
            name: 'missing-jwt-for-jwt-session',
            record: ((record) => {
              delete record.thresholdSessionJwt;
              return record;
            })(makeBaseRecord('missing-jwt')),
          },
          {
            name: 'wrong-record-account',
            record: {
              ...makeBaseRecord('wrong-account'),
              nearAccountId: 'bob.testnet',
            },
          },
          {
            name: 'wrong-record-chain',
            record: {
              ...makeBaseRecord('wrong-chain'),
              chain: 'tempo',
            },
          },
          {
            name: 'wrong-record-source',
            record: {
              ...makeBaseRecord('wrong-source'),
              source: 'email_otp',
              emailOtpAuthContext: {
                policy: 'session',
                retention: 'session',
                reason: 'login',
                authMethod: 'email_otp',
              },
            },
          },
          {
            name: 'missing-email-otp-context',
            record: {
              ...makeBaseRecord('missing-email-otp-context'),
              source: 'email_otp',
            },
          },
          {
            name: 'invalid-email-otp-retention',
            record: {
              ...makeBaseRecord('invalid-email-otp-retention'),
              source: 'email_otp',
              emailOtpAuthContext: {
                policy: 'per_operation',
                retention: 'session',
                reason: 'sign',
                authMethod: 'email_otp',
              },
            },
          },
          {
            name: 'wrong-record-threshold-key',
            record: {
              ...makeBaseRecord('wrong-threshold-key'),
              ecdsaThresholdKeyId: 'ek-other',
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
          for (const attempt of cases) {
            storeMod.clearAllThresholdEcdsaSessionRecords(deps);
            deps.recordsByLane.clear();
            writeRawRecord(attempt.record);
            let lookupAccepted = false;
            try {
              storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
                nearAccountId: lane.nearAccountId,
                chain: lane.chain,
                source: lane.source,
                signingRootId: lane.signingRootId,
                signingRootVersion: lane.signingRootVersion,
              });
              lookupAccepted = true;
            } catch {}
            let reverseAccepted = false;
            let reverseError = '';
            try {
              reverseAccepted = !!storeMod.getStoredThresholdEcdsaSessionRecordByThresholdSessionId(
                String(attempt.record.thresholdSessionId || ''),
              );
            } catch (error) {
              reverseError = readErrorCode(error);
            }
            attempts.push(
              `${attempt.name}:${lookupAccepted ? 'lookup-accepted' : 'lookup-rejected'}:${reverseAccepted ? 'reverse-accepted' : reverseError ? `reverse-error-${reverseError}` : 'reverse-rejected'}`,
            );
          }

          storeMod.clearAllThresholdEcdsaSessionRecords(deps);
          deps.recordsByLane.clear();
          const cookieRecord = {
            ...makeBaseRecord('cookie-without-jwt'),
            thresholdSessionKind: 'cookie',
            thresholdSessionJwt: undefined,
          };
          writeRawRecord(cookieRecord);
          const validCookie = storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
            nearAccountId: lane.nearAccountId,
            chain: lane.chain,
            source: lane.source,
            signingRootId: lane.signingRootId,
            signingRootVersion: lane.signingRootVersion,
          });
          attempts.push(`cookie-without-jwt:${validCookie.thresholdSessionId}`);
          return attempts;
        } finally {
          storeMod.clearAllThresholdEcdsaSessionRecords(deps);
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual([
      'missing-remainingUses:lookup-rejected:reverse-error-invalid:invalid_shape',
      'negative-remainingUses:lookup-rejected:reverse-error-invalid:invalid_shape',
      'missing-expiresAtMs:lookup-rejected:reverse-error-invalid:invalid_shape',
      'missing-jwt-for-jwt-session:lookup-rejected:reverse-error-invalid:invalid_shape',
      'wrong-record-account:lookup-rejected:reverse-rejected',
      'wrong-record-chain:lookup-rejected:reverse-rejected',
      'wrong-record-source:lookup-rejected:reverse-rejected',
      'missing-email-otp-context:lookup-rejected:reverse-error-invalid:invalid_shape',
      'invalid-email-otp-retention:lookup-rejected:reverse-error-invalid:invalid_shape',
      'wrong-record-threshold-key:lookup-rejected:reverse-rejected',
      'cookie-without-jwt:cookie-without-jwt',
    ]);
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
              signingRootId: 'proj_test:dev',
              signingRootVersion: 'v1',
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
        const v3Prefix = 'tatchi:threshold-ecdsa-session:v3';
        const index = JSON.parse(sessionStorage.getItem(`${v3Prefix}:index`) || '[]');
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
    expect(result.parsed).toEqual([
      'alice.testnet',
      'tempo',
      'login',
      'ek-tempo',
      'proj_test:dev',
      'v1',
    ]);
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
                signingRootId: 'proj_test:dev',
                signingRootVersion: 'v1',
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

        const tempoRecord = storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'tempo',
          source: 'login',
        });
        const evmRecord = storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'evm',
          source: 'login',
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

  test('persists canonical threshold ECDSA records and loads canonical lane records', async ({
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
              signingRootId: 'proj_test:dev',
              signingRootVersion: 'v1',
              backendBinding: {
                relayerKeyId: 'rk-evm-hss',
                clientVerifyingShareB64u: 'AQ',
              },
              ecdsaHssExportArtifact: {
                artifactKind: 'ecdsa-hss-secp256k1-key-v1',
                chain: 'evm',
                signingRootId: 'proj_test:dev',
                signingRootVersion: 'v1',
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

        const explicitRecord = storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'evm',
          source: 'registration',
        });
        const explicitKeyRef = storeMod.getThresholdEcdsaKeyRefForLookup(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'evm',
          source: 'registration',
        });
        const explicitStoragePrefix = 'tatchi:threshold-ecdsa-session:v3';
        const explicitLaneIndex = JSON.parse(
          sessionStorage.getItem(`${explicitStoragePrefix}:index`) || '[]',
        );
        const explicitLaneKey = Array.isArray(explicitLaneIndex)
          ? String(explicitLaneIndex[0] || '')
          : '';
        const explicitStoredRaw = explicitLaneKey
          ? sessionStorage.getItem(`${explicitStoragePrefix}:${explicitLaneKey}`) || ''
          : '';
        return {
          explicitRecordHasThresholdKeyId: String(explicitRecord.ecdsaThresholdKeyId || '').trim(),
          explicitKeyRefHasThresholdKeyId: String(explicitKeyRef.ecdsaThresholdKeyId || '').trim(),
          explicitStoredHasPrivateKeyHex: explicitStoredRaw.includes('privateKeyHex'),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      explicitRecordHasThresholdKeyId: 'ek-evm-hss',
      explicitKeyRefHasThresholdKeyId: 'ek-evm-hss',
      explicitStoredHasPrivateKeyHex: false,
    });
  });

  test('Email OTP ECDSA sessions persist only opaque share handles, not derived share bytes', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const deps = { recordsByLane: new Map<string, unknown>() };
        const now = Date.now();
        const secretShareSentinel = 'email-otp-derived-share-must-not-persist';
        const handle = {
          kind: 'email_otp_worker_session',
          sessionId: 'email-otp-session-1',
        };

        storeMod.clearAllThresholdEcdsaSessionRecords(deps);
        storeMod.upsertThresholdEcdsaSessionFromBootstrap(deps, {
          nearAccountId: 'alice.testnet',
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
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: 'ek-email-otp',
              signingRootId: 'proj_test:dev',
              signingRootVersion: 'v1',
              backendBinding: {
                relayerKeyId: 'rk-email-otp',
                clientVerifyingShareB64u: 'AQ',
                clientAdditiveShare32B64u: secretShareSentinel,
                clientAdditiveShareHandle: handle,
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'email-otp-session-1',
              thresholdSessionJwt: 'jwt-email-otp-1',
            },
            keygen: {
              ok: true,
              keygenSessionId: 'kg-email-otp-1',
              rpId: 'example.localhost',
              clientVerifyingShareB64u: 'AQ',
              relayerKeyId: 'rk-email-otp',
              clientAdditiveShare32B64u: secretShareSentinel,
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'email-otp-session-1',
              jwt: 'jwt-email-otp-1',
              expiresAtMs: now + 120_000,
              remainingUses: 9,
            },
          },
        });

        const record = storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'evm',
          source: 'email_otp',
        });
        const keyRef = storeMod.getThresholdEcdsaKeyRefForLookup(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'evm',
          source: 'email_otp',
        });
        const prefix = 'tatchi:threshold-ecdsa-session:v3';
        const index = JSON.parse(sessionStorage.getItem(`${prefix}:index`) || '[]');
        const laneKey = Array.isArray(index) ? String(index[0] || '') : '';
        const storedRaw = laneKey ? sessionStorage.getItem(`${prefix}:${laneKey}`) || '' : '';

        return {
          recordHasInlineShare: Boolean(record.clientAdditiveShare32B64u),
          recordHandle: record.clientAdditiveShareHandle || null,
          keyRefHasInlineShare: Boolean(keyRef.backendBinding?.clientAdditiveShare32B64u),
          keyRefHandle: keyRef.backendBinding?.clientAdditiveShareHandle || null,
          storedContainsSentinel: storedRaw.includes(secretShareSentinel),
          storedContainsHandle: storedRaw.includes('email_otp_worker_session'),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      recordHasInlineShare: false,
      recordHandle: {
        kind: 'email_otp_worker_session',
        sessionId: 'email-otp-session-1',
      },
      keyRefHasInlineShare: false,
      keyRefHandle: {
        kind: 'email_otp_worker_session',
        sessionId: 'email-otp-session-1',
      },
      storedContainsSentinel: false,
      storedContainsHandle: true,
    });
  });

  test('signing-root binding filters persisted ECDSA sessions by root id and version', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const deps = { recordsByLane: new Map<string, unknown>() };
        const now = Date.now();

        const upsert = (
          signingRootId: string,
          signingRootVersion: string,
          sessionId: string,
          ecdsaThresholdKeyId: string,
        ) =>
          storeMod.upsertThresholdEcdsaSessionFromBootstrap(deps, {
            nearAccountId: 'alice.testnet',
            chain: 'evm',
            source: 'login',
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relay.example',
                ecdsaThresholdKeyId,
                signingRootId,
                signingRootVersion,
                backendBinding: {
                  relayerKeyId: `rk-${sessionId}`,
                  clientVerifyingShareB64u: 'AQ',
                },
                participantIds: [1, 2],
                thresholdSessionKind: 'jwt',
                thresholdSessionId: sessionId,
                thresholdSessionJwt: `jwt-${sessionId}`,
              },
              keygen: {
                ok: true,
                keygenSessionId: `kg-${sessionId}`,
                rpId: 'example.localhost',
                clientVerifyingShareB64u: 'AQ',
                relayerKeyId: `rk-${sessionId}`,
                participantIds: [1, 2],
              },
              session: {
                ok: true,
                sessionId,
                jwt: `jwt-${sessionId}`,
                expiresAtMs: now + 120_000,
                remainingUses: 9,
              },
            },
          });

        storeMod.clearAllThresholdEcdsaSessionRecords(deps);
        upsert('proj_a:dev', 'v1', 'session-root-a', 'ek-root-a');
        upsert('proj_b:dev', 'v2', 'session-root-b', 'ek-root-b');

        const rootARecord = storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'evm',
          source: 'login',
          signingRootId: 'proj_a:dev',
          signingRootVersion: 'v1',
        });
        const rootBRecord = storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
          nearAccountId: 'alice.testnet',
          chain: 'evm',
          source: 'login',
          signingRootId: 'proj_b:dev',
          signingRootVersion: 'v2',
        });

        let wrongRootIdError = '';
        try {
          storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
            nearAccountId: 'alice.testnet',
            chain: 'evm',
            source: 'login',
            signingRootId: 'proj_missing:dev',
            signingRootVersion: 'v1',
          });
        } catch (error) {
          wrongRootIdError = error instanceof Error ? error.message : String(error || '');
        }

        let wrongRootVersionError = '';
        try {
          storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
            nearAccountId: 'alice.testnet',
            chain: 'evm',
            source: 'login',
            signingRootId: 'proj_a:dev',
            signingRootVersion: 'v2',
          });
        } catch (error) {
          wrongRootVersionError = error instanceof Error ? error.message : String(error || '');
        }

        return {
          rootASessionId: rootARecord.thresholdSessionId,
          rootBSessionId: rootBRecord.thresholdSessionId,
          wrongRootIdError,
          wrongRootVersionError,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.rootASessionId).toBe('session-root-a');
    expect(result.rootBSessionId).toBe('session-root-b');
    expect(result.wrongRootIdError).toContain('missing canonical threshold ECDSA session');
    expect(result.wrongRootVersionError).toContain('missing canonical threshold ECDSA session');
  });

  test('persisted ECDSA session replay rejects wrong account and mismatched lane root binding', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const deps = { recordsByLane: new Map<string, unknown>() };
        const now = Date.now();
        const prefix = 'tatchi:threshold-ecdsa-session:v3';
        const laneKey = ['alice.testnet', 'evm', 'login', 'ek-root-bound', 'proj_a:dev', 'v1']
          .map((part) => encodeURIComponent(part))
          .join('|');
        sessionStorage.clear();
        sessionStorage.setItem(`${prefix}:index`, JSON.stringify([laneKey]));
        sessionStorage.setItem(
          `${prefix}:${laneKey}`,
          JSON.stringify({
            v: 1,
            record: {
              nearAccountId: 'alice.testnet',
              chain: 'evm',
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: 'ek-root-bound',
              signingRootId: 'proj_b:dev',
              signingRootVersion: 'v1',
              relayerKeyId: 'rk-root-bound',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-root-bound',
              thresholdSessionJwt: 'jwt-root-bound',
              expiresAtMs: now + 120_000,
              remainingUses: 9,
              updatedAtMs: now,
              source: 'login',
            },
          }),
        );

        let mismatchedLaneRootError = '';
        try {
          storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
            nearAccountId: 'alice.testnet',
            chain: 'evm',
            source: 'login',
            signingRootId: 'proj_a:dev',
            signingRootVersion: 'v1',
          });
        } catch (error) {
          mismatchedLaneRootError = error instanceof Error ? error.message : String(error || '');
        }

        let wrongAccountError = '';
        try {
          storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
            nearAccountId: 'bob.testnet',
            chain: 'evm',
            source: 'login',
            signingRootId: 'proj_a:dev',
            signingRootVersion: 'v1',
          });
        } catch (error) {
          wrongAccountError = error instanceof Error ? error.message : String(error || '');
        }

        return { mismatchedLaneRootError, wrongAccountError };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.mismatchedLaneRootError).toContain('missing canonical threshold ECDSA session');
    expect(result.wrongAccountError).toContain('missing canonical threshold ECDSA session');
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
              signingRootId: 'proj_test:dev',
              signingRootVersion: 'v1',
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
          storeMod.getThresholdEcdsaSessionRecordForLookup(deps, {
            nearAccountId: 'alice.testnet',
            chain: 'evm',
            source: 'login',
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

  test('reverse lookup requires canonical session index entries', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const deps = { recordsByLane: new Map<string, unknown>() };
        const now = Date.now();
        const prefix = 'tatchi:threshold-ecdsa-session:v3';
        const laneKey = [
          'alice.testnet',
          'tempo',
          'login',
          'ek-session-index',
          'proj_test:dev',
          'v1',
        ]
          .map((part) => encodeURIComponent(part))
          .join('|');

        sessionStorage.clear();
        sessionStorage.setItem(`${prefix}:index`, JSON.stringify([laneKey]));
        sessionStorage.setItem(
          `${prefix}:${laneKey}`,
          JSON.stringify({
            v: 1,
            record: {
              nearAccountId: 'alice.testnet',
              chain: 'tempo',
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: 'ek-session-index',
              signingRootId: 'proj_test:dev',
              signingRootVersion: 'v1',
              relayerKeyId: 'rk-session-index',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-index-1',
              thresholdSessionJwt: 'jwt-session-index-1',
              expiresAtMs: now + 120_000,
              remainingUses: 9,
              updatedAtMs: now,
              source: 'login',
            },
          }),
        );
        sessionStorage.setItem(
          `${prefix}:session-index`,
          JSON.stringify({
            'wrong-session-id': laneKey,
          }),
        );

        const withoutCanonicalSessionIndex =
          storeMod.getStoredThresholdEcdsaSessionRecordByThresholdSessionId('session-index-1');
        const staleIndexLookup =
          storeMod.getStoredThresholdEcdsaSessionRecordByThresholdSessionId('wrong-session-id');
        const staleSessionIndexRaw = sessionStorage.getItem(`${prefix}:session-index`);

        sessionStorage.setItem(
          `${prefix}:session-index`,
          JSON.stringify({
            'session-index-1': laneKey,
          }),
        );
        const withCanonicalSessionIndex =
          storeMod.getStoredThresholdEcdsaSessionRecordByThresholdSessionId('session-index-1');

        return {
          withoutCanonicalSessionIndex: withoutCanonicalSessionIndex?.thresholdSessionId || null,
          staleIndexLookup: staleIndexLookup?.thresholdSessionId || null,
          staleSessionIndexRaw,
          withCanonicalSessionIndex: withCanonicalSessionIndex?.thresholdSessionId || null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.withoutCanonicalSessionIndex).toBeNull();
    expect(result.staleIndexLookup).toBeNull();
    expect(result.staleSessionIndexRaw).toBe('{}');
    expect(result.withCanonicalSessionIndex).toBe('session-index-1');
  });
});

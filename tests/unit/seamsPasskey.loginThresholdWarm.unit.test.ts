import { expect, test } from '@playwright/test';
import { unlock } from '@/core/SeamsPasskey/login';
import { IndexedDBManager } from '@/core/indexedDB';
import { toAccountId } from '@/core/types/accountIds';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  upsertStoredThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';

const ACCOUNT_ID = toAccountId('alice.testnet');
const TEMPO_ECDSA_THRESHOLD_KEY_ID = 'ehss-login-tempo';
const EVM_ECDSA_THRESHOLD_KEY_ID = 'ehss-login-evm';
const ECDSA_THRESHOLD_KEY_ID = TEMPO_ECDSA_THRESHOLD_KEY_ID;
const ECDSA_CLIENT_ROOT_SHARE32_B64U = Buffer.alloc(32, 7).toString('base64url');
const WALLET_SIGNING_SESSION_ID = 'wsess-login-1';

function canonicalEcdsaRecord(overrides?: Record<string, unknown>): Record<string, unknown> {
  const chainTarget =
    (overrides?.chainTarget as Record<string, unknown> | undefined) || {
      kind: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    };
  const targetKeyId =
    chainTarget.kind === 'evm' ? EVM_ECDSA_THRESHOLD_KEY_ID : TEMPO_ECDSA_THRESHOLD_KEY_ID;
  return {
    source: 'login',
    nearAccountId: ACCOUNT_ID,
    subjectId: 'wallet-subject:alice.testnet',
    ecdsaThresholdKeyId: targetKeyId,
    thresholdSessionId: 'canonical-ecdsa-session-1',
    walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
    chainTarget,
    relayerUrl: 'https://relay.example',
    signingRootId: 'proj_local:dev',
    signingRootVersion: 'default',
    relayerKeyId: 'rk-1',
    clientVerifyingShareB64u: 'AQ',
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt',
    thresholdSessionAuthToken: 'jwt-ecdsa',
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 3,
    updatedAtMs: Date.now(),
    ...(overrides || {}),
  };
}

function ecdsaKeyIdForChainTarget(chainTarget: Record<string, unknown>): string {
  return chainTarget.kind === 'evm' ? EVM_ECDSA_THRESHOLD_KEY_ID : TEMPO_ECDSA_THRESHOLD_KEY_ID;
}

function createBaseContext(args?: {
  signingEngine?: Record<string, unknown>;
  configs?: Record<string, unknown>;
}): any {
  const now = Date.now();
  return {
    signingEngine: {
      assertSealedRefreshStartupParity: async () => undefined,
      getUserBySignerSlot: async () => ({
        nearAccountId: 'alice.testnet',
        signerSlot: 1,
        operationalPublicKey: 'ed25519:alice',
      }),
      getLastUser: async () => ({
        nearAccountId: 'alice.testnet',
        signerSlot: 1,
        operationalPublicKey: 'ed25519:alice',
      }),
      getAuthenticatorsByUser: async () => [{ credentialId: 'cred-1', signerSlot: 1 }],
      connectEd25519Session: async () => ({
        ok: true,
        sessionId: 'session-1',
        walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
        jwt: 'jwt-ed25519',
        remainingUses: 3,
        expiresAtMs: now + 60_000,
        ecdsaHssClientRootShare32B64u: ECDSA_CLIENT_ROOT_SHARE32_B64U,
      }),
      listThresholdEcdsaSessionRecordsForTarget: (args: Record<string, unknown>) => [
        canonicalEcdsaRecord({
          chainTarget: args.chainTarget,
          ecdsaThresholdKeyId: ecdsaKeyIdForChainTarget(
            args.chainTarget as Record<string, unknown>,
          ),
        }),
      ],
      bootstrapEcdsaSession: async (args: Record<string, unknown>) => ({
        thresholdEcdsaKeyRef: {
          type: 'threshold-ecdsa-secp256k1',
          userId: 'alice.testnet',
          relayerUrl: 'https://relay.example',
          ecdsaThresholdKeyId: String(args.ecdsaThresholdKeyId || ''),
          signingRootId: 'proj_local:dev',
          backendBinding: {
            relayerKeyId: 'rk-1',
            clientVerifyingShareB64u: 'AQ',
          },
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'session-1',
          walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
          thresholdSessionAuthToken: 'jwt-ecdsa',
        },
        keygen: {
          ok: true,
          ecdsaThresholdKeyId: String(args.ecdsaThresholdKeyId || ''),
          relayerKeyId: 'rk-1',
          clientVerifyingShareB64u: 'AQ',
          participantIds: [1, 2],
        },
        session: {
          ok: true,
          sessionId: 'session-1',
          walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
          jwt: 'jwt-ecdsa',
          remainingUses: 3,
          expiresAtMs: now + 60_000,
          clientVerifyingShareB64u: 'AQ',
        },
      }),
      clearWarmSigningSessions: async () => undefined,
      getWarmThresholdEd25519SessionStatus: async () => ({
        sessionId: 'session-1',
        status: 'active',
        remainingUses: 3,
        expiresAtMs: now + 60_000,
        createdAtMs: now,
      }),
      scheduleThresholdEcdsaLoginPresignPrefill: async () => ({
        status: 'scheduled',
        reason: 'scheduled',
      }),
      getNonceCoordinator: () => ({
        getDiagnostics: () => null,
        recoverDurableLeases: async () => undefined,
      }),
      setLastUser: async () => undefined,
      updateLastLogin: async () => undefined,
      ...(args?.signingEngine || {}),
    },
    configs: {
      signing: {
        mode: { mode: 'threshold-signer' },
        sessionDefaults: { ttlMs: 60_000, remainingUses: 3 },
      },
      network: {
        relayer: { url: 'https://relay.example' },
        chains: [
          {
            network: 'tempo-testnet',
            rpcUrl: 'https://rpc.tempo.test',
            explorerUrl: 'https://explorer.tempo.test',
            chainId: 42431,
          },
          {
            network: 'arc-testnet',
            rpcUrl: 'https://rpc.arc.test',
            explorerUrl: 'https://explorer.arc.test',
            chainId: 5042002,
          },
        ],
      },
      ...(args?.configs || {}),
    },
  };
}

async function withMockedMostRecentProjection<T>(
  fn: () => Promise<T>,
  options?: { includeThresholdEcdsaProfiles?: boolean },
): Promise<T> {
  const clientDb = IndexedDBManager.clientDB as { getMostRecentNearAccountProjection?: unknown };
  const continuityClientDb = IndexedDBManager.clientDB as {
    getProfileContinuitySnapshot?: unknown;
  };
  const profileLookupClientDb = IndexedDBManager.clientDB as {
    resolveProfileAccountContext?: unknown;
  };
  const accountKeyMaterialDb = IndexedDBManager.accountKeyMaterialDB as { getKeyMaterial?: unknown };
  const original = clientDb.getMostRecentNearAccountProjection;
  const originalContinuity = continuityClientDb.getProfileContinuitySnapshot;
  const originalProfileLookup = profileLookupClientDb.resolveProfileAccountContext;
  const originalKeyMaterial = accountKeyMaterialDb.getKeyMaterial;
  clientDb.getMostRecentNearAccountProjection = async () => null;
  continuityClientDb.getProfileContinuitySnapshot = async () =>
    options?.includeThresholdEcdsaProfiles
      ? {
          chainAccounts: [
            {
              chainIdKey: 'evm:11155111',
              accountAddress: `0x${'11'.repeat(20)}`,
              accountModel: 'erc4337',
            },
          ],
        }
      : { chainAccounts: [] };
  profileLookupClientDb.resolveProfileAccountContext = async (accountRef: {
    chainIdKey: string;
    accountAddress: string;
  }) =>
    accountRef.chainIdKey === 'near:testnet' &&
    String(accountRef.accountAddress || '').trim() === 'alice.testnet'
      ? { profileId: 'legacy-near:alice.testnet', accountRef }
      : null;
  accountKeyMaterialDb.getKeyMaterial = async () => ({
    profileId: 'legacy-near:alice.testnet',
    signerSlot: 1,
    chainIdKey: 'near:testnet',
    keyKind: 'threshold_share_v1',
    algorithm: 'ed25519',
    publicKey: 'ed25519:threshold',
    payload: {
      relayerKeyId: 'rk-1',
      keyVersion: 'threshold-ed25519-hss-v1',
      participants: [
        { id: 1, role: 'client' },
        { id: 2, role: 'relayer', relayerKeyId: 'rk-1' },
      ],
    },
    timestamp: Date.now(),
    schemaVersion: 1,
  });
  try {
    return await fn();
  } finally {
    clientDb.getMostRecentNearAccountProjection = original;
    continuityClientDb.getProfileContinuitySnapshot = originalContinuity;
    profileLookupClientDb.resolveProfileAccountContext = originalProfileLookup;
    accountKeyMaterialDb.getKeyMaterial = originalKeyMaterial;
  }
}

test.describe('unlock threshold warm-session requirements', () => {
  test('returns active signingSession in threshold-signer warm mode', async () => {
    let bootstrapCalls = 0;
    let bootstrapArgs: Record<string, unknown> | null = null;
    const bootstrapChains: string[] = [];
    let prefillCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapCalls += 1;
          bootstrapArgs = args;
          bootstrapChains.push(String((args.chainTarget as Record<string, unknown>)?.kind || ''));
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: String(args.ecdsaThresholdKeyId || ''),
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-1',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              thresholdSessionAuthToken: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: String(args.ecdsaThresholdKeyId || ''),
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'session-1',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
          };
        },
        scheduleThresholdEcdsaLoginPresignPrefill: async () => {
          prefillCalls += 1;
          return { status: 'scheduled', reason: 'scheduled' };
        },
      },
    });
    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect('thresholdEcdsaKeyRef' in (result as unknown as Record<string, unknown>)).toBe(false);
    expect(bootstrapCalls).toBe(2);
    expect(bootstrapChains).toEqual(['tempo', 'evm']);
    expect(String(bootstrapArgs?.['kind'] || '')).toBe(
      'threshold_session_auth_reconnect_ecdsa_bootstrap',
    );
    expect(String(bootstrapArgs?.['source'] || '')).toBe('login');
    const sessionIdentity =
      (bootstrapArgs?.['sessionIdentity'] as Record<string, unknown> | undefined) || {};
    expect(String(sessionIdentity.thresholdSessionId || '')).toMatch(/^threshold-ecdsa-login-/);
    expect(sessionIdentity.walletSigningSessionId).toBe(WALLET_SIGNING_SESSION_ID);
    expect(bootstrapArgs?.['routeAuth']).toEqual({
      kind: 'threshold_session',
      jwt: 'jwt-ed25519',
    });
    expect(bootstrapArgs?.['clientRootShare32B64u']).toBe(ECDSA_CLIENT_ROOT_SHARE32_B64U);
    expect(prefillCalls).toBe(0);
  });

  test('caps passkey unlock warm sessions at three uses', async () => {
    let ed25519RemainingUses: unknown = null;
    const ecdsaRemainingUses: unknown[] = [];
    const context = createBaseContext({
      configs: {
        signing: {
          mode: { mode: 'threshold-signer' },
          sessionDefaults: { ttlMs: 60_000, remainingUses: 6 },
        },
      },
      signingEngine: {
        connectEd25519Session: async (args: Record<string, unknown>) => {
          ed25519RemainingUses = args.remainingUses;
          return {
            ok: true,
            sessionId: 'session-1',
            walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
            jwt: 'jwt-ed25519',
            remainingUses: Number(args.remainingUses),
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssClientRootShare32B64u: ECDSA_CLIENT_ROOT_SHARE32_B64U,
          };
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          ecdsaRemainingUses.push(args.remainingUses);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: String(args.ecdsaThresholdKeyId || ''),
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-1',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              thresholdSessionAuthToken: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: String(args.ecdsaThresholdKeyId || ''),
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'session-1',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: Number(args.remainingUses),
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
          };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () =>
        await unlock(context, ACCOUNT_ID, {
          signingSession: { ttlMs: 60_000, remainingUses: 6 },
        }),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(true);
    expect(ed25519RemainingUses).toBe(3);
    expect(ecdsaRemainingUses).toEqual([3, 3]);
  });

  test('fails closed when threshold warm-up cannot connect Ed25519 session', async () => {
    let setLastUserCalls = 0;
    let updateLastLoginCalls = 0;
    let bootstrapCalls = 0;
    let prefillCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        connectEd25519Session: async () => ({
          ok: false,
          code: 'unauthorized',
          message: 'session bootstrap rejected',
        }),
        bootstrapEcdsaSession: async () => {
          bootstrapCalls += 1;
          throw new Error('should not be called');
        },
        setLastUser: async () => {
          setLastUserCalls += 1;
        },
        updateLastLogin: async () => {
          updateLastLoginCalls += 1;
        },
        scheduleThresholdEcdsaLoginPresignPrefill: async () => {
          prefillCalls += 1;
          return { status: 'scheduled', reason: 'scheduled' };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('threshold Ed25519 warm-up failed');
    expect(setLastUserCalls).toBe(0);
    expect(updateLastLoginCalls).toBe(0);
    expect(bootstrapCalls).toBe(0);
    expect(prefillCalls).toBe(0);
  });

  test('fails closed when threshold warm-up cannot bootstrap ECDSA session', async () => {
    let setLastUserCalls = 0;
    let updateLastLoginCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        bootstrapEcdsaSession: async () => {
          throw new Error('ecdsa bootstrap rejected');
        },
        setLastUser: async () => {
          setLastUserCalls += 1;
        },
        updateLastLogin: async () => {
          updateLastLoginCalls += 1;
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('threshold ECDSA warm-up failed');
    expect(setLastUserCalls).toBe(0);
    expect(updateLastLoginCalls).toBe(0);
  });

  test('fails closed on stale integrated-key ECDSA warm-up during unlock', async () => {
    let bootstrapCalls = 0;
    const bootstrapArgs: Record<string, unknown>[] = [];
    let setLastUserCalls = 0;
    let updateLastLoginCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapCalls += 1;
          bootstrapArgs.push(args);
          throw new Error(
            'threshold-ecdsa bootstrap client verifying share does not match integrated key record',
          );
        },
        setLastUser: async () => {
          setLastUserCalls += 1;
        },
        updateLastLogin: async () => {
          updateLastLoginCalls += 1;
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('threshold ECDSA warm-up failed');
    expect(String(result.error || '')).toContain(
      'threshold-ecdsa bootstrap client verifying share does not match integrated key record',
    );
    expect(bootstrapCalls).toBe(1);
    expect(String(bootstrapArgs[0]?.ecdsaThresholdKeyId || '')).toBe(ECDSA_THRESHOLD_KEY_ID);
    expect(setLastUserCalls).toBe(0);
    expect(updateLastLoginCalls).toBe(0);
  });

  test('skips ECDSA warm-up when no canonical key id exists', async () => {
    let bootstrapCalls = 0;
    const bootstrapArgs: Record<string, unknown>[] = [];
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForTarget: () => [],
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapCalls += 1;
          bootstrapArgs.push(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: 'ehss-login-fresh',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-1',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              thresholdSessionAuthToken: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: 'ehss-login-fresh',
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'session-1',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
          };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(true);
    expect(bootstrapCalls).toBe(0);
    expect(bootstrapArgs).toEqual([]);
  });

  test('login does not invoke ECDSA presign prefill automatically', async () => {
    let prefillCalls = 0;
    let prefillArgs: Record<string, unknown> | null = null;
    const context = createBaseContext({
      signingEngine: {
        scheduleThresholdEcdsaLoginPresignPrefill: async (args: Record<string, unknown>) => {
          prefillCalls += 1;
          prefillArgs = args;
          return { status: 'scheduled', reason: 'scheduled' };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect(prefillCalls).toBe(0);
    expect(prefillArgs).toBeNull();
  });

  test('fails closed when one-prompt ECDSA bootstrap share is unavailable', async () => {
    let bootstrapCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        connectEd25519Session: async () => ({
          ok: true,
          sessionId: 'session-1',
          walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
          jwt: 'jwt-ed25519',
          remainingUses: 3,
          expiresAtMs: Date.now() + 60_000,
        }),
        bootstrapEcdsaSession: async () => {
          bootstrapCalls += 1;
          throw new Error('should not be called');
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain(
      'threshold ECDSA warm-up missing clientRootShare32B64u',
    );
    expect(bootstrapCalls).toBe(0);
  });

  test('login warm-up lets fresh Ed25519 provisioning mint its own session id even when canonical ECDSA state exists', async () => {
    let capturedConnectArgs: Record<string, unknown> | null = null;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForTarget: (args: Record<string, unknown>) => [
          canonicalEcdsaRecord({
            chainTarget: args.chainTarget,
            ecdsaThresholdKeyId: ecdsaKeyIdForChainTarget(
              args.chainTarget as Record<string, unknown>,
            ),
            thresholdSessionId: 'canonical-ecdsa-session-1',
            walletSigningSessionId: 'canonical-wallet-session-1',
          }),
        ],
        connectEd25519Session: async (args: Record<string, unknown>) => {
          capturedConnectArgs = args;
          return {
            ok: true,
            sessionId: 'canonical-ecdsa-session-1',
            walletSigningSessionId: 'wallet-session-fresh-1',
            jwt: 'jwt-ed25519',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssClientRootShare32B64u: ECDSA_CLIENT_ROOT_SHARE32_B64U,
          };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect(capturedConnectArgs).not.toBeNull();
    const requestedSessionId = String(capturedConnectArgs?.['sessionId'] || '').trim();
    expect(requestedSessionId).toBe('');
  });

  test('NEAR-only threshold warm-up does not bootstrap ECDSA sessions', async () => {
    let bootstrapCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        bootstrapEcdsaSession: async () => {
          bootstrapCalls += 1;
          throw new Error('should not be called for NEAR-only warm-up');
        },
        listThresholdEcdsaSessionRecordsForTarget: () => [],
      },
      configs: {
        network: {
          relayer: { url: 'https://relay.example' },
          chains: [],
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: false },
    );

    expect(result.success).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect(bootstrapCalls).toBe(0);
  });

  test('NEAR-only warm-up does not reuse a stored Ed25519 threshold session id', async () => {
    let capturedConnectArgs: Record<string, unknown> | null = null;
    const context = createBaseContext({
      signingEngine: {
        connectEd25519Session: async (args: Record<string, unknown>) => {
          capturedConnectArgs = args;
          return {
            ok: true,
            sessionId: 'fresh-near-only-session-1',
            walletSigningSessionId: 'wallet-session-near-only-1',
            jwt: 'jwt-ed25519',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssClientRootShare32B64u: ECDSA_CLIENT_ROOT_SHARE32_B64U,
          };
        },
      },
      configs: {
        network: {
          relayer: { url: 'https://relay.example' },
          chains: [],
        },
      },
    });

    clearAllStoredThresholdEd25519SessionRecords();
    upsertStoredThresholdEd25519SessionRecord({
      nearAccountId: ACCOUNT_ID,
      rpId: 'wallet.example.localhost',
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'rk-1',
      participantIds: [1, 2],
      thresholdSessionKind: 'jwt',
      thresholdSessionId: 'stored-ed25519-session-1',
      thresholdSessionAuthToken: 'jwt-stale',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 1,
      source: 'manual-connect',
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () => await unlock(context, ACCOUNT_ID),
        { includeThresholdEcdsaProfiles: false },
      );

      expect(result.success).toBe(true);
      expect(capturedConnectArgs).not.toBeNull();
      expect(String(capturedConnectArgs?.['sessionId'] || '')).toBe('');
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
    }
  });

  test('fails fast when /session/exchange route is requested without session.exchange payload', async () => {
    const context = createBaseContext();

    const result = await withMockedMostRecentProjection(
      async () =>
        await unlock(context, ACCOUNT_ID, {
          session: {
            kind: 'jwt',
            route: '/session/exchange',
          },
        }),
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('session.exchange is required');
  });

  test('fails fast when server session is requested without exchange payload', async () => {
    const context = createBaseContext();

    const result = await withMockedMostRecentProjection(
      async () =>
        await unlock(context, ACCOUNT_ID, {
          session: {
            kind: 'jwt',
          },
        }),
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('session.exchange is required');
  });

  test('supports one-step passkey_assertion session exchange', async () => {
    const originalFetch = globalThis.fetch;
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        captured.push({ url, init });
        if (url === 'https://relay.example/wallet/unlock/challenge') {
          return new Response(
            JSON.stringify({
              ok: true,
              challengeId: 'challenge-passkey-1',
              challengeB64u: 'challenge-passkey-b64u-1',
              expiresAtMs: Date.now() + 60_000,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (url === 'https://relay.example/session/exchange') {
          return new Response(
            JSON.stringify({
              ok: true,
              session: { kind: 'app_session_v1', userId: 'alice.testnet' },
              jwt: 'app-jwt-passkey-1',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: false, message: 'not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const context = createBaseContext({
        signingEngine: {
          getRpId: () => 'example.localhost',
          getAuthenticationCredentialsSerialized: async () => ({
            id: 'cred-1',
            rawId: 'cred-1',
            type: 'public-key',
            authenticatorAttachment: undefined,
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: undefined,
              clientExtensionResults: { shouldRedact: true },
            },
            clientExtensionResults: {
              prf: {
                results: {
                  first: 'prf-first',
                  second: 'prf-second',
                },
              },
            },
          }),
        },
        configs: {
          signing: {
            sessionDefaults: { ttlMs: 0, remainingUses: 0 },
          },
        },
      });

      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'jwt',
              exchange: { type: 'passkey_assertion' },
            },
          }),
      );

      expect(result.success).toBe(true);
      expect(result.jwt).toBe('app-jwt-passkey-1');
      expect(captured).toHaveLength(2);
      expect(captured[0]!.url).toBe('https://relay.example/wallet/unlock/challenge');
      expect(captured[1]!.url).toBe('https://relay.example/session/exchange');

      const unlockOptionsBody = JSON.parse(String(captured[0]!.init?.body || '{}')) as Record<
        string,
        unknown
      >;
      expect(unlockOptionsBody.unlockBackend).toBe('passkey');
      expect(unlockOptionsBody.userId).toBe('alice.testnet');
      expect(unlockOptionsBody.rpId).toBe('example.localhost');

      const exchangeBody = JSON.parse(String(captured[1]!.init?.body || '{}')) as Record<
        string,
        unknown
      >;
      const exchange = (exchangeBody.exchange || {}) as Record<string, unknown>;
      expect(exchange.type).toBe('passkey_assertion');
      expect(exchange.challengeId).toBe('challenge-passkey-1');
      const credential = (exchange.webauthn_authentication || {}) as Record<string, unknown>;
      expect(credential.clientExtensionResults).toBeNull();
      expect(
        ((credential.response || {}) as Record<string, unknown>).clientExtensionResults,
      ).toBeNull();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('passkey_assertion warm-up reuses app session authorization and local PRF credential', async () => {
    const originalFetch = globalThis.fetch;
    let credentialPrompts = 0;
    let capturedConnectArgs: Record<string, unknown> | null = null;
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === 'https://relay.example/wallet/unlock/challenge') {
          return new Response(
            JSON.stringify({
              ok: true,
              challengeId: 'challenge-passkey-warm',
              challengeB64u: 'challenge-passkey-warm-b64u',
              expiresAtMs: Date.now() + 60_000,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (url === 'https://relay.example/session/exchange') {
          return new Response(
            JSON.stringify({
              ok: true,
              session: { kind: 'app_session_v1', userId: 'alice.testnet' },
              jwt: 'app-jwt-passkey-warm',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: false, message: 'not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const loginCredential = {
        id: 'cred-warm',
        rawId: 'cred-warm',
        type: 'public-key',
        authenticatorAttachment: undefined,
        response: {
          clientDataJSON: 'client-data-json',
          authenticatorData: 'authenticator-data',
          signature: 'signature',
          userHandle: undefined,
          clientExtensionResults: { shouldRedact: true },
        },
        clientExtensionResults: {
          prf: {
            results: {
              first: 'prf-first-warm',
            },
          },
        },
      };
      const context = createBaseContext({
        signingEngine: {
          getRpId: () => 'example.localhost',
          getAuthenticationCredentialsSerialized: async () => {
            credentialPrompts += 1;
            return loginCredential;
          },
          connectEd25519Session: async (args: Record<string, unknown>) => {
            capturedConnectArgs = args;
            return {
              ok: true,
              sessionId: 'session-passkey-warm',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ed25519',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              ecdsaHssClientRootShare32B64u: ECDSA_CLIENT_ROOT_SHARE32_B64U,
            };
          },
        },
      });

      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'jwt',
              exchange: { type: 'passkey_assertion' },
            },
          }),
      );

      expect(result.success).toBe(true);
      expect(credentialPrompts).toBe(1);
      expect(capturedConnectArgs).not.toBeNull();
      const connectArgs = capturedConnectArgs as Record<string, any> | null;
      expect(String(connectArgs?.appSessionJwt || '')).toBe('app-jwt-passkey-warm');
      expect(connectArgs?.localPrfCredential).toBe(loginCredential);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('passkey_assertion warm-up uses relay ECDSA signer inventory when local ECDSA lanes are absent', async () => {
    const originalFetch = globalThis.fetch;
    let credentialPrompts = 0;
    const bootstrapArgs: Array<Record<string, unknown>> = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url === 'https://relay.example/wallet/unlock/challenge') {
          return new Response(
            JSON.stringify({
              ok: true,
              challengeId: 'challenge-passkey-relay-ecdsa',
              challengeB64u: 'challenge-passkey-relay-ecdsa-b64u',
              expiresAtMs: Date.now() + 60_000,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (url === 'https://relay.example/session/exchange') {
          return new Response(
            JSON.stringify({
              ok: true,
              session: { kind: 'app_session_v1', userId: 'alice.testnet' },
              jwt: 'app-jwt-passkey-relay-ecdsa',
              smartAccountSigners: [
                {
                  status: 'active',
                  signerType: 'threshold',
                  signerId: `0x${'aa'.repeat(20)}`,
                  accountAddress: `0x${'bb'.repeat(20)}`,
                  chainIdKey: 'tempo:42431',
                  metadata: {
                    ecdsaThresholdKeyId: TEMPO_ECDSA_THRESHOLD_KEY_ID,
                    relayerKeyId: 'rk-1',
                    thresholdEcdsaPublicKeyB64u: 'threshold-ecdsa-public-key',
                    ownerAddress: `0x${'aa'.repeat(20)}`,
                    chainTarget: {
                      kind: 'tempo',
                      chainId: 42431,
                      networkSlug: 'tempo-testnet',
                    },
                  },
                },
                {
                  status: 'active',
                  signerType: 'threshold',
                  signerId: `0x${'aa'.repeat(20)}`,
                  accountAddress: `0x${'cc'.repeat(20)}`,
                  chainIdKey: 'evm:5042002',
                  metadata: {
                    ecdsaThresholdKeyId: EVM_ECDSA_THRESHOLD_KEY_ID,
                    relayerKeyId: 'rk-1',
                    thresholdEcdsaPublicKeyB64u: 'threshold-ecdsa-public-key',
                    ownerAddress: `0x${'aa'.repeat(20)}`,
                    chainTarget: {
                      kind: 'evm',
                      namespace: 'eip155',
                      chainId: 5042002,
                      networkSlug: 'arc-testnet',
                    },
                  },
                },
              ],
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: false, message: 'not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const loginCredential = {
        id: 'cred-relay-ecdsa',
        rawId: 'cred-relay-ecdsa',
        type: 'public-key',
        authenticatorAttachment: undefined,
        response: {
          clientDataJSON: 'client-data-json',
          authenticatorData: 'authenticator-data',
          signature: 'signature',
          userHandle: undefined,
          clientExtensionResults: {},
        },
        clientExtensionResults: {
          prf: {
            results: {
              first: 'prf-first-relay-ecdsa',
            },
          },
        },
      };
      const context = createBaseContext({
        signingEngine: {
          getRpId: () => 'example.localhost',
          getAuthenticationCredentialsSerialized: async () => {
            credentialPrompts += 1;
            return loginCredential;
          },
          listThresholdEcdsaSessionRecordsForTarget: () => [],
          bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
            bootstrapArgs.push(args);
            return {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relay.example',
                ecdsaThresholdKeyId: String(args.ecdsaThresholdKeyId || ''),
                signingRootId: 'proj_local:dev',
                backendBinding: {
                  relayerKeyId: 'rk-1',
                  clientVerifyingShareB64u: 'AQ',
                },
                participantIds: [1, 2],
                thresholdSessionKind: 'jwt',
                thresholdSessionId: 'session-1',
                walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
                thresholdSessionAuthToken: 'jwt-ecdsa',
              },
              keygen: {
                ok: true,
                ecdsaThresholdKeyId: String(args.ecdsaThresholdKeyId || ''),
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
                participantIds: [1, 2],
              },
              session: {
                ok: true,
                sessionId: 'session-1',
                walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
                jwt: 'jwt-ecdsa',
                remainingUses: 3,
                expiresAtMs: Date.now() + 60_000,
                clientVerifyingShareB64u: 'AQ',
              },
            };
          },
        },
      });

      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'jwt',
              exchange: { type: 'passkey_assertion' },
            },
          }),
      );

      expect(result.success).toBe(true);
      expect(credentialPrompts).toBe(1);
      expect(bootstrapArgs).toHaveLength(2);
      expect(bootstrapArgs.map((args) => String(args.kind))).toEqual([
        'threshold_session_auth_reconnect_ecdsa_bootstrap',
        'threshold_session_auth_reconnect_ecdsa_bootstrap',
      ]);
      expect(bootstrapArgs.map((args) => args.ecdsaThresholdKeyId)).toEqual([
        TEMPO_ECDSA_THRESHOLD_KEY_ID,
        EVM_ECDSA_THRESHOLD_KEY_ID,
      ]);
      expect(bootstrapArgs.every((args) => args.clientRootShare32B64u === ECDSA_CLIENT_ROOT_SHARE32_B64U)).toBe(
        true,
      );
      expect(bootstrapArgs[0]?.routeAuth).toEqual({
        kind: 'app_session',
        jwt: 'app-jwt-passkey-relay-ecdsa',
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('uses app session JWT for existing-key ECDSA warm-up after session exchange', async () => {
    const originalFetch = globalThis.fetch;
    let bootstrapCalls = 0;
    let bootstrapArgs: Record<string, unknown> | null = null;
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === 'https://relay.example/session/exchange') {
          return new Response(
            JSON.stringify({
              ok: true,
              session: { kind: 'app_session_v1', userId: 'alice.testnet' },
              jwt: 'app-jwt-oidc-1',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: false, message: 'not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const context = createBaseContext({
        signingEngine: {
          listThresholdEcdsaSessionRecordsForTarget: (args: Record<string, unknown>) => [
            canonicalEcdsaRecord({
              chainTarget: args.chainTarget,
              ecdsaThresholdKeyId: ecdsaKeyIdForChainTarget(
                args.chainTarget as Record<string, unknown>,
              ),
              thresholdSessionId: 'canonical-ecdsa-session-1',
              walletSigningSessionId: 'canonical-wallet-session-1',
            }),
          ],
          bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
            bootstrapCalls += 1;
            bootstrapArgs = args;
            return {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relay.example',
                ecdsaThresholdKeyId: String(args.ecdsaThresholdKeyId || ''),
                signingRootId: 'proj_local:dev',
                backendBinding: {
                  relayerKeyId: 'rk-1',
                  clientVerifyingShareB64u: 'AQ',
                },
                participantIds: [1, 2],
                thresholdSessionKind: 'jwt',
                thresholdSessionId: 'session-1',
                walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
                thresholdSessionAuthToken: 'jwt-ecdsa',
              },
              keygen: {
                ok: true,
                ecdsaThresholdKeyId: String(args.ecdsaThresholdKeyId || ''),
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
                participantIds: [1, 2],
              },
              session: {
                ok: true,
                sessionId: 'session-1',
                walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
                jwt: 'jwt-ecdsa',
                remainingUses: 3,
                expiresAtMs: Date.now() + 60_000,
                clientVerifyingShareB64u: 'AQ',
              },
            };
          },
        },
      });

      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'jwt',
              exchange: {
                type: 'oidc_jwt',
                token: 'oidc-token-1',
              },
            },
          }),
        { includeThresholdEcdsaProfiles: true },
      );

      expect(result.success).toBe(true);
      expect(result.jwt).toBe('app-jwt-oidc-1');
      expect(bootstrapCalls).toBe(2);
      const bootstrap = bootstrapArgs as Record<string, unknown> | null;
      expect(bootstrap?.kind).toBe('threshold_session_auth_reconnect_ecdsa_bootstrap');
      expect(bootstrap?.routeAuth).toEqual({
        kind: 'app_session',
        jwt: 'app-jwt-oidc-1',
      });
      const sessionIdentity =
        (bootstrap?.sessionIdentity as Record<string, unknown> | undefined) || {};
      expect(String(sessionIdentity.thresholdSessionId || '')).toMatch(
        /^threshold-ecdsa-login-/,
      );
      expect(sessionIdentity.walletSigningSessionId).toBe(WALLET_SIGNING_SESSION_ID);
      expect(bootstrap?.clientRootShare32B64u).toBe(ECDSA_CLIENT_ROOT_SHARE32_B64U);
      expect(String(bootstrap?.ecdsaThresholdKeyId || '')).toBe(EVM_ECDSA_THRESHOLD_KEY_ID);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('forwards passkey_assertion expectedOrigin override to session exchange', async () => {
    const originalFetch = globalThis.fetch;
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        captured.push({ url, init });
        if (url === 'https://relay.example/wallet/unlock/challenge') {
          return new Response(
            JSON.stringify({
              ok: true,
              challengeId: 'challenge-passkey-2',
              challengeB64u: 'challenge-passkey-b64u-2',
              expiresAtMs: Date.now() + 60_000,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (url === 'https://relay.example/session/exchange') {
          return new Response(
            JSON.stringify({
              ok: true,
              session: { kind: 'app_session_v1', userId: 'alice.testnet' },
              jwt: 'app-jwt-passkey-2',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: false, message: 'not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const context = createBaseContext({
        signingEngine: {
          getRpId: () => 'example.localhost',
          getAuthenticationCredentialsSerialized: async () => ({
            id: 'cred-2',
            rawId: 'cred-2',
            type: 'public-key',
            authenticatorAttachment: undefined,
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: undefined,
              clientExtensionResults: { shouldRedact: true },
            },
            clientExtensionResults: {
              prf: {
                results: {
                  first: 'prf-first',
                  second: 'prf-second',
                },
              },
            },
          }),
        },
        configs: {
          signing: {
            sessionDefaults: { ttlMs: 0, remainingUses: 0 },
          },
        },
      });

      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'jwt',
              exchange: {
                type: 'passkey_assertion',
                expectedOrigin: 'https://wallet.example.localhost',
              },
            },
          }),
      );

      expect(result.success).toBe(true);
      expect(result.jwt).toBe('app-jwt-passkey-2');
      expect(captured).toHaveLength(2);

      const exchangeBody = JSON.parse(String(captured[1]!.init?.body || '{}')) as Record<
        string,
        unknown
      >;
      const exchange = (exchangeBody.exchange || {}) as Record<string, unknown>;
      expect(exchange.type).toBe('passkey_assertion');
      expect(exchange.expected_origin).toBe('https://wallet.example.localhost');
      expect(captured[1]!.init?.credentials).toBe('omit');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('supports cookie-mode passkey_assertion exchange with include credentials', async () => {
    const originalFetch = globalThis.fetch;
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        captured.push({ url, init });
        if (url === 'https://relay.example/wallet/unlock/challenge') {
          return new Response(
            JSON.stringify({
              ok: true,
              challengeId: 'challenge-passkey-cookie',
              challengeB64u: 'challenge-passkey-cookie-b64u',
              expiresAtMs: Date.now() + 60_000,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (url === 'https://relay.example/session/exchange') {
          return new Response(
            JSON.stringify({
              ok: true,
              session: { kind: 'app_session_v1', userId: 'alice.testnet' },
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: false, message: 'not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const context = createBaseContext({
        signingEngine: {
          getRpId: () => 'example.localhost',
          getAuthenticationCredentialsSerialized: async () => ({
            id: 'cred-cookie',
            rawId: 'cred-cookie',
            type: 'public-key',
            authenticatorAttachment: undefined,
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: undefined,
              clientExtensionResults: { shouldRedact: true },
            },
            clientExtensionResults: {
              prf: {
                results: {
                  first: 'prf-first',
                  second: 'prf-second',
                },
              },
            },
          }),
        },
        configs: {
          signing: {
            sessionDefaults: { ttlMs: 0, remainingUses: 0 },
          },
        },
      });

      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'cookie',
              exchange: { type: 'passkey_assertion' },
            },
          }),
      );

      expect(result.success).toBe(true);
      expect(result.jwt).toBeUndefined();
      expect(captured).toHaveLength(2);
      expect(captured[1]!.url).toBe('https://relay.example/session/exchange');
      expect(captured[1]!.init?.credentials).toBe('include');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('cookie-mode passkey_assertion warm-up uses app session cookie authorization', async () => {
    const originalFetch = globalThis.fetch;
    let capturedConnectArgs: Record<string, unknown> | null = null;
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === 'https://relay.example/wallet/unlock/challenge') {
          return new Response(
            JSON.stringify({
              ok: true,
              challengeId: 'challenge-passkey-cookie-warm',
              challengeB64u: 'challenge-passkey-cookie-warm-b64u',
              expiresAtMs: Date.now() + 60_000,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (url === 'https://relay.example/session/exchange') {
          return new Response(
            JSON.stringify({
              ok: true,
              session: { kind: 'app_session_v1', userId: 'alice.testnet' },
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: false, message: 'not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const loginCredential = {
        id: 'cred-cookie-warm',
        rawId: 'cred-cookie-warm',
        type: 'public-key',
        authenticatorAttachment: undefined,
        response: {
          clientDataJSON: 'client-data-json',
          authenticatorData: 'authenticator-data',
          signature: 'signature',
          userHandle: undefined,
          clientExtensionResults: { shouldRedact: true },
        },
        clientExtensionResults: {
          prf: {
            results: {
              first: 'prf-first-cookie-warm',
            },
          },
        },
      };
      const context = createBaseContext({
        signingEngine: {
          getRpId: () => 'example.localhost',
          getAuthenticationCredentialsSerialized: async () => loginCredential,
          connectEd25519Session: async (args: Record<string, unknown>) => {
            capturedConnectArgs = args;
            return {
              ok: true,
              sessionId: 'session-cookie-warm',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ed25519',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              ecdsaHssClientRootShare32B64u: ECDSA_CLIENT_ROOT_SHARE32_B64U,
            };
          },
        },
      });

      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'cookie',
              exchange: { type: 'passkey_assertion' },
            },
          }),
      );

      expect(result.success).toBe(true);
      expect(capturedConnectArgs).not.toBeNull();
      const connectArgs = capturedConnectArgs as Record<string, any> | null;
      expect(String(connectArgs?.appSessionJwt || '')).toBe('');
      expect(connectArgs?.useAppSessionCookie).toBe(true);
      expect(connectArgs?.localPrfCredential).toBe(loginCredential);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

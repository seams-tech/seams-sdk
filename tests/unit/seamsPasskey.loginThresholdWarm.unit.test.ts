import { expect, test } from '@playwright/test';
import { unlock } from '@/core/SeamsPasskey/login';
import { IndexedDBManager } from '@/core/indexedDB';
import { toAccountId } from '@/core/types/accountIds';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  upsertStoredThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  thresholdEcdsaChainTargetKey,
  walletSubjectIdFromWalletProfile,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const ACCOUNT_ID = toAccountId('alice.testnet');
const TEMPO_ECDSA_THRESHOLD_KEY_ID = 'ehss-login-tempo';
const EVM_ECDSA_THRESHOLD_KEY_ID = TEMPO_ECDSA_THRESHOLD_KEY_ID;
const ECDSA_THRESHOLD_KEY_ID = TEMPO_ECDSA_THRESHOLD_KEY_ID;
const ECDSA_KEY_HANDLE = 'ehss-key-login-tempo';
const ECDSA_CLIENT_ROOT_SHARE32_B64U = Buffer.alloc(32, 7).toString('base64url');
const WALLET_SIGNING_SESSION_ID = 'wsess-login-1';
const SUBJECT_ID = walletSubjectIdFromWalletProfile({ walletId: ACCOUNT_ID });
const TEMPO_CHAIN_TARGET = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
} as const satisfies ThresholdEcdsaChainTarget;
const EVM_CHAIN_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
} as const satisfies ThresholdEcdsaChainTarget;
const SEPOLIA_CHAIN_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 11155111,
  networkSlug: 'ethereum-sepolia',
} as const satisfies ThresholdEcdsaChainTarget;
const THRESHOLD_OWNER_ADDRESS = `0x${'aa'.repeat(20)}`;

function canonicalEcdsaRecord(overrides?: Record<string, unknown>): Record<string, unknown> {
  const chainTarget = (overrides?.chainTarget as Record<string, unknown> | undefined) || {
    kind: 'tempo',
    chainId: 42431,
    networkSlug: 'tempo-testnet',
  };
  const targetKeyId =
    chainTarget.kind === 'evm' ? EVM_ECDSA_THRESHOLD_KEY_ID : TEMPO_ECDSA_THRESHOLD_KEY_ID;
  return {
    source: 'login',
    nearAccountId: ACCOUNT_ID,
    walletId: ACCOUNT_ID,
    subjectId: SUBJECT_ID,
    keyHandle: ECDSA_KEY_HANDLE,
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
    ethereumAddress: `0x${'aa'.repeat(20)}`,
    authMetadata: { rpId: 'example.localhost' },
    rpId: 'example.localhost',
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

function bootstrapKey(args: Record<string, unknown>): Record<string, unknown> {
  const key = args.key as Record<string, unknown> | undefined;
  if (!key) throw new Error('test bootstrap requires ECDSA key identity');
  return key;
}

function bootstrapLanePolicy(args: Record<string, unknown>): Record<string, unknown> {
  const lanePolicy = args.lanePolicy as Record<string, unknown> | undefined;
  if (!lanePolicy) throw new Error('test bootstrap requires ECDSA lane policy');
  return lanePolicy;
}

function bootstrapChainTarget(args: Record<string, unknown>): ThresholdEcdsaChainTarget {
  const chainTarget = bootstrapLanePolicy(args).chainTarget as
    | ThresholdEcdsaChainTarget
    | undefined;
  if (!chainTarget) throw new Error('test bootstrap requires lane policy chain target');
  return chainTarget;
}

function bootstrapEcdsaThresholdKeyId(args: Record<string, unknown>): string {
  return String(bootstrapKey(args).ecdsaThresholdKeyId || '');
}

function bootstrapKeyHandle(args: Record<string, unknown>): string {
  return String(args.keyHandle || ECDSA_KEY_HANDLE);
}

function partialEcdsaProfileSigners(): Array<Record<string, unknown>> {
  return [TEMPO_CHAIN_TARGET, EVM_CHAIN_TARGET].map((chainTarget) => ({
    status: 'active',
    signerKind: 'threshold-ecdsa',
    signerAuthMethod: 'passkey',
    metadata: {
      keyHandle: ECDSA_KEY_HANDLE,
      ecdsaThresholdKeyId: ecdsaKeyIdForChainTarget(chainTarget),
      chainTarget,
    },
  }));
}

function ecdsaKeyIdentityTargetRecord(
  chainTarget: ThresholdEcdsaChainTarget,
): Record<string, unknown> {
  const ecdsaThresholdKeyId = ecdsaKeyIdForChainTarget(chainTarget);
  return {
    keyHandle: ECDSA_KEY_HANDLE,
    ecdsaThresholdKeyId,
    chainTarget,
    targetKey: thresholdEcdsaChainTargetKey(chainTarget),
    accountAddress: THRESHOLD_OWNER_ADDRESS,
    ownerAddress: THRESHOLD_OWNER_ADDRESS,
    relayerKeyId: 'rk-1',
    thresholdEcdsaPublicKeyB64u: 'threshold-ecdsa-public-key',
    key: {
      walletId: String(ACCOUNT_ID),
      subjectId: String(SUBJECT_ID),
      rpId: 'example.localhost',
      keyScope: 'evm-family',
      ecdsaThresholdKeyId,
      signingRootId: 'proj_local:dev',
      signingRootVersion: 'default',
      participantIds: [1, 2],
      thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
    },
  };
}

function createBaseContext(args?: {
  signingEngine?: Record<string, unknown>;
  configs?: Record<string, unknown>;
}): any {
  const now = Date.now();
  return {
    signingEngine: {
      assertSealedRefreshStartupParity: async () => undefined,
      getRpId: () => 'example.localhost',
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
      listThresholdEcdsaSessionRecordsForWalletTarget: (args: Record<string, unknown>) => [
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
          keyHandle: bootstrapKeyHandle(args),
          ecdsaThresholdKeyId: bootstrapEcdsaThresholdKeyId(args),
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
          ecdsaThresholdKeyId: bootstrapEcdsaThresholdKeyId(args),
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
      clearVolatileWarmSigningMaterial: async () => undefined,
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
  options?: {
    includeThresholdEcdsaProfiles?: boolean;
    profileContinuitySnapshot?: Record<string, unknown> | null;
  },
): Promise<T> {
  const clientDb = IndexedDBManager.clientDB as { getMostRecentNearAccountProjection?: unknown };
  const continuityClientDb = IndexedDBManager.clientDB as {
    getProfileContinuitySnapshot?: unknown;
  };
  const profileLookupClientDb = IndexedDBManager.clientDB as {
    resolveProfileAccountContext?: unknown;
  };
  const accountKeyMaterialDb = IndexedDBManager.accountKeyMaterialDB as {
    getKeyMaterial?: unknown;
  };
  const original = clientDb.getMostRecentNearAccountProjection;
  const originalContinuity = continuityClientDb.getProfileContinuitySnapshot;
  const originalProfileLookup = profileLookupClientDb.resolveProfileAccountContext;
  const originalKeyMaterial = accountKeyMaterialDb.getKeyMaterial;
  clientDb.getMostRecentNearAccountProjection = async () => null;
  continuityClientDb.getProfileContinuitySnapshot = async () => {
    if (options && 'profileContinuitySnapshot' in options) {
      return options.profileContinuitySnapshot;
    }
    return options?.includeThresholdEcdsaProfiles
      ? {
          chainAccounts: [
            {
              chainIdKey: 'evm:11155111',
              accountAddress: `0x${'11'.repeat(20)}`,
              accountModel: 'threshold-ecdsa',
            },
          ],
        }
      : { chainAccounts: [] };
  };
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
          bootstrapChains.push(String(bootstrapChainTarget(args).kind || ''));
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId: bootstrapEcdsaThresholdKeyId(args),
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
              ecdsaThresholdKeyId: bootstrapEcdsaThresholdKeyId(args),
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
    expect(bootstrapArgs?.['routeAuth']).toEqual({
      kind: 'threshold_session',
      jwt: 'jwt-ed25519',
    });
    const sharedKey = bootstrapArgs?.['key'] as Record<string, unknown> | undefined;
    const lanePolicy = bootstrapArgs?.['lanePolicy'] as Record<string, unknown> | undefined;
    expect(String(lanePolicy?.thresholdSessionId || '')).toMatch(/^threshold-ecdsa-login-/);
    expect(lanePolicy?.walletSigningSessionId).toBe(WALLET_SIGNING_SESSION_ID);
    expect(sharedKey?.keyScope).toBe('evm-family');
    expect(sharedKey?.ecdsaThresholdKeyId).toBe(ECDSA_THRESHOLD_KEY_ID);
    expect(lanePolicy?.chainTarget).toEqual(EVM_CHAIN_TARGET);
    expect('chainTarget' in ((bootstrapArgs || {}) as Record<string, unknown>)).toBe(false);
    expect(bootstrapArgs?.['clientRootShare32B64u']).toBe(ECDSA_CLIENT_ROOT_SHARE32_B64U);
    expect(prefillCalls).toBe(0);
  });

  test('wallet unlock provisions fresh passkey sessions even when restored sessions exist', async () => {
    let restoreCalls = 0;
    let connectCalls = 0;
    let clearCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        restorePersistedSessionsForWallet: async () => {
          restoreCalls += 1;
          return {
            listed: 1,
            attempted: 1,
            restored: 1,
            deferred: 0,
            skipped: 0,
            truncated: 0,
          };
        },
        connectEd25519Session: async (args: Record<string, unknown>) => {
          connectCalls += 1;
          expect(args.source).toBe('login');
          expect(args.remainingUses).toBe(3);
          return {
            ok: true,
            sessionId: 'fresh-passkey-session-1',
            walletSigningSessionId: 'fresh-wallet-session-1',
            jwt: 'jwt-ed25519',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssClientRootShare32B64u: ECDSA_CLIENT_ROOT_SHARE32_B64U,
          };
        },
        clearVolatileWarmSigningMaterial: async () => {
          clearCalls += 1;
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(true);
    expect(connectCalls).toBe(1);
    expect(restoreCalls).toBe(0);
    expect(clearCalls).toBe(1);
  });

  test('wallet unlock fetches relay ECDSA identity after fresh Ed25519 warm-up', async () => {
    const now = Date.now();
    const originalFetch = globalThis.fetch;
    let connectCalls = 0;
    let fetchCalls = 0;
    const bootstrapArgs: Array<Record<string, unknown>> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      fetchCalls += 1;
      expect(connectCalls).toBe(1);
      expect(String(input)).toBe('https://relay.example/threshold-ecdsa/key-identities');
      expect(init?.method).toBe('POST');
      expect((init?.headers as Record<string, string>)?.Authorization).toBe(
        'Bearer jwt-ed25519-fresh',
      );
      const body = JSON.parse(String(init?.body || '{}')) as {
        keyTargets: Array<{
          keyHandle?: string;
          ecdsaThresholdKeyId?: string;
          chainTarget: ThresholdEcdsaChainTarget;
        }>;
      };
      expect(body.keyTargets.map((target) => target.keyHandle || '')).toEqual([
        ECDSA_KEY_HANDLE,
        ECDSA_KEY_HANDLE,
      ]);
      expect(
        body.keyTargets.map((target) => thresholdEcdsaChainTargetKey(target.chainTarget)),
      ).toEqual([
        thresholdEcdsaChainTargetKey(TEMPO_CHAIN_TARGET),
        thresholdEcdsaChainTargetKey(EVM_CHAIN_TARGET),
      ]);
      return new Response(
        JSON.stringify({
          ok: true,
          ecdsaKeyIdentityTargets: [
            ecdsaKeyIdentityTargetRecord(TEMPO_CHAIN_TARGET),
            ecdsaKeyIdentityTargetRecord(EVM_CHAIN_TARGET),
          ],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }) as typeof fetch;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        connectEd25519Session: async () => {
          connectCalls += 1;
          return {
            ok: true,
            sessionId: 'fresh-ed25519-session',
            walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
            jwt: 'jwt-ed25519-fresh',
            remainingUses: 3,
            expiresAtMs: now + 60_000,
            ecdsaHssClientRootShare32B64u: ECDSA_CLIENT_ROOT_SHARE32_B64U,
          };
        },
        getWarmThresholdEd25519SessionStatus: async () => ({
          sessionId: 'fresh-ed25519-session',
          status: 'active',
          authMethod: 'passkey',
          remainingUses: 3,
          expiresAtMs: now + 60_000,
          createdAtMs: now,
        }),
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapArgs.push(args);
          const key = args.key as Record<string, unknown>;
          expect(key.keyScope).toBe('evm-family');
          expect(key.ecdsaThresholdKeyId).toBe(ECDSA_THRESHOLD_KEY_ID);
          expect(args.routeAuth).toEqual({
            kind: 'threshold_session',
            jwt: 'jwt-ed25519-fresh',
          });
          expect(args.clientRootShare32B64u).toBe(ECDSA_CLIENT_ROOT_SHARE32_B64U);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
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
              ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
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
          };
        },
      },
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () => await unlock(context, ACCOUNT_ID),
        {
          profileContinuitySnapshot: {
            chainAccounts: [],
            accountSigners: partialEcdsaProfileSigners(),
          },
        },
      );

      expect(result.success).toBe(true);
      expect(connectCalls).toBe(1);
      expect(fetchCalls).toBe(1);
      expect(bootstrapArgs).toHaveLength(2);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('wallet unlock completes configured ECDSA targets from one shared local key record', async () => {
    const bootstrapArgs: Array<Record<string, unknown>> = [];
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: (args: Record<string, unknown>) => {
          const chainTarget = args.chainTarget as Record<string, unknown>;
          if (chainTarget.kind !== 'tempo') return [];
          return [canonicalEcdsaRecord({ chainTarget })];
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapArgs.push(args);
          const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId,
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
              ecdsaThresholdKeyId,
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
    expect(bootstrapArgs).toHaveLength(2);
    expect(bootstrapArgs.map((args) => bootstrapEcdsaThresholdKeyId(args))).toEqual([
      ECDSA_THRESHOLD_KEY_ID,
      ECDSA_THRESHOLD_KEY_ID,
    ]);
    expect(bootstrapArgs.every((args) => Boolean(args.key && args.lanePolicy))).toBe(true);
  });

  test('wallet unlock fails before ECDSA warm-up when stored shared key ids conflict', async () => {
    let bootstrapCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: (args: Record<string, unknown>) => {
          const chainTarget = args.chainTarget as Record<string, unknown>;
          return [
            canonicalEcdsaRecord({
              chainTarget,
              ecdsaThresholdKeyId:
                chainTarget.kind === 'evm' ? 'ehss-conflicting-evm-key' : ECDSA_THRESHOLD_KEY_ID,
            }),
          ];
        },
        bootstrapEcdsaSession: async () => {
          bootstrapCalls += 1;
          throw new Error('ECDSA bootstrap should not start for ambiguous shared keys');
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('ambiguous shared key handles');
    expect(bootstrapCalls).toBe(0);
  });

  test('wallet unlock ignores profile-only owner metadata before clearing volatile material', async () => {
    const bootstrapArgs: Array<Record<string, unknown>> = [];
    let clearVolatileCalls = 0;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ ok: true, ecdsaKeyIdentityTargets: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })) as typeof fetch;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        clearVolatileWarmSigningMaterial: async () => {
          clearVolatileCalls += 1;
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapArgs.push(args);
          const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId,
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
              ecdsaThresholdKeyId,
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

    try {
      const result = await withMockedMostRecentProjection(
        async () => await unlock(context, ACCOUNT_ID),
        {
          profileContinuitySnapshot: {
            chainAccounts: [
              {
                chainIdKey: 'tempo:42431',
                accountAddress: `0x${'aa'.repeat(20)}`,
                accountModel: 'tempo-native',
                status: 'active',
                isPrimary: true,
              },
            ],
            accountSigners: [
              {
                chainIdKey: 'tempo:42431',
                accountAddress: `0x${'aa'.repeat(20)}`,
                signerId: `0x${'aa'.repeat(20)}`,
                signerKind: 'threshold-ecdsa',
                signerAuthMethod: 'passkey',
                status: 'active',
                metadata: {
                  ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
                  chainTarget: {
                    kind: 'tempo',
                    chainId: 42431,
                    networkSlug: 'tempo-testnet',
                  },
                  subjectId: ACCOUNT_ID,
                  rpId: 'example.localhost',
                  signingRootId: 'proj_local:dev',
                  signingRootVersion: 'default',
                  participantIds: [1, 2],
                  thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
                },
              },
            ],
          },
        },
      );

      expect(result.success).toBe(false);
      expect(String(result.error || '')).toContain('requires keyHandle selectors');
      expect(bootstrapArgs).toHaveLength(0);
      expect(clearVolatileCalls).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('wallet unlock ignores synthetic legacy profile key ids before clearing volatile material', async () => {
    const originalFetch = globalThis.fetch;
    const bootstrapArgs: Array<Record<string, unknown>> = [];
    let clearVolatileCalls = 0;
    globalThis.fetch = (async () => {
      throw new Error('inventory fetch should not run for blocked profile metadata');
    }) as typeof fetch;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        clearVolatileWarmSigningMaterial: async () => {
          clearVolatileCalls += 1;
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapArgs.push(args);
          const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
                clientAdditiveShare32B64u: 'Ag',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-1',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              thresholdSessionAuthToken: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            session: {
              ok: true,
              sessionId: 'session-1',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
            },
          };
        },
      },
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () => await unlock(context, ACCOUNT_ID),
        {
          profileContinuitySnapshot: {
            chainAccounts: [],
            accountSigners: [TEMPO_CHAIN_TARGET, EVM_CHAIN_TARGET].map((chainTarget) => ({
              chainIdKey: thresholdEcdsaChainTargetKey(chainTarget),
              accountAddress: THRESHOLD_OWNER_ADDRESS,
              signerId: THRESHOLD_OWNER_ADDRESS,
              signerKind: 'threshold-ecdsa',
              signerAuthMethod: 'passkey',
              status: 'active',
              metadata: {
                ecdsaThresholdKeyId: `legacy-key-handle:${ECDSA_KEY_HANDLE}`,
                chainTarget,
                subjectId: ACCOUNT_ID,
                rpId: 'example.localhost',
                signingRootId: 'proj_local:dev',
                signingRootVersion: 'default',
                participantIds: [1, 2],
                thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
              },
            })),
          },
        },
      );

      expect(result.success).toBe(false);
      expect(String(result.error || '')).toContain('requires keyHandle selectors');
      expect(bootstrapArgs).toHaveLength(0);
      expect(clearVolatileCalls).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('wallet unlock completes configured shared ECDSA targets when one stale profile signer lacks keyHandle', async () => {
    const originalFetch = globalThis.fetch;
    const bootstrapChains: string[] = [];
    const inventoryRequests: unknown[] = [];
    globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body || '{}')) as { keyTargets?: unknown[] };
      inventoryRequests.push(body);
      const keyTargets = Array.isArray(body.keyTargets) ? body.keyTargets : [];
      return new Response(
        JSON.stringify({
          ok: true,
          ecdsaKeyIdentityTargets: keyTargets.map((target) =>
            ecdsaKeyIdentityTargetRecord(
              (target as { chainTarget: ThresholdEcdsaChainTarget }).chainTarget,
            ),
          ),
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }) as typeof fetch;
    const context = createBaseContext({
      configs: {
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
            {
              network: 'ethereum-sepolia',
              rpcUrl: 'https://rpc.sepolia.test',
              explorerUrl: 'https://explorer.sepolia.test',
              chainId: 11155111,
            },
          ],
        },
      },
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapChains.push(thresholdEcdsaChainTargetKey(bootstrapChainTarget(args)));
          const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
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
              ecdsaThresholdKeyId,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            session: {
              ok: true,
              sessionId: 'session-1',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
            },
          };
        },
      },
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () => await unlock(context, ACCOUNT_ID),
        {
          profileContinuitySnapshot: {
            chainAccounts: [],
            accountSigners: [
              {
                chainIdKey: thresholdEcdsaChainTargetKey(TEMPO_CHAIN_TARGET),
                accountAddress: THRESHOLD_OWNER_ADDRESS,
                signerId: THRESHOLD_OWNER_ADDRESS,
                signerKind: 'threshold-ecdsa',
                signerAuthMethod: 'passkey',
                status: 'active',
                metadata: {
                  keyHandle: ECDSA_KEY_HANDLE,
                  ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
                  chainTarget: TEMPO_CHAIN_TARGET,
                  subjectId: ACCOUNT_ID,
                  rpId: 'example.localhost',
                  signingRootId: 'proj_local:dev',
                  signingRootVersion: 'default',
                  participantIds: [1, 2],
                  thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
                },
              },
              {
                chainIdKey: thresholdEcdsaChainTargetKey(SEPOLIA_CHAIN_TARGET),
                accountAddress: THRESHOLD_OWNER_ADDRESS,
                signerId: THRESHOLD_OWNER_ADDRESS,
                signerKind: 'threshold-ecdsa',
                signerAuthMethod: 'passkey',
                status: 'active',
                metadata: {
                  ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
                  chainTarget: SEPOLIA_CHAIN_TARGET,
                  subjectId: ACCOUNT_ID,
                  rpId: 'example.localhost',
                  signingRootId: 'proj_local:dev',
                  signingRootVersion: 'default',
                  participantIds: [1, 2],
                  thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
                },
              },
            ],
          },
        },
      );

      expect(result.success).toBe(true);
      expect(inventoryRequests).toHaveLength(1);
      expect(bootstrapChains).toEqual([
        'tempo:42431',
        'evm:eip155:5042002',
        'evm:eip155:11155111',
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('caps passkey unlock warm sessions at three uses', async () => {
    let ed25519RemainingUses: unknown = null;
    const ecdsaRemainingUses: unknown[] = [];
    const ecdsaWalletSigningSessionIds: unknown[] = [];
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
          const lanePolicy = bootstrapLanePolicy(args);
          ecdsaRemainingUses.push(lanePolicy.remainingUses);
          ecdsaWalletSigningSessionIds.push(lanePolicy.walletSigningSessionId);
          const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId,
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
              ecdsaThresholdKeyId,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'session-1',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: Number(bootstrapLanePolicy(args).remainingUses),
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
    expect(ecdsaWalletSigningSessionIds).toEqual([
      WALLET_SIGNING_SESSION_ID,
      WALLET_SIGNING_SESSION_ID,
    ]);
  });

  test('uses three unlock budget uses under the dev default', async () => {
    let ed25519RemainingUses: unknown = null;
    const ecdsaRemainingUses: unknown[] = [];
    const context = createBaseContext({
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
          const lanePolicy = bootstrapLanePolicy(args);
          ecdsaRemainingUses.push(lanePolicy.remainingUses);
          const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId,
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
              ecdsaThresholdKeyId,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'session-1',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: Number(lanePolicy.remainingUses),
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
    expect(bootstrapEcdsaThresholdKeyId(bootstrapArgs[0] || {})).toBe(ECDSA_THRESHOLD_KEY_ID);
    expect(setLastUserCalls).toBe(0);
    expect(updateLastLoginCalls).toBe(0);
  });

  test('fails closed when no canonical key id exists', async () => {
    let bootstrapCalls = 0;
    const bootstrapArgs: Record<string, unknown>[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ ok: true, ecdsaKeyIdentityTargets: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })) as typeof fetch;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapCalls += 1;
          bootstrapArgs.push(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
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

    try {
      const result = await withMockedMostRecentProjection(
        async () => await unlock(context, ACCOUNT_ID),
        { includeThresholdEcdsaProfiles: true },
      );

      expect(result.success).toBe(false);
      expect(String(result.error || '')).toContain('requires keyHandle selectors');
      expect(bootstrapCalls).toBe(0);
      expect(bootstrapArgs).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
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
        listThresholdEcdsaSessionRecordsForWalletTarget: (args: Record<string, unknown>) => [
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
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
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
          listThresholdEcdsaSessionRecordsForWalletTarget: (args: Record<string, unknown>) => [
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
            const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
            return {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relay.example',
                keyHandle: bootstrapKeyHandle(args),
                ecdsaThresholdKeyId,
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
                ecdsaThresholdKeyId,
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
      const lanePolicy = bootstrapLanePolicy(bootstrap || {});
      expect(String(lanePolicy.thresholdSessionId || '')).toMatch(/^threshold-ecdsa-login-/);
      expect(lanePolicy.walletSigningSessionId).toBe(WALLET_SIGNING_SESSION_ID);
      expect(bootstrap?.clientRootShare32B64u).toBe(ECDSA_CLIENT_ROOT_SHARE32_B64U);
      expect(bootstrapEcdsaThresholdKeyId(bootstrap || {})).toBe(EVM_ECDSA_THRESHOLD_KEY_ID);
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
    const capturedBootstrapArgs: Record<string, unknown>[] = [];
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
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              ecdsaHssClientRootShare32B64u: ECDSA_CLIENT_ROOT_SHARE32_B64U,
            };
          },
          bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
            capturedBootstrapArgs.push(args);
            const lanePolicy = bootstrapLanePolicy(args);
            const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
            return {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relay.example',
                keyHandle: bootstrapKeyHandle(args),
                ecdsaThresholdKeyId,
                signingRootId: 'proj_local:dev',
                backendBinding: {
                  relayerKeyId: 'rk-1',
                  clientVerifyingShareB64u: 'AQ',
                },
                participantIds: [1, 2],
                thresholdSessionKind: String(lanePolicy.thresholdSessionKind || ''),
                thresholdSessionId: 'session-cookie-ecdsa',
                walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              },
              keygen: {
                ok: true,
                ecdsaThresholdKeyId,
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
                participantIds: [1, 2],
              },
              session: {
                ok: true,
                sessionId: 'session-cookie-ecdsa',
                walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
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
              kind: 'cookie',
              exchange: { type: 'passkey_assertion' },
            },
          }),
        { includeThresholdEcdsaProfiles: true },
      );

      expect(result.success).toBe(true);
      expect(capturedConnectArgs).not.toBeNull();
      const connectArgs = capturedConnectArgs as Record<string, any> | null;
      expect(String(connectArgs?.appSessionJwt || '')).toBe('');
      expect(connectArgs?.useAppSessionCookie).toBe(true);
      expect(connectArgs?.localPrfCredential).toBe(loginCredential);
      expect(capturedBootstrapArgs).toHaveLength(2);
      expect(
        capturedBootstrapArgs.every(
          (args) => bootstrapLanePolicy(args).thresholdSessionKind === 'cookie',
        ),
      ).toBe(true);
      expect(
        capturedBootstrapArgs.every((args) => {
          const routeAuth = args.routeAuth as Record<string, unknown> | undefined;
          return routeAuth?.kind === 'cookie';
        }),
      ).toBe(true);
      expect(
        capturedBootstrapArgs.every(
          (args) => args.clientRootShare32B64u === ECDSA_CLIENT_ROOT_SHARE32_B64U,
        ),
      ).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

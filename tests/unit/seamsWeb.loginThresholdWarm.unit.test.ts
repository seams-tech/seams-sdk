import { expect, test } from '@playwright/test';
import { unlock } from '@/web/SeamsWeb/login';
import { IndexedDBManager } from '@/core/indexedDB';
import { toAccountId } from '@/core/types/accountIds';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  upsertStoredThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  thresholdEcdsaChainTargetKey,
  walletIdFromWalletProfile,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const ACCOUNT_ID = toAccountId('alice.testnet');
const TEMPO_ECDSA_THRESHOLD_KEY_ID = 'ehss-login-tempo';
const EVM_ECDSA_THRESHOLD_KEY_ID = TEMPO_ECDSA_THRESHOLD_KEY_ID;
const ECDSA_THRESHOLD_KEY_ID = TEMPO_ECDSA_THRESHOLD_KEY_ID;
const ECDSA_KEY_HANDLE = 'ehss-key-login-tempo';
const ECDSA_PRF_FIRST_B64U = Buffer.alloc(32, 7).toString('base64url');
const ECDSA_CLIENT_ROOT_SHARE32_B64U = 'oSWxVelT4exizVyl5Q9RgldZH2hte7-Kf3h2qkA4mlY';
const ECDSA_PUBLIC_KEY33_B64U = Buffer.alloc(33, 9).toString('base64url');
const WALLET_SIGNING_SESSION_ID = 'wsess-login-1';
const SUBJECT_ID = walletIdFromWalletProfile({ walletId: ACCOUNT_ID });
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

function completeEcdsaProfileSigners(): Array<Record<string, unknown>> {
  return [TEMPO_CHAIN_TARGET, EVM_CHAIN_TARGET].map((chainTarget) => ({
    status: 'active',
    signerKind: 'threshold-ecdsa',
    signerAuthMethod: 'passkey',
    metadata: {
      keyHandle: ECDSA_KEY_HANDLE,
      chainTarget,
      thresholdEcdsaPublicKeyB64u: ECDSA_PUBLIC_KEY33_B64U,
      sharedEvmFamilyKey: {
        walletId: String(ACCOUNT_ID),
        subjectId: String(SUBJECT_ID),
        rpId: 'example.localhost',
        keyScope: 'evm-family',
        keyHandle: ECDSA_KEY_HANDLE,
        ecdsaThresholdKeyId: ecdsaKeyIdForChainTarget(chainTarget),
        signingRootId: 'proj_local:dev',
        signingRootVersion: 'default',
        participantIds: [1, 2],
        thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
        thresholdEcdsaPublicKeyB64u: ECDSA_PUBLIC_KEY33_B64U,
      },
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
    thresholdEcdsaPublicKeyB64u: ECDSA_PUBLIC_KEY33_B64U,
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

function loginReadySigningLanes(args: {
  walletId: unknown;
  authMethod: 'email_otp' | 'passkey';
}): Record<string, unknown> {
  const expiresAtMs = Date.now() + 60_000;
  const ed25519Lane = {
    authMethod: args.authMethod,
    curve: 'ed25519',
    chain: 'near',
    state: 'ready',
    walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
    thresholdSessionId: 'tsess-login-ed25519',
    remainingUses: 3,
    expiresAtMs,
    updatedAtMs: Date.now(),
    source: 'runtime_session_record',
  };
  const ecdsaLanesByTarget = Object.fromEntries(
    [TEMPO_CHAIN_TARGET, EVM_CHAIN_TARGET].map((chainTarget) => {
      const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
      const lane = {
        authMethod: args.authMethod,
        curve: 'ecdsa',
        chainTarget,
        state: 'ready',
        walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
        thresholdSessionId: `tehss-login-${targetKey}`,
        remainingUses: 3,
        expiresAtMs,
        updatedAtMs: Date.now(),
        source: 'runtime_session_record',
        key: ecdsaKeyIdentityTargetRecord(chainTarget).key,
        publicFacts: {
          keyHandle: ECDSA_KEY_HANDLE,
          publicKeyB64u: ECDSA_PUBLIC_KEY33_B64U,
          participantIds: [1, 2],
          thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
        },
      };
      return [targetKey, lane];
    }),
  );
  return {
    walletId: toAccountId(String(args.walletId || ACCOUNT_ID)),
    generation: Date.now(),
    ecdsa: {
      targets: [TEMPO_CHAIN_TARGET, EVM_CHAIN_TARGET],
      lanesByTarget: ecdsaLanesByTarget,
      candidatesByTarget: Object.fromEntries(
        Object.entries(ecdsaLanesByTarget).map(([targetKey, lane]) => [targetKey, [lane]]),
      ),
    },
    lanes: {
      ed25519: {
        near: ed25519Lane,
      },
    },
    candidates: {
      ed25519: {
        near: [ed25519Lane],
      },
    },
  };
}

function createBaseContext(args?: {
  signingEngine?: Record<string, unknown>;
  configs?: Record<string, unknown>;
}): any {
  const now = Date.now();
  const signingEngine = {
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
      nearAuthenticatorsByAccount: async () => [{ credentialId: 'cred-1', signerSlot: 1 }],
      getAuthenticatorsByUser: async () => [{ credentialId: 'cred-1', signerSlot: 1 }],
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
          clientExtensionResults: {},
        },
        clientExtensionResults: {
          prf: {
            results: {
              first: ECDSA_PRF_FIRST_B64U,
            },
          },
        },
      }),
      readPersistedAvailableSigningLanes: async (input: Record<string, unknown>) =>
        loginReadySigningLanes({
          walletId: input.walletId,
          authMethod: input.authMethod === 'email_otp' ? 'email_otp' : 'passkey',
        }),
      connectEd25519Session: async () => ({
        ok: true,
        sessionId: 'session-1',
        walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
        jwt: 'jwt-ed25519',
        remainingUses: 3,
        expiresAtMs: now + 60_000,
        ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
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
  };
  return {
    signingEngine,
    signingRuntime: {
      services: {
        registrationAccounts: {
          getUserBySignerSlot: (...methodArgs: unknown[]) =>
            (signingEngine.getUserBySignerSlot as (...args: unknown[]) => Promise<unknown>)(
              ...methodArgs,
            ),
          getLastUser: () => signingEngine.getLastUser(),
          nearAuthenticatorsByAccount: (...methodArgs: unknown[]) =>
            (
              signingEngine.nearAuthenticatorsByAccount as (
                ...args: unknown[]
              ) => Promise<unknown>
            )(...methodArgs),
          setLastUser: (...methodArgs: unknown[]) =>
            (signingEngine.setLastUser as (...args: unknown[]) => Promise<unknown>)(
              ...methodArgs,
            ),
          updateLastLogin: (...methodArgs: unknown[]) =>
            (signingEngine.updateLastLogin as (...args: unknown[]) => Promise<unknown>)(
              ...methodArgs,
            ),
          getAllUsers: async () => [],
        },
      },
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
    walletAccountSigners?: Array<Record<string, unknown>>;
  },
): Promise<T> {
  const continuityPort = IndexedDBManager as unknown as {
    getProfileContinuitySnapshot?: unknown;
  };
  const profileLookupPort = IndexedDBManager as unknown as {
    resolveProfileAccountContext?: unknown;
  };
  const keyMaterialPort = IndexedDBManager as unknown as {
    getKeyMaterial?: unknown;
  };
  const signerPort = IndexedDBManager as unknown as {
    listAccountSignersByProfile?: unknown;
  };
  const originalContinuity = continuityPort.getProfileContinuitySnapshot;
  const originalProfileLookup = profileLookupPort.resolveProfileAccountContext;
  const originalKeyMaterial = keyMaterialPort.getKeyMaterial;
  const originalListAccountSignersByProfile = signerPort.listAccountSignersByProfile;
  const resolveMockAccountSigners = (): Array<Record<string, unknown>> => {
    if (options?.walletAccountSigners) {
      return options.walletAccountSigners;
    }
    if (options && 'profileContinuitySnapshot' in options) {
      return Array.isArray(options.profileContinuitySnapshot?.accountSigners)
        ? (options.profileContinuitySnapshot.accountSigners as Array<Record<string, unknown>>)
        : [];
    }
    return options?.includeThresholdEcdsaProfiles ? partialEcdsaProfileSigners() : [];
  };
  continuityPort.getProfileContinuitySnapshot = async () => {
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
          accountSigners: resolveMockAccountSigners(),
        }
      : { chainAccounts: [] };
  };
  signerPort.listAccountSignersByProfile = async () => resolveMockAccountSigners();
  profileLookupPort.resolveProfileAccountContext = async (accountRef: {
    chainIdKey: string;
    accountAddress: string;
  }) =>
    accountRef.chainIdKey === 'near:testnet' &&
    String(accountRef.accountAddress || '').trim() === 'alice.testnet'
      ? { profileId: 'near-profile:alice.testnet', accountRef }
      : null;
  keyMaterialPort.getKeyMaterial = async () => ({
    profileId: 'near-profile:alice.testnet',
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
    continuityPort.getProfileContinuitySnapshot = originalContinuity;
    profileLookupPort.resolveProfileAccountContext = originalProfileLookup;
    keyMaterialPort.getKeyMaterial = originalKeyMaterial;
    signerPort.listAccountSignersByProfile = originalListAccountSignersByProfile;
  }
}

test.describe('unlock threshold warm-session requirements', () => {
  test('passkey wallet unlock lets threshold warm-up own the no-session-exchange assertion', async () => {
    let credentialPrompts = 0;
    const connectCalls: Array<Record<string, unknown>> = [];
    const context = createBaseContext({
      signingEngine: {
        getAuthenticationCredentialsSerialized: async (args: Record<string, unknown>) => {
          credentialPrompts += 1;
          expect(args.nearAccountId).toBe(ACCOUNT_ID);
          expect(String(args.challengeB64u || '')).toMatch(/^[A-Za-z0-9_-]{43}$/);
          expect(args.allowCredentials).toEqual([
            {
              id: 'cred-1',
              type: 'public-key',
              transports: [],
            },
          ]);
          return {
            id: 'cred-1',
            rawId: 'cred-1',
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
                  first: ECDSA_PRF_FIRST_B64U,
                },
              },
            },
          };
        },
        connectEd25519Session: async (args: Record<string, unknown>) => {
          connectCalls.push(args);
          return {
            ok: true,
            sessionId: 'session-1',
            walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
            jwt: 'jwt-ed25519',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(true);
    expect(credentialPrompts).toBe(0);
    expect(connectCalls).toHaveLength(1);
    expect(connectCalls[0]?.auth).toBeUndefined();
  });

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
    expect(bootstrapArgs?.['passkeyPrfFirstB64u']).toBe(ECDSA_PRF_FIRST_B64U);
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
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
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

  test('wallet unlock requires explicit ECDSA key-facts repair before incomplete local warm-up', async () => {
    const originalFetch = globalThis.fetch;
    let connectCalls = 0;
    let fetchCalls = 0;
    let clearCalls = 0;
    let bootstrapCalls = 0;
    globalThis.fetch = (async () => {
      fetchCalls += 1;
      return new Response(JSON.stringify({ ok: false, message: 'unexpected inventory fetch' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
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
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
        clearVolatileWarmSigningMaterial: async () => {
          clearCalls += 1;
        },
        bootstrapEcdsaSession: async () => {
          bootstrapCalls += 1;
          throw new Error('bootstrap should not run before repair');
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

      expect(result.success).toBe(false);
      expect(String(result.error || '')).toContain('requires complete local key facts');
      expect(String(result.error || '')).toContain('explicit ECDSA key-facts repair');
      expect(connectCalls).toBe(0);
      expect(fetchCalls).toBe(0);
      expect(clearCalls).toBe(0);
      expect(bootstrapCalls).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('wallet unlock resolves explicit app-session ECDSA key-facts repair before warm-up', async () => {
    const originalFetch = globalThis.fetch;
    const inventoryBodies: unknown[] = [];
    const bootstrapTargets: string[] = [];
    let clearCalls = 0;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/wallets/alice.testnet/signers/ecdsa/key-facts/inventory')) {
        expect(init?.headers).toMatchObject({
          Authorization: 'Bearer app-session-repair-jwt',
        });
        const body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        inventoryBodies.push(body);
        expect(body).toMatchObject({
          rpId: 'example.localhost',
          auth: {
            kind: 'app_session',
            policy: {
              permission: 'ecdsa_key_facts_inventory',
              walletId: 'alice.testnet',
            },
          },
        });
        return new Response(
          JSON.stringify({
            ok: true,
            ecdsaKeyIdentityTargets: [
              ecdsaKeyIdentityTargetRecord(TEMPO_CHAIN_TARGET),
              ecdsaKeyIdentityTargetRecord(EVM_CHAIN_TARGET),
            ],
            diagnostics: {},
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }
      return new Response(JSON.stringify({ ok: false, message: 'unexpected route' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        clearVolatileWarmSigningMaterial: async () => {
          clearCalls += 1;
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          const chainTarget = bootstrapChainTarget(args);
          bootstrapTargets.push(thresholdEcdsaChainTargetKey(chainTarget));
          expect(bootstrapKey(args).thresholdOwnerAddress).toBe(THRESHOLD_OWNER_ADDRESS);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: ECDSA_KEY_HANDLE,
              ecdsaThresholdKeyId: bootstrapEcdsaThresholdKeyId(args),
              signingRootId: 'proj_local:dev',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: `session-repair-${bootstrapTargets.length}`,
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              thresholdSessionAuthToken: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: bootstrapEcdsaThresholdKeyId(args),
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            session: {
              ok: true,
              sessionId: `session-repair-${bootstrapTargets.length}`,
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
        async () =>
          await unlock(context, ACCOUNT_ID, {
            unlockSelection: { mode: 'ecdsa_only', ecdsa: true },
            ecdsaKeyFactsRepair: {
              mode: 'app_session',
              appSessionJwt: 'app-session-repair-jwt',
              policyTtlMs: 60_000,
            },
          }),
        {
          profileContinuitySnapshot: {
            chainAccounts: [],
            accountSigners: partialEcdsaProfileSigners(),
          },
        },
      );

      expect(result.success).toBe(true);
      expect(inventoryBodies).toHaveLength(1);
      expect(bootstrapTargets.sort()).toEqual(['evm:eip155:5042002', 'tempo:42431']);
      expect(clearCalls).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('wallet unlock acquires WebAuthn ECDSA key-facts repair only when planner needs inventory', async () => {
    const originalFetch = globalThis.fetch;
    const inventoryBodies: unknown[] = [];
    const credentialChallenges: string[] = [];
    const bootstrapTargets: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/wallets/alice.testnet/signers/ecdsa/key-facts/inventory')) {
        const body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        inventoryBodies.push(body);
        const auth = body.auth as Record<string, unknown>;
        expect(auth.kind).toBe('webauthn_assertion');
        expect(String(auth.expectedChallengeDigestB64u || '')).toBe(credentialChallenges[0]);
        expect(String(auth.serverNonceB64u || '')).toBeTruthy();
        return new Response(
          JSON.stringify({
            ok: true,
            ecdsaKeyIdentityTargets: [
              ecdsaKeyIdentityTargetRecord(TEMPO_CHAIN_TARGET),
              ecdsaKeyIdentityTargetRecord(EVM_CHAIN_TARGET),
            ],
            diagnostics: {},
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }
      return new Response(JSON.stringify({ ok: false, message: 'unexpected route' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        getAuthenticationCredentialsSerialized: async (args: Record<string, unknown>) => {
          credentialChallenges.push(String(args.challengeB64u || ''));
          return {
            id: 'cred-1',
            rawId: 'cred-1',
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
                  first: ECDSA_PRF_FIRST_B64U,
                },
              },
            },
          };
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          const chainTarget = bootstrapChainTarget(args);
          bootstrapTargets.push(thresholdEcdsaChainTargetKey(chainTarget));
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: ECDSA_KEY_HANDLE,
              ecdsaThresholdKeyId: bootstrapEcdsaThresholdKeyId(args),
              signingRootId: 'proj_local:dev',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: `session-webauthn-repair-${bootstrapTargets.length}`,
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              thresholdSessionAuthToken: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: bootstrapEcdsaThresholdKeyId(args),
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            session: {
              ok: true,
              sessionId: `session-webauthn-repair-${bootstrapTargets.length}`,
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
        async () =>
          await unlock(context, ACCOUNT_ID, {
            unlockSelection: { mode: 'ecdsa_only', ecdsa: true },
            ecdsaKeyFactsRepair: { mode: 'webauthn' },
          }),
        {
          profileContinuitySnapshot: {
            chainAccounts: [],
            accountSigners: partialEcdsaProfileSigners(),
          },
        },
      );

      expect(result.success).toBe(true);
      expect(credentialChallenges).toHaveLength(1);
      expect(inventoryBodies).toHaveLength(1);
      expect(bootstrapTargets.sort()).toEqual(['evm:eip155:5042002', 'tempo:42431']);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('wallet unlock skips role-local inventory fallback during normal unlock', async () => {
    const originalFetch = globalThis.fetch;
    let fetchCalls = 0;
    let bootstrapCalls = 0;
    globalThis.fetch = (async () => {
      fetchCalls += 1;
      return new Response(JSON.stringify({ ok: false, message: 'unexpected inventory fetch' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        bootstrapEcdsaSession: async () => {
          bootstrapCalls += 1;
          throw new Error('bootstrap should not run before repair');
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

      expect(result.success).toBe(false);
      expect(String(result.error || '')).toContain('explicit ECDSA key-facts repair');
      expect(fetchCalls).toBe(0);
      expect(bootstrapCalls).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('passkey unlock first-bootstraps missing ECDSA lanes from the current assertion', async () => {
    const originalFetch = globalThis.fetch;
    const bootstrapKinds: string[] = [];
    const inventoryRequests: unknown[] = [];
    let credentialPrompts = 0;
    const loginCredential = {
      id: 'cred-first-bootstrap',
      rawId: 'cred-first-bootstrap',
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
            first: ECDSA_PRF_FIRST_B64U,
          },
        },
      },
    };
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === 'https://relay.example/wallet/unlock/challenge') {
        return new Response(
          JSON.stringify({
            ok: true,
            challengeId: 'challenge-first-bootstrap',
            challengeB64u: 'challenge-first-bootstrap-b64u',
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
            jwt: 'app-jwt-first-bootstrap',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url === 'https://relay.example/threshold-ecdsa/key-identities') {
        inventoryRequests.push(url);
      }
      return new Response(JSON.stringify({ ok: false, message: 'unexpected route' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    const context = createBaseContext({
      configs: {
        registration: {
          mode: 'managed',
          environmentId: 'proj_local:dev',
          publishableKey: 'pk_test_local',
        },
      },
      signingEngine: {
        getAuthenticationCredentialsSerialized: async () => {
          credentialPrompts += 1;
          return loginCredential;
        },
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          const kind = String(args.kind || '');
          bootstrapKinds.push(kind);
          if (kind === 'passkey_fresh_ecdsa_bootstrap') {
            expect(args.webauthnAuthentication).toEqual(loginCredential);
            if (args.routeAuth !== undefined) {
              expect(args.routeAuth).toEqual({
                kind: 'app_session',
                jwt: 'app-jwt-first-bootstrap',
              });
            }
            expect(args.passkeyPrfFirstB64u).toBe(ECDSA_PRF_FIRST_B64U);
            expect(args.runtimeScopeBootstrap).toEqual({
              environmentId: 'proj_local:dev',
              publishableKey: 'pk_test_local',
            });
          } else {
            expect(kind).toBe('threshold_session_auth_reconnect_ecdsa_bootstrap');
            expect(bootstrapKey(args).ecdsaThresholdKeyId).toBe(ECDSA_THRESHOLD_KEY_ID);
          }
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: ECDSA_KEY_HANDLE,
              ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-ecdsa-first-bootstrap',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              thresholdSessionAuthToken: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            session: {
              ok: true,
              sessionId: 'session-ecdsa-first-bootstrap',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
            passkeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
      },
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'jwt',
              exchange: { type: 'passkey_assertion' },
            },
          }),
        { profileContinuitySnapshot: { chainAccounts: [], accountSigners: [] } },
      );

      expect(result.success).toBe(true);
      expect(credentialPrompts).toBe(1);
      expect(inventoryRequests).toHaveLength(0);
      expect(bootstrapKinds).toEqual([
        'passkey_fresh_ecdsa_bootstrap',
        'passkey_fresh_ecdsa_bootstrap',
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('passkey unlock without server session uses first ECDSA bootstrap to authorize Ed25519 mint', async () => {
    const bootstrapKinds: string[] = [];
    const bootstrapWalletSigningSessionIds: string[] = [];
    let connectArgs: Record<string, unknown> | null = null;
    let credentialPrompts = 0;
    const loginCredential = {
      id: 'cred-local-first-bootstrap',
      rawId: 'cred-local-first-bootstrap',
      type: 'public-key',
      authenticatorAttachment: undefined,
      response: {
        clientDataJSON: 'client-data-json',
        authenticatorData: 'authenticator-data',
        signature: 'signature',
        userHandle: undefined,
      },
      clientExtensionResults: {
        prf: {
          results: {
            first: 'prf-local-first-bootstrap',
          },
        },
      },
    };
    const context = createBaseContext({
      configs: {
        registration: {
          mode: 'managed',
          environmentId: 'proj_local:dev',
          publishableKey: 'pk_test_local',
        },
      },
      signingEngine: {
        getAuthenticationCredentialsSerialized: async (args: Record<string, unknown>) => {
          credentialPrompts += 1;
          expect(args.nearAccountId).toBe(ACCOUNT_ID);
          expect(String(args.challengeB64u || '')).toMatch(/^[A-Za-z0-9_-]{43}$/);
          return loginCredential;
        },
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        connectEd25519Session: async (args: Record<string, unknown>) => {
          connectArgs = args;
          return {
            ok: true,
            sessionId: 'session-local-first-bootstrap',
            walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
            jwt: 'jwt-ed25519-local-first-bootstrap',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          const kind = String(args.kind || '');
          bootstrapKinds.push(kind);
          const lanePolicy = args.lanePolicy as Record<string, unknown> | undefined;
          const sessionIdentity = args.sessionIdentity as Record<string, unknown> | undefined;
          const walletSigningSessionId = String(
            lanePolicy?.walletSigningSessionId || sessionIdentity?.walletSigningSessionId || '',
          );
          const thresholdSessionId = String(
            lanePolicy?.thresholdSessionId ||
              sessionIdentity?.thresholdSessionId ||
              'session-ecdsa-local-first-bootstrap',
          );
          bootstrapWalletSigningSessionIds.push(walletSigningSessionId);
          if (kind === 'passkey_fresh_ecdsa_bootstrap') {
            expect(args.webauthnAuthentication).toBeUndefined();
            expect(args.routeAuth).toEqual({
              kind: 'publishable_key',
              token: 'pk_test_local',
            });
            expect(args.runtimeScopeBootstrap).toEqual({
              environmentId: 'proj_local:dev',
              publishableKey: 'pk_test_local',
            });
          } else {
            expect(kind).toBe('threshold_session_auth_reconnect_ecdsa_bootstrap');
            expect(bootstrapKey(args).ecdsaThresholdKeyId).toBe(ECDSA_THRESHOLD_KEY_ID);
          }
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: ECDSA_KEY_HANDLE,
              ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId,
              walletSigningSessionId,
              thresholdSessionAuthToken: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            session: {
              ok: true,
              sessionId: thresholdSessionId,
              walletSigningSessionId,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
            passkeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { profileContinuitySnapshot: { chainAccounts: [], accountSigners: [] } },
    );

    expect(result.success).toBe(true);
    expect(credentialPrompts).toBe(0);
    expect(connectArgs).not.toBeNull();
    const capturedConnectArgs = connectArgs as unknown as Record<string, unknown>;
    expect(capturedConnectArgs.auth).toMatchObject({
      kind: 'threshold_ecdsa_session_jwt',
      thresholdEcdsaSessionJwt: 'jwt-ecdsa',
      localSecretSource: {
        kind: 'provided_prf_first_v1',
        prfFirstB64u: ECDSA_PRF_FIRST_B64U,
      },
    });
    expect(capturedConnectArgs.kind).toBe('exact_ed25519_provisioning');
    expect(String(capturedConnectArgs.sessionId || '')).toMatch(/^threshold-login-/);
    expect(capturedConnectArgs.walletSigningSessionId).toBe(bootstrapWalletSigningSessionIds[0]);
    expect(
      bootstrapWalletSigningSessionIds.every(
        (walletSigningSessionId) =>
          walletSigningSessionId === capturedConnectArgs.walletSigningSessionId,
      ),
    ).toBe(true);
    expect(bootstrapKinds).toEqual([
      'passkey_fresh_ecdsa_bootstrap',
      'threshold_session_auth_reconnect_ecdsa_bootstrap',
    ]);
  });

  test('passkey unlock uses complete active wallet-scoped ECDSA key facts without inventory fetch', async () => {
    const originalFetch = globalThis.fetch;
    const inventoryRequests: unknown[] = [];
    const bootstrapKinds: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === 'https://relay.example/threshold-ecdsa/key-identities') {
        inventoryRequests.push(url);
      }
      return new Response(JSON.stringify({ ok: false, message: 'unexpected route' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapKinds.push(String(args.kind || ''));
          expect(args.keyHandle).toBe(ECDSA_KEY_HANDLE);
          expect(bootstrapKey(args).ecdsaThresholdKeyId).toBe(ECDSA_THRESHOLD_KEY_ID);
          expect(bootstrapKey(args).thresholdOwnerAddress).toBe(THRESHOLD_OWNER_ADDRESS);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: ECDSA_KEY_HANDLE,
              ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
              signingRootId: 'proj_local:dev',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-profile-complete',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              thresholdSessionAuthToken: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            session: {
              ok: true,
              sessionId: 'session-profile-complete',
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
          profileContinuitySnapshot: { chainAccounts: [], accountSigners: [] },
          walletAccountSigners: completeEcdsaProfileSigners(),
        },
      );

      expect(result.success).toBe(true);
      expect(inventoryRequests).toHaveLength(0);
      expect(bootstrapKinds).toEqual([
        'threshold_session_auth_reconnect_ecdsa_bootstrap',
        'threshold_session_auth_reconnect_ecdsa_bootstrap',
      ]);
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
      expect(String(result.error || '')).toContain('requires complete local key facts');
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
      expect(String(result.error || '')).toContain('requires complete local key facts');
      expect(bootstrapArgs).toHaveLength(0);
      expect(clearVolatileCalls).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('mutation ledger keeps volatile clear after ECDSA preflight resolution', async () => {
    const now = Date.now();
    const originalFetch = globalThis.fetch;
    const blockedLedger: string[] = [];
    globalThis.fetch = (async () => {
      blockedLedger.push('inventory');
      throw new Error('blocked profile metadata should not fetch inventory');
    }) as typeof fetch;
    const blockedContext = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        connectEd25519Session: async () => {
          blockedLedger.push('connect-ed25519');
          throw new Error('blocked profile metadata should not provision Ed25519');
        },
        clearVolatileWarmSigningMaterial: async () => {
          blockedLedger.push('clear');
        },
        bootstrapEcdsaSession: async () => {
          blockedLedger.push('bootstrap-ecdsa');
          throw new Error('blocked profile metadata should not bootstrap ECDSA');
        },
      },
    });

    try {
      const blockedResult = await withMockedMostRecentProjection(
        async () => await unlock(blockedContext, ACCOUNT_ID),
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
                ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
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

      expect(blockedResult.success).toBe(false);
      expect(String(blockedResult.error || '')).toContain('requires complete local key facts');
      expect(blockedLedger).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }

    const inventoryLedger: string[] = [];
    clearAllStoredThresholdEd25519SessionRecords();
    upsertStoredThresholdEd25519SessionRecord({
      nearAccountId: ACCOUNT_ID,
      rpId: 'example.localhost',
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'rk-1',
      participantIds: [1, 2],
      thresholdSessionKind: 'jwt',
      thresholdSessionId: 'stored-ed25519-inventory-session',
      thresholdSessionAuthToken: 'jwt-ed25519-restored',
      expiresAtMs: now + 60_000,
      remainingUses: 1,
      source: 'manual-connect',
    });
    globalThis.fetch = (async () => {
      inventoryLedger.push('inventory');
      return new Response(JSON.stringify({ ok: false, message: 'unexpected inventory fetch' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    const inventoryContext = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        clearVolatileWarmSigningMaterial: async () => {
          inventoryLedger.push('clear');
        },
        connectEd25519Session: async () => {
          inventoryLedger.push('connect-ed25519');
          return {
            ok: true,
            sessionId: 'fresh-ed25519-after-inventory',
            walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
            jwt: 'jwt-ed25519-fresh',
            remainingUses: 3,
            expiresAtMs: now + 60_000,
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
        getWarmThresholdEd25519SessionStatus: async () => ({
          sessionId: 'fresh-ed25519-after-inventory',
          status: 'active',
          authMethod: 'passkey',
          remainingUses: 3,
          expiresAtMs: now + 60_000,
          createdAtMs: now,
        }),
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          inventoryLedger.push(
            `bootstrap:${thresholdEcdsaChainTargetKey(bootstrapChainTarget(args))}`,
          );
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
              thresholdSessionId: 'session-ecdsa-after-inventory',
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
              sessionId: 'session-ecdsa-after-inventory',
              walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: now + 60_000,
            },
          };
        },
      },
    });

    try {
      const inventoryResult = await withMockedMostRecentProjection(
        async () => await unlock(inventoryContext, ACCOUNT_ID),
        {
          profileContinuitySnapshot: {
            chainAccounts: [],
            accountSigners: partialEcdsaProfileSigners(),
          },
        },
      );

      expect(inventoryResult.success).toBe(false);
      expect(String(inventoryResult.error || '')).toContain('explicit ECDSA key-facts repair');
      expect(inventoryLedger).toEqual([]);
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
      globalThis.fetch = originalFetch;
    }
  });

  test('wallet unlock blocks stale configured ECDSA profile signers before inventory repair', async () => {
    const originalFetch = globalThis.fetch;
    const bootstrapChains: string[] = [];
    const inventoryRequests: unknown[] = [];
    globalThis.fetch = (async () => {
      inventoryRequests.push('unexpected');
      return new Response(JSON.stringify({ ok: false, message: 'unexpected inventory fetch' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
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

      expect(result.success).toBe(false);
      expect(String(result.error || '')).toContain('explicit ECDSA key-facts repair');
      expect(inventoryRequests).toHaveLength(0);
      expect(bootstrapChains).toEqual([]);
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
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
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
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
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
      expect(String(result.error || '')).toContain('requires complete local key facts');
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
      'threshold ECDSA warm-up missing passkey PRF.first',
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
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
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

  test('Ed25519-only unlock selection skips ECDSA warm-up on configured chains', async () => {
    let connectCalls = 0;
    let bootstrapCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        connectEd25519Session: async () => {
          connectCalls += 1;
          return {
            ok: true,
            sessionId: 'ed25519-only-session-1',
            walletSigningSessionId: 'wallet-session-ed25519-only-1',
            jwt: 'jwt-ed25519-only',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
          };
        },
        bootstrapEcdsaSession: async () => {
          bootstrapCalls += 1;
          throw new Error('ECDSA bootstrap should not run for Ed25519-only unlock');
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () =>
        await unlock(context, ACCOUNT_ID, {
          unlockSelection: { mode: 'ed25519_only', ed25519: true },
        }),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect(connectCalls).toBe(1);
    expect(bootstrapCalls).toBe(0);
  });

  test('ECDSA-only unlock selection warms ECDSA without connecting Ed25519', async () => {
    let credentialPrompts = 0;
    let connectCalls = 0;
    const bootstrapArgs: Record<string, unknown>[] = [];
    const walletOnlyUserData = {
      nearAccountId: 'alice.testnet',
      signerSlot: 1,
    };
    const loginCredential = {
      id: 'cred-ecdsa-only',
      rawId: 'cred-ecdsa-only',
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
            first: ECDSA_PRF_FIRST_B64U,
          },
        },
      },
    };
    const context = createBaseContext({
      signingEngine: {
        getUserBySignerSlot: async () => walletOnlyUserData,
        getLastUser: async () => walletOnlyUserData,
        getAuthenticationCredentialsSerialized: async () => {
          credentialPrompts += 1;
          return loginCredential;
        },
        connectEd25519Session: async () => {
          connectCalls += 1;
          throw new Error('Ed25519 connect should not run for ECDSA-only unlock');
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapArgs.push(args);
          const lanePolicy = bootstrapLanePolicy(args);
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
              thresholdSessionId: String(lanePolicy.thresholdSessionId || 'session-ecdsa-only'),
              walletSigningSessionId: String(lanePolicy.walletSigningSessionId || ''),
              thresholdSessionAuthToken: 'jwt-ecdsa-only',
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
              sessionId: String(lanePolicy.thresholdSessionId || 'session-ecdsa-only'),
              walletSigningSessionId: String(lanePolicy.walletSigningSessionId || ''),
              jwt: 'jwt-ecdsa-only',
              remainingUses: Number(lanePolicy.remainingUses || 0),
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
            passkeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () =>
        await unlock(context, ACCOUNT_ID, {
          unlockSelection: { mode: 'ecdsa_only', ecdsa: true },
        }),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.error || '').toBe('');
    expect(result.success).toBe(true);
    expect(result.operationalPublicKey).toBe(null);
    expect(result.signingSession?.status).toBe('active');
    expect(credentialPrompts).toBe(0);
    expect(connectCalls).toBe(0);
    expect(bootstrapArgs).toHaveLength(2);
    expect(
      bootstrapArgs.every(
        (args) =>
          args.kind === 'passkey_fresh_ecdsa_bootstrap' ||
          args.kind === 'threshold_session_auth_reconnect_ecdsa_bootstrap',
      ),
    ).toBe(true);
    const walletSigningSessionIds = bootstrapArgs.map((args) =>
      String(bootstrapLanePolicy(args).walletSigningSessionId || ''),
    );
    expect(new Set(walletSigningSessionIds).size).toBe(1);
    expect(
      walletSigningSessionIds.every((walletSigningSessionId) =>
        walletSigningSessionId.startsWith('wallet-ecdsa-login-'),
      ),
    ).toBe(true);
    expect(
      bootstrapArgs.every((args) =>
        args.kind === 'threshold_session_auth_reconnect_ecdsa_bootstrap'
          ? args.passkeyPrfFirstB64u === ECDSA_PRF_FIRST_B64U
          : args.passkeyPrfFirstB64u === undefined,
      ),
    ).toBe(true);
    expect(bootstrapArgs.every((args) => args.webauthnAuthentication === undefined)).toBe(true);
  });

  test('Ed25519 unlock selection requires a NEAR operational key', async () => {
    let connectCalls = 0;
    const walletOnlyUserData = {
      nearAccountId: 'alice.testnet',
      signerSlot: 1,
    };
    const context = createBaseContext({
      signingEngine: {
        getUserBySignerSlot: async () => walletOnlyUserData,
        getLastUser: async () => walletOnlyUserData,
        connectEd25519Session: async () => {
          connectCalls += 1;
          throw new Error('Ed25519 connect should not run without an operational key');
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () =>
        await unlock(context, ACCOUNT_ID, {
          unlockSelection: { mode: 'ed25519_only', ed25519: true },
        }),
      { includeThresholdEcdsaProfiles: false },
    );

    expect(result.success).toBe(false);
    expect(result.error || '').toContain('No NEAR operational key found');
    expect(connectCalls).toBe(0);
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
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
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
              ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
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
      expect(connectArgs?.auth).toMatchObject({
        kind: 'app_session_jwt',
        appSessionJwt: 'app-jwt-passkey-warm',
        localSecretSource: {
          kind: 'webauthn_prf_first_credential',
          credential: loginCredential,
          secretSource: {
            kind: 'webauthn_prf_first',
            prfFirstB64u: 'prf-first-warm',
            rpId: 'example.localhost',
            credentialIdB64u: 'cred-warm',
          },
        },
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
          getAuthenticationCredentialsSerialized: async () => {
            throw new Error('OIDC unlock must not request a passkey assertion');
          },
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
      expect(bootstrap?.passkeyPrfFirstB64u).toBe(ECDSA_PRF_FIRST_B64U);
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
              ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
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
      expect(connectArgs?.auth).toMatchObject({
        kind: 'app_session_cookie',
        localSecretSource: {
          kind: 'webauthn_prf_first_credential',
          credential: loginCredential,
          secretSource: {
            kind: 'webauthn_prf_first',
            prfFirstB64u: 'prf-first-cookie-warm',
            rpId: 'example.localhost',
            credentialIdB64u: 'cred-cookie-warm',
          },
        },
      });
      expect(capturedBootstrapArgs).toHaveLength(2);
      expect(
        capturedBootstrapArgs.every(
          (args) => bootstrapLanePolicy(args).thresholdSessionKind === 'cookie',
        ),
      ).toBe(true);
      expect(
        capturedBootstrapArgs.every((args) => {
          return args.routeAuth === undefined;
        }),
      ).toBe(true);
      expect(
        capturedBootstrapArgs.every((args) => args.webauthnAuthentication === loginCredential),
      ).toBe(true);
      expect(
        capturedBootstrapArgs.every(
          (args) => args.passkeyPrfFirstB64u === 'prf-first-cookie-warm',
        ),
      ).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

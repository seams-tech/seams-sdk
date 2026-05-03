import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  login: '/sdk/esm/core/SeamsPasskey/login.js',
  indexedDb: '/sdk/esm/core/indexedDB/index.js',
} as const;

test.describe('Email OTP wallet-session readiness', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('treats an active threshold-ECDSA Email OTP session as UI logged in', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const loginMod = await import(paths.login);
        const indexedDbMod = await import(paths.indexedDb);

        const nearAccountId = 'email-otp-alice.testnet';
        const now = Date.now();
        const clientDb = indexedDbMod.IndexedDBManager.clientDB as Record<string, unknown>;
        const originalGetMostRecentNearAccountProjection =
          clientDb.getMostRecentNearAccountProjection;
        const originalResolveNearAccountProfileContinuity =
          clientDb.resolveNearAccountProfileContinuity;

        clientDb.getMostRecentNearAccountProjection = async () => null;
        clientDb.resolveNearAccountProfileContinuity = async () => ({
          chainAccounts: [
            {
              accountModel: 'tempo-native',
              chainIdKey: 'tempo:testnet',
              accountAddress: '0xtempo',
              isPrimary: true,
            },
          ],
        });

        try {
          const context = {
            signingEngine: {
              assertSealedRefreshStartupParity: async () => undefined,
              getLastUser: async () => null,
              getUserBySignerSlot: async () => null,
              getWarmThresholdEd25519SessionStatus: async () => null,
              listWarmThresholdEcdsaSessionStatuses: async (_accountId: string, chain: string) =>
                chain === 'tempo'
                  ? [
                      {
                        sessionId: 'email-otp-ecdsa-session',
                        status: 'active',
                        authMethod: 'email_otp',
                        retention: 'session',
                        remainingUses: 3,
                        expiresAtMs: now + 60_000,
                        createdAtMs: now,
                      },
                    ]
                  : [],
              getThresholdEcdsaSessionRecordForLookup: () => ({
                thresholdEcdsaPublicKeyB64u: 'threshold-ecdsa-public-key',
              }),
              getNonceCoordinator: () => ({
                getDiagnostics: (input: { accountId?: string }) => ({
                  leaseCount: input.accountId === nearAccountId ? 2 : 0,
                  laneCount: input.accountId === nearAccountId ? 1 : 0,
                  metrics: {
                    atMs: now,
                    accountId: input.accountId,
                    leaseCount: input.accountId === nearAccountId ? 2 : 0,
                    laneCount: input.accountId === nearAccountId ? 1 : 0,
                    oldestLeaseAgeMs: 250,
                    oldestInFlightLeaseAgeMs: 250,
                    staleInFlightLeaseCount: 1,
                    staleInFlightLaneCount: 1,
                    reservedLeaseCount: 1,
                    signedLeaseCount: 1,
                    broadcastAcceptedLeaseCount: 0,
                    droppedLeaseCount: 0,
                    replacedLeaseCount: 0,
                    reconciledLeaseCount: 0,
                    releasedLeaseCount: 0,
                  },
                  leasesByState: {
                    reserved: 1,
                    released: 0,
                    expired: 0,
                    signed: 1,
                    signed_lease_expired: 0,
                    broadcast_accepted: 0,
                    broadcast_rejected: 0,
                    finalized: 0,
                    dropped: 0,
                    replaced: 0,
                    reconciled: 0,
                  },
                  lanes: [
                    {
                      family: 'evm',
                      accountId: nearAccountId,
                      networkKey: 'tempo:testnet',
                      chain: 'tempo',
                      chainId: 131316,
                      leaseCount: 2,
                      states: { reserved: 1, signed: 1 },
                    },
                  ],
                  near: {
                    hasContext: true,
                    activeAccountId: nearAccountId,
                    activePublicKey: 'ed25519:near-key',
                    reservedNonceCount: 1,
                    lastReservedNonce: '41',
                  },
                }),
              }),
            },
            configs: {
              signing: {
                mode: { mode: 'threshold-signer' },
              },
            },
          };

          return await loginMod.getWalletSession(context, nearAccountId);
        } finally {
          clientDb.getMostRecentNearAccountProjection = originalGetMostRecentNearAccountProjection;
          clientDb.resolveNearAccountProfileContinuity =
            originalResolveNearAccountProfileContinuity;
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.login?.isLoggedIn).toBe(true);
    expect(result.login?.nearAccountId).toBe('email-otp-alice.testnet');
    expect(result.login?.publicKey).toBeNull();
    expect(result.login?.thresholdEcdsaPublicKeyB64u).toBe('threshold-ecdsa-public-key');
    expect(result.signingSession?.status).toBe('active');
    expect(result.signingSession?.sessionId).toBe('email-otp-ecdsa-session');
    expect(result.signingSession?.authMethod).toBe('email_otp');
    expect(result.signingSession?.retention).toBe('session');
    expect(result.authMethod).toBe('email_otp');
    expect(result.retention).toBe('session');
    expect(result.login?.authMethod).toBe('email_otp');
    expect(result.nonceDiagnostics?.leaseCount).toBe(2);
    expect(result.nonceDiagnostics?.laneCount).toBe(1);
    expect(result.nonceDiagnostics?.leasesByState?.reserved).toBe(1);
    expect(result.nonceDiagnostics?.leasesByState?.signed).toBe(1);
    expect(result.nonceDiagnostics?.near?.reservedNonceCount).toBe(1);
    expect(result.nonceDiagnostics?.metrics?.staleInFlightLeaseCount).toBe(1);
    expect(result.nonceDiagnostics?.metrics?.staleInFlightLaneCount).toBe(1);
  });

  test('reads wallet-session snapshot/status without startup restore side effects', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const loginMod = await import(paths.login);
        const nearAccountId = 'startup-restore.testnet';
        const now = Date.now();
        const events: string[] = [];
        const context = {
          signingEngine: {
            assertSealedRefreshStartupParity: async () => undefined,
            restorePersistedSessionsForAccount: async (args: { walletId: string }) => {
              events.push(`restore:${args.walletId}`);
              return { listed: 1, attempted: 1, restored: 1, deferred: 0, skipped: 0, truncated: 0 };
            },
            readPersistedSigningSessionSnapshot: async (args: { walletId: string }) => {
              events.push(`snapshot:${args.walletId}`);
              return { walletId: args.walletId, lanes: {} };
            },
            getLastUser: async () => null,
            getUserBySignerSlot: async () => null,
            getWarmThresholdEd25519SessionStatus: async () => {
              events.push('ed25519-status');
              return null;
            },
            listWarmThresholdEcdsaSessionStatuses: async (_accountId: string, chain: string) => {
              events.push(`ecdsa-status:${chain}`);
              return chain === 'tempo'
                ? [
                    {
                      sessionId: 'startup-restore-ecdsa',
                      status: 'active',
                      authMethod: 'email_otp',
                      retention: 'session',
                      remainingUses: 3,
                      expiresAtMs: now + 60_000,
                      createdAtMs: now,
                    },
                  ]
                : [];
            },
            getThresholdEcdsaSessionRecordForLookup: () => ({
              thresholdEcdsaPublicKeyB64u: 'threshold-ecdsa-public-key',
            }),
            getNonceCoordinator: () => ({
              getDiagnostics: () => null,
            }),
          },
          configs: {
            signing: {
              mode: { mode: 'threshold-signer' },
            },
          },
        };

        const walletSession = await loginMod.getWalletSession(context, nearAccountId);
        return { walletSession, events };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.walletSession.login?.isLoggedIn).toBe(true);
    expect(result.events).not.toContain('restore:startup-restore.testnet');
    expect(result.events).toContain('snapshot:startup-restore.testnet');
    expect(result.events).toContain('ed25519-status');
  });

  test('treats restored warm signing session as login before ECDSA metadata exists', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const loginMod = await import(paths.login);
        const indexedDbMod = await import(paths.indexedDb);

        const nearAccountId = 'email-otp-immediate-refresh.testnet';
        const now = Date.now();
        const clientDb = indexedDbMod.IndexedDBManager.clientDB as Record<string, unknown>;
        const originalGetMostRecentNearAccountProjection =
          clientDb.getMostRecentNearAccountProjection;
        const originalGetLastProfileState = clientDb.getLastProfileState;
        const originalListChainAccountsByProfile = clientDb.listChainAccountsByProfile;
        const originalResolveNearAccountProfileContinuity =
          clientDb.resolveNearAccountProfileContinuity;

        clientDb.getMostRecentNearAccountProjection = async () => ({
          nearAccountId,
          signerSlot: 1,
        });
        clientDb.getLastProfileState = async () => ({
          profileId: 'profile-email-otp-immediate-refresh',
          activeSignerSlot: 1,
        });
        clientDb.listChainAccountsByProfile = async () => [
          {
            profileId: 'profile-email-otp-immediate-refresh',
            chainIdKey: 'near:testnet',
            accountAddress: nearAccountId,
            accountModel: 'near-native',
            isPrimary: true,
          },
        ];
        clientDb.resolveNearAccountProfileContinuity = async () => ({
          chainAccounts: [],
        });

        try {
          const context = {
            signingEngine: {
              assertSealedRefreshStartupParity: async () => undefined,
              getLastUser: async () => null,
              getUserBySignerSlot: async () => null,
              getWarmThresholdEd25519SessionStatus: async () => null,
              listWarmThresholdEcdsaSessionStatuses: async (_accountId: string, chain: string) =>
                chain === 'tempo'
                  ? [
                      {
                        sessionId: 'email-otp-restored-ecdsa-session',
                        status: 'active',
                        authMethod: 'email_otp',
                        retention: 'session',
                        remainingUses: 8,
                        expiresAtMs: now + 60_000,
                        createdAtMs: now,
                      },
                    ]
                  : [],
              getThresholdEcdsaSessionRecordForLookup: () => {
                throw new Error('metadata not available before first post-refresh sign');
              },
              getNonceCoordinator: () => ({
                getDiagnostics: () => null,
              }),
            },
            configs: {
              signing: {
                mode: { mode: 'threshold-signer' },
              },
            },
          };

          return await loginMod.getWalletSession(context);
        } finally {
          clientDb.getMostRecentNearAccountProjection = originalGetMostRecentNearAccountProjection;
          clientDb.getLastProfileState = originalGetLastProfileState;
          clientDb.listChainAccountsByProfile = originalListChainAccountsByProfile;
          clientDb.resolveNearAccountProfileContinuity =
            originalResolveNearAccountProfileContinuity;
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.login?.isLoggedIn).toBe(true);
    expect(result.login?.nearAccountId).toBe('email-otp-immediate-refresh.testnet');
    expect(result.login?.publicKey).toBeNull();
    expect(result.login?.thresholdEcdsaEthereumAddress).toBeNull();
    expect(result.login?.thresholdEcdsaPublicKeyB64u).toBeNull();
    expect(result.login?.authMethod).toBe('email_otp');
    expect(result.signingSession?.status).toBe('active');
    expect(result.signingSession?.sessionId).toBe('email-otp-restored-ecdsa-session');
    expect(result.authMethod).toBe('email_otp');
  });

  test('does not expose a stale NEAR public key for ECDSA-only Email OTP sessions', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const loginMod = await import(paths.login);
        const indexedDbMod = await import(paths.indexedDb);

        const nearAccountId = 'email-otp-stale-near-key.testnet';
        const now = Date.now();
        const clientDb = indexedDbMod.IndexedDBManager.clientDB as Record<string, unknown>;
        const originalGetMostRecentNearAccountProjection =
          clientDb.getMostRecentNearAccountProjection;
        const originalResolveNearAccountProfileContinuity =
          clientDb.resolveNearAccountProfileContinuity;

        clientDb.getMostRecentNearAccountProjection = async () => null;
        clientDb.resolveNearAccountProfileContinuity = async () => ({
          chainAccounts: [
            {
              accountModel: 'tempo-native',
              chainIdKey: 'tempo:testnet',
              accountAddress: '0xtempo',
              isPrimary: true,
            },
          ],
        });

        try {
          const context = {
            signingEngine: {
              assertSealedRefreshStartupParity: async () => undefined,
              getLastUser: async () => ({
                nearAccountId,
                signerSlot: 1,
                operationalPublicKey: 'ed25519:stale-near-key',
              }),
              getUserBySignerSlot: async () => ({
                nearAccountId,
                signerSlot: 1,
                operationalPublicKey: 'ed25519:stale-near-key',
              }),
              getWarmThresholdEd25519SessionStatus: async () => null,
              listWarmThresholdEcdsaSessionStatuses: async (_accountId: string, chain: string) =>
                chain === 'tempo'
                  ? [
                      {
                        sessionId: 'email-otp-ecdsa-session',
                        status: 'active',
                        authMethod: 'email_otp',
                        retention: 'session',
                        remainingUses: 3,
                        expiresAtMs: now + 60_000,
                        createdAtMs: now,
                      },
                    ]
                  : [],
              getThresholdEcdsaSessionRecordForLookup: () => ({
                thresholdEcdsaPublicKeyB64u: 'threshold-ecdsa-public-key',
              }),
            },
            configs: {
              signing: {
                mode: { mode: 'threshold-signer' },
              },
            },
          };

          return await loginMod.getWalletSession(context, nearAccountId);
        } finally {
          clientDb.getMostRecentNearAccountProjection = originalGetMostRecentNearAccountProjection;
          clientDb.resolveNearAccountProfileContinuity =
            originalResolveNearAccountProfileContinuity;
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.login?.isLoggedIn).toBe(true);
    expect(result.login?.nearAccountId).toBe('email-otp-stale-near-key.testnet');
    expect(result.login?.publicKey).toBeNull();
    expect(result.login?.thresholdEcdsaPublicKeyB64u).toBe('threshold-ecdsa-public-key');
    expect(result.signingSession?.status).toBe('active');
    expect(result.signingSession?.sessionId).toBe('email-otp-ecdsa-session');
    expect(result.signingSession?.authMethod).toBe('email_otp');
    expect(result.authMethod).toBe('email_otp');
    expect(result.login?.authMethod).toBe('email_otp');
  });

  test('reports the lowest active remaining-use budget across Email OTP signing lanes', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const loginMod = await import(paths.login);
        const indexedDbMod = await import(paths.indexedDb);

        const nearAccountId = 'email-otp-budget.testnet';
        const now = Date.now();
        const clientDb = indexedDbMod.IndexedDBManager.clientDB as Record<string, unknown>;
        const originalGetMostRecentNearAccountProjection =
          clientDb.getMostRecentNearAccountProjection;
        const originalResolveNearAccountProfileContinuity =
          clientDb.resolveNearAccountProfileContinuity;

        clientDb.getMostRecentNearAccountProjection = async () => null;
        clientDb.resolveNearAccountProfileContinuity = async () => ({
          chainAccounts: [
            {
              accountModel: 'tempo-native',
              chainIdKey: 'tempo:testnet',
              accountAddress: '0xtempo',
              isPrimary: true,
            },
          ],
        });

        try {
          const context = {
            signingEngine: {
              assertSealedRefreshStartupParity: async () => undefined,
              getLastUser: async () => null,
              getUserBySignerSlot: async () => null,
              getWarmThresholdEd25519SessionStatus: async () => ({
                sessionId: 'email-otp-ed25519-session',
                status: 'active',
                authMethod: 'email_otp',
                retention: 'session',
                remainingUses: 5,
                expiresAtMs: now + 60_000,
                createdAtMs: now,
              }),
              listWarmThresholdEcdsaSessionStatuses: async (_accountId: string, chain: string) =>
                chain === 'tempo'
                  ? [
                      {
                        sessionId: 'email-otp-ecdsa-session',
                        status: 'active',
                        authMethod: 'email_otp',
                        retention: 'session',
                        remainingUses: 1,
                        expiresAtMs: now + 60_000,
                        createdAtMs: now,
                      },
                    ]
                  : [],
              getThresholdEcdsaSessionRecordForLookup: () => ({
                thresholdEcdsaPublicKeyB64u: 'threshold-ecdsa-public-key',
              }),
            },
            configs: {
              signing: {
                mode: { mode: 'threshold-signer' },
              },
            },
          };

          return await loginMod.getWalletSession(context, nearAccountId);
        } finally {
          clientDb.getMostRecentNearAccountProjection = originalGetMostRecentNearAccountProjection;
          clientDb.resolveNearAccountProfileContinuity =
            originalResolveNearAccountProfileContinuity;
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.signingSession?.status).toBe('active');
    expect(result.signingSession?.sessionId).toBe('email-otp-ecdsa-session');
    expect(result.signingSession?.remainingUses).toBe(1);
  });
});

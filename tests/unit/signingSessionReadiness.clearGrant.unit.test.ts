import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { testEcdsaChainTarget } from './helpers/ecdsaChainTarget.fixtures';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import {
  clearSigningGrant,
  discoverLanesForWallet,
} from '@/core/signingEngine/session/availability/readiness';
import {
  buildThresholdEd25519SessionRecordKey,
  clearAllStoredThresholdEd25519SessionRecords,
  clearAllThresholdEcdsaSessionRecords,
  clearThresholdEcdsaSessionRecordForExactIdentity,
  clearStoredThresholdEd25519SessionRecordForLaneKey,
  getStoredThresholdEd25519SessionRecordForLane,
  getThresholdEcdsaSessionRecordByKey,
  toExactEcdsaSigningLaneIdentity,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
  upsertThresholdEd25519SessionFact,
  upsertThresholdEcdsaSessionFromBootstrap,
} from '@/core/signingEngine/session/persistence/records';

const SPLIT_WALLET_ID = toWalletId('frost-clear-grant-k7p9m2');
const SPLIT_NEAR_ACCOUNT_ID = toAccountId('b'.repeat(64));
const PRIMARY_NEAR_ED25519_SIGNING_KEY_ID = 'near-ed25519-clear-grant-primary';
const SIBLING_NEAR_ED25519_SIGNING_KEY_ID = 'near-ed25519-clear-grant-sibling';
const PRIMARY_SIGNING_GRANT_ID = 'grant-clear-split-ed25519-primary';
const SIBLING_SIGNING_GRANT_ID = 'grant-clear-split-ed25519-sibling';
const MISMATCH_WALLET_ID = toWalletId('valid-wallet.testnet');
const MISMATCH_NEAR_ACCOUNT_ID = toAccountId('target.testnet');
const MISMATCH_NEAR_ED25519_SIGNING_KEY_ID = 'near-ed25519-clear-mismatch';
const MISMATCH_SIGNING_GRANT_ID = 'grant-clear-mismatch';
const MISMATCH_THRESHOLD_SESSION_ID = 'tsess-clear-mismatch';
const ECDSA_WALLET_ID = toWalletId('frost-ecdsa-clear-k7p9m2');
const ECDSA_CHAIN_TARGET = testEcdsaChainTarget('tempo');
const PRIMARY_ECDSA_SIGNING_GRANT_ID = 'grant-clear-ecdsa-primary';
const SIBLING_ECDSA_SIGNING_GRANT_ID = 'grant-clear-ecdsa-sibling';
const PRIMARY_ECDSA_THRESHOLD_SESSION_ID = 'tsess-clear-ecdsa-primary';
const SIBLING_ECDSA_THRESHOLD_SESSION_ID = 'tsess-clear-ecdsa-sibling';

function ed25519RouterAbNormalSigning(signingWorkerId: string) {
  return {
    kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
    signingWorkerId,
  };
}

function seedSplitEd25519GrantRecords(): void {
  upsertThresholdEd25519SessionFact({
    walletId: SPLIT_WALLET_ID,
    nearAccountId: SPLIT_NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: PRIMARY_NEAR_ED25519_SIGNING_KEY_ID,
    rpId: 'localhost',
    relayerUrl: 'https://relay.example',
    relayerKeyId: 'rk-1',
    participantIds: [1, 2],
    signerSlot: 1,
    routerAbNormalSigning: ed25519RouterAbNormalSigning('clear-grant-primary-worker'),
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'tsess-clear-split-ed25519-primary',
    signingGrantId: PRIMARY_SIGNING_GRANT_ID,
    passkeyCredentialIdB64u: 'credential-clear-split-ed25519-primary',
    walletSessionJwt: 'jwt-clear-split-ed25519-primary',
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 1,
    signingRootId: 'proj_local:dev',
    signingRootVersion: 'default',
    source: 'login',
  });
  upsertThresholdEd25519SessionFact({
    walletId: SPLIT_WALLET_ID,
    nearAccountId: SPLIT_NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: SIBLING_NEAR_ED25519_SIGNING_KEY_ID,
    rpId: 'localhost',
    relayerUrl: 'https://relay.example',
    relayerKeyId: 'rk-1',
    participantIds: [1, 2],
    signerSlot: 2,
    routerAbNormalSigning: ed25519RouterAbNormalSigning('clear-grant-sibling-worker'),
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'tsess-clear-split-ed25519-sibling',
    signingGrantId: SIBLING_SIGNING_GRANT_ID,
    passkeyCredentialIdB64u: 'credential-clear-split-ed25519-sibling',
    walletSessionJwt: 'jwt-clear-split-ed25519-sibling',
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 1,
    signingRootId: 'proj_local:dev',
    signingRootVersion: 'default',
    source: 'login',
  });
}

function seedMismatchFixtureRecord(): void {
  upsertThresholdEd25519SessionFact({
    walletId: MISMATCH_WALLET_ID,
    nearAccountId: MISMATCH_NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: MISMATCH_NEAR_ED25519_SIGNING_KEY_ID,
    rpId: 'localhost',
    relayerUrl: 'https://relay.example',
    relayerKeyId: 'rk-1',
    participantIds: [1, 2],
    signerSlot: 1,
    routerAbNormalSigning: ed25519RouterAbNormalSigning('clear-grant-mismatch-worker'),
    thresholdSessionKind: 'jwt',
    thresholdSessionId: MISMATCH_THRESHOLD_SESSION_ID,
    signingGrantId: MISMATCH_SIGNING_GRANT_ID,
    passkeyCredentialIdB64u: 'credential-clear-mismatch',
    walletSessionJwt: 'jwt-clear-mismatch',
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 1,
    signingRootId: 'proj_local:dev',
    signingRootVersion: 'default',
    source: 'login',
  });
}

function expectMismatchFixtureRecordPresent(): void {
  expect(getStoredThresholdEd25519SessionRecordForLane({
    walletId: MISMATCH_WALLET_ID,
    nearAccountId: MISMATCH_NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: MISMATCH_NEAR_ED25519_SIGNING_KEY_ID,
    authMethod: 'passkey',
    signingGrantId: MISMATCH_SIGNING_GRANT_ID,
    thresholdSessionId: MISMATCH_THRESHOLD_SESSION_ID,
    signerSlot: 1,
  })).toMatchObject({
    walletId: MISMATCH_WALLET_ID,
    nearAccountId: MISMATCH_NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: MISMATCH_NEAR_ED25519_SIGNING_KEY_ID,
    signingGrantId: MISMATCH_SIGNING_GRANT_ID,
  });
}

function createEcdsaStoreDeps(): ThresholdEcdsaSessionStoreDeps {
  return {
    recordsByLane: new Map(),
    exportArtifactsByLane: new Map(),
    now: () => 1_700_000_000_000,
  };
}

function ecdsaEmailOtpAuthContext(): ThresholdEcdsaEmailOtpAuthContext {
  return buildEmailOtpAuthContextForWalletAuthMethod({
    policy: 'session',
    walletId: ECDSA_WALLET_ID,
    emailHashHex: '11'.repeat(32),
    provider: 'email',
    providerUserId: ECDSA_WALLET_ID,
    retention: 'session',
    reason: 'sign',
  });
}

function seedEcdsaGrantRecord(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    signingGrantId: string;
    thresholdSessionId: string;
  },
): ThresholdEcdsaSessionRecord {
  return upsertThresholdEcdsaSessionFromBootstrap(deps, {
    walletId: ECDSA_WALLET_ID,
    chainTarget: ECDSA_CHAIN_TARGET,
    bootstrap: createThresholdEcdsaBootstrapFixture({
      nearAccountId: String(ECDSA_WALLET_ID),
      chain: 'tempo',
      roleLocalAuthMethod: 'email_otp',
      emailOtpAuthSubjectId: String(ECDSA_WALLET_ID),
      keyHandle: 'ederivation-clear-ecdsa-shared',
      ecdsaThresholdKeyId: 'ek-clear-ecdsa-shared',
      sessionId: args.thresholdSessionId,
      signingGrantId: args.signingGrantId,
      remainingUses: 1,
      expiresAtMs: Date.now() + 60_000,
    }),
    source: 'email_otp',
    emailOtpAuthContext: ecdsaEmailOtpAuthContext(),
  });
}

test.describe('signing-session readiness grant clearing', () => {
  test.afterEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test('clears split Ed25519 grant records by exact lane key', async () => {
    clearAllStoredThresholdEd25519SessionRecords();
    seedSplitEd25519GrantRecords();

    expect(getStoredThresholdEd25519SessionRecordForLane({
      walletId: SPLIT_WALLET_ID,
      nearAccountId: SPLIT_NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: PRIMARY_NEAR_ED25519_SIGNING_KEY_ID,
      authMethod: 'passkey',
      signingGrantId: PRIMARY_SIGNING_GRANT_ID,
      thresholdSessionId: 'tsess-clear-split-ed25519-primary',
      signerSlot: 1,
    })).toMatchObject({
      walletId: SPLIT_WALLET_ID,
      nearAccountId: SPLIT_NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: PRIMARY_NEAR_ED25519_SIGNING_KEY_ID,
      signingGrantId: PRIMARY_SIGNING_GRANT_ID,
    });
    expect(discoverLanesForWallet({}, SPLIT_WALLET_ID)).toHaveLength(2);

    await clearSigningGrant({
      deps: {},
      statusOverrides: new Map(),
      walletId: SPLIT_WALLET_ID,
      signingGrantId: PRIMARY_SIGNING_GRANT_ID,
    });

    expect(getStoredThresholdEd25519SessionRecordForLane({
      walletId: SPLIT_WALLET_ID,
      nearAccountId: SPLIT_NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: PRIMARY_NEAR_ED25519_SIGNING_KEY_ID,
      authMethod: 'passkey',
      signingGrantId: PRIMARY_SIGNING_GRANT_ID,
      thresholdSessionId: 'tsess-clear-split-ed25519-primary',
      signerSlot: 1,
    })).toBeNull();
    expect(getStoredThresholdEd25519SessionRecordForLane({
      walletId: SPLIT_WALLET_ID,
      nearAccountId: SPLIT_NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: SIBLING_NEAR_ED25519_SIGNING_KEY_ID,
      authMethod: 'passkey',
      signingGrantId: SIBLING_SIGNING_GRANT_ID,
      thresholdSessionId: 'tsess-clear-split-ed25519-sibling',
      signerSlot: 2,
    })).toMatchObject({
      walletId: SPLIT_WALLET_ID,
      nearAccountId: SPLIT_NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: SIBLING_NEAR_ED25519_SIGNING_KEY_ID,
      signingGrantId: SIBLING_SIGNING_GRANT_ID,
    });
    expect(discoverLanesForWallet({}, SPLIT_WALLET_ID)).toHaveLength(1);
  });

  test('does not clear when a wallet id is used as the NEAR account lane field', () => {
    clearAllStoredThresholdEd25519SessionRecords();
    seedMismatchFixtureRecord();

    const wrongLaneKey = buildThresholdEd25519SessionRecordKey({
      walletId: MISMATCH_WALLET_ID,
      nearAccountId: String(MISMATCH_WALLET_ID),
      nearEd25519SigningKeyId: MISMATCH_NEAR_ED25519_SIGNING_KEY_ID,
      authMethod: 'passkey',
      signingGrantId: MISMATCH_SIGNING_GRANT_ID,
      thresholdSessionId: MISMATCH_THRESHOLD_SESSION_ID,
      signerSlot: 1,
    });

    expect(clearStoredThresholdEd25519SessionRecordForLaneKey(wrongLaneKey)).toEqual({
      ok: true,
      cleared: false,
    });
    expectMismatchFixtureRecordPresent();
  });

  test('does not clear records with mismatched exact lane fields', () => {
    clearAllStoredThresholdEd25519SessionRecords();
    seedMismatchFixtureRecord();

    const mismatchedLaneKeys = [
      buildThresholdEd25519SessionRecordKey({
        walletId: MISMATCH_WALLET_ID,
        nearAccountId: MISMATCH_NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: 'near-ed25519-clear-mismatch-other',
        authMethod: 'passkey',
        signingGrantId: MISMATCH_SIGNING_GRANT_ID,
        thresholdSessionId: MISMATCH_THRESHOLD_SESSION_ID,
        signerSlot: 1,
      }),
      buildThresholdEd25519SessionRecordKey({
        walletId: MISMATCH_WALLET_ID,
        nearAccountId: MISMATCH_NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: MISMATCH_NEAR_ED25519_SIGNING_KEY_ID,
        authMethod: 'passkey',
        signingGrantId: 'grant-clear-mismatch-other',
        thresholdSessionId: MISMATCH_THRESHOLD_SESSION_ID,
        signerSlot: 1,
      }),
      buildThresholdEd25519SessionRecordKey({
        walletId: MISMATCH_WALLET_ID,
        nearAccountId: MISMATCH_NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: MISMATCH_NEAR_ED25519_SIGNING_KEY_ID,
        authMethod: 'passkey',
        signingGrantId: MISMATCH_SIGNING_GRANT_ID,
        thresholdSessionId: 'tsess-clear-mismatch-other',
        signerSlot: 1,
      }),
      buildThresholdEd25519SessionRecordKey({
        walletId: MISMATCH_WALLET_ID,
        nearAccountId: MISMATCH_NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: MISMATCH_NEAR_ED25519_SIGNING_KEY_ID,
        authMethod: 'passkey',
        signingGrantId: MISMATCH_SIGNING_GRANT_ID,
        thresholdSessionId: MISMATCH_THRESHOLD_SESSION_ID,
        signerSlot: 2,
      }),
    ];

    for (const laneKey of mismatchedLaneKeys) {
      expect(clearStoredThresholdEd25519SessionRecordForLaneKey(laneKey)).toEqual({
        ok: true,
        cleared: false,
      });
    }
    expectMismatchFixtureRecordPresent();
  });

  test('clears split ECDSA grant records by exact identity', async () => {
    const ecdsaStore = createEcdsaStoreDeps();
    try {
      const primaryRecord = seedEcdsaGrantRecord(ecdsaStore, {
        signingGrantId: PRIMARY_ECDSA_SIGNING_GRANT_ID,
        thresholdSessionId: PRIMARY_ECDSA_THRESHOLD_SESSION_ID,
      });
      const siblingRecord = seedEcdsaGrantRecord(ecdsaStore, {
        signingGrantId: SIBLING_ECDSA_SIGNING_GRANT_ID,
        thresholdSessionId: SIBLING_ECDSA_THRESHOLD_SESSION_ID,
      });
      const primaryIdentity = toExactEcdsaSigningLaneIdentity(primaryRecord);
      const siblingIdentity = toExactEcdsaSigningLaneIdentity(siblingRecord);

      await clearSigningGrant({
        deps: {
          clearThresholdEcdsaSessionRecordForExactIdentity: (identity) => {
            clearThresholdEcdsaSessionRecordForExactIdentity(ecdsaStore, identity);
          },
        },
        statusOverrides: new Map(),
        walletId: ECDSA_WALLET_ID,
        signingGrantId: PRIMARY_ECDSA_SIGNING_GRANT_ID,
      });

      expect(getThresholdEcdsaSessionRecordByKey(ecdsaStore, primaryIdentity)).toBeNull();
      expect(getThresholdEcdsaSessionRecordByKey(ecdsaStore, siblingIdentity)).toMatchObject({
        walletId: ECDSA_WALLET_ID,
        signingGrantId: SIBLING_ECDSA_SIGNING_GRANT_ID,
        thresholdSessionId: SIBLING_ECDSA_THRESHOLD_SESSION_ID,
      });
    } finally {
      clearAllThresholdEcdsaSessionRecords(ecdsaStore);
    }
  });
});

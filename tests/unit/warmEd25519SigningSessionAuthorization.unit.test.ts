import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import {
  nearEd25519SigningKeyIdFromString,
  walletIdFromString,
} from '@shared/utils/registrationIntent';
import type { SigningSessionStatus } from '@/core/types/seams';
import type { ThresholdEd25519SessionRecord } from '@/core/signingEngine/session/persistence/records';
import { parseWarmEd25519SigningSessionAuthorizationFromRecord } from '@/core/signingEngine/session/warmCapabilities/ed25519Authorization';

const ACCOUNT_ID = toAccountId('alice.testnet');
const WALLET_ID = walletIdFromString('alice-wallet');
const ED25519_KEY_SCOPE_ID = nearEd25519SigningKeyIdFromString('alice-key-scope');

const runtimePolicyScope = {
  orgId: 'org-test',
  projectId: 'project-test',
  envId: 'dev',
  signingRootVersion: 'default',
};

const routerAbNormalSigning = {
  kind: 'router_ab_ed25519_normal_signing_v1',
  signingWorkerId: 'signing-worker-a',
} as const;

function activeStatus(overrides: Partial<SigningSessionStatus> = {}): SigningSessionStatus {
  return {
    sessionId: 'threshold-session-1',
    status: 'active',
    remainingUses: 3,
    availableUses: 3,
    expiresAtMs: 1_900_000_000_000,
    ...overrides,
  };
}

function ed25519Record(
  overrides: Partial<ThresholdEd25519SessionRecord> = {},
): ThresholdEd25519SessionRecord {
  return {
    walletId: WALLET_ID,
    nearAccountId: ACCOUNT_ID,
    nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
    rpId: 'localhost',
    relayerUrl: 'https://router.test',
    relayerKeyId: 'near-key-1',
    participantIds: [1, 2, 3],
    signingRootId: 'project-test:dev',
    signingRootVersion: 'default',
    runtimePolicyScope,
    routerAbNormalSigning,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
    walletSessionJwt: 'wallet-session-jwt',
    expiresAtMs: 1_900_000_000_000,
    remainingUses: 3,
    signerSlot: 1,
    keyVersion: 'threshold-ed25519-hss-v1',
    materialState: 'auth_ready_material_pending',
    updatedAtMs: 1_800_000_000_000,
    source: 'login',
    ...overrides,
  };
}

test.describe('warm Ed25519 signing session authorization', () => {
  test('accepts material-pending passkey unlock authorization', () => {
    const result = parseWarmEd25519SigningSessionAuthorizationFromRecord({
      record: ed25519Record(),
      walletId: WALLET_ID,
      nearAccountId: ACCOUNT_ID,
      nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
      authMethod: 'passkey',
      signingSessionStatus: activeStatus(),
      nowMs: 1_800_000_000_000,
    });

    expect(result).toMatchObject({
      ok: true,
      value: {
        kind: 'warm_ed25519_signing_session_authorized',
        materialState: 'material_pending',
        signingGrantId: 'signing-grant-1',
        signingWorkerId: 'signing-worker-a',
        prfClaim: {
          kind: 'hot_prf_claim',
          availableUses: 3,
        },
      },
    });
  });

  test('accepts ready material records without exposing material fields as unlock authorization', () => {
    const result = parseWarmEd25519SigningSessionAuthorizationFromRecord({
      record: ed25519Record({
        materialState: 'material_ready',
        clientVerifyingShareB64u: 'client-verifier',
        ed25519WorkerMaterialHandle: 'ed25519-material-handle',
        ed25519WorkerMaterialBindingDigest: 'binding-digest',
        sealedWorkerMaterialRef: 'sealed-material-ref',
        sealedWorkerMaterialB64u: 'sealed-material-blob',
        materialFormatVersion: 'ed25519_worker_material_v1',
        materialKeyId: 'material-key-id',
        materialCreatedAtMs: 1_800_000_000_000,
      }),
      walletId: WALLET_ID,
      nearAccountId: ACCOUNT_ID,
      nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
      authMethod: 'passkey',
      signingSessionStatus: activeStatus(),
      nowMs: 1_800_000_000_000,
    });

    expect(result).toMatchObject({
      ok: true,
      value: {
        materialState: 'material_ready',
      },
    });
    expect(result.ok && 'ed25519WorkerMaterialHandle' in result.value).toBe(false);
    expect(result.ok && 'clientVerifyingShareB64u' in result.value).toBe(false);
    expect(result.ok && 'xClientBaseB64u' in result.value).toBe(false);
  });

  test('rejects missing Wallet Session JWT before unlock succeeds', () => {
    const result = parseWarmEd25519SigningSessionAuthorizationFromRecord({
      record: ed25519Record({ walletSessionJwt: undefined }),
      walletId: WALLET_ID,
      nearAccountId: ACCOUNT_ID,
      nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
      authMethod: 'passkey',
      signingSessionStatus: activeStatus(),
      nowMs: 1_800_000_000_000,
    });

    expect(result).toMatchObject({
      ok: false,
      reason: 'missing_wallet_session_jwt',
    });
  });

  test('rejects exhausted server budget availability', () => {
    const result = parseWarmEd25519SigningSessionAuthorizationFromRecord({
      record: ed25519Record(),
      walletId: WALLET_ID,
      nearAccountId: ACCOUNT_ID,
      nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
      authMethod: 'passkey',
      signingSessionStatus: activeStatus({ availableUses: 0 }),
      nowMs: 1_800_000_000_000,
    });

    expect(result).toMatchObject({
      ok: false,
      reason: 'prf_claim_exhausted',
    });
  });

  test('rejects expired persisted authorization budget', () => {
    const result = parseWarmEd25519SigningSessionAuthorizationFromRecord({
      record: ed25519Record({ expiresAtMs: 1 }),
      walletId: WALLET_ID,
      nearAccountId: ACCOUNT_ID,
      nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
      authMethod: 'passkey',
      signingSessionStatus: activeStatus(),
      nowMs: 1_800_000_000_000,
    });

    expect(result).toMatchObject({
      ok: false,
      reason: 'expired',
    });
  });

  test('rejects fractional persisted authorization budget fields', () => {
    const remainingUsesResult = parseWarmEd25519SigningSessionAuthorizationFromRecord({
      record: ed25519Record({ remainingUses: 2.5 }),
      walletId: WALLET_ID,
      nearAccountId: ACCOUNT_ID,
      nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
      authMethod: 'passkey',
      signingSessionStatus: activeStatus(),
      nowMs: 1_800_000_000_000,
    });
    expect(remainingUsesResult).toMatchObject({
      ok: false,
      reason: 'invalid_budget',
    });

    const expiresAtResult = parseWarmEd25519SigningSessionAuthorizationFromRecord({
      record: ed25519Record({ expiresAtMs: 1_900_000_000_000.5 }),
      walletId: WALLET_ID,
      nearAccountId: ACCOUNT_ID,
      nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
      authMethod: 'passkey',
      signingSessionStatus: activeStatus(),
      nowMs: 1_800_000_000_000,
    });
    expect(expiresAtResult).toMatchObject({
      ok: false,
      reason: 'invalid_budget',
    });
  });

  test('rejects fractional live server budget status fields', () => {
    const remainingUsesResult = parseWarmEd25519SigningSessionAuthorizationFromRecord({
      record: ed25519Record(),
      walletId: WALLET_ID,
      nearAccountId: ACCOUNT_ID,
      nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
      authMethod: 'passkey',
      signingSessionStatus: activeStatus({ remainingUses: 2.5 }),
      nowMs: 1_800_000_000_000,
    });
    expect(remainingUsesResult).toMatchObject({
      ok: false,
      reason: 'prf_claim_exhausted',
    });

    const availableUsesResult = parseWarmEd25519SigningSessionAuthorizationFromRecord({
      record: ed25519Record(),
      walletId: WALLET_ID,
      nearAccountId: ACCOUNT_ID,
      nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
      authMethod: 'passkey',
      signingSessionStatus: activeStatus({ availableUses: 2.5 }),
      nowMs: 1_800_000_000_000,
    });
    expect(availableUsesResult).toMatchObject({
      ok: false,
      reason: 'prf_claim_exhausted',
    });

    const expiresAtResult = parseWarmEd25519SigningSessionAuthorizationFromRecord({
      record: ed25519Record(),
      walletId: WALLET_ID,
      nearAccountId: ACCOUNT_ID,
      nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
      authMethod: 'passkey',
      signingSessionStatus: activeStatus({ expiresAtMs: 1_900_000_000_000.5 }),
      nowMs: 1_800_000_000_000,
    });
    expect(expiresAtResult).toMatchObject({
      ok: false,
      reason: 'prf_claim_not_active',
    });
  });

  test('rejects auth-method mismatches', () => {
    const result = parseWarmEd25519SigningSessionAuthorizationFromRecord({
      record: ed25519Record({ source: 'email_otp' }),
      walletId: WALLET_ID,
      nearAccountId: ACCOUNT_ID,
      nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
      authMethod: 'passkey',
      signingSessionStatus: activeStatus(),
      nowMs: 1_800_000_000_000,
    });

    expect(result).toMatchObject({
      ok: false,
      reason: 'auth_method_mismatch',
    });
  });
});

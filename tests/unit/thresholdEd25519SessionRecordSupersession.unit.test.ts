import { expect, test } from '@playwright/test';
import {
  buildOperationUsableThresholdEd25519SessionRecord,
  buildThresholdEd25519SessionFact,
  clearAllStoredThresholdEd25519SessionRecords,
  commitCurrentThresholdEd25519Session,
  getStoredThresholdEd25519SessionRecordForWallet,
  listStoredThresholdEd25519SessionLaneRecordsForWallet,
  upsertThresholdEd25519SessionFact,
  type OperationUsableThresholdEd25519SessionRecord,
  type ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '@/core/signingEngine/session/identity/laneIdentity';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';

const WALLET_ID = 'wallet-ed25519-supersession';
const NEAR_ACCOUNT_ID = 'alice.testnet';
const NEAR_ED25519_SIGNING_KEY_ID = 'scope-ed25519-supersession';

function makeEd25519Fact(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  expiresAtMs: number;
  remainingUses?: number;
}): ThresholdEd25519SessionRecord {
  const record = buildThresholdEd25519SessionFact({
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: NEAR_ED25519_SIGNING_KEY_ID,
    rpId: 'wallet.example.test',
    relayerUrl: 'https://relay.example',
    relayerKeyId: 'rk-ed25519',
    participantIds: [1, 2],
    signerSlot: 1,
    routerAbNormalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: 'signing-worker-ed25519',
    },
    thresholdSessionKind: 'jwt',
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    walletSessionJwt: `jwt-${args.thresholdSessionId}`,
    expiresAtMs: args.expiresAtMs,
    remainingUses: args.remainingUses ?? 3,
    emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
      policy: 'session',
      walletId: WALLET_ID,
      emailHashHex: '11'.repeat(32),
      retention: 'session',
      reason: 'login',
      provider: 'email',
      providerUserId: WALLET_ID,
    }),
    updatedAtMs: args.expiresAtMs,
    source: 'email_otp',
  });
  if (!record) throw new Error('expected Ed25519 record fixture');
  return record;
}

function requireCurrentEd25519(
  record: ThresholdEd25519SessionRecord,
): OperationUsableThresholdEd25519SessionRecord {
  const current = buildOperationUsableThresholdEd25519SessionRecord(record);
  if (!current) throw new Error('expected operation-usable Ed25519 record fixture');
  return current;
}

function commitCurrent(record: ThresholdEd25519SessionRecord) {
  return commitCurrentThresholdEd25519Session({
    record: requireCurrentEd25519(record),
    transition: 'step_up',
  });
}

test.describe('Threshold Ed25519 session record supersession', () => {
  test.beforeEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test.afterEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test('restore fact write after newer step-up preserves the newer default session', () => {
    const older = makeEd25519Fact({
      thresholdSessionId: 'tsess-ed25519-generation-n',
      signingGrantId: 'wsess-ed25519-generation-n',
      expiresAtMs: 100,
    });
    const newer = makeEd25519Fact({
      thresholdSessionId: 'tsess-ed25519-generation-n-plus-1',
      signingGrantId: 'wsess-ed25519-generation-n-plus-1',
      expiresAtMs: 200,
    });

    expect(commitCurrent(newer)).toMatchObject({ kind: 'committed_current' });
    upsertThresholdEd25519SessionFact(older);

    expect(getStoredThresholdEd25519SessionRecordForWallet(WALLET_ID)?.thresholdSessionId).toBe(
      'tsess-ed25519-generation-n-plus-1',
    );
    expect(
      listStoredThresholdEd25519SessionLaneRecordsForWallet(WALLET_ID).map(
        (record) => record.thresholdSessionId,
      ),
    ).toEqual(['tsess-ed25519-generation-n-plus-1', 'tsess-ed25519-generation-n']);
  });

  test('current commit retires older same-authority same-key facts', () => {
    const older = makeEd25519Fact({
      thresholdSessionId: 'tsess-ed25519-old',
      signingGrantId: 'wsess-ed25519-old',
      expiresAtMs: 100,
    });
    const newer = makeEd25519Fact({
      thresholdSessionId: 'tsess-ed25519-current',
      signingGrantId: 'wsess-ed25519-current',
      expiresAtMs: 200,
    });

    upsertThresholdEd25519SessionFact(older);
    expect(commitCurrent(newer)).toMatchObject({
      kind: 'committed_current',
      retired: [{ thresholdSessionId: 'tsess-ed25519-old' }],
    });

    expect(
      listStoredThresholdEd25519SessionLaneRecordsForWallet(WALLET_ID).map(
        (record) => record.thresholdSessionId,
      ),
    ).toEqual(['tsess-ed25519-current']);
  });

  test('stale current commit is ignored when a newer generated session exists', () => {
    const stale = makeEd25519Fact({
      thresholdSessionId: 'tsess-ed25519-stale',
      signingGrantId: 'wsess-ed25519-stale',
      expiresAtMs: 100,
    });
    const newer = makeEd25519Fact({
      thresholdSessionId: 'tsess-ed25519-newer',
      signingGrantId: 'wsess-ed25519-newer',
      expiresAtMs: 200,
    });

    expect(commitCurrent(newer)).toMatchObject({ kind: 'committed_current' });
    expect(commitCurrent(stale)).toMatchObject({
      kind: 'stale_commit_ignored',
      current: { thresholdSessionId: 'tsess-ed25519-newer' },
    });

    expect(
      listStoredThresholdEd25519SessionLaneRecordsForWallet(WALLET_ID).map(
        (record) => record.thresholdSessionId,
      ),
    ).toEqual(['tsess-ed25519-newer']);
  });

  test('equal generation with the same session idempotently replaces the current fact', () => {
    const first = makeEd25519Fact({
      thresholdSessionId: 'tsess-ed25519-idempotent',
      signingGrantId: 'wsess-ed25519-idempotent',
      expiresAtMs: 200,
      remainingUses: 3,
    });
    const second = makeEd25519Fact({
      thresholdSessionId: 'tsess-ed25519-idempotent',
      signingGrantId: 'wsess-ed25519-idempotent',
      expiresAtMs: 200,
      remainingUses: 2,
    });

    expect(commitCurrent(first)).toMatchObject({ kind: 'committed_current' });
    expect(commitCurrent(second)).toMatchObject({
      kind: 'committed_current',
      current: { remainingUses: 2 },
      retired: [],
    });

    const [record] = listStoredThresholdEd25519SessionLaneRecordsForWallet(WALLET_ID);

    expect(record?.thresholdSessionId).toBe('tsess-ed25519-idempotent');
    expect(record?.remainingUses).toBe(2);
  });

  test('equal generation with a different session leaves the current store unchanged', () => {
    const first = makeEd25519Fact({
      thresholdSessionId: 'tsess-ed25519-equal-a',
      signingGrantId: 'wsess-ed25519-equal-a',
      expiresAtMs: 200,
    });
    const second = makeEd25519Fact({
      thresholdSessionId: 'tsess-ed25519-equal-b',
      signingGrantId: 'wsess-ed25519-equal-b',
      expiresAtMs: 200,
    });

    expect(commitCurrent(first)).toMatchObject({ kind: 'committed_current' });
    expect(commitCurrent(second)).toMatchObject({
      kind: 'same_generation_distinct_session',
      existing: { thresholdSessionId: 'tsess-ed25519-equal-a' },
    });

    expect(
      listStoredThresholdEd25519SessionLaneRecordsForWallet(WALLET_ID).map(
        (record) => record.thresholdSessionId,
      ),
    ).toEqual(['tsess-ed25519-equal-a']);
  });

  test('current commit retires same-group null-generation legacy facts with diagnostics', () => {
    const legacy = makeEd25519Fact({
      thresholdSessionId: 'tsess-ed25519-null-generation',
      signingGrantId: 'wsess-ed25519-null-generation',
      expiresAtMs: 100,
    });
    const current = makeEd25519Fact({
      thresholdSessionId: 'tsess-ed25519-current-generation',
      signingGrantId: 'wsess-ed25519-current-generation',
      expiresAtMs: 200,
    });

    const storedLegacy = upsertThresholdEd25519SessionFact(legacy);
    storedLegacy.expiresAtMs = 0;
    storedLegacy.updatedAtMs = 0;
    expect(commitCurrent(current)).toMatchObject({
      kind: 'committed_current',
      diagnostics: [
        {
          kind: 'retired_null_generation_legacy_fact',
          thresholdSessionId: 'tsess-ed25519-null-generation',
        },
      ],
    });

    expect(
      listStoredThresholdEd25519SessionLaneRecordsForWallet(WALLET_ID).map(
        (record) => record.thresholdSessionId,
      ),
    ).toEqual(['tsess-ed25519-current-generation']);
  });
});

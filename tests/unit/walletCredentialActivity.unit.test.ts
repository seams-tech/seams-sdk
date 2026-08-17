import { expect, test } from '@playwright/test';
import {
  parseWalletCredentialActivityRecordV1,
  recordWalletCredentialUseV1,
  MAX_WALLET_CREDENTIAL_LABEL_LENGTH,
  type WalletCredentialActivityRecordV1,
} from '../../packages/shared-ts/src/passkey-custody/credentialActivity';

/**
 * The credential list a user reads when managing their devices.
 *
 * Purely descriptive, and a sibling of the custody envelope rather than a
 * field on it: the envelope's AAD covers its own fields, so a mutable label
 * inside would mean renaming a device rewrapped custody.
 */

const WALLET_ID = 'alice.testnet';

function raw(overrides: Record<string, unknown> = {}) {
  return {
    kind: 'wallet_credential_activity_v1',
    walletId: WALLET_ID,
    envelopeId: 'passkey-envelope-1',
    createdAtMs: 1_000,
    updatedAtMs: 1_000,
    useCount: 0,
    ...overrides,
  };
}

test('a fresh credential has no last use and no label', () => {
  /* "Never used since registration" must read differently from "used at
     registration time", so both are absent rather than zeroed. */
  const parsed = parseWalletCredentialActivityRecordV1(raw(), { expectedWalletId: WALLET_ID });

  expect(parsed.ok).toBe(true);
  if (!parsed.ok) return;
  expect(parsed.record.lastUsedAtMs).toBeUndefined();
  expect(parsed.record.label).toBeUndefined();
  expect(parsed.record.useCount).toBe(0);
});

test('a record for another wallet is refused', () => {
  // A row naming another wallet would be a mislabelled device in someone
  // else's credential list.
  const parsed = parseWalletCredentialActivityRecordV1(raw({ walletId: 'mallory.testnet' }), {
    expectedWalletId: WALLET_ID,
  });
  expect(parsed.ok).toBe(false);
  expect(!parsed.ok && parsed.reason).toContain('outside the authenticated wallet');
});

test('a use count and a last-use time must agree', () => {
  /* A count with no last-use, or a last-use with no count, describes a history
     that cannot have happened — and is how a partial write shows up. */
  for (const overrides of [{ useCount: 3 }, { useCount: 0, lastUsedAtMs: 2_000 }]) {
    const parsed = parseWalletCredentialActivityRecordV1(raw(overrides), {
      expectedWalletId: WALLET_ID,
    });
    expect(parsed.ok).toBe(false);
    expect(!parsed.ok && parsed.reason).toContain('disagree');
  }
});

test('a blank label is absence, and an over-long one is refused', () => {
  const blank = parseWalletCredentialActivityRecordV1(raw({ label: '   ' }), {
    expectedWalletId: WALLET_ID,
  });
  expect(blank.ok && blank.record.label).toBeUndefined();

  const long = parseWalletCredentialActivityRecordV1(
    raw({ label: 'x'.repeat(MAX_WALLET_CREDENTIAL_LABEL_LENGTH + 1) }),
    { expectedWalletId: WALLET_ID },
  );
  expect(long.ok).toBe(false);
});

test('recording a use never moves the clock backwards', () => {
  /* An out-of-order or replayed report must not make a credential read as
     having gone unused since a time it was actually used after. */
  const base: WalletCredentialActivityRecordV1 = {
    kind: 'wallet_credential_activity_v1',
    walletId: WALLET_ID,
    envelopeId: 'passkey-envelope-1',
    createdAtMs: 1_000,
    updatedAtMs: 5_000,
    lastUsedAtMs: 5_000,
    useCount: 2,
  };

  const late = recordWalletCredentialUseV1(base, 9_000);
  expect(late.lastUsedAtMs).toBe(9_000);
  expect(late.useCount).toBe(3);

  const stale = recordWalletCredentialUseV1(base, 2_000);
  expect(stale.lastUsedAtMs).toBe(5_000);
  // The use still counts: it happened, it was just reported out of order.
  expect(stale.useCount).toBe(3);
});

test('malformed records are refused rather than partially read', () => {
  for (const bad of [
    null,
    'not-a-record',
    [],
    raw({ kind: 'something_else' }),
    raw({ envelopeId: '  ' }),
    raw({ createdAtMs: 0 }),
    raw({ useCount: -1 }),
    raw({ useCount: 1.5 }),
    raw({ useCount: 1, lastUsedAtMs: 'soon' }),
  ]) {
    expect(parseWalletCredentialActivityRecordV1(bad, { expectedWalletId: WALLET_ID }).ok).toBe(
      false,
    );
  }
});

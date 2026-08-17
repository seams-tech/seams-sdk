import { expect, test } from '@playwright/test';
import {
  buildWalletRecoveryBackupAcknowledgementV1,
  parseWalletRecoveryBackupAcknowledgementV1,
  walletRecoveryBackupIsOutstanding,
} from '../../packages/shared-ts/src/wallet-recovery/backupAcknowledgement';

/**
 * The record that decides whether to stop asking the user to save their codes.
 *
 * The property worth testing is the one that is easy to get wrong in the
 * convenient direction: an acknowledgement covers *one issuance*. Rotation
 * issues a new set, and treating the old acknowledgement as covering it would
 * leave the user never prompted to save the codes they now depend on — silent,
 * and only discovered when they need to recover.
 */

const WALLET_ID = 'alice.testnet';

test('an unacknowledged wallet is still outstanding', () => {
  expect(walletRecoveryBackupIsOutstanding({ setIssuedAtMs: 1_000, acknowledgement: null })).toBe(
    true,
  );
});

test('acknowledging the current issuance clears the prompt', () => {
  const acknowledgement = buildWalletRecoveryBackupAcknowledgementV1({
    walletId: WALLET_ID,
    issuedAtMs: 1_000,
    acknowledgedAtMs: 2_000,
  });
  expect(walletRecoveryBackupIsOutstanding({ setIssuedAtMs: 1_000, acknowledgement })).toBe(false);
});

test('rotation re-arms the prompt', () => {
  // The user acknowledged the old codes. The new ones are unacknowledged, and
  // they are the ones that now work.
  const acknowledgement = buildWalletRecoveryBackupAcknowledgementV1({
    walletId: WALLET_ID,
    issuedAtMs: 1_000,
    acknowledgedAtMs: 2_000,
  });
  expect(walletRecoveryBackupIsOutstanding({ setIssuedAtMs: 5_000, acknowledgement })).toBe(true);
});

test('a row naming another wallet is refused', () => {
  const record = buildWalletRecoveryBackupAcknowledgementV1({
    walletId: 'someone-else.testnet',
    issuedAtMs: 1_000,
    acknowledgedAtMs: 2_000,
  });
  const parsed = parseWalletRecoveryBackupAcknowledgementV1(record, {
    expectedWalletId: WALLET_ID,
  });
  // Otherwise it silences the prompt for the wrong person.
  expect(parsed.ok).toBe(false);
});

test('acknowledging before issuance is refused', () => {
  const parsed = parseWalletRecoveryBackupAcknowledgementV1(
    {
      kind: 'wallet_recovery_backup_acknowledgement_v1',
      walletId: WALLET_ID,
      issuedAtMs: 5_000,
      acknowledgedAtMs: 1_000,
    },
    { expectedWalletId: WALLET_ID },
  );
  // Describes something that cannot have happened, and is how a stale row
  // from a previous issuance shows up.
  expect(parsed.ok).toBe(false);
});

test('a well-formed row round-trips', () => {
  const record = buildWalletRecoveryBackupAcknowledgementV1({
    walletId: WALLET_ID,
    issuedAtMs: 1_000,
    acknowledgedAtMs: 2_000,
  });
  const parsed = parseWalletRecoveryBackupAcknowledgementV1(record, {
    expectedWalletId: WALLET_ID,
  });
  expect(parsed.ok).toBe(true);
  if (!parsed.ok) return;
  expect(parsed.record).toEqual(record);
});

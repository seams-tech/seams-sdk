import { expect, test } from '@playwright/test';
import {
  deriveWalletRecoveryKeyId,
  isDerivedWalletRecoveryKeyId,
  parseDerivedWalletRecoveryKeyId,
  WALLET_RECOVERY_KEY_ID_PREFIX_V1,
} from '../../packages/shared-ts/src/wallet-recovery/recoveryCodes';
import { deriveWalletRecoveryKeyIdFromBytes } from '../../packages/shared-ts/src/wallet-recovery/recoveryKeyId';
import { parseDerivedEmailOtpRecoveryKeyId } from '../../packages/shared-ts/src/utils/emailOtpRecoveryKey';
import { base64UrlDecode } from '../../packages/shared-ts/src/utils/encoders';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * The identity of one recovery code inside a wallet's custody set.
 *
 * This exists because the Email OTP id it replaces is bound to an enrollment —
 * a passkey wallet has none, so that derivation could not mint an id for a
 * wallet custody set at all. These own the two properties that follow: the id
 * is wallet-scoped, and it is factor-neutral in both its binding and its
 * spelling.
 */

const WALLET_ID = 'alice.testnet';
const OTHER_WALLET_ID = 'mallory.testnet';
// Crockford Base32, 32 characters, not decimal-only.
const CODE = 'ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345-6789';
const OTHER_CODE = 'ZYXW-VTSR-QPNM-KJHG-FEDC-BA98-7654-3210';

test('an id is deterministic and carries the factor-neutral prefix', async () => {
  const id = await deriveWalletRecoveryKeyId({ recoveryCode: CODE, walletId: WALLET_ID });

  expect(id).toBe(await deriveWalletRecoveryKeyId({ recoveryCode: CODE, walletId: WALLET_ID }));
  expect(id.startsWith(WALLET_RECOVERY_KEY_ID_PREFIX_V1)).toBe(true);
  expect(parseDerivedWalletRecoveryKeyId(id)).toBe(id);
});

test('the id names no factor, so an Email OTP parser rejects it', async () => {
  /* The spelling is the point, not decoration. A wallet custody set belongs to
     the wallet, not to whichever factor established it, and an `email-otp-`
     id on a passkey wallet's recovery code is the kind of wrong name that
     misleads for years — the same collision the glossary records for
     "threshold". */
  const id = await deriveWalletRecoveryKeyId({ recoveryCode: CODE, walletId: WALLET_ID });

  expect(id).not.toContain('email-otp');
  expect(() => parseDerivedEmailOtpRecoveryKeyId(id)).toThrow();
});

test('the same code under another wallet is a different id', async () => {
  /* The wallet is in the digest, so a code typed against the wrong wallet
     finds no wrap rather than colliding with one. */
  const mine = await deriveWalletRecoveryKeyId({ recoveryCode: CODE, walletId: WALLET_ID });
  const theirs = await deriveWalletRecoveryKeyId({
    recoveryCode: CODE,
    walletId: OTHER_WALLET_ID,
  });
  expect(mine).not.toBe(theirs);
});

test('distinct codes in one wallet get distinct ids', async () => {
  // A code is found by its id, so a collision would silently reduce a ten-code
  // set to fewer usable codes.
  const first = await deriveWalletRecoveryKeyId({ recoveryCode: CODE, walletId: WALLET_ID });
  const second = await deriveWalletRecoveryKeyId({
    recoveryCode: OTHER_CODE,
    walletId: WALLET_ID,
  });
  expect(first).not.toBe(second);
});

test('formatting is not identity: the same code in any spelling is one id', async () => {
  // The user may type the code with or without its groups. Both are the same
  // secret, so both must reach the same wrap.
  const grouped = await deriveWalletRecoveryKeyId({ recoveryCode: CODE, walletId: WALLET_ID });
  const bare = await deriveWalletRecoveryKeyId({
    recoveryCode: CODE.replace(/-/g, '').toLowerCase(),
    walletId: WALLET_ID,
  });
  expect(bare).toBe(grouped);
});

test('a set version change re-identifies every code', async () => {
  // Rotating the set must not leave old ids resolving against new wraps.
  const v1 = await deriveWalletRecoveryKeyId({ recoveryCode: CODE, walletId: WALLET_ID });
  const v2 = await deriveWalletRecoveryKeyId({
    recoveryCode: CODE,
    walletId: WALLET_ID,
    setVersion: 'wallet_recovery_envelope_set_v2',
  });
  expect(v1).not.toBe(v2);
});

test('a wallet id is required rather than defaulted', async () => {
  await expect(deriveWalletRecoveryKeyId({ recoveryCode: CODE, walletId: '  ' })).rejects.toThrow(
    /walletId/,
  );
});

test('malformed ids are refused', () => {
  for (const bad of [
    undefined,
    null,
    42,
    '',
    'wallet-rkid-v1-',
    // An Email OTP id, which is exactly what must not pass here.
    `email-otp-rkid-v1-${'A'.repeat(43)}`,
    // Right prefix, wrong digest width.
    `${WALLET_RECOVERY_KEY_ID_PREFIX_V1}${'A'.repeat(42)}`,
    `${WALLET_RECOVERY_KEY_ID_PREFIX_V1}${'A'.repeat(44)}`,
    // Base64url excludes these.
    `${WALLET_RECOVERY_KEY_ID_PREFIX_V1}${'+'.repeat(43)}`,
  ]) {
    expect(isDerivedWalletRecoveryKeyId(bad)).toBe(false);
    expect(() => parseDerivedWalletRecoveryKeyId(bad)).toThrow();
  }
});

/**
 * The cross-boundary vector.
 *
 * The ceremony derives a code's id in Rust and seals a wrap under it; a
 * recovery lookup derives the same id here in TypeScript from the code the
 * user typed. If the two encodings drift, every recovery fails to find its
 * wrap — and nothing else in the system would notice, because each side is
 * self-consistent. This is the only test that holds them together.
 */
test('TypeScript derives the same id Rust sealed the wrap under', async () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  const { inputs, establishCommitPayload } = JSON.parse(
    readFileSync(
      path.join(
        repoRoot,
        'wasm',
        'wallet_custody_ceremony',
        'fixtures',
        'wallet-custody-wire-v1.json',
      ),
      'utf8',
    ),
  ) as {
    inputs: {
      walletId?: string;
      recoveryCodes: readonly { codeBytesB64u: string; recoveryKeyId: string }[];
    };
    establishCommitPayload: { walletId: string };
  };
  const walletId = inputs.walletId ?? establishCommitPayload.walletId;
  expect(inputs.recoveryCodes.length).toBe(10);

  for (const code of inputs.recoveryCodes) {
    const codeBytes = base64UrlDecode(code.codeBytesB64u);
    const derived = await deriveWalletRecoveryKeyIdFromBytes({ codeBytes, walletId });
    expect(derived).toBe(code.recoveryKeyId);
  }
});

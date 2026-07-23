import { expect, test } from '@playwright/test';
import {
  EMAIL_OTP_ESCROW_SECRET_LENGTH,
  decodeEmailOtpEscrowSecret32,
  emailOtpCorruptLocalCustodyError,
} from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/secretEscrow';

function sequentialBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    bytes[index] = index + 1;
  }
  return bytes;
}

test('Email OTP escrow preserves an exact 32-byte plaintext', () => {
  const plaintext = sequentialBytes(32);
  const decoded = decodeEmailOtpEscrowSecret32(plaintext);

  expect(decoded.kind).toBe('secret32');
  if (decoded.kind !== 'secret32') return;
  expect([...decoded.secret32]).toEqual([...plaintext]);
  expect(decoded.secret32).not.toBe(plaintext);
});

test('Email OTP escrow restores the fixed width omitted by a fresh enrollment roundtrip', () => {
  const minimalBigEndianPlaintext = sequentialBytes(31);
  const decoded = decodeEmailOtpEscrowSecret32(minimalBigEndianPlaintext);

  expect(decoded.kind).toBe('secret32');
  if (decoded.kind !== 'secret32') return;
  expect(decoded.secret32).toHaveLength(EMAIL_OTP_ESCROW_SECRET_LENGTH);
  expect(decoded.secret32[0]).toBe(0);
  expect([...decoded.secret32.slice(1)]).toEqual([...minimalBigEndianPlaintext]);
});

test('Email OTP escrow reports empty plaintext as typed corrupt local custody', () => {
  const decoded = decodeEmailOtpEscrowSecret32(new Uint8Array());

  expect(decoded).toEqual({
    kind: 'corrupt_local_custody',
    ok: false,
    code: 'corrupt_local_custody',
    reason: 'invalid_escrow_plaintext_length',
    expectedLength: 32,
    actualLength: 0,
    message: 'Email OTP local custody plaintext has invalid length: expected at most 32 bytes, received 0',
  });
});

test('Email OTP escrow reports over-width plaintext as typed corrupt local custody', () => {
  const decoded = decodeEmailOtpEscrowSecret32(new Uint8Array(33));

  expect(decoded.kind).toBe('corrupt_local_custody');
  if (decoded.kind !== 'corrupt_local_custody') return;
  expect(decoded).toMatchObject({
    ok: false,
    code: 'corrupt_local_custody',
    reason: 'invalid_escrow_plaintext_length',
    expectedLength: 32,
    actualLength: 33,
  });
  expect(emailOtpCorruptLocalCustodyError(decoded)).toMatchObject({
    name: 'EmailOtpCorruptLocalCustodyError',
    code: 'corrupt_local_custody',
    reason: 'invalid_escrow_plaintext_length',
    expectedLength: 32,
    actualLength: 33,
  });
});

import { expect, test } from '@playwright/test';
import { sha256HexUtf8 } from '../../packages/shared-ts/src/utils/digests';
import { buildEmailOtpWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';

test('Email OTP email hash uses unprefixed SHA-256 hex', async () => {
  const hash = await sha256HexUtf8('test@example.com');

  expect(hash).toBe('973dfe463ec85785f5f95af5ba3906eedb2d931c24e69824a89ea65dba4e813b');
  expect(hash).not.toMatch(/^0x/);
  expect(hash).toHaveLength(64);
});

test('Email OTP wallet auth authority binding uses the unprefixed hash', async () => {
  const emailHashHex = await sha256HexUtf8('test@example.com');
  const authority = buildEmailOtpWalletAuthAuthority({
    walletId: 'wallet_hash_test',
    provider: 'google',
    providerUserId: 'google:117142622123955425762',
    emailHashHex,
  });

  expect(authority.verifier.emailHashHex).toBe(emailHashHex);
  expect(authority.bindingId).toBe(`email_otp:wallet_hash_test:${emailHashHex}`);
});

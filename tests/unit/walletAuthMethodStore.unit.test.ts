import { expect, test } from '@playwright/test';
import { normalizeWalletAuthMethod } from '@server/core/WalletAuthMethodStore';

test.describe('wallet auth-method binding normalization', () => {
  test('accepts passkey and Email OTP binding branches', () => {
    expect(
      normalizeWalletAuthMethod({
        version: 'wallet_auth_method_v1',
        kind: 'passkey',
        status: 'active',
        walletId: 'wallet_alice',
        rpId: 'wallet.example.test',
        credentialIdB64u: 'credential',
        credentialPublicKeyB64u: 'public-key',
        counter: 0,
        createdAtMs: 1,
        updatedAtMs: 2,
      }),
    ).toMatchObject({
      kind: 'passkey',
      credentialIdB64u: 'credential',
    });

    expect(
      normalizeWalletAuthMethod({
        version: 'wallet_auth_method_v1',
        kind: 'email_otp',
        status: 'active',
        walletId: 'wallet_alice',
        rpId: 'wallet.example.test',
        emailHashHex: 'abc123',
        challengeId: 'challenge',
        createdAtMs: 1,
        updatedAtMs: 2,
      }),
    ).toMatchObject({
      kind: 'email_otp',
      emailHashHex: 'abc123',
    });
  });

  test('rejects missing Email OTP challenge ids', () => {
    expect(
      normalizeWalletAuthMethod({
        version: 'wallet_auth_method_v1',
        kind: 'email_otp',
        status: 'active',
        walletId: 'wallet_alice',
        rpId: 'wallet.example.test',
        emailHashHex: 'abc123',
        createdAtMs: 1,
        updatedAtMs: 2,
      }),
    ).toBeNull();
  });

  test('rejects branch-mixed bindings at the boundary', () => {
    expect(
      normalizeWalletAuthMethod({
        version: 'wallet_auth_method_v1',
        kind: 'passkey',
        status: 'active',
        walletId: 'wallet_alice',
        rpId: 'wallet.example.test',
        emailHashHex: 'abc123',
        createdAtMs: 1,
        updatedAtMs: 2,
      }),
    ).toBeNull();

    expect(
      normalizeWalletAuthMethod({
        version: 'wallet_auth_method_v1',
        kind: 'email_otp',
        status: 'active',
        walletId: 'wallet_alice',
        rpId: 'wallet.example.test',
        credentialIdB64u: 'credential',
        credentialPublicKeyB64u: 'public-key',
        counter: 0,
        createdAtMs: 1,
        updatedAtMs: 2,
      }),
    ).toBeNull();
  });
});

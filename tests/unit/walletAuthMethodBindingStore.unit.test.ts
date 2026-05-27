import { expect, test } from '@playwright/test';
import { normalizeWalletAuthMethodBinding } from '@server/core/WalletAuthMethodBindingStore';

test.describe('wallet auth-method binding normalization', () => {
  test('accepts passkey and Email OTP binding branches', () => {
    expect(
      normalizeWalletAuthMethodBinding({
        version: 'wallet_auth_method_binding_v1',
        kind: 'passkey',
        status: 'active',
        walletSubjectId: 'wallet_alice',
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
      normalizeWalletAuthMethodBinding({
        version: 'wallet_auth_method_binding_v1',
        kind: 'email_otp',
        status: 'active',
        walletSubjectId: 'wallet_alice',
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

  test('rejects branch-mixed bindings at the boundary', () => {
    expect(
      normalizeWalletAuthMethodBinding({
        version: 'wallet_auth_method_binding_v1',
        kind: 'passkey',
        status: 'active',
        walletSubjectId: 'wallet_alice',
        rpId: 'wallet.example.test',
        emailHashHex: 'abc123',
        createdAtMs: 1,
        updatedAtMs: 2,
      }),
    ).toBeNull();

    expect(
      normalizeWalletAuthMethodBinding({
        version: 'wallet_auth_method_binding_v1',
        kind: 'email_otp',
        status: 'active',
        walletSubjectId: 'wallet_alice',
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

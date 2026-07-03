import { expect, test } from '@playwright/test';
import { normalizeWalletAuthMethod, walletAuthMethodId } from '@server/core/d1WalletAuthMethodStore';
import {
  buildEmailOtpWalletAuthMethodBinding,
  buildPasskeyAuthScope,
  buildPasskeyWalletAuthMethodBinding,
  buildWalletIdentity,
  walletAuthMethodBindingId,
} from '@shared/utils/walletCapabilityBindings';

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
        emailHashHex: 'abc123',
        registrationAuthorityId: 'challenge',
        createdAtMs: 1,
        updatedAtMs: 2,
      }),
    ).toMatchObject({
      kind: 'email_otp',
      emailHashHex: 'abc123',
    });
  });

  test('rejects missing Email OTP registration authority ids', () => {
    expect(
      normalizeWalletAuthMethod({
        version: 'wallet_auth_method_v1',
        kind: 'email_otp',
        status: 'active',
        walletId: 'wallet_alice',
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
        emailHashHex: 'abc123',
        registrationAuthorityId: 'challenge',
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
        credentialIdB64u: 'credential',
        credentialPublicKeyB64u: 'public-key',
        counter: 0,
        createdAtMs: 1,
        updatedAtMs: 2,
      }),
    ).toBeNull();
  });

  test('derives durable binding ids from wallet auth-method identity', () => {
    const passkey = normalizeWalletAuthMethod({
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
    });
    const passkeyRefresh = normalizeWalletAuthMethod({
      version: 'wallet_auth_method_v1',
      kind: 'passkey',
      status: 'active',
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
      credentialIdB64u: 'credential',
      credentialPublicKeyB64u: 'rotated-public-key',
      counter: 7,
      createdAtMs: 8,
      updatedAtMs: 9,
    });
    if (!passkey || !passkeyRefresh) throw new Error('passkey fixtures must normalize');

    expect(walletAuthMethodId(passkey)).toBe('passkey:wallet.example.test:credential');
    expect(walletAuthMethodId(passkeyRefresh)).toBe(walletAuthMethodId(passkey));
    expect(
      walletAuthMethodBindingId(
        buildPasskeyWalletAuthMethodBinding({
          scope: buildPasskeyAuthScope({
            wallet: buildWalletIdentity({ walletId: passkey.walletId }),
            rpId: passkey.rpId,
          }),
          credentialIdB64u: passkey.credentialIdB64u,
        }),
      ),
    ).toBe(walletAuthMethodId(passkey));

    const emailOtp = normalizeWalletAuthMethod({
      version: 'wallet_auth_method_v1',
      kind: 'email_otp',
      status: 'active',
      walletId: 'wallet_alice',
      emailHashHex: 'abc123',
      registrationAuthorityId: 'registration-authority-a',
      createdAtMs: 1,
      updatedAtMs: 2,
    });
    const emailOtpRefresh = normalizeWalletAuthMethod({
      version: 'wallet_auth_method_v1',
      kind: 'email_otp',
      status: 'active',
      walletId: 'wallet_alice',
      emailHashHex: 'abc123',
      registrationAuthorityId: 'registration-authority-b',
      createdAtMs: 8,
      updatedAtMs: 9,
    });
    const emailOtpOtherWallet = normalizeWalletAuthMethod({
      version: 'wallet_auth_method_v1',
      kind: 'email_otp',
      status: 'active',
      walletId: 'wallet_bob',
      emailHashHex: 'abc123',
      registrationAuthorityId: 'registration-authority-b',
      createdAtMs: 8,
      updatedAtMs: 9,
    });
    if (!emailOtp || !emailOtpRefresh || !emailOtpOtherWallet) {
      throw new Error('Email OTP fixtures must normalize');
    }

    expect(walletAuthMethodId(emailOtp)).toBe('email_otp:wallet_alice:abc123');
    expect(walletAuthMethodId(emailOtpRefresh)).toBe(walletAuthMethodId(emailOtp));
    expect(walletAuthMethodId(emailOtpOtherWallet)).not.toBe(walletAuthMethodId(emailOtp));
    expect(
      walletAuthMethodBindingId(
        buildEmailOtpWalletAuthMethodBinding({
          wallet: buildWalletIdentity({ walletId: emailOtp.walletId }),
          emailHashHex: emailOtp.emailHashHex,
          registrationAuthorityId: emailOtp.registrationAuthorityId,
        }),
      ),
    ).toBe(walletAuthMethodId(emailOtp));
  });
});

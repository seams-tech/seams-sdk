import { expect, test } from '@playwright/test';
import {
  canonicalWalletAuthorityBindingDigestInput,
  emailOtpFactorProfile,
  emailOtpWalletAuthAuthorityProvider,
  emailOtpWalletAuthAuthorityProviderUserId,
  parseAuthFactorIdentity,
  parseEmailOtpFactorIdentity,
  parseEmailOtpWalletAuthAuthority,
  parsePasskeyFactorIdentity,
  parsePasskeyWalletAuthAuthority,
  parseWalletAuthAuthority,
  validateAuthBoundaryProofPurpose,
  walletAuthAuthoritiesMatch,
  walletAuthAuthorityRef,
  walletAuthorityBindingDigest,
} from '@shared/utils/walletAuthAuthority';

function emailOtpAuthorityRaw(args?: {
  walletId?: string;
  provider?: string;
  providerUserId?: string;
  emailHashHex?: string;
}) {
  const walletId = args?.walletId || 'alice.testnet';
  const provider = args?.provider || 'google';
  const providerUserId = args?.providerUserId || `${provider}:alice`;
  const emailHashHex = args?.emailHashHex || 'email-hash';
  return {
    walletId,
    factor: {
      kind: 'email_otp',
      provider,
      providerUserId,
    },
    verifier: {
      kind: 'email_otp_wallet_auth_method',
      emailHashHex,
    },
    bindingId: `email_otp:${walletId}:${emailHashHex}`,
  };
}

test.describe('shared wallet auth authority boundary parser', () => {
  test('accepts only canonical Email OTP provider names', () => {
    for (const provider of ['google', 'email']) {
      const raw = emailOtpAuthorityRaw({
        provider,
        providerUserId: `${provider}:alice`,
      });
      expect(parseEmailOtpWalletAuthAuthority(raw)).toEqual(raw);
    }
  });

  test('rejects deleted legacy Google Email OTP provider names', () => {
    for (const provider of ['google_oidc', 'google_sso_email_otp']) {
      expect(
        parseEmailOtpWalletAuthAuthority(
          emailOtpAuthorityRaw({
            provider,
            providerUserId: 'google:alice',
          }),
        ),
      ).toBeNull();
    }
  });

  test('rejects mixed passkey and Email OTP authority branches', () => {
    expect(
      parseWalletAuthAuthority({
        walletId: 'alice.testnet',
        factor: {
          kind: 'passkey',
          credentialIdB64u: 'credential-id',
        },
        verifier: {
          kind: 'webauthn',
          rpId: 'wallet.example.test',
        },
        providerUserId: 'google:alice',
      }),
    ).toBeNull();

    expect(
      parseWalletAuthAuthority({
        kind: 'email_otp',
        provider: 'google',
        providerUserId: 'google:alice',
        rpId: 'wallet.example.test',
      }),
    ).toBeNull();
  });

  test('parses branch-specific authorities without accepting the opposite branch', () => {
    const passkey = {
      walletId: 'alice.testnet',
      factor: {
        kind: 'passkey',
        credentialIdB64u: 'credential-id',
      },
      verifier: {
        kind: 'webauthn',
        rpId: 'wallet.example.test',
      },
      bindingId: 'passkey:wallet.example.test:credential-id',
    };
    const emailOtp = {
      walletId: 'alice.testnet',
      factor: {
        kind: 'email_otp',
        provider: 'email',
        providerUserId: 'email:alice@example.test',
      },
      verifier: {
        kind: 'email_otp_wallet_auth_method',
        emailHashHex: 'email-hash',
      },
      bindingId: 'email_otp:alice.testnet:email-hash',
    };

    expect(parsePasskeyWalletAuthAuthority(passkey)).toEqual(passkey);
    expect(
      parsePasskeyWalletAuthAuthority({
        kind: 'passkey',
        rpId: 'wallet.example.test',
        credentialIdB64u: 'credential-id',
      }),
    ).toBeNull();
    expect(
      parsePasskeyWalletAuthAuthority({
        walletId: 'alice.testnet',
        factor: {
          kind: 'passkey',
          credentialIdB64u: 'credential-id',
        },
        verifier: {
          kind: 'webauthn',
          rpId: 'wallet.example.test',
        },
      }),
    ).toBeNull();
    expect(
      parsePasskeyWalletAuthAuthority({
        walletId: 'alice.testnet',
        factor: {
          kind: 'passkey',
          credentialIdB64u: 'credential-id',
        },
        verifier: {
          kind: 'webauthn',
          rpId: 'wallet.example.test',
        },
        bindingId: 'passkey:wallet.example.test:other-credential',
      }),
    ).toBeNull();
    expect(parseEmailOtpWalletAuthAuthority(passkey)).toBeNull();
    expect(parseEmailOtpWalletAuthAuthority(emailOtp)).toEqual(emailOtp);
    expect(parsePasskeyWalletAuthAuthority(emailOtp)).toBeNull();
    expect(emailOtpWalletAuthAuthorityProvider(emailOtp)).toBe('email');
    expect(emailOtpWalletAuthAuthorityProviderUserId(emailOtp)).toBe('email:alice@example.test');
  });

  test('compares wallet auth authorities by bound wallet, factor, and verifier', () => {
    const emailOtp = parseEmailOtpWalletAuthAuthority(emailOtpAuthorityRaw());
    const sameEmailOtp = parseEmailOtpWalletAuthAuthority(emailOtpAuthorityRaw());
    const differentEmailVerifier = parseEmailOtpWalletAuthAuthority(
      emailOtpAuthorityRaw({ emailHashHex: 'other-email-hash' }),
    );
    const differentWallet = parseEmailOtpWalletAuthAuthority(
      emailOtpAuthorityRaw({
        walletId: 'bob.testnet',
        providerUserId: 'google:alice',
      }),
    );
    const passkey = parsePasskeyWalletAuthAuthority({
      walletId: 'alice.testnet',
      factor: {
        kind: 'passkey',
        credentialIdB64u: 'credential-id',
      },
      verifier: {
        kind: 'webauthn',
        rpId: 'wallet.example.test',
      },
      bindingId: 'passkey:wallet.example.test:credential-id',
    });
    const differentPasskeyVerifier = parsePasskeyWalletAuthAuthority({
      walletId: 'alice.testnet',
      factor: {
        kind: 'passkey',
        credentialIdB64u: 'credential-id',
      },
      verifier: {
        kind: 'webauthn',
        rpId: 'other.example.test',
      },
      bindingId: 'passkey:other.example.test:credential-id',
    });
    if (
      !emailOtp ||
      !sameEmailOtp ||
      !differentEmailVerifier ||
      !differentWallet ||
      !passkey ||
      !differentPasskeyVerifier
    ) {
      throw new Error('authority fixtures must parse');
    }

    expect(walletAuthAuthoritiesMatch(emailOtp, sameEmailOtp)).toBe(true);
    expect(walletAuthAuthoritiesMatch(emailOtp, differentEmailVerifier)).toBe(false);
    expect(walletAuthAuthoritiesMatch(emailOtp, differentWallet)).toBe(false);
    expect(walletAuthAuthoritiesMatch(emailOtp, passkey)).toBe(false);
    expect(walletAuthAuthoritiesMatch(passkey, differentPasskeyVerifier)).toBe(false);
  });

  test('parses pure factor identities without verifier or wallet authority fields', () => {
    const passkeyFactor = {
      kind: 'passkey',
      credentialIdB64u: 'credential-id',
    };
    const emailOtpFactor = {
      kind: 'email_otp',
      provider: 'google',
      providerUserId: 'google:alice',
    };

    expect(parseAuthFactorIdentity(passkeyFactor)).toEqual(passkeyFactor);
    expect(parsePasskeyFactorIdentity(passkeyFactor)).toEqual(passkeyFactor);
    expect(parseEmailOtpFactorIdentity(passkeyFactor)).toBeNull();
    expect(parseAuthFactorIdentity({ ...passkeyFactor, rpId: 'wallet.example.test' })).toBeNull();
    expect(
      parseAuthFactorIdentity({
        ...passkeyFactor,
        walletId: 'alice.testnet',
        verifier: { kind: 'webauthn', rpId: 'wallet.example.test' },
        bindingId: 'passkey:wallet.example.test:credential-id',
      }),
    ).toBeNull();
    expect(parseAuthFactorIdentity(emailOtpFactor)).toEqual(emailOtpFactor);
    expect(parseEmailOtpFactorIdentity(emailOtpFactor)).toEqual(emailOtpFactor);
    expect(parsePasskeyFactorIdentity(emailOtpFactor)).toBeNull();
    expect(
      parseAuthFactorIdentity({ ...emailOtpFactor, credentialIdB64u: 'credential-id' }),
    ).toBeNull();
    expect(
      parseAuthFactorIdentity({
        ...emailOtpFactor,
        walletId: 'alice.testnet',
        verifier: { kind: 'email_otp_enrollment', enrollmentId: 'email_otp:alice.testnet:hash' },
        bindingId: 'email_otp:alice.testnet:hash',
      }),
    ).toBeNull();
  });

  test('builds Email OTP factor profiles without self-labeling kind or wallet authority', () => {
    const factor = parseEmailOtpFactorIdentity({
      kind: 'email_otp',
      provider: 'email',
      providerUserId: 'email:alice@example.test',
    });
    if (!factor) throw new Error('factor fixture must parse');

    expect(
      emailOtpFactorProfile({
        factor,
        email: 'alice@example.test',
      }),
    ).toEqual({
      factor,
      email: 'alice@example.test',
    });
  });

  test('binds authority digests to wallet identity and canonical authority shape', async () => {
    const emailAuthority = parseEmailOtpWalletAuthAuthority(emailOtpAuthorityRaw());
    const bobEmailAuthority = parseEmailOtpWalletAuthAuthority(
      emailOtpAuthorityRaw({
        walletId: 'bob.testnet',
        providerUserId: 'google:alice',
      }),
    );
    const passkeyAuthority = parsePasskeyWalletAuthAuthority({
      walletId: 'alice.testnet',
      factor: {
        kind: 'passkey',
        credentialIdB64u: 'credential-id',
      },
      verifier: {
        kind: 'webauthn',
        rpId: 'wallet.example.test',
      },
      bindingId: 'passkey:wallet.example.test:credential-id',
    });
    if (!emailAuthority || !bobEmailAuthority || !passkeyAuthority) {
      throw new Error('authority fixtures must parse');
    }

    expect(
      canonicalWalletAuthorityBindingDigestInput({
        authority: emailAuthority,
      }),
    ).toBe(
      'seams:wallet-authority-binding:v1|{"bindingId":"email_otp:alice.testnet:email-hash","factor":{"kind":"email_otp","provider":"google","providerUserId":"google:alice"},"verifier":{"emailHashHex":"email-hash","kind":"email_otp_wallet_auth_method"},"walletId":"alice.testnet"}',
    );

    await expect(
      walletAuthorityBindingDigest({
        authority: emailAuthority,
      }),
    ).resolves.not.toEqual(
      await walletAuthorityBindingDigest({
        authority: bobEmailAuthority,
      }),
    );

    await expect(
      walletAuthorityBindingDigest({
        authority: emailAuthority,
      }),
    ).resolves.not.toEqual(
      await walletAuthorityBindingDigest({
        authority: passkeyAuthority,
      }),
    );

    await expect(
      walletAuthAuthorityRef({
        authority: passkeyAuthority,
      }),
    ).resolves.toMatchObject({
      kind: 'wallet_auth_authority_ref',
      walletId: 'alice.testnet',
    });
  });

  test('validates boundary proof purpose shape once at the boundary', () => {
    const emailOtpChallenge = {
      kind: 'email_otp_challenge' as const,
      challengeId: 'challenge-1',
      otpCode: '123456',
      appSessionJwt: 'app-session.jwt',
    };
    const passkeyAssertion = {
      kind: 'passkey_assertion' as const,
      assertion: {},
    };

    expect(
      validateAuthBoundaryProofPurpose({
        purpose: 'unlock',
        proof: emailOtpChallenge,
      }),
    ).toMatchObject({ ok: true });
    expect(
      validateAuthBoundaryProofPurpose({
        purpose: 'key_export',
        proof: passkeyAssertion,
      }),
    ).toMatchObject({ ok: true });
    expect(
      validateAuthBoundaryProofPurpose({
        purpose: 'registration',
        proof: passkeyAssertion,
      }),
    ).toMatchObject({
      ok: false,
      reason: 'registration_requires_registration_proof',
    });
    expect(
      validateAuthBoundaryProofPurpose({
        purpose: 'recovery',
        proof: passkeyAssertion,
      }),
    ).toMatchObject({
      ok: false,
      reason: 'recovery_requires_email_otp_challenge',
    });
    expect(
      validateAuthBoundaryProofPurpose({
        purpose: 'step_up',
        proof: {
          kind: 'google_sso_registration',
          registrationAttemptId: 'attempt',
          registrationOfferId: 'offer',
          registrationCandidateId: 'candidate',
          appSessionJwt: 'app-session.jwt',
        },
      }),
    ).toMatchObject({
      ok: false,
      reason: 'interactive_operation_requires_assertion_or_email_otp_challenge',
    });
  });
});

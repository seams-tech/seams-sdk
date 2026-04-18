import { expect, test } from '@playwright/test';
import { accountAuthFixtures, type AccountAuthFixture } from './helpers/accountAuth.fixtures';

function expectLinkedMethod(fixture: AccountAuthFixture, method: 'passkey' | 'email_otp'): void {
  expect(fixture.metadata.linkedAuthMethods).toContain(method);
}

test.describe('account auth fixtures', () => {
  test('defines canonical passkey-only auth metadata', () => {
    const fixture = accountAuthFixtures.passkeyOnly;

    expect(fixture.kind).toBe('passkey_only');
    expect(fixture.metadata.primaryAuthMethod).toBe('passkey');
    expectLinkedMethod(fixture, 'passkey');
    expect(fixture.metadata.email).toBeUndefined();
    expect(fixture.signers).toEqual([
      {
        signerKind: 'threshold-ed25519',
        signerAuthMethod: 'passkey',
        signerSource: 'passkey_registration',
      },
    ]);
    expect(fixture.expectedUnlockAuthMethod).toBe('passkey');
    expect(fixture.expectedTransactionAuthMethod).toBe('passkey');
  });

  test('defines canonical Email OTP-only auth metadata', () => {
    const fixture = accountAuthFixtures.emailOtpOnly;

    expect(fixture.kind).toBe('email_otp_only');
    expect(fixture.metadata.primaryAuthMethod).toBe('email_otp');
    expectLinkedMethod(fixture, 'email_otp');
    expect(fixture.metadata.passkeyCredentialIds).toBeUndefined();
    expect(fixture.signers).toEqual([
      {
        signerKind: 'threshold-ed25519',
        signerAuthMethod: 'email_otp',
        signerSource: 'email_otp_registration',
      },
      {
        signerKind: 'threshold-ecdsa',
        signerAuthMethod: 'email_otp',
        signerSource: 'email_otp_registration',
      },
    ]);
    expect(fixture.expectedUnlockAuthMethod).toBe('email_otp');
    expect(fixture.expectedTransactionAuthMethod).toBe('email_otp');
  });

  test('defines canonical mixed passkey and Email OTP auth metadata', () => {
    const fixture = accountAuthFixtures.passkeyAndEmailOtp;

    expect(fixture.kind).toBe('passkey_email_otp');
    expect(fixture.metadata.primaryAuthMethod).toBe('passkey');
    expectLinkedMethod(fixture, 'passkey');
    expectLinkedMethod(fixture, 'email_otp');
    expect(fixture.metadata.email).toBe('passkey-email-otp@example.test');
    expect(fixture.metadata.passkeyCredentialIds).toEqual(['credential-passkey-email-otp']);
    expect(fixture.signers).toEqual([
      {
        signerKind: 'threshold-ed25519',
        signerAuthMethod: 'passkey',
        signerSource: 'passkey_registration',
      },
      {
        signerKind: 'threshold-ed25519',
        signerAuthMethod: 'email_otp',
        signerSource: 'email_otp_registration',
      },
      {
        signerKind: 'threshold-ecdsa',
        signerAuthMethod: 'email_otp',
        signerSource: 'email_otp_registration',
      },
    ]);
    expect(fixture.expectedUnlockAuthMethod).toBe('passkey');
    expect(fixture.expectedTransactionAuthMethod).toBe('passkey');
  });
});

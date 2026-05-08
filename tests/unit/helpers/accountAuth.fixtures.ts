import type { AccountAuthMetadata } from '@/core/signingEngine/walletAuth';
import type { WalletAuthMethod } from '@/core/types/seams';
import type { SignerAuthMethod, SignerKind, SignerSource } from '@shared/utils/signerDomain';

export type AccountAuthFixtureKind = 'passkey_only' | 'email_otp_only' | 'passkey_email_otp';

export type AccountAuthSignerFixture = {
  signerKind: SignerKind;
  signerAuthMethod: SignerAuthMethod;
  signerSource: SignerSource;
};

export type AccountAuthFixture = {
  kind: AccountAuthFixtureKind;
  accountId: string;
  metadata: AccountAuthMetadata;
  signers: AccountAuthSignerFixture[];
  expectedTransactionAuthMethod: WalletAuthMethod;
  expectedUnlockAuthMethod: WalletAuthMethod;
};

export const passkeyOnlyAccountAuthFixture: AccountAuthFixture = {
  kind: 'passkey_only',
  accountId: 'passkey-only.testnet',
  metadata: {
    primaryAuthMethod: 'passkey',
    linkedAuthMethods: ['passkey'],
    passkeyCredentialIds: ['credential-passkey-only'],
  },
  signers: [
    {
      signerKind: 'threshold-ed25519',
      signerAuthMethod: 'passkey',
      signerSource: 'passkey_registration',
    },
  ],
  expectedTransactionAuthMethod: 'passkey',
  expectedUnlockAuthMethod: 'passkey',
};

export const emailOtpOnlyAccountAuthFixture: AccountAuthFixture = {
  kind: 'email_otp_only',
  accountId: 'email-otp-only.testnet',
  metadata: {
    primaryAuthMethod: 'email_otp',
    linkedAuthMethods: ['email_otp'],
    email: 'email-otp-only@example.test',
  },
  signers: [
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
  ],
  expectedTransactionAuthMethod: 'email_otp',
  expectedUnlockAuthMethod: 'email_otp',
};

export const passkeyAndEmailOtpAccountAuthFixture: AccountAuthFixture = {
  kind: 'passkey_email_otp',
  accountId: 'passkey-email-otp.testnet',
  metadata: {
    primaryAuthMethod: 'passkey',
    linkedAuthMethods: ['passkey', 'email_otp'],
    email: 'passkey-email-otp@example.test',
    passkeyCredentialIds: ['credential-passkey-email-otp'],
  },
  signers: [
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
  ],
  expectedTransactionAuthMethod: 'passkey',
  expectedUnlockAuthMethod: 'passkey',
};

export const accountAuthFixtures = {
  passkeyOnly: passkeyOnlyAccountAuthFixture,
  emailOtpOnly: emailOtpOnlyAccountAuthFixture,
  passkeyAndEmailOtp: passkeyAndEmailOtpAccountAuthFixture,
} as const;

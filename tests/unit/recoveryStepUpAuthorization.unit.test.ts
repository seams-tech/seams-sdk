import { expect, test } from '@playwright/test';
import { SigningAuthPlanKind } from '../../packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types';
import { buildExportStepUpAuthorization } from '../../packages/sdk-web/src/core/signingEngine/flows/recovery/stepUpAuthorization';
import type { WebAuthnAuthenticationCredential } from '../../packages/sdk-web/src/core/types/webauthn';

const TEST_WEBAUTHN_CREDENTIAL = {
  id: 'credential-id',
  rawId: 'raw-id',
  type: 'public-key',
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: 'client-data',
    authenticatorData: 'authenticator-data',
    signature: 'signature',
    userHandle: undefined,
  },
  clientExtensionResults: {
    prf: {
      results: {
        first: 'first-prf',
        second: undefined,
      },
    },
  },
} satisfies WebAuthnAuthenticationCredential;

test.describe('recovery step-up authorization', () => {
  test('builds typed Email OTP export authorization with challenge identity', () => {
    const authorization = buildExportStepUpAuthorization({
      method: 'email_otp',
      walletSessionUserId: 'alice.testnet',
      chain: 'evm',
      publicKey: '02'.padEnd(66, '1'),
      curve: 'ecdsa',
      intent: 'ecdsa_export',
      emailOtpPrompt: {
        challengeId: 'challenge-1',
        emailHint: 'a***@x.test',
      },
      decision: {
        confirmed: true,
        otpCode: '123456',
        emailOtpChallengeId: 'challenge-1',
      },
    });

    expect(authorization).toEqual({
      kind: 'email_otp',
      signingAuthPlan: {
        kind: SigningAuthPlanKind.EmailOtpReauth,
        method: 'email_otp',
        emailOtpPrompt: {
          challengeId: 'challenge-1',
          emailHint: 'a***@x.test',
        },
      },
      walletSessionUserId: 'alice.testnet',
      chain: 'evm',
      publicKey: '02'.padEnd(66, '1'),
      curve: 'ecdsa',
      intent: 'ecdsa_export',
      challengeId: 'challenge-1',
      otpCode: '123456',
      emailHint: 'a***@x.test',
    });
  });

  test('builds typed passkey export authorization with normalized credential', () => {
    const authorization = buildExportStepUpAuthorization({
      method: 'passkey',
      walletSessionUserId: 'alice.testnet',
      chain: 'evm',
      publicKey: '02'.padEnd(66, '1'),
      curve: 'ecdsa',
      intent: 'ecdsa_export',
      decision: {
        requestId: 'req-1',
        confirmed: true,
        credential: TEST_WEBAUTHN_CREDENTIAL,
      },
    });

    expect(authorization).toEqual({
      kind: 'passkey',
      signingAuthPlan: {
        kind: SigningAuthPlanKind.PasskeyReauth,
        method: 'passkey',
      },
      walletSessionUserId: 'alice.testnet',
      chain: 'evm',
      publicKey: '02'.padEnd(66, '1'),
      curve: 'ecdsa',
      intent: 'ecdsa_export',
      credential: TEST_WEBAUTHN_CREDENTIAL,
    });
  });

  test('builds Email OTP Ed25519 authorization with every exact signer identity field', () => {
    const authorization = buildExportStepUpAuthorization({
      method: 'email_otp',
      walletSessionUserId: 'wallet-1',
      publicKey: 'ed25519:public-key-1',
      curve: 'ed25519',
      intent: 'ed25519_export',
      chain: 'near',
      nearAccountId: 'alice.testnet',
      nearEd25519SigningKeyId: 'near-ed25519-key-1',
      signerSlot: 3,
      thresholdSessionId: 'threshold-session-1',
      signingGrantId: 'signing-grant-1',
      emailOtpPrompt: { challengeId: 'challenge-ed25519' },
      decision: {
        confirmed: true,
        otpCode: '654321',
        emailOtpChallengeId: 'challenge-ed25519',
      },
    });

    expect(authorization).toEqual({
      kind: 'email_otp',
      signingAuthPlan: {
        kind: SigningAuthPlanKind.EmailOtpReauth,
        method: 'email_otp',
        emailOtpPrompt: { challengeId: 'challenge-ed25519' },
      },
      challengeId: 'challenge-ed25519',
      otpCode: '654321',
      walletSessionUserId: 'wallet-1',
      publicKey: 'ed25519:public-key-1',
      curve: 'ed25519',
      intent: 'ed25519_export',
      chain: 'near',
      nearAccountId: 'alice.testnet',
      nearEd25519SigningKeyId: 'near-ed25519-key-1',
      signerSlot: 3,
      thresholdSessionId: 'threshold-session-1',
      signingGrantId: 'signing-grant-1',
    });
  });
});

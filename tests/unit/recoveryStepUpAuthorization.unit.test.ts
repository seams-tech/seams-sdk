import { expect, test } from '@playwright/test';
import { SigningAuthPlanKind } from '../../client/src/core/signingEngine/stepUpConfirmation/types';
import { buildExportStepUpAuthorization } from '../../client/src/core/signingEngine/flows/recovery/stepUpAuthorization';
import type { WebAuthnAuthenticationCredential } from '../../client/src/core/types/webauthn';

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
      nearAccountId: 'alice.testnet',
      chain: 'near',
      publicKey: 'ed25519:abc',
      curve: 'ed25519',
      intent: 'ed25519_export',
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
      nearAccountId: 'alice.testnet',
      chain: 'near',
      publicKey: 'ed25519:abc',
      curve: 'ed25519',
      intent: 'ed25519_export',
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
});

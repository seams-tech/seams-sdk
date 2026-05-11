import { expect, test } from '@playwright/test';
import { SigningAuthPlanKind } from '../../client/src/core/signingEngine/stepUpConfirmation/types';
import { buildNearEd25519StepUpAuthorization } from '../../client/src/core/signingEngine/flows/signNear/stepUpAuthorization';
import { buildEvmFamilyEcdsaStepUpAuthorization } from '../../client/src/core/signingEngine/flows/signEvmFamily/stepUpAuthorization';
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

test.describe('step-up authorization builders', () => {
  test('buildNearEd25519StepUpAuthorization carries Email OTP challenge identity', () => {
    const authorization = buildNearEd25519StepUpAuthorization({
      prepared: {
        kind: 'email_otp',
        confirmationAuthPayload: {
          signingAuthPlan: {
            kind: SigningAuthPlanKind.EmailOtpReauth,
            method: 'email_otp',
            emailOtpPrompt: {
              challengeId: 'otp-1',
              emailHint: 'a***@x.test',
            },
          },
        },
        emailOtpPrompt: {
          challengeId: 'otp-1',
          emailHint: 'a***@x.test',
        },
      },
      confirmation: {
        sessionId: 'near-session',
        transactionContext: {} as never,
        intentDigest: 'digest',
        otpCode: '123456',
      },
    });

    expect(authorization).toEqual({
      kind: 'email_otp',
      signingAuthPlan: {
        kind: SigningAuthPlanKind.EmailOtpReauth,
        method: 'email_otp',
        emailOtpPrompt: {
          challengeId: 'otp-1',
          emailHint: 'a***@x.test',
        },
      },
      challengeId: 'otp-1',
      otpCode: '123456',
      emailHint: 'a***@x.test',
    });
  });

  test('buildEvmFamilyEcdsaStepUpAuthorization normalizes passkey credentials', () => {
    const authorization = buildEvmFamilyEcdsaStepUpAuthorization({
      prepared: {
        kind: 'passkey',
        confirmationAuthPayload: {
          signingAuthPlan: {
            kind: SigningAuthPlanKind.PasskeyReauth,
            method: 'passkey',
          },
        },
        plannedPasskeyReconnect: {
          sessionId: 'threshold-session-passkey',
          walletSigningSessionId: 'wallet-session-passkey',
          sessionPolicyDigest32: 'digest-32',
        },
      },
      confirmation: {
        sessionId: 'evm-session',
        intentDigest: 'digest',
        credential: TEST_WEBAUTHN_CREDENTIAL,
      },
    });

    expect(authorization).toEqual({
      kind: 'passkey',
      signingAuthPlan: {
        kind: SigningAuthPlanKind.PasskeyReauth,
        method: 'passkey',
      },
      credential: TEST_WEBAUTHN_CREDENTIAL,
      plannedPasskeyReconnect: {
        sessionId: 'threshold-session-passkey',
        walletSigningSessionId: 'wallet-session-passkey',
        sessionPolicyDigest32: 'digest-32',
      },
    });
  });
});

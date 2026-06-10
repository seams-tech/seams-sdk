import { expect, test } from '@playwright/test';
import { SigningAuthPlanKind } from '../../packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types';
import { confirmSigningOperation } from '../../packages/sdk-web/src/core/signingEngine/stepUpConfirmation/confirmOperation';
import { buildNearEd25519StepUpAuthorization } from '../../packages/sdk-web/src/core/signingEngine/flows/signNear/stepUpAuthorization';
import { buildEvmFamilyEcdsaStepUpAuthorization } from '../../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/stepUpAuthorization';
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

  test('confirmSigningOperation rejects Email OTP prompt on passkey auth plan', async () => {
    await expect(
      confirmSigningOperation({
        runtime: {
          orchestrateSigningConfirmation: async () => {
            throw new Error('orchestrate should not run');
          },
        },
        request: {
          chain: 'near',
          kind: 'transaction',
          sessionId: 'session-1',
          ctx: { touchConfirm: { requestUserConfirmation: async () => ({ confirmed: true }) } },
          signingAuthPlan: {
            kind: SigningAuthPlanKind.PasskeyReauth,
            method: 'passkey',
          },
          emailOtpPrompt: {
            challengeId: 'otp-should-not-be-here',
          },
          txSigningRequests: [],
          rpcCall: {},
        },
      } as never),
    ).rejects.toThrow('auth_method_route_mismatch');
  });

  test('confirmSigningOperation rejects WebAuthn challenge on Email OTP auth plan', async () => {
    await expect(
      confirmSigningOperation({
        runtime: {
          orchestrateSigningConfirmation: async () => {
            throw new Error('orchestrate should not run');
          },
        },
        request: {
          chain: 'near',
          kind: 'transaction',
          sessionId: 'session-1',
          ctx: { touchConfirm: { requestUserConfirmation: async () => ({ confirmed: true }) } },
          signingAuthPlan: {
            kind: SigningAuthPlanKind.EmailOtpReauth,
            method: 'email_otp',
            emailOtpPrompt: {
              challengeId: 'otp-1',
            },
          },
          webauthnChallenge: {
            kind: 'intent_digest',
            challengeB64u: 'passkey-should-not-be-here',
          },
          txSigningRequests: [],
          rpcCall: {},
        },
      } as never),
    ).rejects.toThrow('auth_method_route_mismatch');
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
          webauthnChallenge: {
            kind: 'ecdsa_role_local_bootstrap',
            digest32B64u: 'digest-32',
            requestId: 'request-1',
            thresholdSessionId: 'threshold-session-passkey',
            walletSigningSessionId: 'wallet-session-passkey',
          },
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
        webauthnChallenge: {
          kind: 'ecdsa_role_local_bootstrap',
          digest32B64u: 'digest-32',
          requestId: 'request-1',
          thresholdSessionId: 'threshold-session-passkey',
          walletSigningSessionId: 'wallet-session-passkey',
        },
      },
    });
  });
});

import { expect, test } from '@playwright/test';
import { validateUserConfirmRequest } from '@/core/signingEngine/uiConfirm/handlers/flows/adapters/request';
import { UserConfirmationType } from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';

function signIntentDigestRequest(payloadOverrides: Record<string, unknown>) {
  return {
    requestId: 'request-signing-auth-plan-validation',
    type: UserConfirmationType.SIGN_INTENT_DIGEST,
    summary: {},
    payload: {
      nearAccountId: 'alice.testnet',
      challengeB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      displayModel: {
        chain: 'tempo',
        signerAccount: 'alice.testnet',
        operations: [],
      },
      ...payloadOverrides,
    },
  };
}

test.describe('touchConfirm signing auth plan validation', () => {
  test('rejects signing requests without signingAuthPlan', () => {
    expect(() => validateUserConfirmRequest(signIntentDigestRequest({}))).toThrow(
      'missing or invalid signingAuthPlan',
    );
  });

  test('rejects direct signingAuthMode payload input', () => {
    expect(() =>
      validateUserConfirmRequest(
        signIntentDigestRequest({
          signingAuthMode: 'webauthn',
          signingAuthPlan: {
            kind: 'passkeyReauth',
            method: 'passkey',
          },
        }),
      ),
    ).toThrow('signingAuthMode is not accepted');
  });

  test('accepts canonical signingAuthPlan payload input', () => {
    const request = validateUserConfirmRequest(
      signIntentDigestRequest({
        signingAuthPlan: {
          kind: 'passkeyReauth',
          method: 'passkey',
        },
        webauthnChallenge: {
          kind: 'ecdsa_role_local_bootstrap',
          digest32B64u: 'challenge-digest',
          requestId: 'request-1',
          thresholdSessionId: 'threshold-session-1',
          walletSigningSessionId: 'wallet-session-1',
        },
      }),
    );

    expect(request.type).toBe(UserConfirmationType.SIGN_INTENT_DIGEST);
  });

  test('rejects passkey intent signing without typed WebAuthn challenge', () => {
    expect(() =>
      validateUserConfirmRequest(
        signIntentDigestRequest({
          signingAuthPlan: {
            kind: 'passkeyReauth',
            method: 'passkey',
          },
        }),
      ),
    ).toThrow('passkey intent signing requires webauthnChallenge');
  });

  test('rejects legacy sessionPolicyDigest32 challenge input', () => {
    expect(() =>
      validateUserConfirmRequest(
        signIntentDigestRequest({
          signingAuthPlan: {
            kind: 'passkeyReauth',
            method: 'passkey',
          },
          sessionPolicyDigest32: 'legacy-digest',
        }),
      ),
    ).toThrow('sessionPolicyDigest32 is not accepted');
  });
});

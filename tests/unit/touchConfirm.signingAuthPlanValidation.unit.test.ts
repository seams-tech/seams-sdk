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
      }),
    );

    expect(request.type).toBe(UserConfirmationType.SIGN_INTENT_DIGEST);
  });
});

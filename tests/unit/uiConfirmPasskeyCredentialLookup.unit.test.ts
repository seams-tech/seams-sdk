import { expect, test } from '@playwright/test';
import { SigningAuthPlanKind } from '@/core/signingEngine/stepUpConfirmation/types';
import { assertPasskeyCredentialLookupAllowed } from '@/core/signingEngine/uiConfirm/handlers/flows/signing';

const baseArgs = {
  nearAccountId: 'wallet.testnet',
  requestId: 'request-1',
} as const;

test.describe('uiConfirm passkey credential lookup routing', () => {
  test('rejects Email OTP auth plans before passkey credential lookup', () => {
    const originalWarn = console.warn;
    console.warn = () => {};
    try {
      for (const stage of ['transaction_prompt', 'intent_digest_prompt'] as const) {
        expect(() =>
          assertPasskeyCredentialLookupAllowed({
            ...baseArgs,
            stage,
            signingAuthPlanKind: SigningAuthPlanKind.EmailOtpReauth,
          }),
        ).toThrow('[SigningEngine] passkey_lookup_for_email_otp');
      }
    } finally {
      console.warn = originalWarn;
    }
  });

  test('allows passkey auth plans to continue to credential lookup', () => {
    for (const stage of ['transaction_prompt', 'intent_digest_prompt'] as const) {
      expect(() =>
        assertPasskeyCredentialLookupAllowed({
          ...baseArgs,
          stage,
          signingAuthPlanKind: SigningAuthPlanKind.PasskeyReauth,
        }),
      ).not.toThrow();
    }
  });
});

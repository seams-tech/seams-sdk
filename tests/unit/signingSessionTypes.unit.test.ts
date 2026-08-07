import { expect, test } from '@playwright/test';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';

test.describe('signing session shared types', () => {
  test('branded id helpers normalize required session ids', () => {
    expect(SigningSessionIds.walletSession(' wsess-1 ')).toBe('wsess-1');
    expect(SigningSessionIds.walletSessionQuota(' quota-1 ')).toBe('quota-1');
    expect(SigningSessionIds.thresholdEd25519Session(' tsess-ed25519 ')).toBe('tsess-ed25519');
    expect(SigningSessionIds.thresholdEcdsaSession(' tsess-ecdsa ')).toBe('tsess-ecdsa');
    expect(SigningSessionIds.emailOtpChallenge(' challenge-1 ')).toBe('challenge-1');
    expect(SigningSessionIds.signingOperation(' op-1 ')).toBe('op-1');
  });

  test('branded id helpers reject empty values at module boundaries', () => {
    expect(() => SigningSessionIds.walletSession('')).toThrow(
      '[SigningSession] walletSessionId is required',
    );
    expect(() => SigningSessionIds.thresholdEcdsaSession('   ')).toThrow(
      '[SigningSession] thresholdEcdsaSessionId is required',
    );
  });
});

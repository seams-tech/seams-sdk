import { expect, test } from '@playwright/test';
import { resolveThresholdEd25519CommitQueueKey } from '@/core/signingEngine/threshold/ed25519/commitQueue';

test.describe('threshold Ed25519 commit queue key resolver', () => {
  test('uses strict session-only key format', async () => {
    const key = resolveThresholdEd25519CommitQueueKey({
      thresholdSessionId: 'tsess-abc',
    });
    expect(key).toBe('session:ed25519:tsess-abc');
  });

  test('throws when thresholdSessionId is missing', async () => {
    expect(() =>
      resolveThresholdEd25519CommitQueueKey({
        thresholdSessionId: '',
      }),
    ).toThrow(
      '[SigningEngine] threshold Ed25519 commit queue requires non-empty thresholdSessionId',
    );
  });
});

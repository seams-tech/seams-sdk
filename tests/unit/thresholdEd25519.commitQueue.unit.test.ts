import { expect, test } from '@playwright/test';
import { resolveThresholdEd25519CommitQueueKey } from '@/core/signingEngine/threshold/ed25519/commitQueue';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

test.describe('threshold Ed25519 commit queue key resolver', () => {
  test('uses exact material activation rather than Wallet Session identity', async () => {
    const key = resolveThresholdEd25519CommitQueueKey({
      materialActivation: buildMpcMaterialActivationRefFixture(
        'activation-1',
        toWalletId('wallet-1'),
      ),
    });
    expect(key).toContain('material:');
    expect(key).toContain('activation-1');
  });

  test('is stable across Wallet Session replacement for the same activation', async () => {
    const materialActivation = buildMpcMaterialActivationRefFixture(
      'activation-1',
      toWalletId('wallet-1'),
    );
    expect(resolveThresholdEd25519CommitQueueKey({ materialActivation })).toBe(
      resolveThresholdEd25519CommitQueueKey({ materialActivation }),
    );
  });
});

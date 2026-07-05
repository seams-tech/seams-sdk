import { intendedTest as test } from './harness';

test('email recovery lifecycle restores signing', async ({ harness }) => {
  await harness.registerPasskeyWallet();
  await harness.recoverEmailToSigning();
  await harness.signNearTransaction('post_unlock');
  await harness.signTempoTransaction('post_unlock');
  await harness.signArcEvmTransaction('post_unlock');
});

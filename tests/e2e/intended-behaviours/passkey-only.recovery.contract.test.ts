import { intendedTest as test } from './harness';

test('a fresh browser recovers a Passkey-only wallet with one code and refuses reuse', async ({
  harness,
}) => {
  await harness.registerPasskeyWallet();
  await harness.awaitNearReady();
  await harness.signTempoTransaction('post_registration');
  await harness.recoverPasskeyWalletFromFreshBrowser();
  await harness.assertSourceWalletSessionRevoked();
  await harness.signNearTransaction('post_unlock');
  await harness.signTempoAndArcEvmConcurrently('post_unlock');
  await harness.assertConsumedRecoveryCodeRefusedGenerically();
});

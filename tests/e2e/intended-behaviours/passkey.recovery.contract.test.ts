import { intendedTest as test } from './harness';

test('a fresh browser recovers one Passkey wallet with one code and signs with unchanged identities', async ({
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

import { intendedTest as test } from './harness';

test('passkey registration establishes an immediately usable signing session', async ({ harness }) => {
  await harness.registerPasskeyWallet();
  await harness.signTempoTransaction('post_registration');
  await harness.awaitNearReady();
  await harness.signNearTransaction('post_registration');
});

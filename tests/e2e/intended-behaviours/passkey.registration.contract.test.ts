import { intendedTest as test } from './harness';

test('passkey registration lifecycle', async ({ harness }) => {
  await harness.registerPasskeyWallet();
  await harness.signTempoTransaction('post_registration');
});

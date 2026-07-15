import { intendedTest as test } from './harness';

test('passkey registration lifecycle', async ({ harness }) => {
  await harness.registerPasskeyWallet();
  await harness.consumeSharedRegistrationSigningBudget();
  await harness.signNearTransaction('after_step_up');
  await harness.signTempoTransaction('after_step_up');
  await harness.exportEd25519Key();
  await harness.exportEd25519Key();
  await harness.exportEcdsaKey();
});

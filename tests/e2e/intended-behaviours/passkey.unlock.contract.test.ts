import { intendedTest as test, type IntendedBehaviourHarness } from './harness';

async function verifyPasskeyUnlockNearSigning({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.registerPasskeyWallet();
  await harness.unlockPasskeyWallet();
  await harness.signNearTransaction('post_unlock');
}

test('passkey unlock restores warm NEAR signing', verifyPasskeyUnlockNearSigning);

async function verifyPasskeyPageRefreshHydration({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.registerPasskeyWallet();
  await harness.unlockPasskeyWallet();
  await harness.refreshPagePreservingWalletStorage();
  await harness.signNearTransaction('after_refresh_recovery');
  await harness.signTempoTransaction('after_refresh_recovery');
  await harness.signArcEvmTransaction('after_refresh_recovery');
  await harness.exhaustSigningBudget();
  await harness.signNearTransaction('after_step_up');
  await harness.signTempoTransaction('after_step_up');
  await harness.signArcEvmTransaction('after_step_up');
  await harness.exportEd25519Key();
  await harness.exportEcdsaKey();
}

test(
  'page refresh hydrates warm signing, one-use step-up, and key export',
  verifyPasskeyPageRefreshHydration,
);

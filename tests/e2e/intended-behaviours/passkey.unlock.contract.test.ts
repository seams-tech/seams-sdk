import { intendedTest as test, type IntendedBehaviourHarness } from './harness';

async function verifyPasskeyUnlockImmediateLifecycle({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.registerPasskeyWallet();
  await harness.unlockPasskeyWallet();
  await harness.exportEd25519Key();
  await harness.exportEcdsaKey();
  await harness.signNearTransaction('post_unlock');
  await harness.signTempoAndArcEvmConcurrently('post_unlock');
  await harness.signNearTransaction('after_step_up');
}

test(
  'passkey unlock restores immediate export and shared-budget signing',
  verifyPasskeyUnlockImmediateLifecycle,
);

async function verifyPasskeyPageRefreshHydration({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.registerPasskeyWallet();
  await harness.unlockPasskeyWallet();
  await harness.refreshPagePreservingWalletStorage();
  await harness.exportEd25519Key();
  await harness.exportEcdsaKey();
  await harness.signNearTransaction('after_refresh_recovery');
  await harness.signTempoTransaction('after_refresh_recovery');
  await harness.signArcEvmTransaction('after_refresh_recovery');
  await harness.exhaustSigningBudget();
  await harness.signNearTransaction('after_step_up');
  await harness.signTempoTransaction('after_step_up');
  await harness.signArcEvmTransaction('after_step_up');
}

test(
  'page refresh hydrates warm signing, one-use step-up, and key export',
  verifyPasskeyPageRefreshHydration,
);

import { intendedTest as test, type IntendedBehaviourHarness } from './harness';

type RecoveryOrigin = {
  readonly name: string;
  readonly register: (harness: IntendedBehaviourHarness) => Promise<void>;
};

async function registerPasskeyFoundedWallet(harness: IntendedBehaviourHarness): Promise<void> {
  await harness.registerPasskeyWallet();
}

async function registerEmailOnlyWallet(harness: IntendedBehaviourHarness): Promise<void> {
  await harness.registerEmailOtpWallet();
}

const recoveryOrigins: readonly RecoveryOrigin[] = [
  { name: 'Passkey-founded', register: registerPasskeyFoundedWallet },
  { name: 'Email-only', register: registerEmailOnlyWallet },
];

for (const origin of recoveryOrigins) {
  test(
    `a fresh browser recovers a ${origin.name} wallet with one code, signs, and refuses reuse`,
    async ({ harness }) => {
      await origin.register(harness);
      await harness.awaitNearReady();
      await harness.recoverPasskeyWalletFromFreshBrowser();
      await harness.signNearTransaction('post_unlock');
      await harness.signTempoAndArcEvmConcurrently('post_unlock');
      await harness.assertConsumedRecoveryCodeRefusedGenerically();
    },
  );
}

import { intendedTest as test, type IntendedBehaviourHarness } from './harness';

test('Email OTP unlock benchmark', runEmailOtpUnlockBenchmark);

async function runEmailOtpUnlockBenchmark({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.registerEmailOtpWallet();
  await harness.unlockEmailOtpWallet();
}

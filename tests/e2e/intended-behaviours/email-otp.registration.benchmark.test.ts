import { intendedTest as test, type IntendedBehaviourHarness } from './harness';

test('Email OTP registration benchmark', runEmailOtpRegistrationBenchmark);

async function runEmailOtpRegistrationBenchmark({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.registerEmailOtpWallet();
}

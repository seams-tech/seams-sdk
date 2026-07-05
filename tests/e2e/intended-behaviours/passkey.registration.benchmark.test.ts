import { intendedTest as test, type IntendedBehaviourHarness } from './harness';

test('passkey registration benchmark', runPasskeyRegistrationBenchmark);

async function runPasskeyRegistrationBenchmark({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.registerPasskeyWallet();
}

import { intendedTest as test, type IntendedBehaviourHarness } from './harness';

async function verifyLocalEd25519YaoRegistration({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.registerPasskeyEd25519YaoWallet();
}

test(
  'public Ed25519 Yao registration persists a ready signer',
  verifyLocalEd25519YaoRegistration,
);

async function verifyLocalEd25519YaoAddSignerAndSigning({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.registerPasskeyEd25519YaoWallet();
  await harness.addPasskeyEd25519YaoWalletSigner();
}

test(
  'public Ed25519 Yao add-signer persists a distinct signer',
  verifyLocalEd25519YaoAddSignerAndSigning,
);

async function verifyExactTransportRetry({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.registerPasskeyEd25519YaoWalletWithExactTransportRetry();
}

test(
  'uncertain Router transport replays the exact admitted request and completes',
  verifyExactTransportRetry,
);

async function verifyTerminalFailureWithoutRetry({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.assertPasskeyEd25519YaoTerminalFailureWithoutRetry();
}

test('terminal burned execution fails without retry', verifyTerminalFailureWithoutRetry);

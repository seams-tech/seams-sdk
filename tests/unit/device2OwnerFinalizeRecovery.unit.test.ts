import { expect, test } from '@playwright/test';
import {
  buildDevice2LinkFlowHarnessV1,
  withCapturedLocalWritesV1,
} from './helpers/device2LinkFlow.fixtures';

/**
 * A successful owner finalize is irreversible: one call registers the passkey,
 * the custody envelope, and the owner binding in a single server transaction.
 * Everything after it is a local write, and the failure mode that matters is
 * recovering from one of those by minting a second credential — the wallet
 * would then carry two owner factors for one device, and only one of them would
 * be in the local projection.
 *
 * These own that boundary: a local failure is retried against the committed
 * response, and nothing on the recovery path is allowed to reach the
 * authenticator.
 */
test('a failed projection write is retried against the committed finalize', async () => {
  const harness = await buildDevice2LinkFlowHarnessV1();
  const writes: string[] = [];
  const profiles: number[] = [];
  let failuresRemaining = 1;
  await withCapturedLocalWritesV1(
    {
      onProfile: () => profiles.push(profiles.length + 1),
      onAuthMethod: (record) => {
        writes.push(String(record.credentialIdB64u));
        if (failuresRemaining > 0) {
          failuresRemaining -= 1;
          throw new Error('IndexedDB write failed');
        }
      },
    },
    async () => {
      const activation = await harness.reachTargetPasskeyPromptV1();
      // The transient failure is recovered inside the activation, so the flow
      // never surfaces it to the host at all.
      await activation.createPasskey().catch(() => undefined);
    },
  );

  expect(writes.length).toBe(2);
  // The whole unit retried, not just the write that failed: a profile written
  // once would mean the retry resumed mid-way through a partial local state.
  expect(profiles.length).toBe(2);
  // The retry wrote the same credential; it did not go and make another one.
  expect(new Set(writes).size).toBe(1);
  // One prompt, one finalize. The replay reused the retained response rather
  // than asking the server to finalize a second time.
  expect(harness.calls.filter((call) => call === 'target-passkey').length).toBe(1);
  expect(harness.calls.filter((call) => call === 'finalize').length).toBe(1);
  // The temporary credential registration is inside the retried unit, so it
  // runs once the projection that precedes it has landed.
  expect(harness.calls).toContain('credential');
});

test('a durable projection failure never mints a second credential', async () => {
  const harness = await buildDevice2LinkFlowHarnessV1();
  let writeAttempts = 0;
  await withCapturedLocalWritesV1(
    {
      onProfile: () => {
        writeAttempts += 1;
        throw new Error('IndexedDB is unavailable');
      },
    },
    async () => {
      const activation = await harness.reachTargetPasskeyPromptV1();
      // Says what is actually true: the server has the credential, this device
      // could not record it. It does not imply nothing happened.
      await expect(activation.createPasskey()).rejects.toThrow(
        'registered but could not be stored locally',
      );

      // What stops a second credential is that the flow tears itself down:
      // the failure advances the run epoch and releases local resources, so
      // the retry the host would naturally make is refused as superseded
      // rather than walking back into the authenticator.
      await expect(activation.createPasskey()).rejects.toThrow('flow was cancelled or reset');
    },
  );

  // Exactly the bounded loop, and not one attempt more: the second activation
  // was refused before it could retry the writes again.
  expect(writeAttempts).toBe(4);
  // The one guarantee that matters — exactly one credential was ever created,
  // across both the retry loop and the host's second attempt.
  expect(harness.calls.filter((call) => call === 'target-passkey').length).toBe(1);
  // Nothing downstream ran on a projection that never landed.
  expect(harness.calls).not.toContain('credential');
});

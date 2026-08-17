import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { buildDevice2LinkFlowHarnessV1 } from './helpers/device2LinkFlow.fixtures';

/**
 * Ordering on Device 2: the custody transfer has to be accepted before the
 * owner credential is finalized, and the temporary R102 credential must not be
 * registered until that finalize has succeeded.
 *
 * The reason is the direction of the dependency. Finalize commits the resealed
 * envelope, which only exists once the transfer is accepted; and the temporary
 * credential is a projection of an enrollment the finalize is what establishes.
 * Registering it first would leave a target credential describing an enrollment
 * that may never commit.
 */
test('finalizes owner custody before registering the temporary target credential', async () => {
  const harness = await buildDevice2LinkFlowHarnessV1({
    // A finalize that answers with a credential nobody asked for. The flow must
    // refuse it rather than persist a projection for someone else's key.
    finalizeOwnerAuthMethodV1: async () => {
      harness.calls.push('finalize');
      return {
        localAccount: {
          kind: 'linked_device_local_account_projection_v1',
          walletId: 'mismatched.testnet',
          nearAccountId: 'mismatched.testnet',
          signerSlot: 4,
          operationalPublicKey: base64UrlEncode(new Uint8Array(32).fill(11)),
          nearEd25519SigningKeyId: 'mismatched.testnet',
        },
        response: {
          ok: true,
          walletId: 'mismatched.testnet',
          rpId: 'wallet.example.localhost',
          authMethod: {
            kind: 'passkey' as const,
            status: 'active' as const,
            credentialIdB64u: base64UrlEncode(new Uint8Array(32).fill(9)),
            credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(10)),
            counter: 0,
            device: {
              label: 'Chrome on macOS',
              browser: 'chrome' as const,
              os: 'macos' as const,
              synced: false,
              transports: ['internal'],
            },
          },
        },
      } as never;
    },
  });

  const activation = await harness.reachTargetPasskeyPromptV1();
  await expect(activation.createPasskey()).rejects.toThrow(
    'linked-device owner finalize returned a mismatched auth method',
  );

  expect(harness.calls).toContain('finalize');
  // The refusal happened before anything downstream of it ran.
  expect(harness.calls).not.toContain('credential');
  expect(harness.calls.indexOf('finalize')).toBeGreaterThan(harness.calls.indexOf('accept'));
});

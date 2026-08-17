import { expect, test } from '@playwright/test';
import { createDeviceLinkingCustodyTransferPortV1 } from '../../packages/sdk-web/src/SeamsWeb/operations/devices/deviceLinkingCustodyTransfer';
import type { WalletCustodyCeremonyTransportPort } from '../../packages/sdk-web/src/core/signingEngine/walletCustody/ceremonyStepRunner';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import {
  LINKED_DEVICE_TRANSFER_EPHEMERAL_PUBLIC_KEY_B64U,
  LINKED_DEVICE_TRANSFER_RECIPIENT_PUBLIC_KEY_B64U,
  LINKED_DEVICE_TRANSFER_SEALED_AT_MS,
  buildLinkedDeviceCustodyTransferPackageFixtureV1,
  buildLinkedDeviceCustodyTransferRecipientFixtureV1,
  buildUnlockedCustodyCapabilityFixtureV1,
} from './helpers/linkedDeviceCustodyTransfer.fixtures';

type WorkerCall = { readonly type: string; readonly payload: Record<string, unknown> };

/**
 * Stands in for the wallet custody ceremony worker. The real one holds the
 * seed and both PRFs inside wasm; this records what crossed the boundary so
 * the tests can assert that nothing secret did.
 */
function fakeWorker(results: Readonly<Record<string, unknown>>): {
  readonly transport: WalletCustodyCeremonyTransportPort;
  readonly calls: WorkerCall[];
} {
  const calls: WorkerCall[] = [];
  return {
    calls,
    transport: {
      async requestOperation(args) {
        const request = args.request as { type: string; payload: Record<string, unknown> };
        calls.push({ type: request.type, payload: request.payload });
        const result = results[request.type];
        if (result === undefined) throw new Error(`unexpected worker operation ${request.type}`);
        return result;
      },
    },
  };
}

const RESEALED = {
  nonceB64u: base64UrlEncode(new Uint8Array(12).fill(8)),
  sealedCustodySecretB64u: base64UrlEncode(new Uint8Array(48).fill(3)),
  aadHashB64u: base64UrlEncode(new Uint8Array(32).fill(1)),
  ciphertextDigestB64u: base64UrlEncode(new Uint8Array(32).fill(2)),
};

const SEALED = {
  ephemeralPublicKeyB64u: LINKED_DEVICE_TRANSFER_EPHEMERAL_PUBLIC_KEY_B64U,
  nonceB64u: base64UrlEncode(new Uint8Array(12).fill(4)),
  sealedCustodySecretB64u: base64UrlEncode(new Uint8Array(48).fill(9)),
  aadHashB64u: base64UrlEncode(new Uint8Array(32).fill(5)),
  ciphertextDigestB64u: base64UrlEncode(new Uint8Array(32).fill(6)),
};

test('Device 2 publishes a recipient key generated inside the worker', async () => {
  const worker = fakeWorker({
    createLinkedDeviceCustodyTransferRecipient: {
      recipientHandleId: 'handle-1',
      recipientPublicKeyB64u: LINKED_DEVICE_TRANSFER_RECIPIENT_PUBLIC_KEY_B64U,
    },
  });
  const port = createDeviceLinkingCustodyTransferPortV1(worker.transport);
  const recipient = await port.createRecipientV1({
    identity: {
      linkSessionId: 'link-session:r103p8',
      walletId: buildLinkedDeviceCustodyTransferRecipientFixtureV1().walletId,
      enrollmentId: buildLinkedDeviceCustodyTransferRecipientFixtureV1().enrollmentId,
      deviceId: buildLinkedDeviceCustodyTransferRecipientFixtureV1().deviceId,
    },
    registeredAtMs: LINKED_DEVICE_TRANSFER_SEALED_AT_MS,
  });

  expect(recipient.recipientHandleId).toBe('handle-1');
  expect(recipient.registration).toEqual(buildLinkedDeviceCustodyTransferRecipientFixtureV1());
  // Only a handle id crosses back; the private half stays in the worker.
  expect(worker.calls).toEqual([
    { type: 'createLinkedDeviceCustodyTransferRecipient', payload: {} },
  ]);
});

test('Device 1 rebuilds the transfer binding locally rather than echoing the relay', async () => {
  const worker = fakeWorker({ sealWalletCustodySeedForLinkedDevice: SEALED });
  const port = createDeviceLinkingCustodyTransferPortV1(worker.transport);
  const capability = buildUnlockedCustodyCapabilityFixtureV1();

  const sealed = await port.sealForLinkedDeviceV1({
    recipient: buildLinkedDeviceCustodyTransferRecipientFixtureV1(),
    capability,
    sealedAtMs: LINKED_DEVICE_TRANSFER_SEALED_AT_MS,
  });

  expect(sealed).toEqual(buildLinkedDeviceCustodyTransferPackageFixtureV1());

  // The binding is the AAD. It is constructed from the device's own view of
  // the enrollment, so the relay cannot choose what the seal authenticates.
  // R103: no envelope and no factor secret cross this boundary — only the
  // opaque capability reference and the binding.
  const call = worker.calls[0];
  expect(call?.type).toBe('sealWalletCustodySeedForLinkedDevice');
  expect(Object.keys(call?.payload ?? {}).sort()).toEqual([
    'capability',
    'transferBindingJson',
  ]);
  expect(call?.payload.capability).toEqual(capability);
  expect(JSON.parse(String(call?.payload.transferBindingJson))).toEqual({
    walletId: 'alice.testnet',
    enrollmentId: 'enrollment:device-2',
    deviceId: 'device:2',
    recipientPublicKeyB64u: LINKED_DEVICE_TRANSFER_RECIPIENT_PUBLIC_KEY_B64U,
    binding: {
      kind: 'wallet_custody_seed_v1',
      derivationScheme: 'wallet_seed_parallel_hkdf_sha256_v1',
    },
  });
});

test('Device 1 refuses a capability naming another wallet before it reaches the worker', async () => {
  const worker = fakeWorker({ sealWalletCustodySeedForLinkedDevice: SEALED });
  const port = createDeviceLinkingCustodyTransferPortV1(worker.transport);

  await expect(
    port.sealForLinkedDeviceV1({
      recipient: buildLinkedDeviceCustodyTransferRecipientFixtureV1({ walletId: 'bob.testnet' }),
      capability: buildUnlockedCustodyCapabilityFixtureV1(),
      sealedAtMs: LINKED_DEVICE_TRANSFER_SEALED_AT_MS,
    }),
  ).rejects.toThrow(/names another wallet/);
  expect(worker.calls).toEqual([]);
});

test('Device 2 opens and reseals in one worker call', async () => {
  const worker = fakeWorker({ acceptLinkedDeviceCustodyTransfer: RESEALED });
  const port = createDeviceLinkingCustodyTransferPortV1(worker.transport);

  const resealed = await port.acceptTransferV1({
    recipient: {
      recipientHandleId: 'handle-1',
      registration: buildLinkedDeviceCustodyTransferRecipientFixtureV1(),
    },
    transferPackage: buildLinkedDeviceCustodyTransferPackageFixtureV1(),
    replacementEnvelopeBindingJson: '{"walletId":"alice.testnet"}',
    replacementFactorSecret: new Uint8Array(32).fill(11),
  });

  expect(resealed).toEqual(RESEALED);
  // One call, not two: splitting the open from the reseal would leave the
  // opened seed parked behind a handle between turns.
  expect(worker.calls).toHaveLength(1);
  expect(worker.calls[0]?.type).toBe('acceptLinkedDeviceCustodyTransfer');
});

test('Device 2 refuses a package addressed to another device before it reaches wasm', async () => {
  const worker = fakeWorker({ acceptLinkedDeviceCustodyTransfer: RESEALED });
  const port = createDeviceLinkingCustodyTransferPortV1(worker.transport);

  for (const misaddressed of [
    buildLinkedDeviceCustodyTransferPackageFixtureV1({ deviceId: 'device:3' }),
    buildLinkedDeviceCustodyTransferPackageFixtureV1({ enrollmentId: 'enrollment:other' }),
    buildLinkedDeviceCustodyTransferPackageFixtureV1({ walletId: 'bob.testnet' }),
  ]) {
    await expect(
      port.acceptTransferV1({
        recipient: {
          recipientHandleId: 'handle-1',
          registration: buildLinkedDeviceCustodyTransferRecipientFixtureV1(),
        },
        transferPackage: misaddressed,
        replacementEnvelopeBindingJson: '{}',
        replacementFactorSecret: new Uint8Array(32).fill(11),
      }),
    ).rejects.toThrow(/addressed to another device/);
  }
  expect(worker.calls).toEqual([]);
});

test('discarding a recipient zeroizes it in the worker', async () => {
  const worker = fakeWorker({
    discardLinkedDeviceCustodyTransferRecipient: {
      recipientHandleId: 'handle-1',
      discarded: true,
    },
  });
  const port = createDeviceLinkingCustodyTransferPortV1(worker.transport);
  await port.discardRecipientV1({
    recipientHandleId: 'handle-1',
    registration: buildLinkedDeviceCustodyTransferRecipientFixtureV1(),
  });
  expect(worker.calls).toEqual([
    {
      type: 'discardLinkedDeviceCustodyTransferRecipient',
      payload: { recipientHandleId: 'handle-1' },
    },
  ]);
});

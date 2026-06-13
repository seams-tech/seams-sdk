import { expect, test } from '@playwright/test';
import {
  openSigningRootSecretShareWireV1,
  sealSigningRootSecretShareWireV1,
  type SigningRootSecretShareKekResolutionInput,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootSecretSealing';
import type {
  SigningRootSecretShareId,
  SigningRootSecretShareWireV1,
  SealedSigningRootSecretShare,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootSecretShareWires';

const PROJECT_ID = 'project-alpha';
const SIGNING_ROOT_VERSION = 'root-v1';
const KEK_ID = 'kek-v1';
const KEK_BYTES = new Uint8Array(32).fill(0x42);

function signingRootSecretShareWire(shareId: SigningRootSecretShareId, fill: number): SigningRootSecretShareWireV1 {
  return new Uint8Array([shareId, ...new Array(32).fill(fill)]) as SigningRootSecretShareWireV1;
}

function createKekResolver(calls: SigningRootSecretShareKekResolutionInput[]) {
  return async (input: SigningRootSecretShareKekResolutionInput): Promise<Uint8Array> => {
    calls.push(input);
    return KEK_BYTES;
  };
}

function sealedRecord(input: {
  readonly shareId: SigningRootSecretShareId;
  readonly sealedShare: Uint8Array;
  readonly signingRootVersion?: string;
  readonly kekId?: string;
}): SealedSigningRootSecretShare {
  return {
    signingRootId: PROJECT_ID,
    shareId: input.shareId,
    sealedShare: input.sealedShare,
    ...(input.signingRootVersion ? { signingRootVersion: input.signingRootVersion } : {}),
    ...(input.kekId ? { kekId: input.kekId } : {}),
  };
}

test('signing-root AES-GCM sealing round-trips share wires and binds KEK metadata', async () => {
  const calls: SigningRootSecretShareKekResolutionInput[] = [];
  const resolveKek = createKekResolver(calls);
  const plaintext = signingRootSecretShareWire(1, 0x11);

  const sealedShare = await sealSigningRootSecretShareWireV1({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    shareId: 1,
    kekId: KEK_ID,
    plaintextShareWire: plaintext,
    resolveKek,
  });
  expect(sealedShare.length).toBeGreaterThan(33);
  expect(Array.from(plaintext.slice(0, 2))).toEqual([1, 0x11]);

  const opened = await openSigningRootSecretShareWireV1({
    record: sealedRecord({ shareId: 1, signingRootVersion: SIGNING_ROOT_VERSION, kekId: KEK_ID, sealedShare }),
    resolveKek,
  });

  expect(Array.from(opened)).toEqual(Array.from(plaintext));
  opened.fill(0);
  expect(calls).toEqual([
    { signingRootId: PROJECT_ID, signingRootVersion: SIGNING_ROOT_VERSION, shareId: 1, kekId: KEK_ID },
    { signingRootId: PROJECT_ID, signingRootVersion: SIGNING_ROOT_VERSION, shareId: 1, kekId: KEK_ID },
  ]);
});

test('signing-root AES-GCM sealing rejects wrong metadata and malformed envelopes', async () => {
  const calls: SigningRootSecretShareKekResolutionInput[] = [];
  const resolveKek = createKekResolver(calls);
  const sealedShare = await sealSigningRootSecretShareWireV1({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    shareId: 1,
    kekId: KEK_ID,
    plaintextShareWire: signingRootSecretShareWire(1, 0x11),
    resolveKek,
  });

  await expect(
    openSigningRootSecretShareWireV1({
      record: sealedRecord({ shareId: 1, signingRootVersion: 'other-root', kekId: KEK_ID, sealedShare }),
      resolveKek,
    }),
  ).rejects.toThrow();

  await expect(
    openSigningRootSecretShareWireV1({
      record: sealedRecord({
        shareId: 1,
        signingRootVersion: SIGNING_ROOT_VERSION,
        kekId: KEK_ID,
        sealedShare: new Uint8Array([0x00, 0x01]),
      }),
      resolveKek,
    }),
  ).rejects.toThrow(/too short/);
});

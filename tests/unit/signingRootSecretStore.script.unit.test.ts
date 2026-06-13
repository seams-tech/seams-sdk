import { expect, test } from '@playwright/test';
import {
  InMemorySigningRootSecretStore,
  type SigningRootSecretStore,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/SigningRootSecretStore';
import type {
  SigningRootSecretShareId,
  SealedSigningRootSecretShare,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootSecretShareWires';

const PROJECT_ID = 'project-alpha';
const SIGNING_ROOT_VERSION = 'root-v1';

function sealedShareBytes(shareId: SigningRootSecretShareId, fill: number): Uint8Array {
  return new Uint8Array([shareId, fill, fill, fill]);
}

async function putShare(input: {
  readonly store: SigningRootSecretStore;
  readonly shareId: SigningRootSecretShareId;
  readonly fill: number;
  readonly signingRootVersion?: string;
}): Promise<Uint8Array> {
  const sealedShare = sealedShareBytes(input.shareId, input.fill);
  await input.store.putSealedSigningRootSecretShare({
    signingRootId: PROJECT_ID,
    signingRootVersion: input.signingRootVersion,
    shareId: input.shareId,
    sealedShare,
    storageId: `store-${input.shareId}`,
    kekId: `kek-${input.shareId}`,
  });
  return sealedShare;
}

function expectRecord(record: SealedSigningRootSecretShare, shareId: SigningRootSecretShareId): void {
  expect(record).toMatchObject({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    shareId,
    storageId: `store-${shareId}`,
    kekId: `kek-${shareId}`,
  });
}

test('in-memory signing-root share store lists copied sealed shares by project and root version', async () => {
  const store = new InMemorySigningRootSecretStore();
  const originalShare2 = await putShare({
    store,
    signingRootVersion: SIGNING_ROOT_VERSION,
    shareId: 2,
    fill: 0x22,
  });
  await putShare({ store, signingRootVersion: SIGNING_ROOT_VERSION, shareId: 1, fill: 0x11 });
  await putShare({ store, signingRootVersion: 'other-root', shareId: 3, fill: 0x33 });

  originalShare2.fill(0);

  const listed = await store.listSealedSigningRootSecretShares({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });

  expect(listed).toHaveLength(2);
  expectRecord(listed[0], 1);
  expectRecord(listed[1], 2);
  expect(Array.from(listed[1].sealedShare)).toEqual([2, 0x22, 0x22, 0x22]);

  listed[1].sealedShare.fill(0);
  const listedAgain = await store.listSealedSigningRootSecretShares({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  expect(Array.from(listedAgain[1].sealedShare)).toEqual([2, 0x22, 0x22, 0x22]);
});

test('in-memory signing-root share store supports default root version and deletion', async () => {
  const store = new InMemorySigningRootSecretStore();
  await putShare({ store, shareId: 1, fill: 0x11 });
  await putShare({ store, signingRootVersion: SIGNING_ROOT_VERSION, shareId: 2, fill: 0x22 });

  expect(await store.listSealedSigningRootSecretShares({ signingRootId: PROJECT_ID })).toHaveLength(1);
  expect(
    await store.listSealedSigningRootSecretShares({ signingRootId: PROJECT_ID, signingRootVersion: SIGNING_ROOT_VERSION }),
  ).toHaveLength(1);

  await store.deleteSigningRootSecretShares({ signingRootId: PROJECT_ID });
  expect(await store.listSealedSigningRootSecretShares({ signingRootId: PROJECT_ID })).toHaveLength(0);
  expect(
    await store.listSealedSigningRootSecretShares({ signingRootId: PROJECT_ID, signingRootVersion: SIGNING_ROOT_VERSION }),
  ).toHaveLength(1);
});

import { expect, test } from '@playwright/test';
import {
  SIGNING_ROOT_SECRET_SHARE_WIRE_V1_LENGTH,
  type SigningRootSecretShareId,
  type SealedSigningRootSecretShare,
  parseSigningRootSecretShareWireV1,
  signingRootSecretShareIdFromWire,
  resolveSigningRootSecretShareWirePair,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootSecretShareWires';

const PROJECT_ID = 'project_test_123';

function signingRootSecretShareWireBytes(shareId: SigningRootSecretShareId, fill: number): Uint8Array {
  const bytes = new Uint8Array(SIGNING_ROOT_SECRET_SHARE_WIRE_V1_LENGTH);
  bytes[0] = shareId;
  bytes.fill(fill, 1);
  return bytes;
}

function sealedShareRecord(shareId: SigningRootSecretShareId): SealedSigningRootSecretShare {
  return {
    signingRootId: PROJECT_ID,
    shareId,
    sealedShare: new Uint8Array([shareId, 0xaa]),
    signingRootVersion: 'root-v1',
    storageId: `store-${shareId}`,
    kekId: `kek-${shareId}`,
  };
}

test('parseSigningRootSecretShareWireV1 copies fixed-width share wires', () => {
  const source = signingRootSecretShareWireBytes(2, 0x42);
  const parsed = parseSigningRootSecretShareWireV1(source);

  expect(parsed.ok).toBe(true);
  if (!parsed.ok) throw new Error(parsed.message);
  expect(signingRootSecretShareIdFromWire(parsed.value)).toBe(2);

  source.fill(0);
  expect(signingRootSecretShareIdFromWire(parsed.value)).toBe(2);
  expect(parsed.value[1]).toBe(0x42);
});

test('parseSigningRootSecretShareWireV1 rejects malformed public wire inputs', () => {
  expect(parseSigningRootSecretShareWireV1(new Uint8Array(32))).toMatchObject({
    ok: false,
    code: 'invalid_share_wire',
  });

  const invalidId = signingRootSecretShareWireBytes(1, 0x11);
  invalidId[0] = 4;
  expect(parseSigningRootSecretShareWireV1(invalidId)).toMatchObject({
    ok: false,
    code: 'invalid_share_id',
  });
});

test('resolveSigningRootSecretShareWirePair decrypts preferred shares, copies them, and zeroizes plaintext scratch buffers', async () => {
  const decrypted = new Map<SigningRootSecretShareId, Uint8Array>([
    [1, signingRootSecretShareWireBytes(1, 0x11)],
    [2, signingRootSecretShareWireBytes(2, 0x22)],
    [3, signingRootSecretShareWireBytes(3, 0x33)],
  ]);

  const resolved = await resolveSigningRootSecretShareWirePair({
    signingRootId: PROJECT_ID,
    records: [sealedShareRecord(1), sealedShareRecord(2), sealedShareRecord(3)],
    preferredShareIds: [3, 1],
    decryptShare: async (record) => decrypted.get(record.shareId)!,
  });

  expect(resolved.ok).toBe(true);
  if (!resolved.ok) throw new Error(resolved.message);

  expect(Array.from(resolved.value[0])).toEqual(Array.from(signingRootSecretShareWireBytes(3, 0x33)));
  expect(Array.from(resolved.value[1])).toEqual(Array.from(signingRootSecretShareWireBytes(1, 0x11)));
  expect(Array.from(decrypted.get(3)!)).toEqual(
    new Array(SIGNING_ROOT_SECRET_SHARE_WIRE_V1_LENGTH).fill(0),
  );
  expect(Array.from(decrypted.get(1)!)).toEqual(
    new Array(SIGNING_ROOT_SECRET_SHARE_WIRE_V1_LENGTH).fill(0),
  );
  expect(Array.from(decrypted.get(2)!)).toEqual(Array.from(signingRootSecretShareWireBytes(2, 0x22)));
});

test('resolveSigningRootSecretShareWirePair rejects ambiguous or mismatched share records', async () => {
  const duplicate = await resolveSigningRootSecretShareWirePair({
    signingRootId: PROJECT_ID,
    records: [sealedShareRecord(1), sealedShareRecord(1)],
    decryptShare: async (record) => signingRootSecretShareWireBytes(record.shareId, 0x11),
  });
  expect(duplicate).toMatchObject({ ok: false, code: 'duplicate_share' });

  const mismatchPlaintext = signingRootSecretShareWireBytes(2, 0x22);
  const mismatched = await resolveSigningRootSecretShareWirePair({
    signingRootId: PROJECT_ID,
    records: [sealedShareRecord(1), sealedShareRecord(2)],
    preferredShareIds: [1, 2],
    decryptShare: async (record) =>
      record.shareId === 1 ? mismatchPlaintext : signingRootSecretShareWireBytes(record.shareId, 0x22),
  });

  expect(mismatched).toMatchObject({ ok: false, code: 'invalid_share_id' });
  expect(Array.from(mismatchPlaintext)).toEqual(
    new Array(SIGNING_ROOT_SECRET_SHARE_WIRE_V1_LENGTH).fill(0),
  );
});

test('resolveSigningRootSecretShareWirePair rejects missing preferred shares and project mismatches before decrypt', async () => {
  let decryptCalls = 0;
  const decryptShare = async (record: SealedSigningRootSecretShare) => {
    decryptCalls += 1;
    return signingRootSecretShareWireBytes(record.shareId, 0x11);
  };

  const missingPreferred = await resolveSigningRootSecretShareWirePair({
    signingRootId: PROJECT_ID,
    records: [sealedShareRecord(1), sealedShareRecord(2)],
    preferredShareIds: [1, 3],
    decryptShare,
  });
  expect(missingPreferred).toMatchObject({ ok: false, code: 'missing_share' });

  const projectMismatch = await resolveSigningRootSecretShareWirePair({
    signingRootId: PROJECT_ID,
    records: [{ ...sealedShareRecord(1), signingRootId: 'other-project' }, sealedShareRecord(2)],
    decryptShare,
  });
  expect(projectMismatch).toMatchObject({ ok: false, code: 'invalid_signing_root_id' });
  expect(decryptCalls).toBe(0);
});

test('resolveSigningRootSecretShareWirePair zeroizes the first plaintext wire when the second decrypt fails', async () => {
  const firstPlaintext = signingRootSecretShareWireBytes(1, 0x11);

  const resolved = await resolveSigningRootSecretShareWirePair({
    signingRootId: PROJECT_ID,
    records: [sealedShareRecord(1), sealedShareRecord(2)],
    preferredShareIds: [1, 2],
    decryptShare: async (record) => {
      if (record.shareId === 2) throw new Error('decrypt failed');
      return firstPlaintext;
    },
  });

  expect(resolved).toMatchObject({ ok: false, code: 'decrypt_failed' });
  expect(Array.from(firstPlaintext)).toEqual(new Array(SIGNING_ROOT_SECRET_SHARE_WIRE_V1_LENGTH).fill(0));
});

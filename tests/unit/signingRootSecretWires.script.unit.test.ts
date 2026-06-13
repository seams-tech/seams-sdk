import { expect, test } from '@playwright/test';
import {
  SIGNING_ROOT_SECRET_SHARE_WIRE_V1_LENGTH,
  type SigningRootSecretShareId,
  parseSigningRootSecretShareWireV1,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootSecretShareWires';

function signingRootSecretShareWireBytes(shareId: SigningRootSecretShareId, fill: number): Uint8Array {
  const bytes = new Uint8Array(SIGNING_ROOT_SECRET_SHARE_WIRE_V1_LENGTH);
  bytes[0] = shareId;
  bytes.fill(fill, 1);
  return bytes;
}

test('parseSigningRootSecretShareWireV1 copies fixed-width share wires', () => {
  const source = signingRootSecretShareWireBytes(2, 0x42);
  const parsed = parseSigningRootSecretShareWireV1(source);

  expect(parsed.ok).toBe(true);
  if (!parsed.ok) throw new Error(parsed.message);
  expect(parsed.value[0]).toBe(2);

  source.fill(0);
  expect(parsed.value[0]).toBe(2);
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

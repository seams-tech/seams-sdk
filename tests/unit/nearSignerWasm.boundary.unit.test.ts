import { expect, test } from '@playwright/test';
import { parseCosePublicKeyBytesFromWorker } from '../../client/src/core/signingEngine/chains/near/nearSignerWasm';

test('COSE public key worker parser accepts Uint8Array bytes', () => {
  const parsed = parseCosePublicKeyBytesFromWorker(new Uint8Array([1, 2, 3]));

  expect(parsed).toBeInstanceOf(Uint8Array);
  expect(Array.from(parsed)).toEqual([1, 2, 3]);
});

test('COSE public key worker parser accepts serde byte arrays', () => {
  const parsed = parseCosePublicKeyBytesFromWorker([4, 5, 6]);

  expect(parsed).toBeInstanceOf(Uint8Array);
  expect(Array.from(parsed)).toEqual([4, 5, 6]);
});

test('COSE public key worker parser rejects invalid byte arrays', () => {
  expect(() => parseCosePublicKeyBytesFromWorker([1, 256])).toThrow(
    'COSE public key extraction returned invalid byte array',
  );
});

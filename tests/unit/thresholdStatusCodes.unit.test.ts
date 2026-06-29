import { expect, test } from '@playwright/test';
import { thresholdEcdsaStatusCode } from '../../packages/sdk-server-ts/src/threshold/statusCodes';

test('threshold ECDSA route maps missing signing-root KEK to 503', () => {
  expect(
    thresholdEcdsaStatusCode({
      ok: false,
      code: 'missing_signing_root_kek',
    }),
  ).toBe(503);
});

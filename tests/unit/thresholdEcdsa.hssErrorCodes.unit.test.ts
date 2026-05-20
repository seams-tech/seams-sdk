import { expect, test } from '@playwright/test';
import type { EcdsaHssErrorCode } from '../../server/src/core/types';

const ECDSA_HSS_ERROR_CODES = [
  'invalid_body',
  'unauthorized',
  'forbidden',
  'not_found',
  'stale_state',
  'relayer_key_mismatch',
  'context_mismatch',
  'public_key_invalid',
  'identity_mismatch',
  'zero_canonical_key',
  'export_authorization_invalid',
  'export_authorization_expired',
  'export_nonce_replay',
  'presign_session_invalid',
  'presign_session_burned',
  'pool_empty',
  'internal',
] as const satisfies readonly EcdsaHssErrorCode[];

type MissingEcdsaHssErrorCode = Exclude<
  EcdsaHssErrorCode,
  (typeof ECDSA_HSS_ERROR_CODES)[number]
>;
type UnexpectedEcdsaHssErrorCode = Exclude<
  (typeof ECDSA_HSS_ERROR_CODES)[number],
  EcdsaHssErrorCode
>;

const coversEveryCode: MissingEcdsaHssErrorCode extends never ? true : never = true;
const hasNoUnexpectedCode: UnexpectedEcdsaHssErrorCode extends never ? true : never = true;

test('threshold ECDSA HSS error-code taxonomy is explicit and stable', () => {
  expect(coversEveryCode).toBe(true);
  expect(hasNoUnexpectedCode).toBe(true);
  expect(ECDSA_HSS_ERROR_CODES).toEqual([
    'invalid_body',
    'unauthorized',
    'forbidden',
    'not_found',
    'stale_state',
    'relayer_key_mismatch',
    'context_mismatch',
    'public_key_invalid',
    'identity_mismatch',
    'zero_canonical_key',
    'export_authorization_invalid',
    'export_authorization_expired',
    'export_nonce_replay',
    'presign_session_invalid',
    'presign_session_burned',
    'pool_empty',
    'internal',
  ]);
});

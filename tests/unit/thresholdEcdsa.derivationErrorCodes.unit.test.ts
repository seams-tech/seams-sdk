import { expect, test } from '@playwright/test';
import type { EcdsaDerivationErrorCode } from '../../packages/sdk-server-ts/src/core/types';

const ECDSA_DERIVATION_ERROR_CODES = [
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
] as const satisfies readonly EcdsaDerivationErrorCode[];

type MissingEcdsaDerivationErrorCode = Exclude<
  EcdsaDerivationErrorCode,
  (typeof ECDSA_DERIVATION_ERROR_CODES)[number]
>;
type UnexpectedEcdsaDerivationErrorCode = Exclude<
  (typeof ECDSA_DERIVATION_ERROR_CODES)[number],
  EcdsaDerivationErrorCode
>;

const coversEveryCode: MissingEcdsaDerivationErrorCode extends never ? true : never = true;
const hasNoUnexpectedCode: UnexpectedEcdsaDerivationErrorCode extends never ? true : never = true;

test('threshold ECDSA derivation error-code taxonomy is explicit and stable', () => {
  expect(coversEveryCode).toBe(true);
  expect(hasNoUnexpectedCode).toBe(true);
  expect(ECDSA_DERIVATION_ERROR_CODES).toEqual([
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

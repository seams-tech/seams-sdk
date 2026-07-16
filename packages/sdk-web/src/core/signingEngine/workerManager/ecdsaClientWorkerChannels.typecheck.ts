import type { EcdsaDerivationAdditiveShareResponse } from './ecdsaClientWorkerChannels';

const additiveShare32 = new ArrayBuffer(32);

void ({
  kind: 'ecdsa_derivation_additive_share_result_v1',
  requestId: 'request-success',
  ok: true,
  additiveShare32,
} satisfies EcdsaDerivationAdditiveShareResponse);

void ({
  kind: 'ecdsa_derivation_additive_share_result_v1',
  requestId: 'request-failure',
  ok: false,
  error: 'material unavailable',
} satisfies EcdsaDerivationAdditiveShareResponse);

void ({
  kind: 'ecdsa_derivation_additive_share_result_v1',
  requestId: 'request-ambiguous',
  ok: true,
  // @ts-expect-error The retired ambiguous field cannot cross the derivation/presign boundary.
  signingShare32: additiveShare32,
} satisfies EcdsaDerivationAdditiveShareResponse);

void ({
  kind: 'ecdsa_derivation_additive_share_result_v1',
  requestId: 'request-invalid-failure',
  ok: false,
  additiveShare32,
  error: 'material unavailable',
  // @ts-expect-error Failure responses cannot carry secret share material.
} satisfies EcdsaDerivationAdditiveShareResponse);

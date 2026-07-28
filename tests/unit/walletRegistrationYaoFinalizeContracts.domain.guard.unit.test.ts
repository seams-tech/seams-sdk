import { expect, test } from '@playwright/test';

import { parseWalletRegistrationFinalizeRequest } from '../../packages/sdk-server-ts/src/router/walletRegistrationRoutes';

const ACTIVATION_REFERENCE = {
  kind: 'router_ab_ed25519_yao_activation_reference_v1',
  lifecycle_id: 'registration-lifecycle-1',
  session_id: Array.from({ length: 32 }, (_, index) => index + 1),
};
const IDEMPOTENCY_KEY = 'registration-finalize-contract';

test('rejects finalize without an idempotency key', () => {
  const parsed = parseWalletRegistrationFinalizeRequest({
    registrationCeremonyId: 'registration-ceremony-without-idempotency',
    kind: 'near_ed25519',
    ed25519: { activationReference: ACTIVATION_REFERENCE },
  });

  expect(parsed).toEqual({
    ok: false,
    code: 'invalid_body',
    message: 'idempotencyKey is required',
  });
});

test('parses Ed25519-only finalize without an ECDSA branch', () => {
  const parsed = parseWalletRegistrationFinalizeRequest({
    registrationCeremonyId: 'registration-ceremony-1',
    idempotencyKey: IDEMPOTENCY_KEY,
    kind: 'near_ed25519',
    ed25519: { activationReference: ACTIVATION_REFERENCE },
  });

  expect(parsed).toEqual({
    ok: true,
    value: {
      registrationCeremonyId: 'registration-ceremony-1',
      idempotencyKey: IDEMPOTENCY_KEY,
      kind: 'near_ed25519',
      ed25519: { activationReference: ACTIVATION_REFERENCE },
    },
  });
});

/* Refactor 94 Phase 4+5: finalize commits one signer branch per call. The
   combined kind is gone from the wire, so the parser must reject it rather
   than admit a request no server path can serve. */
test('rejects a combined Ed25519 and ECDSA finalize request', () => {
  const parsed = parseWalletRegistrationFinalizeRequest({
    registrationCeremonyId: 'registration-ceremony-2',
    idempotencyKey: IDEMPOTENCY_KEY,
    kind: 'near_ed25519_and_evm_family_ecdsa',
    ed25519: { activationReference: ACTIVATION_REFERENCE },
    ecdsa: { expectedKeyHandles: [' key-handle-1 '] },
  });

  expect(parsed).toMatchObject({ ok: false });
});

test('rejects an ECDSA finalize request that smuggles Ed25519 work alongside it', () => {
  const parsed = parseWalletRegistrationFinalizeRequest({
    registrationCeremonyId: 'registration-ceremony-2',
    idempotencyKey: IDEMPOTENCY_KEY,
    kind: 'evm_family_ecdsa',
    ed25519: { activationReference: ACTIVATION_REFERENCE },
    ecdsa: { expectedKeyHandles: ['key-handle-1'] },
  });

  expect(parsed).toMatchObject({ ok: false });
});

test('keeps strict ECDSA finalize available through its explicit variant', () => {
  const parsed = parseWalletRegistrationFinalizeRequest({
    registrationCeremonyId: 'registration-ceremony-3',
    idempotencyKey: IDEMPOTENCY_KEY,
    kind: 'evm_family_ecdsa',
    ecdsa: { expectedKeyHandles: [' key-handle-3 '] },
  });

  expect(parsed).toEqual({
    ok: true,
    value: {
      registrationCeremonyId: 'registration-ceremony-3',
      idempotencyKey: IDEMPOTENCY_KEY,
      kind: 'evm_family_ecdsa',
      ecdsa: { expectedKeyHandles: ['key-handle-3'] },
    },
  });
});

test('rejects an Ed25519 finalize without its activation reference', () => {
  const parsed = parseWalletRegistrationFinalizeRequest({
    registrationCeremonyId: 'registration-ceremony-4',
    idempotencyKey: IDEMPOTENCY_KEY,
    kind: 'near_ed25519',
    ed25519: {},
  });

  expect(parsed).toEqual({
    ok: false,
    code: 'invalid_body',
    message: 'ed25519.activationReference is required',
  });
});

test('rejects caller-supplied Yao public receipts', () => {
  const parsed = parseWalletRegistrationFinalizeRequest({
    registrationCeremonyId: 'registration-ceremony-5',
    idempotencyKey: IDEMPOTENCY_KEY,
    kind: 'near_ed25519',
    ed25519: {
      activationReference: ACTIVATION_REFERENCE,
      public_receipt: { registered_public_key: Array.from({ length: 32 }, () => 7) },
    },
  });

  expect(parsed).toEqual({
    ok: false,
    code: 'invalid_body',
    message: 'ed25519.public_receipt is not supported',
  });
});

test('rejects the former un-discriminated ECDSA finalize shape', () => {
  const parsed = parseWalletRegistrationFinalizeRequest({
    registrationCeremonyId: 'registration-ceremony-6',
    idempotencyKey: IDEMPOTENCY_KEY,
    ecdsa: {},
  });

  expect(parsed).toEqual({
    ok: false,
    code: 'invalid_body',
    message: 'wallet registration finalize kind is invalid',
  });
});

test('rejects zero and malformed Yao activation session identifiers', () => {
  const zeroSession = parseWalletRegistrationFinalizeRequest({
    registrationCeremonyId: 'registration-ceremony-7',
    idempotencyKey: IDEMPOTENCY_KEY,
    kind: 'near_ed25519',
    ed25519: {
      activationReference: {
        ...ACTIVATION_REFERENCE,
        session_id: Array.from({ length: 32 }, () => 0),
      },
    },
  });
  const shortSession = parseWalletRegistrationFinalizeRequest({
    registrationCeremonyId: 'registration-ceremony-8',
    idempotencyKey: IDEMPOTENCY_KEY,
    kind: 'near_ed25519',
    ed25519: {
      activationReference: {
        ...ACTIVATION_REFERENCE,
        session_id: [1, 2, 3],
      },
    },
  });

  expect(zeroSession).toEqual({
    ok: false,
    code: 'invalid_body',
    message: 'ed25519.activationReference.session_id must be nonzero',
  });
  expect(shortSession).toEqual({
    ok: false,
    code: 'invalid_body',
    message: 'ed25519.activationReference.session_id must contain 32 bytes',
  });
});

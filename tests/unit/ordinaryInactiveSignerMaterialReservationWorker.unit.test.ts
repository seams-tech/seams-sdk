import { expect, test } from '@playwright/test';
import {
  createCloudflareOrdinaryInactiveSignerMaterialReservationServiceV1,
  createUnavailableOrdinaryInactiveSignerMaterialReservationWorkerV1,
  type CloudflareOrdinaryInactiveSignerMaterialReservationEndpointV1,
  CloudflareOrdinaryInactiveSignerMaterialReservationWorkerV1,
} from '../../packages/wallet-server/src/router/cloudflare/signingLanes/cloudflareOrdinaryInactiveSignerMaterialReservation';
import type {
  OrdinaryEcdsaSignerMaterialReservationRequestV1,
  OrdinaryEd25519SignerMaterialReservationRequestV1,
} from '../../packages/wallet-server/src/core/signingMaterial/ordinaryInactiveSignerMaterialReservation';
import {
  buildOrdinaryEcdsaClientMaterialFixture,
  buildOrdinaryEcdsaSignerFixture,
  buildOrdinaryEd25519ClientMaterialFixture,
  buildOrdinaryEd25519SignerFixture,
  buildOrdinaryEd25519ReservationPreparationFixture,
  buildOrdinaryEcdsaReservationPreparationFixture,
  buildOrdinaryMaterialActivationFixture,
} from './helpers/ordinarySignerMaterialReservation.fixtures';

class ReservationEndpointFixture implements CloudflareOrdinaryInactiveSignerMaterialReservationEndpointV1 {
  readonly ed25519Calls: OrdinaryEd25519SignerMaterialReservationRequestV1[] = [];
  readonly ecdsaCalls: OrdinaryEcdsaSignerMaterialReservationRequestV1[] = [];

  constructor(private readonly ecdsaRecipientPublicKey?: string) {}

  async reserveInactiveEd25519SignerMaterialV1(
    input: OrdinaryEd25519SignerMaterialReservationRequestV1,
  ): Promise<unknown> {
    this.ed25519Calls.push(input);
    return {
      kind: 'ordinary_ed25519_signer_material_worker_reservation_v1',
      keyFamily: 'ed25519',
      state: 'inactive',
      signer: input.signer,
      materialActivation: input.plannedActivationRef,
      clientMaterial: buildOrdinaryEd25519ClientMaterialFixture('worker-ed25519'),
      serverMaterialReservationId: 'server-reservation-ed25519',
    };
  }

  async reserveInactiveEcdsaSignerMaterialV1(
    input: OrdinaryEcdsaSignerMaterialReservationRequestV1,
  ): Promise<unknown> {
    this.ecdsaCalls.push(input);
    return {
      kind: 'ordinary_ecdsa_signer_material_worker_reservation_v1',
      keyFamily: 'ecdsa_secp256k1',
      state: 'inactive',
      signer: input.signer,
      materialActivation: input.plannedActivationRef,
      clientMaterial: buildOrdinaryEcdsaClientMaterialFixture(
        'worker-ecdsa',
        this.ecdsaRecipientPublicKey ?? input.preparation.registrationRequest.client_ephemeral_public_key,
        input.preparation.registrationRequest.signer_set.signer_a.key_epoch,
      ),
      serverMaterialReservationId: 'server-reservation-ecdsa',
    };
  }
}

test('ordinary Ed25519 reservation retries by exact activation ref without a second worker call', async () => {
  const endpoint = new ReservationEndpointFixture();
  const worker = new CloudflareOrdinaryInactiveSignerMaterialReservationWorkerV1(endpoint);
  const request = ed25519Request('ed25519', 'activation');

  const first = await worker.reserveInactiveEd25519SignerMaterialV1(request);
  const second = await worker.reserveInactiveEd25519SignerMaterialV1(request);

  expect(endpoint.ed25519Calls).toHaveLength(1);
  expect(first).toEqual(second);
  expect(first.state).toBe('inactive');
  expect(first.serverMaterialReservationId).toBe('server-reservation-ed25519');
});

test('ordinary ECDSA reservation keeps the exact inactive role envelopes', async () => {
  const endpoint = new ReservationEndpointFixture();
  const worker = new CloudflareOrdinaryInactiveSignerMaterialReservationWorkerV1(endpoint);
  const request = ecdsaRequest('ecdsa', 'activation');

  const result = await worker.reserveInactiveEcdsaSignerMaterialV1(request);
  const replay = await worker.reserveInactiveEcdsaSignerMaterialV1(request);

  expect(endpoint.ecdsaCalls).toHaveLength(1);
  expect(replay).toEqual(result);
  expect(result.state).toBe('inactive');
  expect(result.clientMaterial.deriver_a_client_package.recipient_role).toBe('signer_a');
  expect(result.clientMaterial.deriver_b_client_package.recipient_role).toBe('signer_b');
  expect(result.serverMaterialReservationId).toBe('server-reservation-ecdsa');
});

test('ordinary ECDSA reservation rejects a Deriver-recipient package', async () => {
  const endpoint = new ReservationEndpointFixture(`x25519:${'11'.repeat(32)}`);
  const worker = new CloudflareOrdinaryInactiveSignerMaterialReservationWorkerV1(endpoint);
  const request = ecdsaRequest('ecdsa-deriver-recipient', 'activation');

  await expect(worker.reserveInactiveEcdsaSignerMaterialV1(request)).rejects.toThrow(
    'browser client recipient',
  );
});

test('ordinary reservation rejects a conflicting signer for an existing activation ref', async () => {
  const endpoint = new ReservationEndpointFixture();
  const worker = new CloudflareOrdinaryInactiveSignerMaterialReservationWorkerV1(endpoint);
  const first = ed25519Request('first', 'same-activation');
  const conflicting = ed25519Request('conflicting', 'same-activation');

  await worker.reserveInactiveEd25519SignerMaterialV1(first);
  await expect(worker.reserveInactiveEd25519SignerMaterialV1(conflicting)).rejects.toThrow(
    'conflicts for activation ref',
  );
  expect(endpoint.ed25519Calls).toHaveLength(1);
});

test('ordinary reservation service composes with the validated worker adapter', async () => {
  const endpoint = new ReservationEndpointFixture();
  const service = createCloudflareOrdinaryInactiveSignerMaterialReservationServiceV1({ endpoint });
  const request = ecdsaRequest('service', 'activation');

  const result = await service.reserveOrdinaryInactiveSignerMaterialV1(request);

  expect(result.kind).toBe('ordinary_ecdsa_signer_material_reservation_v1');
  expect(result.state).toBe('inactive');
  expect(result.serverMaterial.reservationId).toBe('server-reservation-ecdsa');
  expect(result).not.toHaveProperty('activatedAtMs');
  expect(result).not.toHaveProperty('activationReceipt');
});

test('unavailable ordinary reservation worker fails closed without an activation fallback', async () => {
  const worker = createUnavailableOrdinaryInactiveSignerMaterialReservationWorkerV1();

  await expect(
    worker.reserveInactiveEd25519SignerMaterialV1(ed25519Request('unavailable-ed', 'activation')),
  ).rejects.toThrow('refusing activation fallback');
  await expect(
    worker.reserveInactiveEcdsaSignerMaterialV1(ecdsaRequest('unavailable-ecdsa', 'activation')),
  ).rejects.toThrow('refusing activation fallback');
});

function ed25519Request(
  signerLabel: string,
  activationLabel: string,
): OrdinaryEd25519SignerMaterialReservationRequestV1 {
  return {
    kind: 'ordinary_ed25519_signer_material_reservation_request_v1',
    keyFamily: 'ed25519',
    signer: buildOrdinaryEd25519SignerFixture(signerLabel),
    plannedActivationRef: buildOrdinaryMaterialActivationFixture(activationLabel),
    preparation: buildOrdinaryEd25519ReservationPreparationFixture(
      activationLabel,
      buildOrdinaryMaterialActivationFixture(activationLabel),
    ),
  };
}

function ecdsaRequest(
  signerLabel: string,
  activationLabel: string,
): OrdinaryEcdsaSignerMaterialReservationRequestV1 {
  return {
    kind: 'ordinary_ecdsa_signer_material_reservation_request_v1',
    keyFamily: 'ecdsa_secp256k1',
    signer: buildOrdinaryEcdsaSignerFixture(signerLabel),
    plannedActivationRef: buildOrdinaryMaterialActivationFixture(activationLabel),
    preparation: buildOrdinaryEcdsaReservationPreparationFixture(
      activationLabel,
      buildOrdinaryMaterialActivationFixture(activationLabel),
    ),
  };
}

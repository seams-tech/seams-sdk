import { expect, test } from '@playwright/test';
import {
  OrdinaryInactiveSignerMaterialReservationServiceV1,
  type OrdinaryEd25519SignerMaterialReservationRequestV1,
  type OrdinaryEd25519SignerMaterialWorkerReservationV1,
  type OrdinaryEcdsaSignerMaterialReservationRequestV1,
  type OrdinaryEcdsaSignerMaterialWorkerReservationV1,
  type OrdinaryInactiveSignerMaterialReservationWorkerPortV1,
} from '../../packages/wallet-server/src/core/signingMaterial/ordinaryInactiveSignerMaterialReservation';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { CommittedEcdsaSignerPackageV1 } from '../../packages/shared-ts/src/device-linking/committedSignerPackages';
import {
  buildOrdinaryEcdsaClientMaterialFixture,
  buildOrdinaryEcdsaSignerFixture,
  buildOrdinaryEd25519ClientMaterialFixture,
  buildOrdinaryEd25519SignerFixture,
  buildOrdinaryMaterialActivationFixture,
} from './helpers/ordinarySignerMaterialReservation.fixtures';

class IdempotentWorkerFixture implements OrdinaryInactiveSignerMaterialReservationWorkerPortV1 {
  readonly ed25519Calls: OrdinaryEd25519SignerMaterialReservationRequestV1[] = [];
  readonly ecdsaCalls: OrdinaryEcdsaSignerMaterialReservationRequestV1[] = [];
  private readonly ed25519Reservations = new Map<
    string,
    OrdinaryEd25519SignerMaterialWorkerReservationV1
  >();
  private readonly ecdsaReservations = new Map<
    string,
    OrdinaryEcdsaSignerMaterialWorkerReservationV1
  >();

  constructor(
    private readonly activationOverride: MpcMaterialActivationRef | null = null,
    private readonly serverReservationId = 'server-reservation-1',
  ) {}

  async reserveInactiveEd25519SignerMaterialV1(
    input: OrdinaryEd25519SignerMaterialReservationRequestV1,
  ): Promise<OrdinaryEd25519SignerMaterialWorkerReservationV1> {
    this.ed25519Calls.push(input);
    const key = activationKey(input.plannedActivationRef);
    const existing = this.ed25519Reservations.get(key);
    if (existing) return existing;
    const reservation: OrdinaryEd25519SignerMaterialWorkerReservationV1 = {
      kind: 'ordinary_ed25519_signer_material_worker_reservation_v1',
      keyFamily: 'ed25519',
      state: 'inactive',
      signer: input.signer,
      materialActivation: this.activationOverride ?? input.plannedActivationRef,
      clientMaterial: buildOrdinaryEd25519ClientMaterialFixture('ed25519'),
      serverMaterialReservationId: this.serverReservationId,
    };
    this.ed25519Reservations.set(key, reservation);
    return reservation;
  }

  async reserveInactiveEcdsaSignerMaterialV1(
    input: OrdinaryEcdsaSignerMaterialReservationRequestV1,
  ): Promise<OrdinaryEcdsaSignerMaterialWorkerReservationV1> {
    this.ecdsaCalls.push(input);
    const key = activationKey(input.plannedActivationRef);
    const existing = this.ecdsaReservations.get(key);
    if (existing) return existing;
    const reservation: OrdinaryEcdsaSignerMaterialWorkerReservationV1 = {
      kind: 'ordinary_ecdsa_signer_material_worker_reservation_v1',
      keyFamily: 'ecdsa_secp256k1',
      state: 'inactive',
      signer: input.signer,
      materialActivation: this.activationOverride ?? input.plannedActivationRef,
      clientMaterial: buildOrdinaryEcdsaClientMaterialFixture('ecdsa'),
      serverMaterialReservationId: this.serverReservationId,
    };
    this.ecdsaReservations.set(key, reservation);
    return reservation;
  }
}

test('reserves inactive Ed25519 material and reuses the exact activation reservation', async () => {
  const worker = new IdempotentWorkerFixture();
  const service = new OrdinaryInactiveSignerMaterialReservationServiceV1(worker);
  const request: OrdinaryEd25519SignerMaterialReservationRequestV1 = {
    kind: 'ordinary_ed25519_signer_material_reservation_request_v1',
    keyFamily: 'ed25519',
    signer: buildOrdinaryEd25519SignerFixture('ed25519'),
    plannedActivationRef: buildOrdinaryMaterialActivationFixture('ed25519'),
  };

  const first = await service.reserveOrdinaryInactiveSignerMaterialV1(request);
  const second = await service.reserveOrdinaryInactiveSignerMaterialV1(request);

  expect(worker.ed25519Calls).toHaveLength(2);
  expect(worker.ed25519Calls[0].plannedActivationRef).toBe(request.plannedActivationRef);
  expect(first).toEqual(second);
  expect(first.state).toBe('inactive');
  expect(first.serverMaterial.reservationId).toBe('server-reservation-1');
  expect(first).not.toHaveProperty('activatedAtMs');
  expect(first).not.toHaveProperty('activationReceipt');
});

test('reserves inactive ECDSA material in the committed role-envelope shape', async () => {
  const worker = new IdempotentWorkerFixture();
  const service = new OrdinaryInactiveSignerMaterialReservationServiceV1(worker);
  const request: OrdinaryEcdsaSignerMaterialReservationRequestV1 = {
    kind: 'ordinary_ecdsa_signer_material_reservation_request_v1',
    keyFamily: 'ecdsa_secp256k1',
    signer: buildOrdinaryEcdsaSignerFixture('ecdsa'),
    plannedActivationRef: buildOrdinaryMaterialActivationFixture('ecdsa'),
  };

  const result = await service.reserveOrdinaryInactiveSignerMaterialV1(request);

  expect(worker.ecdsaCalls).toHaveLength(1);
  expect(result.keyFamily).toBe('ecdsa_secp256k1');
  expect(result.clientMaterial.kind).toBe('ordinary_ecdsa_client_material_v1');
  expect(result.clientMaterial.deriver_a_client_package.recipient_role).toBe('signer_a');
  expect(result.clientMaterial.deriver_b_client_package.recipient_role).toBe('signer_b');
  expect(result.serverMaterial.reservationId).toBe('server-reservation-1');

  const committed: CommittedEcdsaSignerPackageV1 = {
    kind: 'committed_ecdsa_signer_package_v1',
    materialActivation: result.materialActivation,
    deriver_a_client_package: result.clientMaterial.deriver_a_client_package,
    deriver_b_client_package: result.clientMaterial.deriver_b_client_package,
  };
  expect(committed.deriver_a_client_package.recipient_role).toBe('signer_a');
});

test('rejects a worker response for a different planned activation reference', async () => {
  const worker = new IdempotentWorkerFixture(buildOrdinaryMaterialActivationFixture('other'));
  const service = new OrdinaryInactiveSignerMaterialReservationServiceV1(worker);
  const request: OrdinaryEd25519SignerMaterialReservationRequestV1 = {
    kind: 'ordinary_ed25519_signer_material_reservation_request_v1',
    keyFamily: 'ed25519',
    signer: buildOrdinaryEd25519SignerFixture('ed25519-mismatch'),
    plannedActivationRef: buildOrdinaryMaterialActivationFixture('ed25519-mismatch'),
  };

  await expect(service.reserveOrdinaryInactiveSignerMaterialV1(request)).rejects.toThrow(
    'activation ref does not match',
  );
});

function activationKey(ref: MpcMaterialActivationRef): string {
  return [
    ref.activationId,
    ref.capability,
    ref.materialOwner,
    ref.keyBinding,
    ref.lifecycleBinding,
    ref.signingWorker,
  ].join('|');
}

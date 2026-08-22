import type {
  ExactAdministeredEcdsaSignerV1,
  ExactAdministeredEd25519SignerV1,
} from '@shared/device-linking/delegatedActivationPlan';
import {
  parseExactAdministeredSignerManifestV1,
  type ExactAdministeredSignerManifestV1,
} from '@shared/device-linking/delegatedActivationPlan';
import {
  parseRouterAbEcdsaDerivationRoleEncryptedEnvelopeV1,
  parseRouterAbEcdsaRegistrationRequestV1,
  type RouterAbEcdsaRegistrationRequestV1,
  type RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { requireRouterAbX25519PublicKey } from '@shared/utils/routerAbPublicKeyset';
import {
  parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1,
  parseRouterAbEd25519YaoActivationPublicReceiptV1,
  parseRouterAbEd25519YaoParticipantIdsV1,
  type RouterAbEd25519YaoActivationPublicReceiptV1,
  parseRouterAbEd25519YaoEncryptedPackageV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationClientPackageV1,
} from '@shared/utils/routerAbEd25519Yao';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  hasWhitespaceOrControlCharacters,
  mpcMaterialActivationRefsEqual,
  parseMpcMaterialActivationRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';

export type OrdinarySignerFamilyV1 = 'ed25519' | 'ecdsa_secp256k1';
type OrdinarySignerByFamilyV1 = {
  readonly ed25519: ExactAdministeredEd25519SignerV1;
  readonly ecdsa_secp256k1: ExactAdministeredEcdsaSignerV1;
};

export type OrdinaryEd25519ClientMaterialV1 = {
  readonly kind: 'ordinary_ed25519_client_material_v1';
  readonly deriver_a_client_package: RouterAbEd25519YaoActivationClientPackageV1<'deriver_a'>;
  readonly deriver_b_client_package: RouterAbEd25519YaoActivationClientPackageV1<'deriver_b'>;
};

export type OrdinaryEcdsaClientMaterialV1 = {
  readonly kind: 'ordinary_ecdsa_client_material_v1';
  readonly deriver_a_client_package: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_a'>;
  readonly deriver_b_client_package: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_b'>;
};

type OrdinaryClientMaterialByFamilyV1 = {
  readonly ed25519: OrdinaryEd25519ClientMaterialV1;
  readonly ecdsa_secp256k1: OrdinaryEcdsaClientMaterialV1;
};
type OrdinaryRequestKindByFamilyV1 = {
  readonly ed25519: 'ordinary_ed25519_signer_material_reservation_request_v1';
  readonly ecdsa_secp256k1: 'ordinary_ecdsa_signer_material_reservation_request_v1';
};
type OrdinaryWorkerKindByFamilyV1 = {
  readonly ed25519: 'ordinary_ed25519_signer_material_worker_reservation_v1';
  readonly ecdsa_secp256k1: 'ordinary_ecdsa_signer_material_worker_reservation_v1';
};
type OrdinaryReservationKindByFamilyV1 = {
  readonly ed25519: 'ordinary_ed25519_signer_material_reservation_v1';
  readonly ecdsa_secp256k1: 'ordinary_ecdsa_signer_material_reservation_v1';
};

type OrdinaryReservationFieldsV1<F extends OrdinarySignerFamilyV1> = {
  readonly keyFamily: F;
  readonly state: 'inactive';
  readonly signer: OrdinarySignerByFamilyV1[F];
  readonly materialActivation: MpcMaterialActivationRef;
  readonly clientMaterial: OrdinaryClientMaterialByFamilyV1[F];
} & (F extends 'ed25519'
  ? {
      readonly activationReceipt: RouterAbEd25519YaoActivationPublicReceiptV1;
      readonly participantIds: readonly [number, number];
    }
  : { readonly activationReceipt?: never; readonly participantIds?: never });

export type OrdinaryInactiveServerMaterialReservationIdV1 = string & {
  readonly __ordinaryInactiveServerMaterialReservationIdBrand: unique symbol;
};

export type OrdinaryInactiveServerMaterialV1 = {
  readonly kind: 'ordinary_inactive_server_material_v1';
  readonly reservationId: OrdinaryInactiveServerMaterialReservationIdV1;
};

export type OrdinaryEd25519SignerMaterialReservationPreparationV1 = {
  readonly kind: 'ordinary_ed25519_signer_material_reservation_preparation_v1';
  readonly activationRequest: RouterAbEd25519YaoActivationExecuteRequestV1<'registration'>;
  readonly participantIds: readonly [number, number];
};

export type OrdinaryEcdsaSignerMaterialReservationPreparationV1 = {
  readonly kind: 'ordinary_ecdsa_signer_material_reservation_preparation_v1';
  readonly registrationRequest: RouterAbEcdsaRegistrationRequestV1;
  readonly materialActivation: MpcMaterialActivationRef;
};

export type OrdinaryEd25519SignerMaterialReservationRequestV1 =
  OrdinarySignerMaterialReservationRequestV1<'ed25519'>;
export type OrdinaryEcdsaSignerMaterialReservationRequestV1 =
  OrdinarySignerMaterialReservationRequestV1<'ecdsa_secp256k1'>;
export type OrdinaryInactiveSignerMaterialReservationRequestV1 =
  | OrdinaryEd25519SignerMaterialReservationRequestV1
  | OrdinaryEcdsaSignerMaterialReservationRequestV1;

type OrdinarySignerMaterialReservationRequestV1<F extends OrdinarySignerFamilyV1> = {
  readonly kind: OrdinaryRequestKindByFamilyV1[F];
  readonly keyFamily: F;
  readonly signer: OrdinarySignerByFamilyV1[F];
  readonly plannedActivationRef: MpcMaterialActivationRef;
  readonly preparation: F extends 'ed25519'
    ? OrdinaryEd25519SignerMaterialReservationPreparationV1
    : OrdinaryEcdsaSignerMaterialReservationPreparationV1;
};

export type OrdinaryEd25519SignerMaterialWorkerReservationV1 =
  OrdinarySignerMaterialWorkerReservationV1<'ed25519'>;
export type OrdinaryEcdsaSignerMaterialWorkerReservationV1 =
  OrdinarySignerMaterialWorkerReservationV1<'ecdsa_secp256k1'>;

type OrdinarySignerMaterialWorkerReservationV1<F extends OrdinarySignerFamilyV1> =
  OrdinaryReservationFieldsV1<F> & {
    readonly kind: OrdinaryWorkerKindByFamilyV1[F];
    readonly serverMaterialReservationId: string;
    readonly activatedAtMs?: never;
  };

export type OrdinaryEd25519SignerMaterialReservationV1 =
  OrdinarySignerMaterialReservationV1<'ed25519'>;
export type OrdinaryEcdsaSignerMaterialReservationV1 =
  OrdinarySignerMaterialReservationV1<'ecdsa_secp256k1'>;
export type OrdinaryInactiveSignerMaterialReservationV1 =
  | OrdinaryEd25519SignerMaterialReservationV1
  | OrdinaryEcdsaSignerMaterialReservationV1;

type OrdinarySignerMaterialReservationV1<F extends OrdinarySignerFamilyV1> =
  OrdinaryReservationFieldsV1<F> & {
    readonly kind: OrdinaryReservationKindByFamilyV1[F];
    readonly serverMaterial: OrdinaryInactiveServerMaterialV1;
    readonly activatedAtMs?: never;
  };

/** The worker adapter must reserve by the exact ref and leave material inactive. */
export type OrdinaryInactiveSignerMaterialReservationWorkerPortV1 = {
  reserveInactiveEd25519SignerMaterialV1(
    input: OrdinaryEd25519SignerMaterialReservationRequestV1,
  ): Promise<OrdinaryEd25519SignerMaterialWorkerReservationV1>;
  reserveInactiveEcdsaSignerMaterialV1(
    input: OrdinaryEcdsaSignerMaterialReservationRequestV1,
  ): Promise<OrdinaryEcdsaSignerMaterialWorkerReservationV1>;
};

type OrdinarySignerMaterialDeactivationKindByFamilyV1 = {
  readonly ed25519: 'ordinary_ed25519_signer_material_deactivation_v1';
  readonly ecdsa_secp256k1: 'ordinary_ecdsa_signer_material_deactivation_v1';
};

type OrdinarySignerMaterialDeactivationRequestV1<F extends OrdinarySignerFamilyV1> = {
  readonly keyFamily: F;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly requestedAtMs: number;
};

export type OrdinaryEd25519SignerMaterialDeactivationRequestV1 =
  OrdinarySignerMaterialDeactivationRequestV1<'ed25519'>;
export type OrdinaryEcdsaSignerMaterialDeactivationRequestV1 =
  OrdinarySignerMaterialDeactivationRequestV1<'ecdsa_secp256k1'>;
export type OrdinaryInactiveSignerMaterialDeactivationRequestV1 =
  | OrdinaryEd25519SignerMaterialDeactivationRequestV1
  | OrdinaryEcdsaSignerMaterialDeactivationRequestV1;

type OrdinarySignerMaterialDeactivationResultV1<F extends OrdinarySignerFamilyV1> = {
  readonly kind: OrdinarySignerMaterialDeactivationKindByFamilyV1[F];
  readonly keyFamily: F;
  readonly state: 'revoked';
  readonly materialActivation: MpcMaterialActivationRef;
  readonly serverMaterialReservationId: OrdinaryInactiveServerMaterialReservationIdV1;
  readonly revokedAtMs: number;
};

export type OrdinaryEd25519SignerMaterialDeactivationResultV1 =
  OrdinarySignerMaterialDeactivationResultV1<'ed25519'>;
export type OrdinaryEcdsaSignerMaterialDeactivationResultV1 =
  OrdinarySignerMaterialDeactivationResultV1<'ecdsa_secp256k1'>;
export type OrdinaryInactiveSignerMaterialDeactivationResultV1 =
  | OrdinaryEd25519SignerMaterialDeactivationResultV1
  | OrdinaryEcdsaSignerMaterialDeactivationResultV1;

/** Deactivation is a terminal exact-family/ref operation; it never activates material. */
export type OrdinaryInactiveSignerMaterialDeactivationPortV1 = {
  deactivateOrdinarySignerMaterialV1(
    input: OrdinaryInactiveSignerMaterialDeactivationRequestV1,
  ): Promise<void>;
};

export function validateOrdinaryInactiveSignerMaterialDeactivationRequestV1(
  request: OrdinaryInactiveSignerMaterialDeactivationRequestV1,
): void {
  if (!Number.isSafeInteger(request.requestedAtMs) || request.requestedAtMs < 0) {
    throw new Error('ordinary signer material deactivation time is invalid');
  }
  const materialActivation = parseMpcMaterialActivationRef(request.materialActivation);
  if (!materialActivation.ok) {
    throw new Error(
      `ordinary signer material deactivation ref: ${materialActivation.error.message}`,
    );
  }
  switch (request.keyFamily) {
    case 'ed25519':
    case 'ecdsa_secp256k1':
      return;
    default:
      return assertNever(request);
  }
}

export function parseOrdinaryEd25519SignerMaterialDeactivationResultV1(
  request: OrdinaryEd25519SignerMaterialDeactivationRequestV1,
  raw: unknown,
): OrdinaryEd25519SignerMaterialDeactivationResultV1 {
  return parseOrdinarySignerMaterialDeactivationResultV1(
    request,
    raw,
    'ed25519',
    'ordinary_ed25519_signer_material_deactivation_v1',
  );
}

export function parseOrdinaryEcdsaSignerMaterialDeactivationResultV1(
  request: OrdinaryEcdsaSignerMaterialDeactivationRequestV1,
  raw: unknown,
): OrdinaryEcdsaSignerMaterialDeactivationResultV1 {
  return parseOrdinarySignerMaterialDeactivationResultV1(
    request,
    raw,
    'ecdsa_secp256k1',
    'ordinary_ecdsa_signer_material_deactivation_v1',
  );
}

function parseOrdinarySignerMaterialDeactivationResultV1<F extends OrdinarySignerFamilyV1>(
  request: OrdinarySignerMaterialDeactivationRequestV1<F>,
  raw: unknown,
  expectedFamily: F,
  expectedKind: OrdinarySignerMaterialDeactivationKindByFamilyV1[F],
): OrdinarySignerMaterialDeactivationResultV1<F> {
  const result = exactRecord(
    raw,
    [
      'kind',
      'keyFamily',
      'state',
      'materialActivation',
      'serverMaterialReservationId',
      'revokedAtMs',
    ],
    `ordinary ${expectedFamily} signer material deactivation`,
  );
  if (
    result.kind !== expectedKind ||
    result.keyFamily !== expectedFamily ||
    result.state !== 'revoked'
  ) {
    throw new Error(`ordinary ${expectedFamily} deactivation returned the wrong terminal state`);
  }
  const materialActivation = parseWorkerMaterialActivationV1(result.materialActivation);
  assertMaterialActivationMatchesV1(request.materialActivation, materialActivation);
  if (
    typeof result.revokedAtMs !== 'number' ||
    !Number.isSafeInteger(result.revokedAtMs) ||
    result.revokedAtMs < 0
  ) {
    throw new Error(`ordinary ${expectedFamily} deactivation timestamp is invalid`);
  }
  return {
    kind: expectedKind,
    keyFamily: expectedFamily,
    state: 'revoked',
    materialActivation,
    serverMaterialReservationId: parseServerMaterialReservationIdV1(
      result.serverMaterialReservationId,
    ),
    revokedAtMs: result.revokedAtMs,
  };
}

export class OrdinaryInactiveSignerMaterialReservationServiceV1 {
  constructor(private readonly worker: OrdinaryInactiveSignerMaterialReservationWorkerPortV1) {}

  async reserveOrdinaryInactiveSignerMaterialV1(
    request: OrdinaryInactiveSignerMaterialReservationRequestV1,
  ): Promise<OrdinaryInactiveSignerMaterialReservationV1> {
    validateOrdinaryInactiveSignerMaterialReservationRequestV1(request);
    switch (request.kind) {
      case 'ordinary_ed25519_signer_material_reservation_request_v1':
        return this.reserveEd25519V1(request);
      case 'ordinary_ecdsa_signer_material_reservation_request_v1':
        return this.reserveEcdsaV1(request);
      default:
        return assertNever(request);
    }
  }

  private async reserveEd25519V1(
    request: OrdinaryEd25519SignerMaterialReservationRequestV1,
  ): Promise<OrdinaryEd25519SignerMaterialReservationV1> {
    const reservation = parseOrdinaryEd25519SignerMaterialWorkerReservationV1(
      request,
      await this.worker.reserveInactiveEd25519SignerMaterialV1(request),
    );
    return {
      kind: 'ordinary_ed25519_signer_material_reservation_v1',
      keyFamily: 'ed25519',
      state: 'inactive',
      signer: request.signer,
      materialActivation: request.plannedActivationRef,
      activationReceipt: reservation.activationReceipt,
      participantIds: reservation.participantIds,
      clientMaterial: reservation.clientMaterial,
      serverMaterial: buildServerMaterialV1(reservation.serverMaterialReservationId),
    };
  }

  private async reserveEcdsaV1(
    request: OrdinaryEcdsaSignerMaterialReservationRequestV1,
  ): Promise<OrdinaryEcdsaSignerMaterialReservationV1> {
    const reservation = parseOrdinaryEcdsaSignerMaterialWorkerReservationV1(
      request,
      await this.worker.reserveInactiveEcdsaSignerMaterialV1(request),
    );
    return {
      kind: 'ordinary_ecdsa_signer_material_reservation_v1',
      keyFamily: 'ecdsa_secp256k1',
      state: 'inactive',
      signer: request.signer,
      materialActivation: request.plannedActivationRef,
      clientMaterial: reservation.clientMaterial,
      serverMaterial: buildServerMaterialV1(reservation.serverMaterialReservationId),
    };
  }
}

export function validateOrdinaryInactiveSignerMaterialReservationRequestV1(
  request: OrdinaryInactiveSignerMaterialReservationRequestV1,
): void {
  switch (request.kind) {
    case 'ordinary_ed25519_signer_material_reservation_request_v1': {
      if (
        request.preparation.kind !== 'ordinary_ed25519_signer_material_reservation_preparation_v1'
      ) {
        throw new Error('ordinary Ed25519 reservation preparation kind is invalid');
      }
      const parsed = parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1(
        request.preparation.activationRequest,
      );
      if (!parsed.ok) {
        throw new Error(`ordinary Ed25519 reservation preparation: ${parsed.message}`);
      }
      assertMaterialActivationMatchesV1(
        request.plannedActivationRef,
        routerAbMpcMaterialActivationRefFromWire(parsed.value.binding.material_activation),
      );
      parseRouterAbEd25519YaoParticipantIdsV1(request.preparation.participantIds);
      return;
    }
    case 'ordinary_ecdsa_signer_material_reservation_request_v1':
      if (
        request.preparation.kind !== 'ordinary_ecdsa_signer_material_reservation_preparation_v1'
      ) {
        throw new Error('ordinary ECDSA reservation preparation kind is invalid');
      }
      parseRouterAbEcdsaRegistrationRequestV1(request.preparation.registrationRequest);
      assertMaterialActivationMatchesV1(
        request.plannedActivationRef,
        request.preparation.materialActivation,
      );
      return;
    default:
      return assertNever(request);
  }
}

export function createOrdinaryInactiveSignerMaterialReservationServiceV1(input: {
  readonly worker: OrdinaryInactiveSignerMaterialReservationWorkerPortV1;
}): OrdinaryInactiveSignerMaterialReservationServiceV1 {
  return new OrdinaryInactiveSignerMaterialReservationServiceV1(input.worker);
}

export function parseOrdinaryEd25519SignerMaterialWorkerReservationV1(
  request: OrdinaryEd25519SignerMaterialReservationRequestV1,
  raw: unknown,
): OrdinaryEd25519SignerMaterialWorkerReservationV1 {
  const reservation = exactRecord(
    raw,
    [
      'kind',
      'keyFamily',
      'state',
      'signer',
      'materialActivation',
      'participantIds',
      'activationReceipt',
      'clientMaterial',
      'serverMaterialReservationId',
    ],
    'ordinary Ed25519 worker reservation',
  );
  if (
    reservation.kind !== 'ordinary_ed25519_signer_material_worker_reservation_v1' ||
    reservation.keyFamily !== 'ed25519' ||
    reservation.state !== 'inactive'
  ) {
    throw new Error('ordinary Ed25519 worker returned the wrong reservation family');
  }
  const signer = parseEd25519SignerV1(reservation.signer, request.signer);
  const materialActivation = parseWorkerMaterialActivationV1(reservation.materialActivation);
  assertEd25519SignerMatchesV1(request.signer, signer);
  assertMaterialActivationMatchesV1(request.plannedActivationRef, materialActivation);
  const participantIds = parseRouterAbEd25519YaoParticipantIdsV1(reservation.participantIds);
  if (
    participantIds[0] !== request.preparation.participantIds[0] ||
    participantIds[1] !== request.preparation.participantIds[1]
  ) {
    throw new Error('ordinary Ed25519 worker reservation participant ids do not match the request');
  }
  const activationReceipt = parseRouterAbEd25519YaoActivationPublicReceiptV1(
    reservation.activationReceipt,
  );
  assertMaterialActivationMatchesV1(
    request.plannedActivationRef,
    routerAbMpcMaterialActivationRefFromWire(activationReceipt.material_activation),
  );
  const clientMaterial = parseEd25519ClientMaterialV1(reservation.clientMaterial);
  if (
    !sameBytes(activationReceipt.transcript, clientMaterial.deriver_a_client_package.transcript) ||
    !sameBytes(activationReceipt.transcript, clientMaterial.deriver_b_client_package.transcript)
  ) {
    throw new Error('ordinary Ed25519 worker receipt transcript does not match client packages');
  }
  return {
    kind: 'ordinary_ed25519_signer_material_worker_reservation_v1',
    keyFamily: 'ed25519',
    state: 'inactive',
    signer,
    materialActivation,
    activationReceipt,
    participantIds,
    clientMaterial,
    serverMaterialReservationId: parseServerMaterialReservationIdV1(
      reservation.serverMaterialReservationId,
    ),
  };
}

export function parseOrdinaryEcdsaSignerMaterialWorkerReservationV1(
  request: OrdinaryEcdsaSignerMaterialReservationRequestV1,
  raw: unknown,
): OrdinaryEcdsaSignerMaterialWorkerReservationV1 {
  const reservation = exactRecord(
    raw,
    [
      'kind',
      'keyFamily',
      'state',
      'signer',
      'materialActivation',
      'clientMaterial',
      'serverMaterialReservationId',
    ],
    'ordinary ECDSA worker reservation',
  );
  if (
    reservation.kind !== 'ordinary_ecdsa_signer_material_worker_reservation_v1' ||
    reservation.keyFamily !== 'ecdsa_secp256k1' ||
    reservation.state !== 'inactive'
  ) {
    throw new Error('ordinary ECDSA worker returned the wrong reservation family');
  }
  const signer = parseEcdsaSignerV1(reservation.signer, request.signer);
  const materialActivation = parseWorkerMaterialActivationV1(reservation.materialActivation);
  assertEcdsaSignerMatchesV1(request.signer, signer);
  assertMaterialActivationMatchesV1(request.plannedActivationRef, materialActivation);
  return {
    kind: 'ordinary_ecdsa_signer_material_worker_reservation_v1',
    keyFamily: 'ecdsa_secp256k1',
    state: 'inactive',
    signer,
    materialActivation,
    clientMaterial: parseEcdsaClientMaterialV1(
      reservation.clientMaterial,
      request.preparation.registrationRequest,
    ),
    serverMaterialReservationId: parseServerMaterialReservationIdV1(
      reservation.serverMaterialReservationId,
    ),
  };
}

function parseEd25519SignerV1(
  raw: unknown,
  expected: ExactAdministeredEd25519SignerV1,
): ExactAdministeredEd25519SignerV1 {
  const manifest = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ed25519'],
    signers: [raw],
  });
  if (!isEd25519Manifest(manifest)) {
    throw new Error('ordinary Ed25519 worker reservation signer has the wrong family');
  }
  assertEd25519SignerMatchesV1(expected, manifest.signers[0]);
  return manifest.signers[0];
}

function parseEcdsaSignerV1(
  raw: unknown,
  expected: ExactAdministeredEcdsaSignerV1,
): ExactAdministeredEcdsaSignerV1 {
  const manifest = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ecdsa_secp256k1'],
    signers: [raw],
  });
  if (!isEcdsaManifest(manifest)) {
    throw new Error('ordinary ECDSA worker reservation signer has the wrong family');
  }
  assertEcdsaSignerMatchesV1(expected, manifest.signers[0]);
  return manifest.signers[0];
}

function parseWorkerMaterialActivationV1(raw: unknown): MpcMaterialActivationRef {
  const parsed = parseMpcMaterialActivationRef(raw);
  if (!parsed.ok) throw new Error(`worker material activation: ${parsed.error.message}`);
  return parsed.value;
}

function parseEd25519ClientMaterialV1(raw: unknown): OrdinaryEd25519ClientMaterialV1 {
  const record = exactRecord(
    raw,
    ['kind', 'deriver_a_client_package', 'deriver_b_client_package'],
    'ordinary Ed25519 client material',
  );
  if (record.kind !== 'ordinary_ed25519_client_material_v1') {
    throw new Error('ordinary Ed25519 client material kind is invalid');
  }
  return {
    kind: 'ordinary_ed25519_client_material_v1',
    deriver_a_client_package: parseEd25519ClientPackageV1(
      record.deriver_a_client_package,
      'deriver_a_client_package',
      'deriver_a',
    ),
    deriver_b_client_package: parseEd25519ClientPackageV1(
      record.deriver_b_client_package,
      'deriver_b_client_package',
      'deriver_b',
    ),
  };
}

function parseEcdsaClientMaterialV1(
  raw: unknown,
  registration: RouterAbEcdsaRegistrationRequestV1,
): OrdinaryEcdsaClientMaterialV1 {
  const record = exactRecord(
    raw,
    ['kind', 'deriver_a_client_package', 'deriver_b_client_package'],
    'ordinary ECDSA client material',
  );
  if (record.kind !== 'ordinary_ecdsa_client_material_v1') {
    throw new Error('ordinary ECDSA client material kind is invalid');
  }
  return {
    kind: 'ordinary_ecdsa_client_material_v1',
    deriver_a_client_package: parseEcdsaClientPackageV1(
      record.deriver_a_client_package,
      'deriver_a_client_package',
      'signer_a',
      registration.signer_set.signer_a.key_epoch,
      registration.client_ephemeral_public_key,
    ),
    deriver_b_client_package: parseEcdsaClientPackageV1(
      record.deriver_b_client_package,
      'deriver_b_client_package',
      'signer_b',
      registration.signer_set.signer_b.key_epoch,
      registration.client_ephemeral_public_key,
    ),
  };
}

function parseEcdsaClientPackageV1<Role extends 'signer_a' | 'signer_b'>(
  raw: unknown,
  label: string,
  expectedRole: Role,
  expectedKeyEpoch: string,
  expectedRecipientPublicKey: string,
): RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<Role> {
  const packageValue = parseRouterAbEcdsaDerivationRoleEncryptedEnvelopeV1(
    raw,
    label,
    expectedRole,
  );
  const payload = parseEcdsaSignerEnvelopePayloadV1(packageValue.ciphertext.bytes, label);
  if (
    payload.recipientRole !== expectedRole ||
    payload.keyEpoch !== expectedKeyEpoch ||
    payload.recipientPublicKey !==
      requireRouterAbX25519PublicKey(
        expectedRecipientPublicKey,
        `${label}.expectedRecipientPublicKey`,
      )
  ) {
    throw new Error(`${label} is not sealed for the browser client recipient`);
  }
  if (!sameBytes(payload.aadDigest, packageValue.aad_digest.bytes)) {
    throw new Error(`${label} payload AAD digest differs from its envelope`);
  }
  return packageValue;
}

type EcdsaSignerEnvelopePayloadV1 = {
  readonly recipientRole: 'signer_a' | 'signer_b';
  readonly keyEpoch: string;
  readonly recipientPublicKey: string;
  readonly aadDigest: readonly number[];
};

type EcdsaPayloadCursorV1 = {
  readonly bytes: readonly number[];
  offset: number;
};

function parseEcdsaSignerEnvelopePayloadV1(
  bytes: readonly number[],
  label: string,
): EcdsaSignerEnvelopePayloadV1 {
  const cursor: EcdsaPayloadCursorV1 = { bytes, offset: 0 };
  const version = readEcdsaPayloadTextV1(cursor, label, 'version');
  if (version !== 'router-ab-protocol/signer-envelope-hpke/v1') {
    throw new Error(`${label} payload version is invalid`);
  }
  const algorithm = readEcdsaPayloadTextV1(cursor, label, 'algorithm');
  if (algorithm !== 'hpke-x25519-hkdf-sha256-aes256gcm/v1') {
    throw new Error(`${label} payload algorithm is invalid`);
  }
  const recipientRole = readEcdsaPayloadTextV1(cursor, label, 'recipientRole');
  if (recipientRole !== 'signer_a' && recipientRole !== 'signer_b') {
    throw new Error(`${label} payload recipient role is invalid`);
  }
  const keyEpoch = readEcdsaPayloadTextV1(cursor, label, 'keyEpoch');
  const recipientPublicKey = readEcdsaPayloadTextV1(cursor, label, 'recipientPublicKey');
  requireRouterAbX25519PublicKey(recipientPublicKey, `${label}.payload.recipientPublicKey`);
  const aadDigest = readEcdsaPayloadBytesV1(cursor, label, 'aadDigest');
  if (aadDigest.length !== 32) throw new Error(`${label} payload AAD digest is invalid`);
  const encappedKey = readEcdsaPayloadBytesV1(cursor, label, 'encappedKey');
  if (encappedKey.length !== 32) throw new Error(`${label} payload encapsulated key is invalid`);
  if (readEcdsaPayloadU32V1(cursor, label, 'tagLength') !== 16) {
    throw new Error(`${label} payload tag length is invalid`);
  }
  const ciphertext = readEcdsaPayloadBytesV1(cursor, label, 'ciphertext');
  if (ciphertext.length <= 16 || cursor.offset !== bytes.length) {
    throw new Error(`${label} payload ciphertext is invalid`);
  }
  return { recipientRole, keyEpoch, recipientPublicKey, aadDigest };
}

function readEcdsaPayloadTextV1(
  cursor: EcdsaPayloadCursorV1,
  label: string,
  field: string,
): string {
  const bytes = readEcdsaPayloadBytesV1(cursor, label, field);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
  } catch {
    throw new Error(`${label} payload ${field} is not valid UTF-8`);
  }
}

function readEcdsaPayloadBytesV1(
  cursor: EcdsaPayloadCursorV1,
  label: string,
  field: string,
): readonly number[] {
  const length = readEcdsaPayloadU32V1(cursor, label, `${field}.length`);
  const end = cursor.offset + length;
  if (!Number.isSafeInteger(end) || end > cursor.bytes.length) {
    throw new Error(`${label} payload ${field} is truncated`);
  }
  const value = cursor.bytes.slice(cursor.offset, end);
  cursor.offset = end;
  return value;
}

function readEcdsaPayloadU32V1(cursor: EcdsaPayloadCursorV1, label: string, field: string): number {
  const end = cursor.offset + 4;
  if (end > cursor.bytes.length) throw new Error(`${label} payload ${field} is truncated`);
  const value =
    cursor.bytes[cursor.offset]! * 0x1000000 +
    cursor.bytes[cursor.offset + 1]! * 0x10000 +
    cursor.bytes[cursor.offset + 2]! * 0x100 +
    cursor.bytes[cursor.offset + 3]!;
  cursor.offset = end;
  return value;
}

function sameBytes(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function parseEd25519ClientPackageV1<Role extends 'deriver_a' | 'deriver_b'>(
  raw: unknown,
  label: string,
  expectedRole: Role,
): RouterAbEd25519YaoActivationClientPackageV1<Role> {
  const parsed = parseRouterAbEd25519YaoEncryptedPackageV1(raw);
  if (!parsed.ok) throw new Error(`${label} ${parsed.message}`);
  if (parsed.value.kind !== 'activation_client' || parsed.value.deriver !== expectedRole) {
    throw new Error(`${label} must be an activation_client for ${expectedRole}`);
  }
  return {
    kind: 'activation_client',
    deriver: expectedRole,
    session: parsed.value.session,
    transcript: parsed.value.transcript,
    encapsulated_key: parsed.value.encapsulated_key,
    ciphertext: parsed.value.ciphertext,
  };
}

function exactRecord(
  raw: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`${label} must be an object`);
  }
  const record = Object.fromEntries(Object.entries(raw));
  const expected = new Set(keys);
  const actual = Object.keys(record);
  if (
    actual.length !== keys.length ||
    actual.some((key) => !expected.has(key)) ||
    keys.some((key) => !Object.prototype.hasOwnProperty.call(record, key))
  ) {
    throw new Error(`${label} contains unexpected fields`);
  }
  return record;
}

function isEd25519Manifest(
  manifest: ExactAdministeredSignerManifestV1,
): manifest is Extract<
  ExactAdministeredSignerManifestV1,
  { readonly keyFamilies: readonly ['ed25519'] }
> {
  return manifest.keyFamilies.length === 1 && manifest.keyFamilies[0] === 'ed25519';
}

function isEcdsaManifest(
  manifest: ExactAdministeredSignerManifestV1,
): manifest is Extract<
  ExactAdministeredSignerManifestV1,
  { readonly keyFamilies: readonly ['ecdsa_secp256k1'] }
> {
  return manifest.keyFamilies.length === 1 && manifest.keyFamilies[0] === 'ecdsa_secp256k1';
}

function assertEd25519SignerMatchesV1(
  expected: ExactAdministeredEd25519SignerV1,
  actual: ExactAdministeredEd25519SignerV1,
): void {
  if (
    actual.kind !== expected.kind ||
    actual.keyFamily !== expected.keyFamily ||
    actual.walletId !== expected.walletId ||
    actual.walletKeyId !== expected.walletKeyId ||
    actual.registeredPublicKeyB64u !== expected.registeredPublicKeyB64u
  ) {
    throw new Error('ordinary Ed25519 worker reservation signer does not match the request');
  }
}

function assertEcdsaSignerMatchesV1(
  expected: ExactAdministeredEcdsaSignerV1,
  actual: ExactAdministeredEcdsaSignerV1,
): void {
  if (
    actual.kind !== expected.kind ||
    actual.keyFamily !== expected.keyFamily ||
    actual.walletId !== expected.walletId ||
    actual.walletKeyId !== expected.walletKeyId ||
    actual.thresholdPublicKey33B64u !== expected.thresholdPublicKey33B64u ||
    actual.evmAddress !== expected.evmAddress
  ) {
    throw new Error('ordinary ECDSA worker reservation signer does not match the request');
  }
}

function assertMaterialActivationMatchesV1(
  expected: MpcMaterialActivationRef,
  actual: MpcMaterialActivationRef,
): void {
  if (!mpcMaterialActivationRefsEqual(expected, actual)) {
    throw new Error('ordinary signer material worker reservation activation ref does not match');
  }
}

function buildServerMaterialV1(
  serverMaterialReservationId: string,
): OrdinaryInactiveServerMaterialV1 {
  return {
    kind: 'ordinary_inactive_server_material_v1',
    reservationId: parseServerMaterialReservationIdV1(serverMaterialReservationId),
  };
}

function parseServerMaterialReservationIdV1(
  value: unknown,
): OrdinaryInactiveServerMaterialReservationIdV1 {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.trim() !== value ||
    hasWhitespaceOrControlCharacters(value)
  ) {
    throw new Error('ordinary signer material worker reservation id is invalid');
  }
  return value as OrdinaryInactiveServerMaterialReservationIdV1;
}

function assertNever(value: never): never {
  throw new Error(`unsupported ordinary signer material reservation request: ${String(value)}`);
}

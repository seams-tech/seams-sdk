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
  type RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  parseRouterAbEd25519YaoEncryptedPackageV1,
  type RouterAbEd25519YaoActivationClientPackageV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  hasWhitespaceOrControlCharacters,
  mpcMaterialActivationRefsEqual,
  parseMpcMaterialActivationRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';

type OrdinarySignerFamilyV1 = 'ed25519' | 'ecdsa_secp256k1';
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
};

export type OrdinaryInactiveServerMaterialReservationIdV1 = string & {
  readonly __ordinaryInactiveServerMaterialReservationIdBrand: unique symbol;
};

export type OrdinaryInactiveServerMaterialV1 = {
  readonly kind: 'ordinary_inactive_server_material_v1';
  readonly reservationId: OrdinaryInactiveServerMaterialReservationIdV1;
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
    readonly activationReceipt?: never;
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
    readonly activationReceipt?: never;
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

export class OrdinaryInactiveSignerMaterialReservationServiceV1 {
  constructor(private readonly worker: OrdinaryInactiveSignerMaterialReservationWorkerPortV1) {}

  async reserveOrdinaryInactiveSignerMaterialV1(
    request: OrdinaryInactiveSignerMaterialReservationRequestV1,
  ): Promise<OrdinaryInactiveSignerMaterialReservationV1> {
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
    const reservation = parseEd25519WorkerReservationV1(
      request,
      await this.worker.reserveInactiveEd25519SignerMaterialV1(request),
    );
    return {
      kind: 'ordinary_ed25519_signer_material_reservation_v1',
      keyFamily: 'ed25519',
      state: 'inactive',
      signer: request.signer,
      materialActivation: request.plannedActivationRef,
      clientMaterial: reservation.clientMaterial,
      serverMaterial: buildServerMaterialV1(reservation.serverMaterialReservationId),
    };
  }

  private async reserveEcdsaV1(
    request: OrdinaryEcdsaSignerMaterialReservationRequestV1,
  ): Promise<OrdinaryEcdsaSignerMaterialReservationV1> {
    const reservation = parseEcdsaWorkerReservationV1(
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

export function createOrdinaryInactiveSignerMaterialReservationServiceV1(input: {
  readonly worker: OrdinaryInactiveSignerMaterialReservationWorkerPortV1;
}): OrdinaryInactiveSignerMaterialReservationServiceV1 {
  return new OrdinaryInactiveSignerMaterialReservationServiceV1(input.worker);
}

function parseEd25519WorkerReservationV1(
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
  return {
    kind: 'ordinary_ed25519_signer_material_worker_reservation_v1',
    keyFamily: 'ed25519',
    state: 'inactive',
    signer,
    materialActivation,
    clientMaterial: parseEd25519ClientMaterialV1(reservation.clientMaterial),
    serverMaterialReservationId: parseServerMaterialReservationIdV1(
      reservation.serverMaterialReservationId,
    ),
  };
}

function parseEcdsaWorkerReservationV1(
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
    clientMaterial: parseEcdsaClientMaterialV1(reservation.clientMaterial),
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

function parseEcdsaClientMaterialV1(raw: unknown): OrdinaryEcdsaClientMaterialV1 {
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
    deriver_a_client_package: parseRouterAbEcdsaDerivationRoleEncryptedEnvelopeV1(
      record.deriver_a_client_package,
      'deriver_a_client_package',
      'signer_a',
    ),
    deriver_b_client_package: parseRouterAbEcdsaDerivationRoleEncryptedEnvelopeV1(
      record.deriver_b_client_package,
      'deriver_b_client_package',
      'signer_b',
    ),
  };
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
): manifest is Extract<ExactAdministeredSignerManifestV1, { readonly keyFamilies: readonly ['ed25519'] }> {
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

import {
  createOrdinaryInactiveSignerMaterialReservationServiceV1,
  parseOrdinaryEcdsaSignerMaterialDeactivationResultV1,
  parseOrdinaryEd25519SignerMaterialDeactivationResultV1,
  parseOrdinaryEcdsaSignerMaterialWorkerReservationV1,
  parseOrdinaryEd25519SignerMaterialWorkerReservationV1,
  validateOrdinaryInactiveSignerMaterialDeactivationRequestV1,
  validateOrdinaryInactiveSignerMaterialReservationRequestV1,
  type OrdinaryEcdsaSignerMaterialReservationRequestV1,
  type OrdinaryEcdsaSignerMaterialDeactivationRequestV1,
  type OrdinaryEcdsaSignerMaterialWorkerReservationV1,
  type OrdinaryEd25519SignerMaterialReservationRequestV1,
  type OrdinaryEd25519SignerMaterialDeactivationRequestV1,
  type OrdinaryEd25519SignerMaterialWorkerReservationV1,
  type OrdinaryInactiveSignerMaterialDeactivationPortV1,
  type OrdinaryInactiveSignerMaterialDeactivationRequestV1,
  type OrdinaryInactiveSignerMaterialReservationServiceV1,
  type OrdinaryInactiveSignerMaterialReservationWorkerPortV1,
} from '../../../core/signingMaterial/ordinaryInactiveSignerMaterialReservation';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import {
  routerAbMpcMaterialActivationRefFromWire,
  routerAbMpcMaterialActivationRefToWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import type { OrdinaryInactiveSignerMaterialActivationPortV1 } from '../d1/deviceLinking/d1LinkedDeviceAuthorityInstallService';
import type {
  OrdinaryEcdsaSignerMaterialReservationPreparationV1,
  OrdinaryEd25519SignerMaterialReservationPreparationV1,
} from '../../../core/signingMaterial/ordinaryInactiveSignerMaterialReservation';

/** Dedicated SigningWorker paths implemented by the Cloudflare worker. */
export const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_RESERVE_INACTIVE_PATH_V1 =
  '/router-ab/signing-worker/ed25519-yao/reserve-inactive' as const;
export const CLOUDFLARE_SIGNING_WORKER_ECDSA_RESERVE_INACTIVE_PATH_V1 =
  '/router-ab/signing-worker/ecdsa-derivation/reserve-inactive' as const;
export const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_ACTIVATE_RESERVATION_PATH_V1 =
  '/router-ab/signing-worker/ed25519-yao/activate-reservation' as const;
export const CLOUDFLARE_SIGNING_WORKER_ECDSA_ACTIVATE_RESERVATION_PATH_V1 =
  '/router-ab/signing-worker/ecdsa-derivation/activate-reservation' as const;
export const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_DEACTIVATE_RESERVATION_PATH_V1 =
  '/router-ab/signing-worker/ed25519-yao/deactivate-reservation' as const;
export const CLOUDFLARE_SIGNING_WORKER_ECDSA_DEACTIVATE_RESERVATION_PATH_V1 =
  '/router-ab/signing-worker/ecdsa-derivation/deactivate-reservation' as const;

/**
 * Boundary for the dedicated ordinary reservation operation. Its response is
 * deliberately unknown until the core reservation parser has checked the
 * family, exact activation reference, inactive state, and package shape.
 * Implementations call one of the dedicated paths above; activation routes
 * are deliberately outside this port.
 */
export type CloudflareOrdinaryInactiveSignerMaterialReservationEndpointV1 = {
  reserveInactiveEd25519SignerMaterialV1(
    input: OrdinaryEd25519SignerMaterialReservationRequestV1,
  ): Promise<unknown>;
  reserveInactiveEcdsaSignerMaterialV1(
    input: OrdinaryEcdsaSignerMaterialReservationRequestV1,
  ): Promise<unknown>;
};

export type CloudflareOrdinaryInactiveSignerMaterialActivationEndpointV1 = {
  activateInactiveEd25519SignerMaterialV1(input: {
    readonly activationRequest: OrdinaryEd25519SignerMaterialReservationPreparationV1['activationRequest'];
    readonly reservationId: string;
  }): Promise<unknown>;
  activateInactiveEcdsaSignerMaterialV1(input: {
    readonly preparation: OrdinaryEcdsaSignerMaterialReservationPreparationV1;
    readonly reservationId: string;
  }): Promise<unknown>;
};

export type CloudflareOrdinaryInactiveSignerMaterialDeactivationEndpointV1 = {
  deactivateInactiveEd25519SignerMaterialV1(input: {
    readonly materialActivation: OrdinaryEd25519SignerMaterialDeactivationRequestV1['materialActivation'];
  }): Promise<unknown>;
  deactivateInactiveEcdsaSignerMaterialV1(input: {
    readonly materialActivation: OrdinaryEcdsaSignerMaterialDeactivationRequestV1['materialActivation'];
  }): Promise<unknown>;
};

export function createCloudflareOrdinaryInactiveSignerMaterialDeactivationEndpointV1(input: {
  readonly fetch: typeof fetch;
  readonly internalServiceAuthSecret: string;
}): CloudflareOrdinaryInactiveSignerMaterialDeactivationEndpointV1 {
  return {
    deactivateInactiveEd25519SignerMaterialV1: async ({ materialActivation }) =>
      await postDeactivationRequestV1(
        input,
        CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_DEACTIVATE_RESERVATION_PATH_V1,
        materialActivation,
        'ed25519',
      ),
    deactivateInactiveEcdsaSignerMaterialV1: async ({ materialActivation }) =>
      await postDeactivationRequestV1(
        input,
        CLOUDFLARE_SIGNING_WORKER_ECDSA_DEACTIVATE_RESERVATION_PATH_V1,
        materialActivation,
        'ecdsa_secp256k1',
      ),
  };
}

async function postDeactivationRequestV1(
  input: {
    readonly fetch: typeof fetch;
    readonly internalServiceAuthSecret: string;
  },
  path: string,
  materialActivation: MpcMaterialActivationRef,
  keyFamily: 'ed25519' | 'ecdsa_secp256k1',
): Promise<unknown> {
  const response = await input.fetch(
    new Request(`https://signing-worker.router-ab.internal${path}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-router-ab-internal-service-auth': input.internalServiceAuthSecret,
      },
      body: JSON.stringify({
        material_activation: routerAbMpcMaterialActivationRefToWire(materialActivation),
      }),
    }),
  );
  if (!response.ok) {
    throw new Error(`ordinary ${keyFamily} material deactivation failed with HTTP ${response.status}`);
  }
  let raw: unknown;
  try {
    raw = await response.json();
  } catch {
    throw new Error(`ordinary ${keyFamily} material deactivation returned invalid JSON`);
  }
  return parseDeactivationResponseV1(raw, keyFamily);
}

function parseDeactivationResponseV1(
  raw: unknown,
  keyFamily: 'ed25519' | 'ecdsa_secp256k1',
): Record<string, unknown> {
  if (
    !isRecordV1(raw) ||
    !hasExactKeysV1(raw, ['state', 'reservation_id', 'material_activation', 'revoked_at_ms']) ||
    raw.state !== 'revoked' ||
    typeof raw.reservation_id !== 'string' ||
    typeof raw.revoked_at_ms !== 'number'
  ) {
    throw new Error(`ordinary ${keyFamily} material deactivation response is invalid`);
  }
  return {
    kind: keyFamily === 'ed25519'
      ? 'ordinary_ed25519_signer_material_deactivation_v1'
      : 'ordinary_ecdsa_signer_material_deactivation_v1',
    keyFamily,
    state: 'revoked',
    materialActivation: routerAbMpcMaterialActivationRefFromWire(raw.material_activation),
    serverMaterialReservationId: raw.reservation_id,
    revokedAtMs: raw.revoked_at_ms,
  };
}

function isRecordV1(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeysV1(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

type CachedEd25519ReservationV1 = {
  readonly requestFingerprint: string;
  readonly reservation: OrdinaryEd25519SignerMaterialWorkerReservationV1;
};

type CachedEcdsaReservationV1 = {
  readonly requestFingerprint: string;
  readonly reservation: OrdinaryEcdsaSignerMaterialWorkerReservationV1;
};

/**
 * Adapter for the ordinary inactive reservation endpoint. The endpoint owns
 * durable idempotency; this process-local journal prevents a retry from
 * silently changing the request while preserving the endpoint's exact result.
 */
export class CloudflareOrdinaryInactiveSignerMaterialReservationWorkerV1 implements OrdinaryInactiveSignerMaterialReservationWorkerPortV1 {
  private readonly ed25519Reservations = new Map<string, CachedEd25519ReservationV1>();
  private readonly ecdsaReservations = new Map<string, CachedEcdsaReservationV1>();

  constructor(
    private readonly endpoint: CloudflareOrdinaryInactiveSignerMaterialReservationEndpointV1,
  ) {}

  async reserveInactiveEd25519SignerMaterialV1(
    input: OrdinaryEd25519SignerMaterialReservationRequestV1,
  ): Promise<OrdinaryEd25519SignerMaterialWorkerReservationV1> {
    validateOrdinaryInactiveSignerMaterialReservationRequestV1(input);
    const activationKey = materialActivationKeyV1(input.plannedActivationRef);
    const requestFingerprint = ed25519RequestFingerprintV1(input);
    const cached = this.ed25519Reservations.get(activationKey);
    if (cached) {
      assertSameReservationRequestV1(cached.requestFingerprint, requestFingerprint, 'Ed25519');
      return cached.reservation;
    }
    const raw = await this.endpoint.reserveInactiveEd25519SignerMaterialV1(input);
    const reservation = parseOrdinaryEd25519SignerMaterialWorkerReservationV1(input, raw);
    this.ed25519Reservations.set(activationKey, { requestFingerprint, reservation });
    return reservation;
  }

  async reserveInactiveEcdsaSignerMaterialV1(
    input: OrdinaryEcdsaSignerMaterialReservationRequestV1,
  ): Promise<OrdinaryEcdsaSignerMaterialWorkerReservationV1> {
    validateOrdinaryInactiveSignerMaterialReservationRequestV1(input);
    const activationKey = materialActivationKeyV1(input.plannedActivationRef);
    const requestFingerprint = ecdsaRequestFingerprintV1(input);
    const cached = this.ecdsaReservations.get(activationKey);
    if (cached) {
      assertSameReservationRequestV1(cached.requestFingerprint, requestFingerprint, 'ECDSA');
      return cached.reservation;
    }
    const raw = await this.endpoint.reserveInactiveEcdsaSignerMaterialV1(input);
    const reservation = parseOrdinaryEcdsaSignerMaterialWorkerReservationV1(input, raw);
    this.ecdsaReservations.set(activationKey, { requestFingerprint, reservation });
    return reservation;
  }
}

export function createCloudflareOrdinaryInactiveSignerMaterialReservationServiceV1(input: {
  readonly endpoint: CloudflareOrdinaryInactiveSignerMaterialReservationEndpointV1;
}): OrdinaryInactiveSignerMaterialReservationServiceV1 {
  return createOrdinaryInactiveSignerMaterialReservationServiceV1({
    worker: new CloudflareOrdinaryInactiveSignerMaterialReservationWorkerV1(input.endpoint),
  });
}

export class CloudflareOrdinaryInactiveSignerMaterialDeactivationWorkerV1 implements OrdinaryInactiveSignerMaterialDeactivationPortV1 {
  private readonly terminalOperations = new Map<string, Promise<void>>();

  constructor(
    private readonly endpoint: CloudflareOrdinaryInactiveSignerMaterialDeactivationEndpointV1,
  ) {}

  async deactivateOrdinarySignerMaterialV1(
    input: OrdinaryInactiveSignerMaterialDeactivationRequestV1,
  ): Promise<void> {
    validateOrdinaryInactiveSignerMaterialDeactivationRequestV1(input);
    const operationKey = `${input.keyFamily}:${materialActivationKeyV1(input.materialActivation)}`;
    const existing = this.terminalOperations.get(operationKey);
    if (existing) return existing;
    const operation = this.performDeactivationV1(input);
    this.terminalOperations.set(operationKey, operation);
    try {
      await operation;
    } catch (error) {
      this.terminalOperations.delete(operationKey);
      throw error;
    }
  }

  private async performDeactivationV1(
    input: OrdinaryInactiveSignerMaterialDeactivationRequestV1,
  ): Promise<void> {
    switch (input.keyFamily) {
      case 'ed25519': {
        const raw = await this.endpoint.deactivateInactiveEd25519SignerMaterialV1({
          materialActivation: input.materialActivation,
        });
        parseOrdinaryEd25519SignerMaterialDeactivationResultV1(input, raw);
        return;
      }
      case 'ecdsa_secp256k1': {
        const raw = await this.endpoint.deactivateInactiveEcdsaSignerMaterialV1({
          materialActivation: input.materialActivation,
        });
        parseOrdinaryEcdsaSignerMaterialDeactivationResultV1(input, raw);
        return;
      }
      default:
        return assertNever(input);
    }
  }
}

export function createCloudflareOrdinaryInactiveSignerMaterialDeactivationPortV1(input: {
  readonly endpoint: CloudflareOrdinaryInactiveSignerMaterialDeactivationEndpointV1;
}): OrdinaryInactiveSignerMaterialDeactivationPortV1 {
  return new CloudflareOrdinaryInactiveSignerMaterialDeactivationWorkerV1(input.endpoint);
}

export class UnavailableOrdinaryInactiveSignerMaterialDeactivationWorkerV1 implements OrdinaryInactiveSignerMaterialDeactivationPortV1 {
  async deactivateOrdinarySignerMaterialV1(
    _input: OrdinaryInactiveSignerMaterialDeactivationRequestV1,
  ): Promise<void> {
    throw ordinaryReservationEndpointUnavailableErrorV1();
  }
}

export function createUnavailableOrdinaryInactiveSignerMaterialDeactivationPortV1(): OrdinaryInactiveSignerMaterialDeactivationPortV1 {
  return new UnavailableOrdinaryInactiveSignerMaterialDeactivationWorkerV1();
}

export function createCloudflareOrdinaryInactiveSignerMaterialActivationPortV1(input: {
  readonly endpoint: CloudflareOrdinaryInactiveSignerMaterialActivationEndpointV1;
}): OrdinaryInactiveSignerMaterialActivationPortV1 {
  return new CloudflareOrdinaryInactiveSignerMaterialActivationWorkerV1(input.endpoint);
}

/** Explicit fail-closed port for deployments without a configured endpoint. */
export class UnavailableOrdinaryInactiveSignerMaterialReservationWorkerV1 implements OrdinaryInactiveSignerMaterialReservationWorkerPortV1 {
  async reserveInactiveEd25519SignerMaterialV1(
    _input: OrdinaryEd25519SignerMaterialReservationRequestV1,
  ): Promise<OrdinaryEd25519SignerMaterialWorkerReservationV1> {
    throw ordinaryReservationEndpointUnavailableErrorV1();
  }

  async reserveInactiveEcdsaSignerMaterialV1(
    _input: OrdinaryEcdsaSignerMaterialReservationRequestV1,
  ): Promise<OrdinaryEcdsaSignerMaterialWorkerReservationV1> {
    throw ordinaryReservationEndpointUnavailableErrorV1();
  }
}

export function createUnavailableOrdinaryInactiveSignerMaterialReservationWorkerV1(): OrdinaryInactiveSignerMaterialReservationWorkerPortV1 {
  return new UnavailableOrdinaryInactiveSignerMaterialReservationWorkerV1();
}

function materialActivationKeyV1(ref: MpcMaterialActivationRef): string {
  return JSON.stringify([
    ref.activationId,
    ref.capability,
    ref.materialOwner,
    ref.keyBinding,
    ref.lifecycleBinding,
    ref.signingWorker,
  ]);
}

function ed25519RequestFingerprintV1(
  input: OrdinaryEd25519SignerMaterialReservationRequestV1,
): string {
  return JSON.stringify([
    input.kind,
    input.keyFamily,
    input.signer.kind,
    input.signer.walletId,
    input.signer.walletKeyId,
    input.signer.registeredPublicKeyB64u,
    materialActivationKeyV1(input.plannedActivationRef),
    JSON.stringify(input.preparation),
  ]);
}

function ecdsaRequestFingerprintV1(input: OrdinaryEcdsaSignerMaterialReservationRequestV1): string {
  return JSON.stringify([
    input.kind,
    input.keyFamily,
    input.signer.kind,
    input.signer.walletId,
    input.signer.walletKeyId,
    input.signer.thresholdPublicKey33B64u,
    input.signer.evmAddress,
    materialActivationKeyV1(input.plannedActivationRef),
    JSON.stringify(input.preparation),
  ]);
}

function assertSameReservationRequestV1(
  expectedFingerprint: string,
  actualFingerprint: string,
  family: 'Ed25519' | 'ECDSA',
): void {
  if (expectedFingerprint === actualFingerprint) return;
  throw new Error(
    `ordinary inactive ${family} signer material reservation conflicts for activation ref`,
  );
}

function ordinaryReservationEndpointUnavailableErrorV1(): Error {
  return new Error(
    'ordinary inactive signer material reservation endpoint is unavailable; refusing activation fallback',
  );
}

function assertNever(value: never): never {
  throw new Error(`unsupported ordinary signer material family: ${String(value)}`);
}

class CloudflareOrdinaryInactiveSignerMaterialActivationWorkerV1 implements OrdinaryInactiveSignerMaterialActivationPortV1 {
  constructor(
    private readonly endpoint: CloudflareOrdinaryInactiveSignerMaterialActivationEndpointV1,
  ) {}

  async activateOrdinaryInactiveSignerMaterialV1(input: {
    readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
    readonly reservationId: string;
    readonly materialActivation: MpcMaterialActivationRef;
    readonly activatedAtMs: number;
    readonly preparation:
      | {
          readonly keyFamily: 'ed25519';
          readonly preparation: OrdinaryEd25519SignerMaterialReservationPreparationV1;
        }
      | {
          readonly keyFamily: 'ecdsa_secp256k1';
          readonly preparation: OrdinaryEcdsaSignerMaterialReservationPreparationV1;
        };
  }): Promise<void> {
    if (!Number.isSafeInteger(input.activatedAtMs) || input.activatedAtMs < 0) {
      throw new Error('ordinary signer material activation time is invalid');
    }
    if (input.keyFamily !== input.preparation.keyFamily) {
      throw new Error('ordinary signer material activation family does not match preparation');
    }
    if (input.preparation.keyFamily === 'ed25519') {
      const prepared = input.preparation.preparation;
      if (
        !mpcMaterialActivationRefsEqual(
          input.materialActivation,
          routerAbMpcMaterialActivationRefFromWire(
            prepared.activationRequest.binding.material_activation,
          ),
        )
      ) {
        throw new Error('ordinary Ed25519 activation reference does not match preparation');
      }
      await this.endpoint.activateInactiveEd25519SignerMaterialV1({
        activationRequest: prepared.activationRequest,
        reservationId: input.reservationId,
      });
      return;
    }
    const prepared = input.preparation.preparation;
    if (!mpcMaterialActivationRefsEqual(input.materialActivation, prepared.materialActivation)) {
      throw new Error('ordinary ECDSA activation reference does not match preparation');
    }
    await this.endpoint.activateInactiveEcdsaSignerMaterialV1({
      preparation: prepared,
      reservationId: input.reservationId,
    });
  }
}

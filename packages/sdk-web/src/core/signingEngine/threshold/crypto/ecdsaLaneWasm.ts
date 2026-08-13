import type {
  EcdsaAdditiveLaneHolderPreparationV1,
  EcdsaAdditiveLaneHolderRoundV1,
  EcdsaAdditiveLaneJobV1,
  EcdsaLaneProtocolWasmV1,
} from '@shared/signing-lanes/rotation';
import {
  parseEcdsaAdditiveLaneHolderRoundV1,
  parseLaneHolderPackageWireV1,
  parseRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import {
  executeWorkerOperation,
  type WorkerOperationContext,
} from '../../workerManager/executeWorkerOperation';
import {
  EcdsaDerivationClientCustomRequestType,
  EcdsaDerivationClientCustomResponseType,
} from '../../workerManager/workerTypes';

const ECDSA_LANE_PREPARATION_TIMEOUT_MS = 20_000;

function parseEcdsaJob(value: unknown): EcdsaAdditiveLaneJobV1 {
  const parsed = parseRotatableSigningLaneJobV1(value);
  if (parsed.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('ECDSA lane WASM requires an ECDSA lane job');
  }
  return parsed;
}

function assertEcdsaHolderRound(value: unknown): EcdsaAdditiveLaneHolderRoundV1 {
  return parseEcdsaAdditiveLaneHolderRoundV1(value);
}

function nonEmpty(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} is required`);
  return value;
}

export function parseEcdsaAdditiveLaneHolderPreparationV1(
  value: unknown,
): EcdsaAdditiveLaneHolderPreparationV1 {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('ECDSA holder preparation must be an object');
  }
  const allowed = new Set(['kind', 'holderRound', 'holderPackage', 'encryptedDeltaPackageJson']);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`ECDSA holder preparation.${key} is not allowed`);
  }
  const kind = Reflect.get(value, 'kind');
  if (kind !== 'ecdsa_additive_lane_holder_preparation_v1') {
    throw new Error('ECDSA holder preparation kind is invalid');
  }
  const holderPackage = parseLaneHolderPackageWireV1(Reflect.get(value, 'holderPackage'));
  if (holderPackage.kind !== 'ecdsa_additive_lane_holder_package_v1') {
    throw new Error('ECDSA holder preparation returned the wrong package family');
  }
  return {
    kind,
    holderRound: assertEcdsaHolderRound(Reflect.get(value, 'holderRound')),
    holderPackage,
    encryptedDeltaPackageJson: nonEmpty(
      Reflect.get(value, 'encryptedDeltaPackageJson'),
      'encryptedDeltaPackageJson',
    ),
  };
}

export async function prepareEcdsaAdditiveLaneHolderRoundV1(
  wasm: EcdsaLaneProtocolWasmV1,
  input: unknown,
): Promise<EcdsaAdditiveLaneHolderPreparationV1> {
  const job = parseEcdsaJob(input);
  return parseEcdsaAdditiveLaneHolderPreparationV1(
    await wasm.prepareEcdsaAdditiveLaneHolderRoundV1(job),
  );
}

export type EcdsaLaneWasmAdapterV1 = EcdsaLaneProtocolWasmV1;

export function createEcdsaLaneWasmAdapterV1(
  wasm: EcdsaLaneProtocolWasmV1,
): EcdsaLaneWasmAdapterV1 {
  return {
    async prepareEcdsaAdditiveLaneHolderRoundV1(input) {
      return await prepareEcdsaAdditiveLaneHolderRoundV1(wasm, input);
    },
  };
}

export const createEcdsaLaneWasmAdapter = createEcdsaLaneWasmAdapterV1;

export type EcdsaLaneDerivationWorkerWasmV1Config = {
  readonly workerCtx: WorkerOperationContext;
  readonly nowMs: () => number;
};

class EcdsaLaneDerivationWorkerWasmV1 implements EcdsaLaneProtocolWasmV1 {
  constructor(private readonly config: EcdsaLaneDerivationWorkerWasmV1Config) {}

  async prepareEcdsaAdditiveLaneHolderRoundV1(
    input: EcdsaAdditiveLaneJobV1,
  ): Promise<EcdsaAdditiveLaneHolderPreparationV1> {
    const job = parseEcdsaJob(input);
    const holderCommittedAtMs = this.config.nowMs();
    if (!Number.isSafeInteger(holderCommittedAtMs) || holderCommittedAtMs < 0) {
      throw new Error('ECDSA lane holder commitment time must be a non-negative safe integer');
    }
    const result = await executeWorkerOperation({
      ctx: this.config.workerCtx,
      kind: 'ecdsaDerivationClient',
      request: {
        type: EcdsaDerivationClientCustomRequestType.PrepareEcdsaAdditiveLaneHolder,
        payload: {
          kind: 'prepare_ecdsa_additive_lane_holder_v1',
          job,
          holderCommittedAtMs,
        },
        timeoutMs: ECDSA_LANE_PREPARATION_TIMEOUT_MS,
      },
    });
    if (
      result.type !== EcdsaDerivationClientCustomResponseType.PrepareEcdsaAdditiveLaneHolderSuccess
    ) {
      throw new Error('ECDSA derivation worker returned an unexpected lane response type');
    }
    return parseEcdsaAdditiveLaneHolderPreparationV1(result.payload);
  }
}

export function createEcdsaLaneDerivationWorkerWasmV1(
  config: EcdsaLaneDerivationWorkerWasmV1Config,
): EcdsaLaneProtocolWasmV1 {
  return new EcdsaLaneDerivationWorkerWasmV1(config);
}

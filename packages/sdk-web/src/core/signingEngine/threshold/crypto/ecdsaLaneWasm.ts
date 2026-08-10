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

function parseHolderPreparation(value: unknown): EcdsaAdditiveLaneHolderPreparationV1 {
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
  return parseHolderPreparation(await wasm.prepareEcdsaAdditiveLaneHolderRoundV1(job));
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

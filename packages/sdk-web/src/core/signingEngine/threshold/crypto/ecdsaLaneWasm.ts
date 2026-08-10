import type {
  EcdsaAdditiveLaneHolderRoundV1,
  EcdsaAdditiveLaneJobV1,
  EcdsaLaneProtocolWasmV1,
} from '@shared/signing-lanes/rotation';
import {
  parseEcdsaAdditiveLaneHolderRoundV1,
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

export async function prepareEcdsaAdditiveLaneHolderRoundV1(
  wasm: EcdsaLaneProtocolWasmV1,
  input: unknown,
): Promise<EcdsaAdditiveLaneHolderRoundV1> {
  const job = parseEcdsaJob(input);
  const round = await wasm.prepareEcdsaAdditiveLaneHolderRoundV1(job);
  return assertEcdsaHolderRound(round);
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

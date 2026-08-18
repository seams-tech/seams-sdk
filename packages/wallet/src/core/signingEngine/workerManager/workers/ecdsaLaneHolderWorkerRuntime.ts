import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import { parseEcdsaAdditiveLaneHolderPreparationV1 } from '../../threshold/crypto/ecdsaLaneWasm';
import type {
  PrepareEcdsaAdditiveLaneHolderRequestV1,
  PrepareEcdsaAdditiveLaneHolderResultV1,
} from '../ecdsaClientWorkerChannels';

export type CanonicalEcdsaLaneSourceMaterialV1 = {
  readonly materialActivation: MpcMaterialActivationRef;
  readonly stateBlobB64u: string;
};

export type EcdsaLaneHolderSessionPortV1 = {
  prepare(inputJson: string): string;
  free(): void;
};

export type EcdsaLaneHolderSessionFactoryV1 = {
  create(stateBlobB64u: string): EcdsaLaneHolderSessionPortV1;
};

export function resolveExactEcdsaLaneSourceMaterialV1(
  request: PrepareEcdsaAdditiveLaneHolderRequestV1,
  candidates: readonly CanonicalEcdsaLaneSourceMaterialV1[],
): CanonicalEcdsaLaneSourceMaterialV1 {
  const matches: CanonicalEcdsaLaneSourceMaterialV1[] = [];
  for (const candidate of candidates) {
    if (
      mpcMaterialActivationRefsEqual(
        candidate.materialActivation,
        request.job.source.materialActivation,
      )
    ) {
      matches.push(candidate);
    }
  }
  if (matches.length === 0) {
    throw new Error('ECDSA lane source material is not loaded for the exact activation');
  }
  if (matches.length !== 1) {
    throw new Error('ECDSA lane source activation resolves to multiple loaded materials');
  }
  return matches[0];
}

export function prepareEcdsaLaneHolderInWorkerV1(args: {
  readonly request: PrepareEcdsaAdditiveLaneHolderRequestV1;
  readonly candidates: readonly CanonicalEcdsaLaneSourceMaterialV1[];
  readonly sessionFactory: EcdsaLaneHolderSessionFactoryV1;
}): PrepareEcdsaAdditiveLaneHolderResultV1 {
  const source = resolveExactEcdsaLaneSourceMaterialV1(args.request, args.candidates);
  const session = args.sessionFactory.create(source.stateBlobB64u);
  try {
    const output = JSON.parse(
      session.prepare(
        JSON.stringify({
          job: args.request.job,
          holderCommittedAtMs: args.request.holderCommittedAtMs,
        }),
      ),
    );
    return parseEcdsaAdditiveLaneHolderPreparationV1(output);
  } finally {
    session.free();
  }
}

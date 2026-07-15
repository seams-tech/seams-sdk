import type { SelectedEcdsaLane } from '../../session/identity/laneIdentity';
import type { ThresholdOwnerAddress } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { SigningSessionPlan } from '../../session/operationState/types';
import type { EvmFamilyExecutorThresholdEcdsaState } from './transactionExecutor';

export type PreparedEvmFamilyPublicIdentityContinuity =
  | {
      kind: 'lane_identity_only';
      verifiedMaterialThresholdOwnerAddress?: never;
    }
  | {
      kind: 'verified_material_identity';
      verifiedMaterialThresholdOwnerAddress: ThresholdOwnerAddress;
    };

export function resolvePreparedEvmFamilyThresholdOwnerAddress(args: {
  laneThresholdOwnerAddress: ThresholdOwnerAddress;
  publicIdentityContinuity: PreparedEvmFamilyPublicIdentityContinuity;
}): ThresholdOwnerAddress {
  switch (args.publicIdentityContinuity.kind) {
    case 'lane_identity_only':
      return args.laneThresholdOwnerAddress;
    case 'verified_material_identity':
      if (
        args.publicIdentityContinuity.verifiedMaterialThresholdOwnerAddress !==
        args.laneThresholdOwnerAddress
      ) {
        throw new Error(
          '[SigningEngine][ecdsa] prepared material owner address does not match the exact signing lane',
        );
      }
      return args.laneThresholdOwnerAddress;
    default:
      args.publicIdentityContinuity satisfies never;
      throw new Error('[SigningEngine][ecdsa] unsupported prepared public identity state');
  }
}

export function buildPreparedEvmFamilyExecutorThresholdEcdsaState(args: {
  transactionLane: SelectedEcdsaLane;
  signingSessionPlan: SigningSessionPlan;
  laneThresholdOwnerAddress: ThresholdOwnerAddress;
  publicIdentityContinuity: PreparedEvmFamilyPublicIdentityContinuity;
}): Extract<EvmFamilyExecutorThresholdEcdsaState, { kind: 'prepared' }> {
  const thresholdOwnerAddress = resolvePreparedEvmFamilyThresholdOwnerAddress(args);
  return {
    kind: 'prepared',
    lane: args.transactionLane,
    signingSessionPlan: args.signingSessionPlan,
    thresholdOwnerAddress,
  };
}

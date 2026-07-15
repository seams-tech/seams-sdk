import type { ThresholdOwnerAddress } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { PreparedEvmFamilyPublicIdentityContinuity } from './executorThresholdState';

declare const thresholdOwnerAddress: ThresholdOwnerAddress;

const laneIdentityOnly: PreparedEvmFamilyPublicIdentityContinuity = {
  kind: 'lane_identity_only',
};
void laneIdentityOnly;

const verifiedMaterialIdentity: PreparedEvmFamilyPublicIdentityContinuity = {
  kind: 'verified_material_identity',
  verifiedMaterialThresholdOwnerAddress: thresholdOwnerAddress,
};
void verifiedMaterialIdentity;

// @ts-expect-error Lane-only continuity cannot carry unverified material identity.
const invalidLaneIdentityOnly: PreparedEvmFamilyPublicIdentityContinuity = {
  kind: 'lane_identity_only',
  verifiedMaterialThresholdOwnerAddress: thresholdOwnerAddress,
};
void invalidLaneIdentityOnly;

// @ts-expect-error Verified material continuity requires its exact owner address.
const invalidVerifiedMaterialIdentity: PreparedEvmFamilyPublicIdentityContinuity = {
  kind: 'verified_material_identity',
  verifiedMaterialThresholdOwnerAddress: undefined,
};
void invalidVerifiedMaterialIdentity;

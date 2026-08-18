import type { ProfileRecord } from '../../../packages/wallet/src/core/indexedDB/passkeyClientDB.types';
import type { NearProvisioningState } from '../../../packages/wallet/src/core/types/seams';

export function createNearProvisioningProfileRecordFixture(input: {
  readonly profileId: string;
  readonly nearProvisioning: NearProvisioningState | undefined;
  readonly existing: ProfileRecord | undefined;
}): ProfileRecord {
  return {
    profileId: input.profileId,
    defaultSignerSlot: input.existing?.defaultSignerSlot ?? 1,
    ...(input.nearProvisioning ? { nearProvisioning: input.nearProvisioning } : {}),
    createdAt: input.existing?.createdAt ?? 1,
    updatedAt: 2,
  };
}

import type { EcdsaRoleLocalReadyRecord } from '@/core/platform/types';
import type { HydratedEcdsaSignerMaterial } from '../../../session/identity/evmFamilyEcdsaIdentity';

declare const hydratedSignerMaterial: HydratedEcdsaSignerMaterial;
declare const roleLocalReadyRecord: EcdsaRoleLocalReadyRecord;

type OldRoleLocalReadyStateBlobShare = {
  kind: 'role_local_ready_state_blob';
  stateBlob: EcdsaRoleLocalReadyRecord['stateBlob'];
  ecdsaRoleLocalReadyRecord: EcdsaRoleLocalReadyRecord;
};

const validSignableSessionWithLoadedClientShare = {
  ...hydratedSignerMaterial,
  clientShare: hydratedSignerMaterial.clientShare,
} satisfies HydratedEcdsaSignerMaterial;
void validSignableSessionWithLoadedClientShare;

const oldRoleLocalReadyStateBlobShare = {
  kind: 'role_local_ready_state_blob',
  stateBlob: roleLocalReadyRecord.stateBlob,
  ecdsaRoleLocalReadyRecord: roleLocalReadyRecord,
} satisfies OldRoleLocalReadyStateBlobShare;

// @ts-expect-error final ECDSA signing requires worker-owned role-local material handles.
const invalidSignableRawRoleLocalBlobShare: HydratedEcdsaSignerMaterial['clientShare'] =
  oldRoleLocalReadyStateBlobShare;
void invalidSignableRawRoleLocalBlobShare;

export {};

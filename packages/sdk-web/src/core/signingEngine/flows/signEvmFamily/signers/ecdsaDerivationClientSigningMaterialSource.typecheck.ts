import type { EcdsaRoleLocalReadyRecord } from '@/core/platform/types';
import type { ReadyEcdsaSignerSession } from '../../../session/identity/evmFamilyEcdsaIdentity';
import type { SignableReadyEcdsaSignerSession } from './ecdsaDerivationClientSigningMaterialSource';

declare const readySignerSession: ReadyEcdsaSignerSession;
declare const signableReadySignerSession: SignableReadyEcdsaSignerSession;
declare const roleLocalReadyRecord: EcdsaRoleLocalReadyRecord;

type OldRoleLocalReadyStateBlobShare = {
  kind: 'role_local_ready_state_blob';
  stateBlob: EcdsaRoleLocalReadyRecord['stateBlob'];
  ecdsaRoleLocalReadyRecord: EcdsaRoleLocalReadyRecord;
};

const validSignableSessionWithLoadedClientShare = {
  ...readySignerSession,
  clientShare: signableReadySignerSession.clientShare,
} satisfies SignableReadyEcdsaSignerSession;
void validSignableSessionWithLoadedClientShare;

const oldRoleLocalReadyStateBlobShare = {
  kind: 'role_local_ready_state_blob',
  stateBlob: roleLocalReadyRecord.stateBlob,
  ecdsaRoleLocalReadyRecord: roleLocalReadyRecord,
} satisfies OldRoleLocalReadyStateBlobShare;

// @ts-expect-error final ECDSA signing requires worker-owned role-local material handles.
const invalidSignableRawRoleLocalBlobShare: SignableReadyEcdsaSignerSession['clientShare'] =
  oldRoleLocalReadyStateBlobShare;
void invalidSignableRawRoleLocalBlobShare;

export {};

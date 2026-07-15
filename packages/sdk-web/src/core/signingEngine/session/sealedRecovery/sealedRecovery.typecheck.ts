import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ExactEcdsaSigningLaneIdentity } from '../identity/exactSigningLaneIdentity';
import type { EcdsaThresholdKeyId } from '../keyMaterialBrands';
import type { RestorePersistedSessionForSigningInput } from './sealedRecovery.types';

declare const ecdsaLane: ExactEcdsaSigningLaneIdentity;
declare const ecdsaThresholdKeyId: EcdsaThresholdKeyId;
declare const chainTarget: ThresholdEcdsaChainTarget;

const ecdsaRestoreInput: RestorePersistedSessionForSigningInput = {
  walletId: String(ecdsaLane.signer.walletId),
  authMethod: ecdsaLane.auth.kind,
  signingGrantId: String(ecdsaLane.signingGrantId),
  thresholdSessionId: String(ecdsaLane.thresholdSessionId),
  reason: 'export',
  curve: 'ecdsa',
  chainTarget,
  materialRestoreIdentity: {
    kind: 'ecdsa_role_local_restore',
    lane: ecdsaLane,
    ecdsaThresholdKeyId,
  },
};
void ecdsaRestoreInput;

const invalidCurveRestore = {
  ...ecdsaRestoreInput,
  // @ts-expect-error Ed25519 has no sealed-material restore branch.
  curve: 'ed25519',
} satisfies RestorePersistedSessionForSigningInput;
void invalidCurveRestore;

const invalidMaterialRestore = {
  ...ecdsaRestoreInput,
  materialRestoreIdentity: {
    ...ecdsaRestoreInput.materialRestoreIdentity,
    // @ts-expect-error ECDSA restore accepts only role-local material identity.
    material: 'worker-material',
  },
} satisfies RestorePersistedSessionForSigningInput;
void invalidMaterialRestore;

export {};

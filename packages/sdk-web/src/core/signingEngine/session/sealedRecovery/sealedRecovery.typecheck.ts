import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ExactEcdsaSigningLaneIdentity,
  ExactEd25519SigningLaneIdentity,
} from '../identity/exactSigningLaneIdentity';
import type {
  EcdsaThresholdKeyId,
  Ed25519WorkerMaterialBindingDigest,
  Ed25519WorkerMaterialKeyId,
} from '../keyMaterialBrands';
import type { RestorePersistedSessionForSigningInput } from './sealedRecovery.types';

declare const ed25519Lane: ExactEd25519SigningLaneIdentity;
declare const ecdsaLane: ExactEcdsaSigningLaneIdentity;
declare const materialBindingDigest: Ed25519WorkerMaterialBindingDigest;
declare const materialKeyId: Ed25519WorkerMaterialKeyId;
declare const ecdsaThresholdKeyId: EcdsaThresholdKeyId;
declare const chainTarget: ThresholdEcdsaChainTarget;

const ed25519RestoreInput: RestorePersistedSessionForSigningInput = {
  walletId: String(ed25519Lane.signer.account.wallet.walletId),
  authMethod: ed25519Lane.auth.kind,
  signingGrantId: String(ed25519Lane.signingGrantId),
  thresholdSessionId: String(ed25519Lane.thresholdSessionId),
  reason: 'transaction',
  curve: 'ed25519',
  chain: 'near',
  materialRestoreIdentity: {
    kind: 'ed25519_worker_material_restore',
    lane: ed25519Lane,
    materialBindingDigest,
    materialKeyId,
  },
};
void ed25519RestoreInput;

// @ts-expect-error Ed25519 restore requires material binding and key identity.
const ed25519RestoreMissingMaterial: RestorePersistedSessionForSigningInput = {
  walletId: String(ed25519Lane.signer.account.wallet.walletId),
  authMethod: ed25519Lane.auth.kind,
  signingGrantId: String(ed25519Lane.signingGrantId),
  thresholdSessionId: String(ed25519Lane.thresholdSessionId),
  reason: 'transaction',
  curve: 'ed25519',
  chain: 'near',
};
void ed25519RestoreMissingMaterial;

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

const ecdsaRestoreWithEd25519Material: RestorePersistedSessionForSigningInput = {
  walletId: String(ecdsaLane.signer.walletId),
  authMethod: ecdsaLane.auth.kind,
  signingGrantId: String(ecdsaLane.signingGrantId),
  thresholdSessionId: String(ecdsaLane.thresholdSessionId),
  reason: 'export',
  curve: 'ecdsa',
  chainTarget,
  // @ts-expect-error ECDSA restore does not carry Ed25519 material digest.
  materialRestoreIdentity: {
    kind: 'ecdsa_role_local_restore',
    lane: ecdsaLane,
    ecdsaThresholdKeyId,
    materialBindingDigest,
  },
};
void ecdsaRestoreWithEd25519Material;

export {};

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
import type { Ed25519RestoreMaterialIdentity } from '../ed25519MaterialAuthority';
import type { RestorePersistedSessionForSigningInput } from './sealedRecovery.types';

declare const ed25519Lane: ExactEd25519SigningLaneIdentity;
declare const ecdsaLane: ExactEcdsaSigningLaneIdentity;
declare const materialBindingDigest: Ed25519WorkerMaterialBindingDigest;
declare const materialKeyId: Ed25519WorkerMaterialKeyId;
declare const resolvedRestoreMaterial: Ed25519RestoreMaterialIdentity;
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
    material: resolvedRestoreMaterial,
  },
};
void ed25519RestoreInput;

// @ts-expect-error Ed25519 restore requires a boundary-resolved material identity.
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

// A raw (unresolved) binding digest + key id pair is planning data, not a
// boundary-resolved identity — it must not satisfy the restore port. This is the
// type-level guarantee that lane snapshots and durable-cache identities cannot
// flow into a restore request without passing through
// resolveEd25519RestoreMaterialIdentity.
const ed25519RestoreWithRawSnapshot: RestorePersistedSessionForSigningInput = {
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
    // @ts-expect-error raw snapshot identities do not satisfy the resolved-material brand.
    material: { bindingDigest: materialBindingDigest, materialKeyId, source: 'live_record' },
  },
};
void ed25519RestoreWithRawSnapshot;

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
  // @ts-expect-error ECDSA restore does not carry Ed25519 restore material.
  materialRestoreIdentity: {
    kind: 'ecdsa_role_local_restore',
    lane: ecdsaLane,
    ecdsaThresholdKeyId,
    material: resolvedRestoreMaterial,
  },
};
void ecdsaRestoreWithEd25519Material;

export {};

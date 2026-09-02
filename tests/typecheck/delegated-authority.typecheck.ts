import {
  buildFullOwnerDelegatedWalletAuthorityV1,
  buildSigningOnlyDelegatedWalletAuthorityV1,
  parseDelegatedWalletPermissionSetV1,
  type CanonicalDelegatedWalletPermissionSetV1,
  type DelegatedWalletAuthorityV1,
} from '../../packages/shared-ts/src/authorization/delegatedAuthority';
import type {
  ExactAdministeredEd25519SignerV1,
  ExactAdministeredEcdsaSignerV1,
  ExactAdministeredSignerManifestV1,
} from '../../packages/shared-ts/src/device-linking/delegatedActivationPlan';

declare const ed25519: ExactAdministeredEd25519SignerV1;
declare const ecdsa: ExactAdministeredEcdsaSignerV1;
declare const permissionSet: CanonicalDelegatedWalletPermissionSetV1;

const fullOwner = buildFullOwnerDelegatedWalletAuthorityV1();
const signingOnly = buildSigningOnlyDelegatedWalletAuthorityV1();
void fullOwner;
void signingOnly;

const parsed = parseDelegatedWalletPermissionSetV1(['revoke_devices', 'sign']);
if (parsed.ok) {
  const authority: DelegatedWalletAuthorityV1 = {
    kind: 'delegated_wallet_authority_v1',
    permissions: parsed.value,
  };
  void authority;
}

const forgedPermissionSet: CanonicalDelegatedWalletPermissionSetV1 = {
  // @ts-expect-error Canonical permission sets cannot be forged as object literals.
  kind: 'canonical_delegated_wallet_permission_set_v1',
  permissions: ['sign'],
};
void forgedPermissionSet;

// @ts-expect-error Preset names are builder inputs, never persisted authority branches.
const legacyPresetAuthority: DelegatedWalletAuthorityV1 = { kind: 'full_owner' };
void legacyPresetAuthority;

const ed25519OnlyManifest: ExactAdministeredSignerManifestV1 = {
  kind: 'exact_administered_signer_manifest_v1',
  keyFamilies: ['ed25519'],
  signers: [ed25519],
};
const dualManifest: ExactAdministeredSignerManifestV1 = {
  kind: 'exact_administered_signer_manifest_v1',
  keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
  signers: [ed25519, ecdsa],
};
void ed25519OnlyManifest;
void dualManifest;

const emptyManifest: ExactAdministeredSignerManifestV1 = {
  kind: 'exact_administered_signer_manifest_v1',
  // @ts-expect-error An administered manifest cannot be empty.
  keyFamilies: [],
  // @ts-expect-error An administered manifest cannot be empty.
  signers: [],
};
void emptyManifest;

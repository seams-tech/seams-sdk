import type {
  CommittedEd25519SignerPackageV1,
  CommittedEcdsaSignerPackageV1,
  CommittedAuthorityPackagesV1,
  CommittedSignerPackageSetV1,
} from '../../packages/shared-ts/src/device-linking/committedSignerPackages';
import type { LocalAuthorityInstallationReceiptV1 } from '../../packages/shared-ts/src/device-linking/contracts';

declare const ed25519Package: CommittedEd25519SignerPackageV1;
declare const ecdsaPackage: CommittedEcdsaSignerPackageV1;

const ed25519Only: Extract<
  CommittedSignerPackageSetV1,
  { readonly keyFamilies: readonly ['ed25519'] }
> = {
  kind: 'committed_signer_package_set_v1',
  keyFamilies: ['ed25519'],
  ed25519: ed25519Package,
};
void ed25519Only;

const ecdsaOnly: Extract<
  CommittedSignerPackageSetV1,
  { readonly keyFamilies: readonly ['ecdsa_secp256k1'] }
> = {
  kind: 'committed_signer_package_set_v1',
  keyFamilies: ['ecdsa_secp256k1'],
  ecdsa: ecdsaPackage,
};
void ecdsaOnly;

const dualFamily: Extract<
  CommittedSignerPackageSetV1,
  { readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'] }
> = {
  kind: 'committed_signer_package_set_v1',
  keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
  ed25519: ed25519Package,
  ecdsa: ecdsaPackage,
};
void dualFamily;

const invalidEd25519Only: Extract<
  CommittedSignerPackageSetV1,
  { readonly keyFamilies: readonly ['ed25519'] }
> = {
  kind: 'committed_signer_package_set_v1',
  keyFamilies: ['ed25519'],
  ed25519: ed25519Package,
  // @ts-expect-error An Ed25519-only set cannot carry an ECDSA package.
  ecdsa: ecdsaPackage,
};
void invalidEd25519Only;

const invalidEcdsaOnly: Extract<
  CommittedSignerPackageSetV1,
  { readonly keyFamilies: readonly ['ecdsa_secp256k1'] }
> = {
  kind: 'committed_signer_package_set_v1',
  keyFamilies: ['ecdsa_secp256k1'],
  ecdsa: ecdsaPackage,
  // @ts-expect-error An ECDSA-only set cannot carry an Ed25519 package.
  ed25519: ed25519Package,
};
void invalidEcdsaOnly;

declare const committedAuthorityPackages: CommittedAuthorityPackagesV1;
// @ts-expect-error A committed package delivery requires its auth-method identity.
const missingCommittedAuthMethod: CommittedAuthorityPackagesV1 = {
  ...committedAuthorityPackages,
  authMethod: undefined,
};
void missingCommittedAuthMethod;

declare const installationReceipt: LocalAuthorityInstallationReceiptV1;
// @ts-expect-error An installation receipt requires the target device identity.
const missingInstallationDevice: LocalAuthorityInstallationReceiptV1 = {
  ...installationReceipt,
  deviceId: undefined,
};
void missingInstallationDevice;

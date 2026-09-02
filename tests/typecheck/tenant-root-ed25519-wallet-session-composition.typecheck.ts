import type { WalletSessionOperationCredentialAdmission } from '../../packages/wallet-server/src/router/auth/commonRouterUtils';
import { NEAR_ED25519_MPC_OPERATION_KINDS } from '../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  resolveTenantRootEd25519WalletSessionCompositionV1,
  type TenantRootEd25519ActiveMaterialV1,
  type TenantRootEd25519MaterialActivationResolverV1,
  type TenantRootEd25519WalletSessionCompositionResultV1,
  type TenantRootEd25519WalletSessionExportAdmissionV1,
} from '../../packages/wallet-server/src/router/domains/tenantRoot/tenantRootEd25519WalletSessionComposition';
import type { TenantRootIdentityV1 } from '../../packages/wallet-server/src/router/domains/tenantRoot/tenantRootIdentityResolution';

type Ed25519WalletSessionOperationAdmissionV1 = Extract<
  WalletSessionOperationCredentialAdmission,
  { readonly curve: 'ed25519' }
>;

type Ed25519SignWalletSessionOperationAdmissionV1 = Omit<
  Ed25519WalletSessionOperationAdmissionV1,
  'admission'
> & {
  readonly admission: Omit<
    Ed25519WalletSessionOperationAdmissionV1['admission'],
    'operationKind'
  > & {
    readonly operationKind: (typeof NEAR_ED25519_MPC_OPERATION_KINDS)['signTransaction'];
  };
};

declare const ed25519ExportAdmission: TenantRootEd25519WalletSessionExportAdmissionV1;
declare const ed25519SignAdmission: Ed25519SignWalletSessionOperationAdmissionV1;
declare const ecdsaAdmission: Extract<
  WalletSessionOperationCredentialAdmission,
  { readonly curve: 'ecdsa' }
>;
declare const resolveEd25519MaterialActivation: TenantRootEd25519MaterialActivationResolverV1;
declare const activeMaterial: TenantRootEd25519ActiveMaterialV1;
declare const tenantRootIdentity: TenantRootIdentityV1;

resolveTenantRootEd25519WalletSessionCompositionV1({
  admission: ed25519ExportAdmission,
  resolveEd25519MaterialActivation,
});

resolveTenantRootEd25519WalletSessionCompositionV1({
  // @ts-expect-error Tenant-root composition accepts only Ed25519 export admission.
  admission: ed25519SignAdmission,
  resolveEd25519MaterialActivation,
});

resolveTenantRootEd25519WalletSessionCompositionV1({
  // @ts-expect-error The Ed25519 composition cannot consume ECDSA admission.
  admission: ecdsaAdmission,
  resolveEd25519MaterialActivation,
});

resolveTenantRootEd25519WalletSessionCompositionV1({
  admission: ed25519ExportAdmission,
  resolveEd25519MaterialActivation,
  // @ts-expect-error Authenticated deployment configuration supplies the tenant identity.
  orgId: 'caller-org',
});

resolveTenantRootEd25519WalletSessionCompositionV1({
  admission: ed25519ExportAdmission,
  resolveEd25519MaterialActivation,
  // @ts-expect-error The custody control plane supplies the active epoch.
  tenantRootShareEpoch: 2,
});

resolveTenantRootEd25519WalletSessionCompositionV1({
  admission: ed25519ExportAdmission,
  resolveEd25519MaterialActivation,
  // @ts-expect-error A caller cannot select the Deriver role.
  role: 'deriver_a',
});

resolveTenantRootEd25519WalletSessionCompositionV1({
  admission: ed25519ExportAdmission,
  resolveEd25519MaterialActivation,
  // @ts-expect-error Raw Wallet Session state cannot select tenant-root custody.
  walletSession: {},
});

const invalidSuccess: TenantRootEd25519WalletSessionCompositionResultV1 = {
  ok: true,
  admission: ed25519ExportAdmission,
  activeMaterial,
  tenantRootIdentity,
  // @ts-expect-error Successful composition never carries an active R120 epoch.
  tenantRootShareEpoch: 2,
};
void invalidSuccess;

// @ts-expect-error Successful composition retains the exact resolved B5 material.
const invalidSuccessWithoutActiveMaterial: TenantRootEd25519WalletSessionCompositionResultV1 = {
  ok: true,
  admission: ed25519ExportAdmission,
  tenantRootIdentity,
};
void invalidSuccessWithoutActiveMaterial;

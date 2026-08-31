import type { WalletSessionOperationCredentialAdmission } from '../../packages/wallet-server/src/router/auth/commonRouterUtils';
import { EVM_ECDSA_MPC_OPERATION_KINDS } from '../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  resolveTenantRootEcdsaWalletSessionCompositionV1,
  type TenantRootEcdsaActiveMaterialV1,
  type TenantRootEcdsaMaterialActivationResolverV1,
  type TenantRootEcdsaWalletSessionExportAdmissionV1,
  type TenantRootEcdsaWalletSessionCompositionInputV1,
  type TenantRootEcdsaWalletSessionCompositionResultV1,
} from '../../packages/wallet-server/src/router/domains/tenantRoot/tenantRootEcdsaWalletSessionComposition';
import type { TenantRootIdentityV1 } from '../../packages/wallet-server/src/router/domains/tenantRoot/tenantRootIdentityResolution';

type EcdsaWalletSessionOperationAdmissionV1 = Extract<
  WalletSessionOperationCredentialAdmission,
  { readonly curve: 'ecdsa' }
>;

type EcdsaSignTransactionWalletSessionOperationAdmissionV1 = Omit<
  EcdsaWalletSessionOperationAdmissionV1,
  'admission'
> & {
  readonly admission: Omit<EcdsaWalletSessionOperationAdmissionV1['admission'], 'operationKind'> & {
    readonly operationKind: (typeof EVM_ECDSA_MPC_OPERATION_KINDS)['signTransaction'];
  };
};

type IsNever<T> = [T] extends [never] ? true : false;

const exportAdmissionIsConcrete: IsNever<TenantRootEcdsaWalletSessionExportAdmissionV1> = false;
const signAdmissionIsConcrete: IsNever<EcdsaSignTransactionWalletSessionOperationAdmissionV1> = false;
void exportAdmissionIsConcrete;
void signAdmissionIsConcrete;

declare const ecdsaAdmission: TenantRootEcdsaWalletSessionExportAdmissionV1;
declare const ecdsaSignTransactionAdmission: EcdsaSignTransactionWalletSessionOperationAdmissionV1;
declare const ed25519Admission: Extract<
  WalletSessionOperationCredentialAdmission,
  { readonly curve: 'ed25519' }
>;
declare const resolveEcdsaMaterialActivation: TenantRootEcdsaMaterialActivationResolverV1;
declare const activeMaterial: TenantRootEcdsaActiveMaterialV1;

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  // @ts-expect-error Tenant-root identity composition only accepts ECDSA export/derivation admission.
  admission: ecdsaSignTransactionAdmission,
  resolveEcdsaMaterialActivation,
});

const validInput: TenantRootEcdsaWalletSessionCompositionInputV1 = {
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
};
void validInput;

resolveTenantRootEcdsaWalletSessionCompositionV1({
  // @ts-expect-error The ECDSA composition cannot consume an Ed25519 admission.
  admission: ed25519Admission,
  resolveEcdsaMaterialActivation,
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error The composition derives wallet identity from the admitted session.
  orgId: 'caller-org',
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error The composition derives deployment project identity from B5 material.
  projectId: 'caller-project',
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error The composition derives deployment environment identity from B5 material.
  envId: 'caller-env',
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error Callers cannot override the stable signing-root ID.
  signingRootId: 'caller-root',
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error Callers cannot override the stable signing-root version.
  signingRootVersion: 'caller-version',
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error Callers cannot override the admitted wallet identity.
  walletId: 'caller-wallet',
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error Callers cannot provide a material selector.
  materialActivation: {},
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error Callers cannot provide a tenant-root identity.
  tenantRootIdentity: {},
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error Callers cannot provide a tenant-root ID.
  tenantRootId: 'caller-tenant-root',
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error R120 epoch state is resolved by the custody control plane.
  tenantRootShareEpoch: 'caller-epoch',
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error R103F root-share epoch vocabulary cannot select R120 material.
  rootShareEpoch: 'caller-root-epoch',
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error Callers cannot select an epoch.
  epoch: 'caller-epoch',
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error Callers cannot select a Deriver role.
  role: 'deriver_a',
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error Raw Wallet Session state cannot select a tenant root.
  walletSession: {},
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error A Wallet Session ID cannot select a tenant root.
  walletSessionId: 'caller-session',
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error Raw authorization state cannot select a tenant root.
  authorization: {},
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error An authorization ID cannot select a tenant root.
  authorizationId: 'caller-authorization',
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error Raw credential state cannot select a tenant root.
  credential: {},
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error A credential ID cannot select a tenant root.
  credentialIdB64u: 'caller-credential',
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error Raw browser state cannot select a tenant root.
  browser: {},
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error A browser record cannot select a tenant root.
  browserRecord: {},
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error A request body cannot select a tenant root.
  requestBody: {},
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error A request ID cannot select a tenant root.
  requestId: 'caller-request',
});

resolveTenantRootEcdsaWalletSessionCompositionV1({
  admission: ecdsaAdmission,
  resolveEcdsaMaterialActivation,
  // @ts-expect-error Diagnostics cannot select a tenant root.
  diagnostics: {},
});

declare const tenantRootIdentity: TenantRootIdentityV1;
const invalidSuccess: TenantRootEcdsaWalletSessionCompositionResultV1 = {
  ok: true,
  admission: ecdsaAdmission,
  activeMaterial,
  tenantRootIdentity,
  // @ts-expect-error Successful composition results never carry an R120 epoch selector.
  tenantRootShareEpoch: 'caller-epoch',
};
void invalidSuccess;

// @ts-expect-error Successful composition results must include the full B5 active material.
const invalidSuccessWithoutActiveMaterial: TenantRootEcdsaWalletSessionCompositionResultV1 = {
  ok: true,
  admission: ecdsaAdmission,
  tenantRootIdentity,
};
void invalidSuccessWithoutActiveMaterial;

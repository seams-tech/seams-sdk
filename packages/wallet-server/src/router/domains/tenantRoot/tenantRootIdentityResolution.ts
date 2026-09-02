import {
  signingRootScopeFromRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import {
  sameRouterAbMpcMaterialActivationRef,
} from '@shared/utils/routerAbNormalSigningIdentity';
import type { RouterApiWalletRegistrationService } from '../../framework/authServicePort';

export type TenantRootIdentityV1 = {
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
};

export type ActiveEd25519MaterialActivationV1 = Extract<
  Awaited<ReturnType<RouterApiWalletRegistrationService['resolveEd25519MaterialActivation']>>,
  { readonly ok: true }
>;

export type ActiveEcdsaMaterialActivationV1 = Extract<
  Awaited<ReturnType<RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation']>>,
  { readonly ok: true }
>;

export type ForbiddenTenantRootSelectorFieldsV1 = {
  readonly orgId?: never;
  readonly projectId?: never;
  readonly envId?: never;
  readonly signingRootId?: never;
  readonly signingRootVersion?: never;
  readonly walletId?: never;
  readonly materialActivation?: never;
  readonly tenantRootIdentity?: never;
  readonly tenantRootId?: never;
  readonly tenantRootShareEpoch?: never;
  readonly rootShareEpoch?: never;
  readonly epoch?: never;
  readonly role?: never;
  readonly walletSession?: never;
  readonly walletSessionId?: never;
  readonly authorization?: never;
  readonly authorizationId?: never;
  readonly credential?: never;
  readonly credentialIdB64u?: never;
  readonly browser?: never;
  readonly browserRecord?: never;
  readonly requestBody?: never;
  readonly requestId?: never;
  readonly diagnostics?: never;
};

const FORBIDDEN_TENANT_ROOT_SELECTOR_FIELDS_V1 = [
  'orgId',
  'projectId',
  'envId',
  'signingRootId',
  'signingRootVersion',
  'walletId',
  'materialActivation',
  'tenantRootIdentity',
  'tenantRootId',
  'tenantRootShareEpoch',
  'rootShareEpoch',
  'epoch',
  'role',
  'walletSession',
  'walletSessionId',
  'authorization',
  'authorizationId',
  'credential',
  'credentialIdB64u',
  'browser',
  'browserRecord',
  'requestBody',
  'requestId',
  'diagnostics',
] as const;

export type ForbiddenTenantRootSelectorFieldV1 =
  (typeof FORBIDDEN_TENANT_ROOT_SELECTOR_FIELDS_V1)[number];

export type ServerResolvedTenantRootMaterialV1 =
  | (ForbiddenTenantRootSelectorFieldsV1 & {
      readonly kind: 'ed25519_b5_active_material';
      readonly activeMaterial: ActiveEd25519MaterialActivationV1;
    })
  | (ForbiddenTenantRootSelectorFieldsV1 & {
      readonly kind: 'ecdsa_b5_active_material';
      readonly activeMaterial: ActiveEcdsaMaterialActivationV1;
    });

export type TenantRootIdentityResolutionErrorCodeV1 =
  | 'caller_selected_tenant_root'
  | 'material_activation_mismatch'
  | 'non_canonical_tenant_root_field'
  | 'signing_root_id_mismatch'
  | 'signing_root_version_mismatch';

export type TenantRootIdentityResolutionResultV1 =
  | {
      readonly ok: true;
      readonly identity: TenantRootIdentityV1;
    }
  | {
      readonly ok: false;
      readonly code: TenantRootIdentityResolutionErrorCodeV1;
      readonly message: string;
    };

type StableMaterialRootBindingV1 = {
  readonly materialActivationMatches: boolean;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
};

const TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIELDS_V1 = [
  'orgId',
  'projectId',
  'envId',
  'signingRootVersion',
] as const;

type TenantRootRuntimePolicyScopeFieldV1 =
  (typeof TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIELDS_V1)[number];

function findNonCanonicalRuntimePolicyScopeFieldV1(
  scope: RuntimePolicyScope,
): TenantRootRuntimePolicyScopeFieldV1 | null {
  for (const field of TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIELDS_V1) {
    const value = scope[field];
    if (value.length === 0 || value.trim() !== value) return field;
  }
  return null;
}

function ed25519StableMaterialRootBinding(
  activeMaterial: ActiveEd25519MaterialActivationV1,
): StableMaterialRootBindingV1 {
  return {
    materialActivationMatches: sameRouterAbMpcMaterialActivationRef(
      activeMaterial.materialActivation,
      activeMaterial.exportIdentity.scope.material_activation,
    ),
    signingRootId: activeMaterial.exportIdentity.application_binding.signing_root_id,
    // This R103F field carries the stable signing-root version here. It is never
    // interpreted as an R120 TenantRootShareEpoch.
    signingRootVersion: activeMaterial.exportIdentity.scope.root_share_epoch,
  };
}

function ecdsaStableMaterialRootBinding(
  activeMaterial: ActiveEcdsaMaterialActivationV1,
): StableMaterialRootBindingV1 {
  const scope = activeMaterial.routerAbEcdsaDerivationNormalSigning.scope;
  return {
    materialActivationMatches: sameRouterAbMpcMaterialActivationRef(
      activeMaterial.materialActivation,
      scope.material_activation,
    ),
    signingRootId: scope.signing_root_id,
    signingRootVersion: scope.signing_root_version,
  };
}

function assertNeverServerResolvedMaterial(value: never): never {
  throw new Error(`Unsupported server-resolved tenant-root material: ${String(value)}`);
}

function mismatch(
  code: TenantRootIdentityResolutionErrorCodeV1,
  message: string,
): TenantRootIdentityResolutionResultV1 {
  return { ok: false, code, message };
}

export function findForbiddenTenantRootSelectorFieldV1(
  input: object,
): ForbiddenTenantRootSelectorFieldV1 | null {
  for (const field of FORBIDDEN_TENANT_ROOT_SELECTOR_FIELDS_V1) {
    if (Object.prototype.hasOwnProperty.call(input, field)) return field;
  }
  return null;
}

export function resolveTenantRootIdentityV1(
  input: ServerResolvedTenantRootMaterialV1,
): TenantRootIdentityResolutionResultV1 {
  const forbiddenSelector = findForbiddenTenantRootSelectorFieldV1(input);
  if (forbiddenSelector) {
    return mismatch(
      'caller_selected_tenant_root',
      `Caller-supplied tenant-root selector field is forbidden: ${forbiddenSelector}`,
    );
  }

  let runtimePolicyScope;
  let materialRootBinding: StableMaterialRootBindingV1;
  switch (input.kind) {
    case 'ed25519_b5_active_material':
      runtimePolicyScope = input.activeMaterial.runtimePolicyScope;
      materialRootBinding = ed25519StableMaterialRootBinding(input.activeMaterial);
      break;
    case 'ecdsa_b5_active_material':
      runtimePolicyScope = input.activeMaterial.runtimePolicyScope;
      materialRootBinding = ecdsaStableMaterialRootBinding(input.activeMaterial);
      break;
    default:
      return assertNeverServerResolvedMaterial(input);
  }

  if (!materialRootBinding.materialActivationMatches) {
    return mismatch(
      'material_activation_mismatch',
      'B5 material activation does not match its established material identity',
    );
  }

  const nonCanonicalScopeField = findNonCanonicalRuntimePolicyScopeFieldV1(runtimePolicyScope);
  if (nonCanonicalScopeField) {
    return mismatch(
      'non_canonical_tenant_root_field',
      `B5 runtime policy scope field is not canonical: ${nonCanonicalScopeField}`,
    );
  }

  const expectedSigningRoot = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
  if (materialRootBinding.signingRootId !== expectedSigningRoot.signingRootId) {
    return mismatch(
      'signing_root_id_mismatch',
      'B5 signing-root ID does not match authenticated deployment configuration',
    );
  }
  if (materialRootBinding.signingRootVersion !== expectedSigningRoot.signingRootVersion) {
    return mismatch(
      'signing_root_version_mismatch',
      'B5 signing-root version does not match authenticated deployment configuration',
    );
  }

  return {
    ok: true,
    identity: {
      orgId: runtimePolicyScope.orgId,
      projectId: runtimePolicyScope.projectId,
      envId: runtimePolicyScope.envId,
      signingRootId: expectedSigningRoot.signingRootId,
      signingRootVersion: expectedSigningRoot.signingRootVersion,
    },
  };
}

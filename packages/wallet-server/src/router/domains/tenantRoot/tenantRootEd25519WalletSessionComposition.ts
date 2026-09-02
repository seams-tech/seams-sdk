import type { WalletSessionOperationCredentialAdmission } from '../../auth/commonRouterUtils';
import type { RouterApiWalletRegistrationService } from '../../framework/authServicePort';
import { NEAR_ED25519_MPC_OPERATION_KINDS } from '@shared/authorization/capabilityKinds';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  routerAbMpcMaterialActivationRefToWire,
  sameRouterAbMpcMaterialActivationRef,
  type RouterAbMpcMaterialActivationRefWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import {
  findForbiddenTenantRootSelectorFieldV1,
  resolveTenantRootIdentityV1,
  type ForbiddenTenantRootSelectorFieldsV1,
  type TenantRootIdentityResolutionErrorCodeV1,
  type TenantRootIdentityV1,
} from './tenantRootIdentityResolution';

type Ed25519WalletSessionOperationAdmissionV1 = Extract<
  WalletSessionOperationCredentialAdmission,
  { readonly curve: 'ed25519' }
>;

export type TenantRootEd25519WalletSessionExportAdmissionV1 = Omit<
  Ed25519WalletSessionOperationAdmissionV1,
  'admission'
> & {
  readonly admission: Omit<
    Ed25519WalletSessionOperationAdmissionV1['admission'],
    'operationKind'
  > & {
    readonly operationKind: (typeof NEAR_ED25519_MPC_OPERATION_KINDS)['exportKey'];
  };
};

export type TenantRootEd25519MaterialActivationResolverV1 =
  RouterApiWalletRegistrationService['resolveEd25519MaterialActivation'];

export type TenantRootEd25519MaterialActivationResolutionV1 = Awaited<
  ReturnType<TenantRootEd25519MaterialActivationResolverV1>
>;

export type TenantRootEd25519ActiveMaterialV1 = Extract<
  TenantRootEd25519MaterialActivationResolutionV1,
  { readonly ok: true }
>;

export type TenantRootEd25519WalletSessionCompositionInputV1 =
  ForbiddenTenantRootSelectorFieldsV1 & {
    readonly admission: TenantRootEd25519WalletSessionExportAdmissionV1;
    readonly resolveEd25519MaterialActivation: TenantRootEd25519MaterialActivationResolverV1;
  };

export type TenantRootEd25519WalletSessionCompositionErrorCodeV1 =
  | 'not_found'
  | 'internal'
  | 'material_activation_mismatch'
  | 'wallet_mismatch'
  | 'registered_public_key_mismatch'
  | TenantRootIdentityResolutionErrorCodeV1;

export type TenantRootEd25519WalletSessionCompositionResultV1 =
  | {
      readonly ok: true;
      readonly admission: TenantRootEd25519WalletSessionExportAdmissionV1;
      readonly activeMaterial: TenantRootEd25519ActiveMaterialV1;
      readonly tenantRootIdentity: TenantRootIdentityV1;
    }
  | {
      readonly ok: false;
      readonly code: TenantRootEd25519WalletSessionCompositionErrorCodeV1;
      readonly message: string;
    };

function compositionFailure(
  code: TenantRootEd25519WalletSessionCompositionErrorCodeV1,
  message: string,
): TenantRootEd25519WalletSessionCompositionResultV1 {
  return { ok: false, code, message };
}

function ed25519WalletSessionWalletId(
  admission: TenantRootEd25519WalletSessionExportAdmissionV1,
): string {
  return String(admission.context.authorization.session.walletId);
}

function ed25519WalletSessionMaterialActivation(
  admission: TenantRootEd25519WalletSessionExportAdmissionV1,
): RouterAbMpcMaterialActivationRefWire {
  return routerAbMpcMaterialActivationRefToWire(admission.admission.materialActivation);
}

function b5MaterialMatchesEd25519WalletSessionAdmission(input: {
  readonly admission: TenantRootEd25519WalletSessionExportAdmissionV1;
  readonly activeMaterial: TenantRootEd25519ActiveMaterialV1;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
}): TenantRootEd25519WalletSessionCompositionResultV1 | null {
  if (
    !sameRouterAbMpcMaterialActivationRef(
      input.activeMaterial.materialActivation,
      input.materialActivation,
    )
  ) {
    return compositionFailure(
      'material_activation_mismatch',
      'B5 material activation does not match the exact B4 admission',
    );
  }

  const exportIdentity = input.activeMaterial.exportIdentity;
  const signer = input.admission.admission.signer;
  if (
    exportIdentity.scope.account_id !== String(signer.walletId) ||
    exportIdentity.application_binding.wallet_id !== String(signer.walletId)
  ) {
    return compositionFailure(
      'wallet_mismatch',
      'B5 Ed25519 wallet ID does not match the B4 signer',
    );
  }
  if (
    base64UrlEncode(Uint8Array.from(exportIdentity.registered_public_key)) !==
    signer.registeredPublicKeyB64u
  ) {
    return compositionFailure(
      'registered_public_key_mismatch',
      'B5 Ed25519 public key does not match the B4 signer',
    );
  }
  return null;
}

export async function resolveTenantRootEd25519WalletSessionCompositionV1(
  input: TenantRootEd25519WalletSessionCompositionInputV1,
): Promise<TenantRootEd25519WalletSessionCompositionResultV1> {
  const forbiddenSelector = findForbiddenTenantRootSelectorFieldV1(input);
  if (forbiddenSelector) {
    return compositionFailure(
      'caller_selected_tenant_root',
      `Caller-supplied tenant-root selector field is forbidden: ${forbiddenSelector}`,
    );
  }

  const materialActivation = ed25519WalletSessionMaterialActivation(input.admission);
  const activeMaterial = await input.resolveEd25519MaterialActivation({
    walletId: ed25519WalletSessionWalletId(input.admission),
    materialActivation,
  });
  if (!activeMaterial.ok) {
    return compositionFailure(activeMaterial.code, activeMaterial.message);
  }

  const admissionMismatch = b5MaterialMatchesEd25519WalletSessionAdmission({
    admission: input.admission,
    activeMaterial,
    materialActivation,
  });
  if (admissionMismatch) return admissionMismatch;

  const identity = resolveTenantRootIdentityV1({
    kind: 'ed25519_b5_active_material',
    activeMaterial,
  });
  if (!identity.ok) return compositionFailure(identity.code, identity.message);

  return {
    ok: true,
    admission: input.admission,
    activeMaterial,
    tenantRootIdentity: identity.identity,
  };
}

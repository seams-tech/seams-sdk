import type { WalletSessionOperationCredentialAdmission } from '../../auth/commonRouterUtils';
import type { RouterApiWalletRegistrationService } from '../../framework/authServicePort';
import { EVM_ECDSA_MPC_OPERATION_KINDS } from '@shared/authorization/capabilityKinds';
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

type EcdsaWalletSessionOperationAdmissionV1 = Extract<
  WalletSessionOperationCredentialAdmission,
  { readonly curve: 'ecdsa' }
>;

export type TenantRootEcdsaWalletSessionExportAdmissionV1 = Omit<
  EcdsaWalletSessionOperationAdmissionV1,
  'admission'
> & {
  readonly admission: Omit<EcdsaWalletSessionOperationAdmissionV1['admission'], 'operationKind'> & {
    readonly operationKind: (typeof EVM_ECDSA_MPC_OPERATION_KINDS)['exportKey'];
  };
};

export type TenantRootEcdsaMaterialActivationResolverV1 =
  RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation'];

export type TenantRootEcdsaMaterialActivationResolutionV1 = Awaited<
  ReturnType<TenantRootEcdsaMaterialActivationResolverV1>
>;

export type TenantRootEcdsaActiveMaterialV1 = Extract<
  TenantRootEcdsaMaterialActivationResolutionV1,
  { readonly ok: true }
>;

export type TenantRootEcdsaWalletSessionCompositionInputV1 = ForbiddenTenantRootSelectorFieldsV1 & {
  readonly admission: TenantRootEcdsaWalletSessionExportAdmissionV1;
  readonly resolveEcdsaMaterialActivation: TenantRootEcdsaMaterialActivationResolverV1;
};

export type TenantRootEcdsaWalletSessionCompositionErrorCodeV1 =
  | 'not_found'
  | 'internal'
  | 'material_activation_mismatch'
  | 'wallet_mismatch'
  | 'threshold_public_key_mismatch'
  | TenantRootIdentityResolutionErrorCodeV1;

export type TenantRootEcdsaWalletSessionCompositionResultV1 =
  | {
      readonly ok: true;
      readonly admission: TenantRootEcdsaWalletSessionExportAdmissionV1;
      readonly activeMaterial: TenantRootEcdsaActiveMaterialV1;
      readonly tenantRootIdentity: TenantRootIdentityV1;
    }
  | {
      readonly ok: false;
      readonly code: TenantRootEcdsaWalletSessionCompositionErrorCodeV1;
      readonly message: string;
    };

function compositionFailure(
  code: TenantRootEcdsaWalletSessionCompositionErrorCodeV1,
  message: string,
): TenantRootEcdsaWalletSessionCompositionResultV1 {
  return { ok: false, code, message };
}

function ecdsaWalletSessionWalletId(
  admission: TenantRootEcdsaWalletSessionExportAdmissionV1,
): string {
  return String(admission.context.authorization.session.walletId);
}

function ecdsaWalletSessionMaterialActivation(
  admission: TenantRootEcdsaWalletSessionExportAdmissionV1,
): RouterAbMpcMaterialActivationRefWire {
  return routerAbMpcMaterialActivationRefToWire(admission.admission.materialActivation);
}

function b5MaterialMatchesEcdsaWalletSessionAdmission(input: {
  readonly admission: TenantRootEcdsaWalletSessionExportAdmissionV1;
  readonly activeMaterial: TenantRootEcdsaActiveMaterialV1;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
}): TenantRootEcdsaWalletSessionCompositionResultV1 | null {
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

  const normalSigning = input.activeMaterial.routerAbEcdsaDerivationNormalSigning;
  const signer = input.admission.admission.signer;
  if (normalSigning.scope.wallet_id !== String(signer.walletId)) {
    return compositionFailure(
      'wallet_mismatch',
      'B5 normal-signing wallet ID does not match the B4 signer',
    );
  }
  if (
    normalSigning.scope.public_identity.threshold_public_key33_b64u !==
    signer.thresholdPublicKey33B64u
  ) {
    return compositionFailure(
      'threshold_public_key_mismatch',
      'B5 normal-signing threshold public key does not match the B4 signer',
    );
  }
  return null;
}

export async function resolveTenantRootEcdsaWalletSessionCompositionV1(
  input: TenantRootEcdsaWalletSessionCompositionInputV1,
): Promise<TenantRootEcdsaWalletSessionCompositionResultV1> {
  const forbiddenSelector = findForbiddenTenantRootSelectorFieldV1(input);
  if (forbiddenSelector) {
    return compositionFailure(
      'caller_selected_tenant_root',
      `Caller-supplied tenant-root selector field is forbidden: ${forbiddenSelector}`,
    );
  }

  const materialActivation = ecdsaWalletSessionMaterialActivation(input.admission);
  const activeMaterial = await input.resolveEcdsaMaterialActivation({
    walletId: ecdsaWalletSessionWalletId(input.admission),
    materialActivation,
  });
  if (!activeMaterial.ok) {
    return compositionFailure(activeMaterial.code, activeMaterial.message);
  }

  const admissionMismatch = b5MaterialMatchesEcdsaWalletSessionAdmission({
    admission: input.admission,
    activeMaterial,
    materialActivation,
  });
  if (admissionMismatch) return admissionMismatch;

  const identity = resolveTenantRootIdentityV1({
    kind: 'ecdsa_b5_active_material',
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

import { EVM_ECDSA_MPC_OPERATION_KINDS } from '../../../packages/shared-ts/src/authorization/capabilityKinds';
import { buildFullOwnerPermissionsV1 } from '../../../packages/shared-ts/src/authorization/delegatedAuthority';
import {
  routerAbMpcMaterialActivationRefFromWire,
  type RouterAbMpcMaterialActivationRefWire,
} from '../../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { parseWalletKeyId } from '../../../packages/shared-ts/src/utils/domainIds';
import { parseSecp256k1CompressedPublicKeyB64u } from '../../../packages/shared-ts/src/passkey-custody/primitives';
import {
  resolveWalletSessionOperationCredentialAdmissionFromContext,
  type WalletSessionOperationCredentialAdmission,
} from '../../../packages/wallet-server/src/router/auth/commonRouterUtils';
import {
  buildActiveEcdsaMaterialFixture,
  TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE,
} from './tenantRootB5Material.fixtures';
import {
  buildLinkedDeviceManagementAuthorityFixture,
  type LinkedDeviceManagementAuthorityFixture,
} from './linkedDeviceManagement.fixtures';
import type {
  TenantRootEcdsaActiveMaterialV1,
  TenantRootEcdsaMaterialActivationResolutionV1,
  TenantRootEcdsaMaterialActivationResolverV1,
  TenantRootEcdsaWalletSessionExportAdmissionV1,
} from '../../../packages/wallet-server/src/router/domains/tenantRoot/tenantRootEcdsaWalletSessionComposition';

type EcdsaWalletSessionOperationAdmissionV1 = TenantRootEcdsaWalletSessionExportAdmissionV1;

type EcdsaWalletSessionOperationAdmissionFromB4V1 = Extract<
  WalletSessionOperationCredentialAdmission,
  { readonly curve: 'ecdsa' }
>;

function isEcdsaExportAdmission(
  admission: EcdsaWalletSessionOperationAdmissionFromB4V1,
): admission is TenantRootEcdsaWalletSessionExportAdmissionV1 {
  return admission.admission.operationKind === EVM_ECDSA_MPC_OPERATION_KINDS.exportKey;
}

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

export type TenantRootEcdsaMaterialActivationResolverCallV1 =
  Parameters<TenantRootEcdsaMaterialActivationResolverV1>[0];

export class RecordingTenantRootEcdsaMaterialActivationResolverV1 {
  readonly calls: TenantRootEcdsaMaterialActivationResolverCallV1[] = [];

  constructor(readonly result: TenantRootEcdsaMaterialActivationResolutionV1) {}

  async resolveEcdsaMaterialActivation(
    input: TenantRootEcdsaMaterialActivationResolverCallV1,
  ): Promise<TenantRootEcdsaMaterialActivationResolutionV1> {
    this.calls.push(input);
    return this.result;
  }
}

export type TenantRootEcdsaWalletSessionCompositionFixture = {
  readonly authorityFixture: LinkedDeviceManagementAuthorityFixture;
  readonly admission: EcdsaWalletSessionOperationAdmissionV1;
  readonly activeMaterial: TenantRootEcdsaActiveMaterialV1;
  readonly resolver: RecordingTenantRootEcdsaMaterialActivationResolverV1;
};

export function buildSuccessfulTenantRootEcdsaMaterialFixture(): TenantRootEcdsaActiveMaterialV1 {
  const activeMaterial = buildActiveEcdsaMaterialFixture();
  return {
    ok: true,
    materialActivation: activeMaterial.materialActivation,
    keyHandle: 'ecdsa-key-handle-tenant-root-composition',
    relayerKeyId: 'ecdsa-relayer-key-tenant-root-composition',
    participantIds: [1, 2],
    runtimePolicyScope: TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE,
    routerAbEcdsaDerivationNormalSigning: activeMaterial.routerAbEcdsaDerivationNormalSigning,
  };
}

export async function buildTenantRootEcdsaWalletSessionCompositionFixture(): Promise<TenantRootEcdsaWalletSessionCompositionFixture> {
  const activeMaterial = buildSuccessfulTenantRootEcdsaMaterialFixture();
  const normalSigning = activeMaterial.routerAbEcdsaDerivationNormalSigning;
  const walletKeyId = required(parseWalletKeyId('wallet-key:tenant-root-ecdsa-composition'));
  const thresholdPublicKey33B64u = parseSecp256k1CompressedPublicKeyB64u(
    normalSigning.scope.public_identity.threshold_public_key33_b64u,
  );
  const authorityFixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'tenant-root-ecdsa-composition',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ecdsa_secp256k1',
    materialActivation: routerAbMpcMaterialActivationRefFromWire(activeMaterial.materialActivation),
    identity: {
      walletId: normalSigning.scope.wallet_id,
      authorityId: 'authority:tenant-root-ecdsa-composition',
      walletAuthMethodId: 'auth-method:tenant-root-ecdsa-composition',
      rpId: 'tenant-root-composition.example.test',
    },
    ecdsaSigner: {
      walletKeyId,
      thresholdPublicKey33B64u,
      evmAddress: '0x1111111111111111111111111111111111111111',
    },
    expiresAtMs: 10_000,
  });
  const admitted = resolveWalletSessionOperationCredentialAdmissionFromContext({
    context: {
      authorization: authorityFixture.issuedSession,
      authority: authorityFixture.authority,
      authMethod: authorityFixture.authMethod,
      retiredAtMs: null,
    },
    nowMs: 1_000,
    operation: {
      keyFamily: 'ecdsa_secp256k1',
      operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.exportKey,
    },
  });
  if (
    admitted.kind !== 'admitted' ||
    admitted.admission.curve !== 'ecdsa' ||
    !isEcdsaExportAdmission(admitted.admission)
  ) {
    throw new Error('tenant-root ECDSA composition fixture failed B4 admission');
  }
  const resolver = new RecordingTenantRootEcdsaMaterialActivationResolverV1(activeMaterial);
  return {
    authorityFixture,
    admission: admitted.admission,
    activeMaterial,
    resolver,
  };
}

export function materialActivationWithActivationId(
  materialActivation: RouterAbMpcMaterialActivationRefWire,
  activationId: string,
): RouterAbMpcMaterialActivationRefWire {
  return { ...materialActivation, activation_id: activationId };
}

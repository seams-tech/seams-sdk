import { NEAR_ED25519_MPC_OPERATION_KINDS } from '../../../packages/shared-ts/src/authorization/capabilityKinds';
import { buildFullOwnerPermissionsV1 } from '../../../packages/shared-ts/src/authorization/delegatedAuthority';
import { parseEd25519PublicKeyB64u } from '../../../packages/shared-ts/src/passkey-custody/primitives';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import { parseWalletKeyId } from '../../../packages/shared-ts/src/utils/domainIds';
import {
  routerAbMpcMaterialActivationRefFromWire,
  type RouterAbMpcMaterialActivationRefWire,
} from '../../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import {
  resolveWalletSessionOperationCredentialAdmissionFromContext,
  type WalletSessionOperationCredentialAdmission,
} from '../../../packages/wallet-server/src/router/auth/commonRouterUtils';
import type {
  TenantRootEd25519ActiveMaterialV1,
  TenantRootEd25519MaterialActivationResolutionV1,
  TenantRootEd25519MaterialActivationResolverV1,
  TenantRootEd25519WalletSessionExportAdmissionV1,
} from '../../../packages/wallet-server/src/router/domains/tenantRoot/tenantRootEd25519WalletSessionComposition';
import {
  buildActiveEd25519MaterialFixture,
  TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE,
} from './tenantRootB5Material.fixtures';
import {
  buildLinkedDeviceManagementAuthorityFixture,
  type LinkedDeviceManagementAuthorityFixture,
} from './linkedDeviceManagement.fixtures';

type Ed25519WalletSessionOperationAdmissionFromB4V1 = Extract<
  WalletSessionOperationCredentialAdmission,
  { readonly curve: 'ed25519' }
>;

function isEd25519ExportAdmission(
  admission: Ed25519WalletSessionOperationAdmissionFromB4V1,
): admission is TenantRootEd25519WalletSessionExportAdmissionV1 {
  return admission.admission.operationKind === NEAR_ED25519_MPC_OPERATION_KINDS.exportKey;
}

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

export type TenantRootEd25519MaterialActivationResolverCallV1 =
  Parameters<TenantRootEd25519MaterialActivationResolverV1>[0];

export class RecordingTenantRootEd25519MaterialActivationResolverV1 {
  readonly calls: TenantRootEd25519MaterialActivationResolverCallV1[] = [];

  constructor(readonly result: TenantRootEd25519MaterialActivationResolutionV1) {}

  async resolveEd25519MaterialActivation(
    input: TenantRootEd25519MaterialActivationResolverCallV1,
  ): Promise<TenantRootEd25519MaterialActivationResolutionV1> {
    this.calls.push(input);
    return this.result;
  }
}

export type TenantRootEd25519WalletSessionCompositionFixture = {
  readonly authorityFixture: LinkedDeviceManagementAuthorityFixture;
  readonly admission: TenantRootEd25519WalletSessionExportAdmissionV1;
  readonly activeMaterial: TenantRootEd25519ActiveMaterialV1;
  readonly resolver: RecordingTenantRootEd25519MaterialActivationResolverV1;
};

export async function buildSuccessfulTenantRootEd25519MaterialFixture(): Promise<TenantRootEd25519ActiveMaterialV1> {
  const activeMaterial = await buildActiveEd25519MaterialFixture();
  return {
    ok: true,
    materialActivation: activeMaterial.materialActivation,
    nearAccountId: activeMaterial.exportIdentity.scope.account_id,
    signerSlot: activeMaterial.exportIdentity.application_binding.key_creation_signer_slot,
    signingWorkerId: activeMaterial.exportIdentity.scope.signing_worker_id,
    participantIds: activeMaterial.exportIdentity.participant_ids,
    runtimePolicyScope: TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE,
    exportIdentity: activeMaterial.exportIdentity,
  };
}

export async function buildTenantRootEd25519WalletSessionCompositionFixture(): Promise<TenantRootEd25519WalletSessionCompositionFixture> {
  const activeMaterial = await buildSuccessfulTenantRootEd25519MaterialFixture();
  const exportIdentity = activeMaterial.exportIdentity;
  const walletKeyId = required(parseWalletKeyId('wallet-key:tenant-root-ed25519-composition'));
  const registeredPublicKeyB64u = parseEd25519PublicKeyB64u(
    base64UrlEncode(Uint8Array.from(exportIdentity.registered_public_key)),
  );
  const authorityFixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'tenant-root-ed25519-composition',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    materialActivation: routerAbMpcMaterialActivationRefFromWire(activeMaterial.materialActivation),
    identity: {
      walletId: exportIdentity.application_binding.wallet_id,
      authorityId: 'authority:tenant-root-ed25519-composition',
      walletAuthMethodId: 'auth-method:tenant-root-ed25519-composition',
      rpId: 'tenant-root-ed25519-composition.example.test',
    },
    ed25519Signer: {
      walletKeyId,
      registeredPublicKeyB64u,
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
      keyFamily: 'ed25519',
      operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.exportKey,
    },
  });
  if (
    admitted.kind !== 'admitted' ||
    admitted.admission.curve !== 'ed25519' ||
    !isEd25519ExportAdmission(admitted.admission)
  ) {
    throw new Error('tenant-root Ed25519 composition fixture failed B4 admission');
  }
  const resolver = new RecordingTenantRootEd25519MaterialActivationResolverV1(activeMaterial);
  return {
    authorityFixture,
    admission: admitted.admission,
    activeMaterial,
    resolver,
  };
}

export function ed25519MaterialActivationWithActivationId(
  materialActivation: RouterAbMpcMaterialActivationRefWire,
  activationId: string,
): RouterAbMpcMaterialActivationRefWire {
  return { ...materialActivation, activation_id: activationId };
}

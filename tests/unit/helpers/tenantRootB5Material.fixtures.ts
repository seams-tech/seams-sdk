import type { RuntimePolicyScope } from '../../../packages/shared-ts/src/threshold/signingRootScope';
import {
  deriveRouterAbEd25519YaoRuntimePolicyBindingV1,
  parseRouterAbEd25519YaoExportAdmissionRequestV1,
} from '../../../packages/shared-ts/src/utils/routerAbEd25519Yao';
import {
  requireRouterAbEcdsaDerivationNormalSigningStateV1,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
} from '../../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import {
  parseRouterAbMpcMaterialActivationRef,
  type RouterAbMpcMaterialActivationRefWire,
} from '../../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import type {
  ActiveEcdsaMaterialActivationV1,
  ActiveEd25519MaterialActivationV1,
} from '../../../packages/wallet-server/src/router/domains/tenantRoot/tenantRootIdentityResolution';

export const TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE: RuntimePolicyScope = {
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
  signingRootVersion: 'root-v1',
};

const WALLET_ID = 'wallet-tenant-root-b5';
const SIGNING_ROOT_ID = 'project-a:env-a';
const DIGEST32_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const PUBLIC_KEY33_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const SERVER_PUBLIC_KEY33_B64U = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function bytes32(seed: number): number[] {
  return new Array<number>(32).fill(seed);
}

function materialActivation(label: string): RouterAbMpcMaterialActivationRefWire {
  return parseRouterAbMpcMaterialActivationRef({
    kind: 'mpc_material_activation_ref',
    activation_id: `activation:${label}`,
    capability: `capability:${label}`,
    material_owner: WALLET_ID,
    key_binding: `key:${label}`,
    lifecycle_binding: `lifecycle:${label}`,
    signing_worker: 'signing-worker-tenant-root-b5',
  });
}

export async function buildActiveEd25519MaterialFixture(): Promise<ActiveEd25519MaterialActivationV1> {
  const activation = materialActivation('ed25519-tenant-root-b5');
  const parsed = parseRouterAbEd25519YaoExportAdmissionRequestV1({
    scope: {
      lifecycle_id: 'lifecycle-ed25519-tenant-root-b5',
      root_share_epoch: TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE.signingRootVersion,
      account_id: WALLET_ID,
      threshold_session_id: 'threshold-session-ed25519-tenant-root-b5',
      signer_set_id: 'signer-set-ed25519-tenant-root-b5',
      signing_worker_id: activation.signing_worker,
      material_activation: activation,
    },
    application_binding: {
      wallet_id: WALLET_ID,
      near_ed25519_signing_key_id: 'near-ed25519-tenant-root-b5',
      signing_root_id: SIGNING_ROOT_ID,
      key_creation_signer_slot: 1,
    },
    participant_ids: [1, 2],
    registered_public_key: bytes32(1),
    state_epoch: 1,
    runtime_policy_binding: await deriveRouterAbEd25519YaoRuntimePolicyBindingV1(
      TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE,
    ),
    authorization: {
      confirmation_digest: bytes32(2),
      authorization_digest: bytes32(3),
      nonce: bytes32(4),
      issued_at_ms: 1_800_000_000_000,
      expires_at_ms: 1_800_000_060_000,
    },
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return {
    ok: true,
    materialActivation: activation,
    runtimePolicyScope: TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE,
    exportIdentity: {
      scope: parsed.value.scope,
      application_binding: parsed.value.application_binding,
      participant_ids: parsed.value.participant_ids,
      registered_public_key: parsed.value.registered_public_key,
      state_epoch: parsed.value.state_epoch,
      runtime_policy_binding: parsed.value.runtime_policy_binding,
    },
  };
}

export function buildActiveEcdsaMaterialFixture(): ActiveEcdsaMaterialActivationV1 {
  const activation = materialActivation('ecdsa-tenant-root-b5');
  const normalSigning = requireRouterAbEcdsaDerivationNormalSigningStateV1({
    kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
    scope: {
      wallet_id: WALLET_ID,
      ecdsa_threshold_key_id: 'ecdsa-threshold-key-tenant-root-b5',
      signing_root_id: SIGNING_ROOT_ID,
      signing_root_version: TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE.signingRootVersion,
      context: {
        application_binding_digest_b64u: DIGEST32_B64U,
      },
      public_identity: {
        context_binding_b64u: DIGEST32_B64U,
        derivation_client_share_public_key33_b64u: PUBLIC_KEY33_B64U,
        server_public_key33_b64u: SERVER_PUBLIC_KEY33_B64U,
        threshold_public_key33_b64u: PUBLIC_KEY33_B64U,
        ethereum_address20_b64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAA',
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      material_activation: activation,
      signing_worker: {
        server_id: activation.signing_worker,
        key_epoch: 'signing-worker-key-epoch-1',
        recipient_encryption_key:
          'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
      activation_epoch: 'activation-epoch-1',
    },
  });
  return {
    ok: true,
    materialActivation: activation,
    runtimePolicyScope: TENANT_ROOT_RUNTIME_POLICY_SCOPE_FIXTURE,
    routerAbEcdsaDerivationNormalSigning: normalSigning,
  };
}

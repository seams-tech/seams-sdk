import type { RuntimePolicyScope } from '../../packages/shared-ts/src/threshold/signingRootScope';
import {
  registrationNearEd25519BranchKey,
  type WalletId,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import {
  parseRouterAbEd25519YaoRegistrationActivationResultV1,
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '../../packages/shared-ts/src/utils/routerAbEd25519Yao';
import type { WalletEd25519YaoActiveCapabilityRecord } from '../../packages/sdk-server-ts/src/core/WalletStore';
import { ed25519NearPublicKeyFromBytes } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoWalletSigner';
import { buildRouterAbEd25519YaoRegistrationCapabilityRecordV1 } from '../../packages/sdk-server-ts/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';

export type Ed25519YaoCapabilityFixture = {
  readonly capability: WalletEd25519YaoActiveCapabilityRecord;
  readonly publicKey: string;
};

function fixtureBytes(seed: number, length = 32): number[] {
  return new Array<number>(length).fill(seed);
}

function activationClientPackageFixture(
  session: readonly number[],
  deriver: 'deriver_a' | 'deriver_b',
  seed: number,
) {
  return {
    kind: 'activation_client',
    deriver,
    session,
    transcript: fixtureBytes(seed),
    encapsulated_key: fixtureBytes(seed + 1),
    ciphertext: fixtureBytes(seed + 2, 16),
  };
}

export function buildEd25519YaoCapabilityFixture(input: {
  readonly walletId: WalletId;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly thresholdSessionId: string;
  readonly signerSlot: number;
  readonly signingWorkerId: string;
  readonly participantIds: readonly [number, number];
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly seed: number;
  /**
   * Overrides the synthetic lifecycle id. A fixture that must satisfy a real
   * admission request has to carry that request's lifecycle id, because the
   * receipt binding mirrors the request scope and the runtime compares them.
   */
  readonly lifecycleId?: string;
  /** Overrides the derived signer-set id, for the same reason. */
  readonly signerSetId?: string;
  /**
   * Overrides the synthetic material activation ref. Also for the same reason,
   * and load-bearing past admission: finalize compares the activation the
   * runtime returns against the ceremony's stored branch, so a fixture serving
   * a real ceremony must carry that ceremony's own ref rather than ids it
   * invented from the lifecycle id.
   */
  readonly materialActivation?: Record<string, unknown>;
}): Ed25519YaoCapabilityFixture {
  /* Derived, never overridable: the capability builder checks this against the
     runtime policy scope, so a separate override could only ever desync them. */
  const signingRootId = `${input.runtimePolicyScope.projectId}:${input.runtimePolicyScope.envId}`;
  const lifecycleId = input.lifecycleId ?? `registration-fixture-${input.seed}`;
  const signerSetId =
    input.signerSetId ?? String(registrationNearEd25519BranchKey(input.signerSlot));
  const materialActivation = input.materialActivation ?? {
    kind: 'mpc_material_activation_ref' as const,
    activation_id: `${lifecycleId}-activation`,
    capability: `${lifecycleId}-capability`,
    material_owner: input.walletId,
    key_binding: `${lifecycleId}-key`,
    lifecycle_binding: `${lifecycleId}-lifecycle-binding`,
    signing_worker: input.signingWorkerId,
  };
  const admissionRequest = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1({
    scope: {
      lifecycle_id: lifecycleId,
      root_share_epoch: input.runtimePolicyScope.signingRootVersion,
      account_id: input.walletId,
      threshold_session_id: input.thresholdSessionId,
      signer_set_id: signerSetId,
      signing_worker_id: input.signingWorkerId,
      material_activation: materialActivation,
    },
    application_binding: {
      wallet_id: input.walletId,
      near_ed25519_signing_key_id: input.nearEd25519SigningKeyId,
      signing_root_id: signingRootId,
      key_creation_signer_slot: input.signerSlot,
    },
    participant_ids: input.participantIds,
  });
  if (!admissionRequest.ok) throw new Error(admissionRequest.message);
  const session = fixtureBytes(input.seed);
  const binding = {
    lifecycle: {
      lifecycle_id: lifecycleId,
      work_kind: 'registration_prepare',
      primitive_request_kind: 'registration',
      root_share_epoch: input.runtimePolicyScope.signingRootVersion,
      account_id: input.walletId,
      session_id: input.thresholdSessionId,
      signer_set_id: signerSetId,
      selected_server_id: input.signingWorkerId,
    },
    operation: 'registration',
    session_id: session,
    stable_key_context_binding: fixtureBytes(input.seed + 1),
    material_activation: materialActivation,
  };
  const registeredPublicKey = fixtureBytes(input.seed + 2);
  const admissionReceipt = parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1({
    binding,
    keyset: {
      deriver_a_input_public_key: fixtureBytes(input.seed + 8),
      deriver_b_input_public_key: fixtureBytes(input.seed + 9),
      signing_worker_recipient_public_key: fixtureBytes(input.seed + 10),
    },
  });
  if (!admissionReceipt.ok) throw new Error(admissionReceipt.message);
  const activationResult = parseRouterAbEd25519YaoRegistrationActivationResultV1({
    binding,
    deriver_a_client_package: activationClientPackageFixture(session, 'deriver_a', input.seed + 3),
    deriver_b_client_package: activationClientPackageFixture(session, 'deriver_b', input.seed + 3),
    public_receipt: {
      transcript: fixtureBytes(input.seed + 3),
      registered_public_key: registeredPublicKey,
      joined_client_commitment: fixtureBytes(input.seed + 6),
      joined_signing_worker_commitment: fixtureBytes(input.seed + 7),
      signing_worker_verifying_share: fixtureBytes(input.seed + 7),
      state_epoch: 1,
      material_activation: materialActivation,
    },
  });
  if (!activationResult.ok) throw new Error(activationResult.message);
  const capability = buildRouterAbEd25519YaoRegistrationCapabilityRecordV1({
    kind: 'router_ab_ed25519_yao_registration_finalize_capability_v1',
    activeCapabilityBinding: session,
    nearAccountId: input.nearAccountId,
    registrationAdmissionRequest: admissionRequest.value,
    registrationAdmissionReceipt: admissionReceipt.value,
    registrationResult: activationResult.value,
    runtimePolicyScope: input.runtimePolicyScope,
  });
  if (!capability.ok) throw new Error(capability.message);
  return {
    capability: capability.record,
    publicKey: ed25519NearPublicKeyFromBytes(registeredPublicKey),
  };
}

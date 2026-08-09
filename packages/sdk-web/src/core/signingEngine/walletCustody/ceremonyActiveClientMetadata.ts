import {
  parseRouterAbEd25519YaoRegistrationActivationResultV1,
  parseRouterAbEd25519YaoRecoveryActivationResultV1,
  type RouterAbEd25519YaoRecoveryActivationReceiptV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { parseMpcMaterialActivationRef } from '@shared/utils/domainIds';
import {
  ROUTER_AB_ED25519_YAO_ACTIVE_CLIENT_KIND_V1,
  type RouterAbEd25519YaoActiveClientMetadataV1,
} from '../threshold/ed25519/yaoClient';

/**
 * The active-client metadata for a key set the ceremony registered.
 *
 * The PRF-derived path read this off the live client it kept. A ceremony keeps
 * no client — it seals the material and returns public facts — so the metadata
 * has to be rebuilt from the two things that produced it: the admission request
 * this run registered under, and the Router's activation result.
 *
 * **Every identity here comes from the Router's receipt, not from this side.**
 * That matters most for `materialActivation`: it is a Refactor 90 identity, and
 * the boundary that mints it is the Router, exactly as on the PRF path. Nothing
 * here invents one — a locally minted activation ref would be a second owner
 * for state Refactor 90 owns.
 */
export function walletCustodyEd25519ActiveClientMetadataV1(input: {
  readonly admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  readonly activationResultJson: string;
}): RouterAbEd25519YaoActiveClientMetadataV1 {
  let raw: unknown;
  try {
    raw = JSON.parse(input.activationResultJson);
  } catch {
    throw new Error('the Router activation result is not JSON');
  }
  const result = parseRouterAbEd25519YaoRegistrationActivationResultV1(raw);
  if (!result.ok) {
    throw new Error(`Router activation result is invalid: ${result.message}`);
  }
  const activation = result.value;
  const receipt = activation.public_receipt;

  /* Bound before anything is built from it: a result for another lifecycle
     would otherwise hand this wallet metadata describing someone else's key,
     and every record below would carry it. */
  if (activation.binding.lifecycle.lifecycle_id !== input.admissionRequest.scope.lifecycle_id) {
    throw new Error('the Router activation result belongs to another lifecycle');
  }

  const wire = receipt.material_activation;
  const materialActivation = parseMpcMaterialActivationRef({
    kind: wire.kind,
    activationId: wire.activation_id,
    capability: wire.capability,
    materialOwner: wire.material_owner,
    keyBinding: wire.key_binding,
    lifecycleBinding: wire.lifecycle_binding,
    signingWorker: wire.signing_worker,
  });
  if (!materialActivation.ok) {
    throw new Error(`Invalid activation material reference: ${materialActivation.error.message}`);
  }

  const participantIds = input.admissionRequest.participant_ids;
  if (participantIds.length !== 2) {
    throw new Error('an Ed25519 Yao registration has exactly two participants');
  }

  return {
    kind: ROUTER_AB_ED25519_YAO_ACTIVE_CLIENT_KIND_V1,
    scope: input.admissionRequest.scope,
    applicationBinding: input.admissionRequest.application_binding,
    participantIds: [participantIds[0], participantIds[1]],
    registeredPublicKey: Uint8Array.from(receipt.registered_public_key),
    signingWorkerVerifyingShare: Uint8Array.from(receipt.signing_worker_verifying_share),
    stateEpoch: BigInt(receipt.state_epoch),
    transcript: Uint8Array.from(receipt.transcript),
    activeCapabilityBinding: activation.binding.session_id,
    materialActivation: materialActivation.value,
  };
}

export function walletRecoveryEd25519ActiveClientMetadataV1(input: {
  readonly admissionRequest: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  readonly activationResultJson: string;
  readonly activationReceipt: RouterAbEd25519YaoRecoveryActivationReceiptV1;
}): RouterAbEd25519YaoActiveClientMetadataV1 {
  let raw: unknown;
  try {
    raw = JSON.parse(input.activationResultJson);
  } catch {
    throw new Error('the Router recovery result is not JSON');
  }
  const parsed = parseRouterAbEd25519YaoRecoveryActivationResultV1(raw);
  if (!parsed.ok) {
    throw new Error(`Router recovery result is invalid: ${parsed.message}`);
  }
  const result = parsed.value;
  if (result.binding.lifecycle.lifecycle_id !== input.admissionRequest.scope.lifecycle_id) {
    throw new Error('the Router recovery result belongs to another lifecycle');
  }
  if (
    input.activationReceipt.binding.lifecycle.lifecycle_id !==
    input.admissionRequest.scope.lifecycle_id
  ) {
    throw new Error('the Router recovery activation belongs to another lifecycle');
  }
  const receipt = input.activationReceipt.public_receipt;
  const materialActivation = parseMpcMaterialActivationRef({
    kind: receipt.material_activation.kind,
    activationId: receipt.material_activation.activation_id,
    capability: receipt.material_activation.capability,
    materialOwner: receipt.material_activation.material_owner,
    keyBinding: receipt.material_activation.key_binding,
    lifecycleBinding: receipt.material_activation.lifecycle_binding,
    signingWorker: receipt.material_activation.signing_worker,
  });
  if (!materialActivation.ok) {
    throw new Error(`Invalid recovery material reference: ${materialActivation.error.message}`);
  }
  return {
    kind: ROUTER_AB_ED25519_YAO_ACTIVE_CLIENT_KIND_V1,
    scope: input.admissionRequest.scope,
    applicationBinding: input.admissionRequest.application_binding,
    participantIds: [
      input.admissionRequest.participant_ids[0],
      input.admissionRequest.participant_ids[1],
    ],
    registeredPublicKey: Uint8Array.from(receipt.registered_public_key),
    signingWorkerVerifyingShare: Uint8Array.from(receipt.signing_worker_verifying_share),
    stateEpoch: BigInt(receipt.state_epoch),
    transcript: Uint8Array.from(receipt.transcript),
    activeCapabilityBinding: Uint8Array.from(input.activationReceipt.active_capability_binding),
    materialActivation: materialActivation.value,
  };
}

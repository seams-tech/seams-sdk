import {
  ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
  parseRouterAbEd25519YaoRecoveryActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRecoveryActivationReceiptV1,
  parseRouterAbEd25519YaoRecoveryActivationResultV1,
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoRecoveryActivationReceiptV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  buildMpcMaterialActivationRef,
  parseMpcLifecycleBindingRef,
  parseMpcMaterialActivationId,
} from '@shared/utils/domainIds';
import { sameRouterAbMpcMaterialActivationRef } from '@shared/utils/routerAbNormalSigningIdentity';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  deriveWalletRecoveryKeyLifecycleId,
  parseRecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import type { WalletRecoveryPreparationKeyManifestEntry } from '@/core/rpcClients/relayer/walletRecoveryPrepare';
import type { RouterAbEd25519YaoRecoveryTransportV1 } from '../threshold/ed25519/yaoClient';

type NearRecoveryEntry = Extract<
  WalletRecoveryPreparationKeyManifestEntry,
  { readonly kind: 'near_ed25519' }
>;

export type WalletRecoveryEd25519Admission = {
  readonly request: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  readonly receipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'recovery'>;
};

function equalBytes(left: readonly number[], right: readonly number[]): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function requireParsed<T>(
  parsed: { readonly ok: true; readonly value: T } | { readonly ok: false; readonly message: string },
  label: string,
): T {
  if (!parsed.ok) throw new Error(`${label}: ${parsed.message}`);
  return parsed.value;
}

export async function buildWalletRecoveryEd25519AdmissionRequestV1(input: {
  readonly reservationId: string;
  readonly entry: NearRecoveryEntry;
}): Promise<RouterAbEd25519YaoRecoveryAdmissionRequestV1> {
  const reservationId = parseRecoveryCodeReservationId(input.reservationId);
  const lifecycleId = await deriveWalletRecoveryKeyLifecycleId({
    reservationId,
    keySetId: input.entry.keySetId,
  });
  const current = input.entry.recoveryBasis.scope.material_activation;
  const activationId = parseMpcMaterialActivationId(
    secureRandomId(
      'wallet-recovery-ed25519-material-activation',
      32,
      'wallet recovery Ed25519 activation identities',
    ),
  );
  const lifecycleBinding = parseMpcLifecycleBindingRef(`${lifecycleId}:material-activation`);
  if (!activationId.ok || !lifecycleBinding.ok) {
    throw new Error('wallet recovery Ed25519 material activation identity is invalid');
  }
  const materialActivation = buildMpcMaterialActivationRef({
    activationId: activationId.value,
    capability: current.capability,
    materialOwner: current.material_owner,
    keyBinding: current.key_binding,
    lifecycleBinding: lifecycleBinding.value,
    signingWorker: current.signing_worker,
  });
  const replacementCapabilityBinding = new Uint8Array(32);
  globalThis.crypto.getRandomValues(replacementCapabilityBinding);
  try {
    return requireParsed(
      parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
        scope: {
          lifecycle_id: lifecycleId,
          root_share_epoch: input.entry.recoveryBasis.scope.root_share_epoch,
          account_id: input.entry.recoveryBasis.scope.account_id,
          threshold_session_id: `${lifecycleId}:threshold-session`,
          signer_set_id: input.entry.recoveryBasis.scope.signer_set_id,
          signing_worker_id: input.entry.recoveryBasis.scope.signing_worker_id,
          material_activation: {
            kind: materialActivation.kind,
            activation_id: materialActivation.activationId,
            capability: materialActivation.capability,
            material_owner: materialActivation.materialOwner,
            key_binding: materialActivation.keyBinding,
            lifecycle_binding: materialActivation.lifecycleBinding,
            signing_worker: materialActivation.signingWorker,
          },
        },
        active_material_activation: current,
        application_binding: input.entry.recoveryBasis.applicationBinding,
        participant_ids: input.entry.recoveryBasis.participantIds,
        active_capability_binding: input.entry.recoveryBasis.activeCapabilityBinding,
        replacement_capability_binding: [...replacementCapabilityBinding],
        registered_public_key: input.entry.recoveryBasis.registeredPublicKey,
      }),
      'wallet recovery Ed25519 admission request is invalid',
    );
  } finally {
    replacementCapabilityBinding.fill(0);
  }
}

export async function admitWalletRecoveryEd25519V1(input: {
  readonly request: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  readonly transport: RouterAbEd25519YaoRecoveryTransportV1;
}): Promise<WalletRecoveryEd25519Admission> {
  const response = await input.transport.send({
    kind: 'recovery_admit',
    path: ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
    body: input.request,
  });
  if (!response.ok) {
    throw new Error(`Router Ed25519 recovery admission failed: ${response.message}`);
  }
  const receipt = requireParsed(
    parseRouterAbEd25519YaoRecoveryActivationAdmissionReceiptV1(response.value),
    'Router Ed25519 recovery admission is invalid',
  );
  const lifecycle = receipt.binding.lifecycle;
  if (
    lifecycle.lifecycle_id !== input.request.scope.lifecycle_id ||
    !sameRouterAbMpcMaterialActivationRef(
      receipt.binding.material_activation,
      input.request.scope.material_activation,
    )
  ) {
    throw new Error('Router Ed25519 recovery admission changed the requested lifecycle');
  }
  return { request: input.request, receipt };
}

export async function executeWalletRecoveryEd25519RoundV1(input: {
  readonly executeRequestJson: string;
  readonly transport: RouterAbEd25519YaoRecoveryTransportV1;
}): Promise<string> {
  const executeRequest: RouterAbEd25519YaoActivationExecuteRequestV1<'recovery'> = requireParsed(
    parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1(
      JSON.parse(input.executeRequestJson),
    ),
    'wallet recovery Ed25519 execute request is invalid',
  );
  const response = await input.transport.send({
    kind: 'recovery_execute',
    path: ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
    body: executeRequest,
  });
  if (!response.ok) {
    throw new Error(`Router Ed25519 recovery execute failed: ${response.message}`);
  }
  const result = requireParsed(
    parseRouterAbEd25519YaoRecoveryActivationResultV1(response.value),
    'Router Ed25519 recovery result is invalid',
  );
  return JSON.stringify(result);
}

export async function activateWalletRecoveryEd25519V1(input: {
  readonly request: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  readonly protocolResultJson: string;
  readonly transport: RouterAbEd25519YaoRecoveryTransportV1;
}): Promise<RouterAbEd25519YaoRecoveryActivationReceiptV1> {
  const result = requireParsed(
    parseRouterAbEd25519YaoRecoveryActivationResultV1(JSON.parse(input.protocolResultJson)),
    'Router Ed25519 recovery result is invalid',
  );
  const response = await input.transport.send({
    kind: 'recovery_activate',
    path: ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
    body: {
      binding: result.binding,
      public_receipt: result.public_receipt,
    },
  });
  if (!response.ok) {
    throw new Error(`Router Ed25519 recovery activation failed: ${response.message}`);
  }
  const receipt = requireParsed(
    parseRouterAbEd25519YaoRecoveryActivationReceiptV1(response.value),
    'Router Ed25519 recovery activation is invalid',
  );
  if (
    !equalBytes(receipt.active_capability_binding, input.request.replacement_capability_binding) ||
    !equalBytes(receipt.retired_capability_binding, input.request.active_capability_binding) ||
    !equalBytes(receipt.public_receipt.transcript, result.public_receipt.transcript) ||
    !equalBytes(
      receipt.public_receipt.registered_public_key,
      result.public_receipt.registered_public_key,
    ) ||
    !equalBytes(
      receipt.public_receipt.signing_worker_verifying_share,
      result.public_receipt.signing_worker_verifying_share,
    ) ||
    receipt.public_receipt.state_epoch !== result.public_receipt.state_epoch ||
    !sameRouterAbMpcMaterialActivationRef(
      receipt.public_receipt.material_activation,
      input.request.scope.material_activation,
    )
  ) {
    throw new Error('Router Ed25519 recovery activation changed the requested identity');
  }
  return receipt;
}

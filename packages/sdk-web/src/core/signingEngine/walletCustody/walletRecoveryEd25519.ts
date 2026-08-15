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
import {
  routerAbMpcMaterialActivationRefFromWire,
  routerAbMpcMaterialActivationRefToWire,
  sameRouterAbMpcMaterialActivationRef,
} from '@shared/utils/routerAbNormalSigningIdentity';
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

export type WalletSessionEd25519RecoveryBasisV1 = {
  readonly materialActivation: ReturnType<typeof routerAbMpcMaterialActivationRefFromWire>;
  readonly activeCapabilityBinding: readonly number[];
  readonly registeredPublicKey: readonly number[];
  readonly applicationBinding: RouterAbEd25519YaoRecoveryAdmissionRequestV1['application_binding'];
  readonly participantIds: readonly [number, number];
  readonly lifecycle: {
    readonly lifecycleId: string;
    readonly rootShareEpoch: string;
    readonly accountId: string;
    readonly thresholdSessionId: string;
    readonly signerSetId: string;
    readonly signingWorkerId: string;
  };
};

type Ed25519RecoveryCurrentScopeV1 = {
  readonly root_share_epoch: string;
  readonly account_id: string;
  readonly signer_set_id: string;
  readonly signing_worker_id: string;
  readonly material_activation: RouterAbEd25519YaoRecoveryAdmissionRequestV1['active_material_activation'];
};

async function buildEd25519RecoveryAdmissionRequestV1(input: {
  readonly lifecycleId: string;
  readonly thresholdSessionId: string;
  readonly currentScope: Ed25519RecoveryCurrentScopeV1;
  readonly applicationBinding: RouterAbEd25519YaoRecoveryAdmissionRequestV1['application_binding'];
  readonly participantIds: readonly [number, number];
  readonly activeCapabilityBinding: readonly number[];
  readonly registeredPublicKey: readonly number[];
}): Promise<RouterAbEd25519YaoRecoveryAdmissionRequestV1> {
  const currentActivation = routerAbMpcMaterialActivationRefFromWire(
    input.currentScope.material_activation,
  );
  const activationId = parseMpcMaterialActivationId(
    secureRandomId(
      'wallet-recovery-ed25519-material-activation',
      32,
      'wallet recovery Ed25519 activation identities',
    ),
  );
  const lifecycleBinding = parseMpcLifecycleBindingRef(
    `${input.lifecycleId}:material-activation`,
  );
  if (!activationId.ok || !lifecycleBinding.ok) {
    throw new Error('wallet recovery Ed25519 material activation identity is invalid');
  }
  const materialActivation = buildMpcMaterialActivationRef({
    activationId: activationId.value,
    capability: currentActivation.capability,
    materialOwner: currentActivation.materialOwner,
    keyBinding: currentActivation.keyBinding,
    lifecycleBinding: lifecycleBinding.value,
    signingWorker: currentActivation.signingWorker,
  });
  const replacementCapabilityBinding = new Uint8Array(32);
  globalThis.crypto.getRandomValues(replacementCapabilityBinding);
  try {
    return requireParsed(
      parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
        scope: {
          lifecycle_id: input.lifecycleId,
          root_share_epoch: input.currentScope.root_share_epoch,
          account_id: input.currentScope.account_id,
          threshold_session_id: input.thresholdSessionId,
          signer_set_id: input.currentScope.signer_set_id,
          signing_worker_id: input.currentScope.signing_worker_id,
          material_activation: routerAbMpcMaterialActivationRefToWire(materialActivation),
        },
        active_material_activation: input.currentScope.material_activation,
        application_binding: input.applicationBinding,
        participant_ids: input.participantIds,
        active_capability_binding: input.activeCapabilityBinding,
        replacement_capability_binding: [...replacementCapabilityBinding],
        registered_public_key: input.registeredPublicKey,
      }),
      'wallet recovery Ed25519 admission request is invalid',
    );
  } finally {
    replacementCapabilityBinding.fill(0);
  }
}

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
  return await buildEd25519RecoveryAdmissionRequestV1({
    lifecycleId,
    thresholdSessionId: `${lifecycleId}:threshold-session`,
    currentScope: input.entry.recoveryBasis.scope,
    applicationBinding: input.entry.recoveryBasis.applicationBinding,
    participantIds: input.entry.recoveryBasis.participantIds,
    activeCapabilityBinding: input.entry.recoveryBasis.activeCapabilityBinding,
    registeredPublicKey: input.entry.recoveryBasis.registeredPublicKey,
  });
}

export async function buildWalletSessionEd25519RecoveryAdmissionRequestV1(input: {
  readonly basis: WalletSessionEd25519RecoveryBasisV1;
}): Promise<RouterAbEd25519YaoRecoveryAdmissionRequestV1> {
  const lifecycleId = secureRandomId(
    'wallet-session-ed25519-recovery',
    32,
    'wallet-session Ed25519 recovery lifecycles',
  );
  return await buildEd25519RecoveryAdmissionRequestV1({
    lifecycleId,
    thresholdSessionId: input.basis.lifecycle.thresholdSessionId,
    currentScope: {
      root_share_epoch: input.basis.lifecycle.rootShareEpoch,
      account_id: input.basis.lifecycle.accountId,
      signer_set_id: input.basis.lifecycle.signerSetId,
      signing_worker_id: input.basis.lifecycle.signingWorkerId,
      material_activation: routerAbMpcMaterialActivationRefToWire(input.basis.materialActivation),
    },
    applicationBinding: input.basis.applicationBinding,
    participantIds: input.basis.participantIds,
    activeCapabilityBinding: input.basis.activeCapabilityBinding,
    registeredPublicKey: input.basis.registeredPublicKey,
  });
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

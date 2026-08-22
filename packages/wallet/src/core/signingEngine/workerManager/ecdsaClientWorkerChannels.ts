import { isObject } from '@shared/utils/validation';
import type {
  RouterAbEcdsaClientProofFinalizationV1,
  RouterAbEcdsaDerivationActivationRefreshRequestV1,
  RouterAbEcdsaDerivationExplicitExportRequestV1,
  RouterAbEcdsaDerivationExplicitExportProtocolRequestV1,
  RouterAbEcdsaOperationStepUpPreparationV1Wire,
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaRegistrationRecipientKeysV1,
  RouterAbEcdsaSigningWorkerExportShareEnvelopeV1,
  RouterAbEcdsaSigningWorkerExportShareBindingV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type {
  EcdsaRoleLocalPersistedMaterialRef,
  EcdsaRoleLocalWorkerHandle,
} from '@/core/signingEngine/session/keyMaterialBrands';
import type { EcdsaRoleLocalPublicFacts } from '@/core/platform';
import type { EcdsaRoleLocalReadyStateBlob } from '@/core/platform';
import type { EcdsaClientPresignPoolIdentity } from './ecdsaPresignPoolIdentity';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { RouterAbMpcMaterialActivationRefWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { RouterAbNormalSigningAuthorizationWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type {
  WalletRecoveryEcdsaPossessionChallengeV1,
  WalletRecoveryEcdsaPossessionProofV1,
} from '@shared/wallet-recovery/walletRecoveryEcdsaPossession';
import type {
  EcdsaAdditiveLaneHolderPreparationV1,
  EcdsaAdditiveLaneJobV1,
} from '@shared/signing-lanes/rotation';
import { parseRotatableSigningLaneJobV1 } from '@shared/signing-lanes/rotationParsers';
import {
  parseLinkedDeviceEcdsaSourceContributionPackageV1,
  parseLinkedDeviceEcdsaSourceContributionPreparationV1,
  type LinkedDeviceEcdsaSourceContributionPackageV1,
  type LinkedDeviceEcdsaSourceContributionPreparationV1,
} from '@shared/device-linking/sourceContribution';

export const EcdsaClientWorkerControlKind = {
  AttachDerivationToPresign: 'attach_ecdsa_derivation_to_presign_v1',
  AttachLinkedHolderToPresign: 'attach_linked_holder_to_ecdsa_presign_v1',
  AttachPresignToOnline: 'attach_ecdsa_presign_to_online_v1',
} as const;

export type AttachEcdsaDerivationToPresignPort = {
  readonly kind: typeof EcdsaClientWorkerControlKind.AttachDerivationToPresign;
  readonly port: MessagePort;
};

export type AttachLinkedHolderToPresignPort = {
  readonly kind: typeof EcdsaClientWorkerControlKind.AttachLinkedHolderToPresign;
  readonly port: MessagePort;
};

export type AttachPresignToOnlinePort = {
  readonly kind: typeof EcdsaClientWorkerControlKind.AttachPresignToOnline;
  readonly port: MessagePort;
};

type OpaqueEcdsaPresignRequestBaseV1 = {
  readonly requestId: string;
};

type OpaqueEcdsaPresignSessionRequestBaseV1 = OpaqueEcdsaPresignRequestBaseV1 & {
  readonly sessionId: string;
};

type OpaqueEcdsaPresignSessionInitBaseV1 = OpaqueEcdsaPresignSessionRequestBaseV1 & {
  readonly kind: 'opaque_ecdsa_presign_session_init_v1';
  readonly poolIdentity: EcdsaClientPresignPoolIdentity;
  readonly groupPublicKey33: ArrayBuffer;
  readonly materialExpiresAtMs: number;
};

export type OpaqueEcdsaPresignAuthorityRequestV1 =
  | (OpaqueEcdsaPresignSessionInitBaseV1 & {
      readonly authority: {
        readonly kind: 'role_local_derivation_handle';
        readonly materialHandle: string;
        readonly material:
          | {
              readonly kind: 'persisted';
              readonly materialRef: EcdsaRoleLocalPersistedMaterialRef;
              readonly expectedBindingDigest?: never;
            }
          | {
              readonly kind: 'runtime_loaded';
              readonly expectedBindingDigest: string;
              readonly materialRef?: never;
            };
        readonly holderHandleId?: never;
      };
    })
  | (OpaqueEcdsaPresignSessionInitBaseV1 & {
      readonly authority: {
        readonly kind: 'linked_holder_signing_material';
        readonly holderHandleId: string;
        readonly materialHandle?: never;
        readonly material?: never;
      };
    })
  | (OpaqueEcdsaPresignSessionRequestBaseV1 & {
      readonly kind: 'opaque_ecdsa_presign_session_step_v1';
      readonly stage: 'triples' | 'presign';
      readonly incomingMessages: readonly ArrayBuffer[];
    })
  | (OpaqueEcdsaPresignSessionRequestBaseV1 & {
      readonly kind: 'opaque_ecdsa_presign_session_abort_v1';
    })
  | (OpaqueEcdsaPresignRequestBaseV1 & {
      readonly kind: 'opaque_ecdsa_online_compute_v1';
      readonly materialHandle: string;
      readonly groupPublicKey33: ArrayBuffer;
      readonly expectedPresignBigR33: ArrayBuffer;
      readonly digest32: ArrayBuffer;
      readonly clientRerandomizationContribution32: ArrayBuffer;
      readonly signingWorkerRerandomizationContribution32: ArrayBuffer;
    })
  | (OpaqueEcdsaPresignRequestBaseV1 & {
      readonly kind: 'opaque_ecdsa_presign_material_destroy_v1';
      readonly materialHandle: string;
    });

export type OpaqueEcdsaPresignAuthorityResponseV1 =
  | {
      readonly kind: 'opaque_ecdsa_presign_authority_result_v1';
      readonly requestId: string;
      readonly ok: true;
      readonly result:
        | {
            readonly kind: 'progress';
            readonly progress: {
              readonly stage: 'triples' | 'triples_done' | 'presign' | 'done';
              readonly event: 'none' | 'triples_done' | 'presign_done';
              readonly outgoingMessages: ArrayBuffer[];
              readonly presignatureHandle?: string;
              readonly presignatureBigR33?: ArrayBuffer;
            };
          }
        | {
            readonly kind: 'metered_progress';
            readonly progress: {
              readonly stage: 'triples' | 'triples_done' | 'presign' | 'done';
              readonly event: 'none' | 'triples_done' | 'presign_done';
              readonly outgoingMessages: ArrayBuffer[];
              readonly presignatureHandle?: string;
              readonly presignatureBigR33?: ArrayBuffer;
            };
            readonly remainingUses: number;
            readonly expiresAtMs: number;
          }
        | {
            readonly kind: 'aborted';
            readonly sessionId: string;
          }
        | {
            readonly kind: 'online_share';
            readonly signatureShare32: ArrayBuffer;
          }
        | {
            readonly kind: 'material_destroyed';
            readonly materialHandle: string;
          };
      readonly error?: never;
    }
  | {
      readonly kind: 'opaque_ecdsa_presign_authority_result_v1';
      readonly requestId: string;
      readonly ok: false;
      readonly result?: never;
      readonly error: string;
    };

export type RehydrateEcdsaRoleLocalSigningMaterialRequestV1 = {
  readonly kind: 'open_ecdsa_role_local_signing_material_v1';
  readonly authority: WalletAuthAuthorityRef;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly materialRef?: never;
};

export type RehydrateEcdsaRoleLocalSigningMaterialResultV1 =
  | {
      readonly kind: 'ecdsa_role_local_signing_material_opened_v1';
      readonly ok: true;
      readonly liveHandle: EcdsaRoleLocalWorkerHandle;
      readonly materialRef: EcdsaRoleLocalPersistedMaterialRef;
      readonly reason?: never;
    }
  | {
      readonly kind: 'ecdsa_role_local_signing_material_unavailable_v1';
      readonly ok: false;
      readonly reason: 'missing' | 'expired' | 'binding_mismatch' | 'corrupt';
      readonly liveHandle?: never;
      readonly materialRef?: never;
    };

export type SignWalletRecoveryEcdsaMaterialPossessionProofRequestV1 = {
  readonly kind: 'sign_wallet_recovery_ecdsa_material_possession_proof_v1';
  readonly challenge: WalletRecoveryEcdsaPossessionChallengeV1;
  readonly stateBlob: EcdsaRoleLocalReadyStateBlob;
};

export type SignWalletRecoveryEcdsaMaterialPossessionProofResultV1 = {
  readonly kind: 'ecdsa_wallet_recovery_material_possession_proof_v1';
  readonly proof: WalletRecoveryEcdsaPossessionProofV1;
  readonly challengeDigestB64u: DigestB64u;
  readonly derivationClientSharePublicKey33B64u: string;
};

export type PrepareEcdsaAdditiveLaneHolderRequestV1 = {
  readonly kind: 'prepare_ecdsa_additive_lane_holder_v1';
  readonly job: EcdsaAdditiveLaneJobV1;
  readonly holderCommittedAtMs: number;
};

export type PrepareEcdsaAdditiveLaneHolderResultV1 = EcdsaAdditiveLaneHolderPreparationV1;

export type PrepareLinkedDeviceEcdsaSourceContributionRequestV1 = {
  readonly kind: 'prepare_linked_device_ecdsa_source_contribution_v1';
  readonly preparation: LinkedDeviceEcdsaSourceContributionPreparationV1;
};

export type PrepareLinkedDeviceEcdsaSourceContributionResultV1 = {
  readonly kind: 'linked_device_ecdsa_source_contribution_package_v1';
  readonly package: LinkedDeviceEcdsaSourceContributionPackageV1;
};

export function parsePrepareEcdsaAdditiveLaneHolderRequestV1(
  raw: unknown,
): PrepareEcdsaAdditiveLaneHolderRequestV1 {
  if (!isObject(raw) || Array.isArray(raw)) {
    throw new Error('ECDSA lane holder request must be an object');
  }
  const fields = Object.keys(raw);
  if (
    fields.length !== 3 ||
    !fields.includes('kind') ||
    !fields.includes('job') ||
    !fields.includes('holderCommittedAtMs')
  ) {
    throw new Error('ECDSA lane holder request has invalid fields');
  }
  if (raw.kind !== 'prepare_ecdsa_additive_lane_holder_v1') {
    throw new Error('ECDSA lane holder request kind is invalid');
  }
  const job = parseRotatableSigningLaneJobV1(raw.job, 'ecdsaLaneHolderRequest.job');
  if (job.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('ECDSA lane holder request requires an ECDSA lane job');
  }
  const holderCommittedAtMs = raw.holderCommittedAtMs;
  if (
    typeof holderCommittedAtMs !== 'number' ||
    !Number.isSafeInteger(holderCommittedAtMs) ||
    holderCommittedAtMs < 0
  ) {
    throw new Error('ECDSA lane holder request holderCommittedAtMs is invalid');
  }
  return {
    kind: 'prepare_ecdsa_additive_lane_holder_v1',
    job,
    holderCommittedAtMs,
  };
}

export function parsePrepareLinkedDeviceEcdsaSourceContributionRequestV1(
  raw: unknown,
): PrepareLinkedDeviceEcdsaSourceContributionRequestV1 {
  if (!isObject(raw) || Array.isArray(raw)) {
    throw new Error('linked-device ECDSA source contribution request must be an object');
  }
  const fields = Object.keys(raw);
  if (fields.length !== 2 || !fields.includes('kind') || !fields.includes('preparation')) {
    throw new Error('linked-device ECDSA source contribution request has invalid fields');
  }
  if (raw.kind !== 'prepare_linked_device_ecdsa_source_contribution_v1') {
    throw new Error('linked-device ECDSA source contribution request kind is invalid');
  }
  return {
    kind: 'prepare_linked_device_ecdsa_source_contribution_v1',
    preparation: parseLinkedDeviceEcdsaSourceContributionPreparationV1(raw.preparation),
  };
}

export function parsePrepareLinkedDeviceEcdsaSourceContributionResultV1(
  raw: unknown,
): PrepareLinkedDeviceEcdsaSourceContributionResultV1 {
  if (!isObject(raw) || Array.isArray(raw)) {
    throw new Error('linked-device ECDSA source contribution result must be an object');
  }
  const fields = Object.keys(raw);
  if (fields.length !== 2 || !fields.includes('kind') || !fields.includes('package')) {
    throw new Error('linked-device ECDSA source contribution result has invalid fields');
  }
  if (raw.kind !== 'linked_device_ecdsa_source_contribution_package_v1') {
    throw new Error('linked-device ECDSA source contribution result kind is invalid');
  }
  return {
    kind: 'linked_device_ecdsa_source_contribution_package_v1',
    package: parseLinkedDeviceEcdsaSourceContributionPackageV1(raw.package),
  };
}

type RouterAbEcdsaExplicitExportRequestFactsBaseV1 = Omit<
  RouterAbEcdsaDerivationExplicitExportProtocolRequestV1,
  'client_ephemeral_public_key' | 'deriver_a_export_envelope' | 'deriver_b_export_envelope'
> & {
  readonly deriver_recipient_keys: RouterAbEcdsaRegistrationRecipientKeysV1;
};

type RouterAbEcdsaReusableExplicitExportRequestFactsV1 =
  RouterAbEcdsaExplicitExportRequestFactsBaseV1 & {
    readonly authorization: Extract<
      RouterAbNormalSigningAuthorizationWire,
      { readonly kind: 'reusable_wallet_session' }
    >;
    readonly operation?: never;
    readonly authorization_id?: never;
  };

type RouterAbEcdsaOperationStepUpExplicitExportRequestFactsV1 =
  RouterAbEcdsaExplicitExportRequestFactsBaseV1 & {
    readonly authorization: Extract<
      RouterAbNormalSigningAuthorizationWire,
      { readonly kind: 'operation_step_up' }
    >;
    readonly operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
    readonly authorization_id: DigestB64u;
  };

export type RouterAbEcdsaExplicitExportRequestFactsV1 =
  | RouterAbEcdsaReusableExplicitExportRequestFactsV1
  | RouterAbEcdsaOperationStepUpExplicitExportRequestFactsV1;

type RouterAbEcdsaReusableExplicitExportRequestWasmInputV1 =
  RouterAbEcdsaExplicitExportRequestFactsBaseV1 & {
    readonly authorization: Extract<
      RouterAbNormalSigningAuthorizationWire,
      { readonly kind: 'reusable_wallet_session' }
    >;
    readonly authorization_id?: never;
  };

type RouterAbEcdsaOperationStepUpExplicitExportRequestWasmInputV1 = Omit<
  RouterAbEcdsaExplicitExportRequestFactsBaseV1,
  'authorization'
> & {
  readonly authorization: {
    readonly kind: 'operation_step_up';
    readonly authorization_id: DigestB64u;
  };
};

export type RouterAbEcdsaExplicitExportRequestWasmInputV1 =
  | RouterAbEcdsaReusableExplicitExportRequestWasmInputV1
  | RouterAbEcdsaOperationStepUpExplicitExportRequestWasmInputV1;

function isOperationStepUpExplicitExportFacts(
  request: RouterAbEcdsaExplicitExportRequestFactsV1,
): request is RouterAbEcdsaOperationStepUpExplicitExportRequestFactsV1 {
  return request.authorization.kind === 'operation_step_up';
}

function projectReusableExplicitExportRequestForWasm(
  request: RouterAbEcdsaReusableExplicitExportRequestFactsV1,
): RouterAbEcdsaReusableExplicitExportRequestWasmInputV1 {
  const { operation: _operation, authorization_id: _authorizationId, ...wasmInput } = request;
  return wasmInput;
}

function projectOperationStepUpExplicitExportRequestForWasm(
  request: RouterAbEcdsaOperationStepUpExplicitExportRequestFactsV1,
): RouterAbEcdsaOperationStepUpExplicitExportRequestWasmInputV1 {
  const {
    operation: _operation,
    authorization: _authorization,
    authorization_id: authorizationId,
    ...wasmInput
  } = request;
  if (!authorizationId) {
    throw new Error('ECDSA explicit-export operation authorization id is missing');
  }
  return {
    ...wasmInput,
    authorization: {
      kind: 'operation_step_up',
      authorization_id: authorizationId,
    },
  };
}

export function projectRouterAbEcdsaExplicitExportRequestForWasmV1(
  request: RouterAbEcdsaExplicitExportRequestFactsV1,
): RouterAbEcdsaExplicitExportRequestWasmInputV1 {
  if (isOperationStepUpExplicitExportFacts(request)) {
    return projectOperationStepUpExplicitExportRequestForWasm(request);
  }
  return projectReusableExplicitExportRequestForWasm(request);
}

export function attachRouterAbEcdsaExplicitExportOperationV1(input: {
  readonly facts: RouterAbEcdsaExplicitExportRequestFactsV1;
  readonly protocolRequest: RouterAbEcdsaDerivationExplicitExportProtocolRequestV1;
}): RouterAbEcdsaDerivationExplicitExportRequestV1 {
  if (!isOperationStepUpExplicitExportFacts(input.facts)) {
    if (input.protocolRequest.authorization.kind !== 'reusable_wallet_session') {
      throw new Error('ECDSA explicit-export authorization changed across the WASM boundary');
    }
    return {
      ...input.protocolRequest,
      authorization: input.protocolRequest.authorization,
    };
  }
  if (input.protocolRequest.authorization.kind !== 'operation_step_up') {
    throw new Error('ECDSA explicit-export authorization changed across the WASM boundary');
  }
  return {
    ...input.protocolRequest,
    authorization: input.protocolRequest.authorization,
    operation: input.facts.operation,
  };
}

export type RouterAbEcdsaActivationRefreshRequestFactsV1 = Omit<
  RouterAbEcdsaDerivationActivationRefreshRequestV1,
  'deriver_a_refresh_envelope' | 'deriver_b_refresh_envelope'
> & {
  readonly deriver_recipient_keys: RouterAbEcdsaRegistrationRecipientKeysV1;
};

export type CreateRouterAbEcdsaPostRegistrationCeremonyRequestV1 =
  | {
      readonly kind: 'create_router_ab_ecdsa_explicit_export_ceremony_v1';
      readonly ceremonyId: string;
      readonly request: RouterAbEcdsaExplicitExportRequestFactsV1;
    }
  | {
      readonly kind: 'create_router_ab_ecdsa_activation_refresh_ceremony_v1';
      readonly ceremonyId: string;
      readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
      readonly request: RouterAbEcdsaActivationRefreshRequestFactsV1;
    };

export type CreateRouterAbEcdsaPostRegistrationCeremonyResultV1 =
  | {
      readonly kind: 'router_ab_ecdsa_explicit_export_ceremony_created_v1';
      readonly ceremonyId: string;
      readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
      readonly requestDigestB64u: string;
    }
  | {
      readonly kind: 'router_ab_ecdsa_activation_refresh_ceremony_created_v1';
      readonly ceremonyId: string;
      readonly request: RouterAbEcdsaDerivationActivationRefreshRequestV1;
      readonly requestDigestB64u: string;
    };

export type FinalizeRouterAbEcdsaExplicitExportRequestV1 = {
  readonly kind: 'finalize_router_ab_ecdsa_explicit_export_v1';
  readonly ceremonyId: string;
  readonly clientProofFinalization: RouterAbEcdsaClientProofFinalizationV1;
  readonly signingWorkerExport: RouterAbEcdsaSigningWorkerExportShareEnvelopeV1;
  readonly authorizationKind: RouterAbEcdsaSigningWorkerExportShareBindingV1['authorization_kind'];
  readonly authorizationId: RouterAbEcdsaSigningWorkerExportShareBindingV1['authorization_id'];
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly roleLocalMaterial: EcdsaRoleLocalWorkerHandle;
  readonly roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef;
  readonly publicFacts: EcdsaRoleLocalPublicFacts;
};

export type FinalizeRouterAbEcdsaExplicitExportResultV1 = {
  readonly kind: 'router_ab_ecdsa_explicit_export_finalized_v1';
  readonly ceremonyId: string;
  readonly artifactKind: 'ecdsa-derivation-secp256k1-export';
  readonly publicKeyHex: string;
  readonly privateKeyHex: string;
  readonly ethereumAddress: string;
  readonly stateBlob?: never;
  readonly output32B64u?: never;
};

export type VerifyRouterAbEcdsaPostRegistrationProofsRequestV1 = {
  readonly kind: 'verify_router_ab_ecdsa_post_registration_proofs_v1';
  readonly ceremonyId: string;
  readonly clientProofFinalization: RouterAbEcdsaClientProofFinalizationV1;
};

export type VerifyRouterAbEcdsaPostRegistrationProofsResultV1 = {
  readonly kind: 'router_ab_ecdsa_activation_refresh_proofs_verified_v1';
  readonly ceremonyId: string;
};

export type CloseRouterAbEcdsaPostRegistrationCeremonyRequestV1 = {
  readonly kind: 'close_router_ab_ecdsa_post_registration_ceremony_v1';
  readonly ceremonyId: string;
};

export type CloseRouterAbEcdsaPostRegistrationCeremonyResultV1 = {
  readonly kind: 'router_ab_ecdsa_post_registration_ceremony_closed_v1';
  readonly ceremonyId: string;
};

type ParsedWorkerChannelControl = {
  readonly kind: unknown;
  readonly port: unknown;
};

function parseWorkerChannelControl(value: unknown): ParsedWorkerChannelControl | null {
  if (!isObject(value)) return null;
  return { kind: value.kind, port: value.port };
}

export function isAttachEcdsaDerivationToPresignPort(
  value: unknown,
): value is AttachEcdsaDerivationToPresignPort {
  const parsed = parseWorkerChannelControl(value);
  return (
    parsed?.kind === EcdsaClientWorkerControlKind.AttachDerivationToPresign &&
    parsed.port instanceof MessagePort
  );
}

export function isAttachLinkedHolderToPresignPort(
  value: unknown,
): value is AttachLinkedHolderToPresignPort {
  const parsed = parseWorkerChannelControl(value);
  return (
    parsed?.kind === EcdsaClientWorkerControlKind.AttachLinkedHolderToPresign &&
    parsed.port instanceof MessagePort
  );
}

export function isAttachPresignToOnlinePort(value: unknown): value is AttachPresignToOnlinePort {
  const parsed = parseWorkerChannelControl(value);
  return (
    parsed?.kind === EcdsaClientWorkerControlKind.AttachPresignToOnline &&
    parsed.port instanceof MessagePort
  );
}

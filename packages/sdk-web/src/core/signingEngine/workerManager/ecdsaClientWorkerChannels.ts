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

export const EcdsaClientWorkerControlKind = {
  AttachDerivationToPresign: 'attach_ecdsa_derivation_to_presign_v1',
  AttachEmailOtpToPresign: 'attach_email_otp_to_ecdsa_presign_v1',
} as const;

export type AttachEcdsaDerivationToPresignPort = {
  readonly kind: typeof EcdsaClientWorkerControlKind.AttachDerivationToPresign;
  readonly port: MessagePort;
};

export type AttachEmailOtpToPresignPort = {
  readonly kind: typeof EcdsaClientWorkerControlKind.AttachEmailOtpToPresign;
  readonly port: MessagePort;
};

export type EcdsaDerivationAdditiveShareRequest = {
  readonly kind: 'ecdsa_derivation_additive_share_request_v1';
  readonly requestId: string;
  readonly materialHandle: string;
  readonly poolIdentity: EcdsaClientPresignPoolIdentity;
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
};

export type EcdsaDerivationAdditiveShareResponse =
  | {
      readonly kind: 'ecdsa_derivation_additive_share_result_v1';
      readonly requestId: string;
      readonly ok: true;
      readonly additiveShare32: ArrayBuffer;
      readonly error?: never;
    }
  | {
      readonly kind: 'ecdsa_derivation_additive_share_result_v1';
      readonly requestId: string;
      readonly ok: false;
      readonly additiveShare32?: never;
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

export type EmailOtpEcdsaSigningShareRequest = {
  readonly kind: 'email_otp_ecdsa_signing_share_request_v1';
  readonly requestId: string;
  readonly thresholdSessionId: string;
};

export type EmailOtpEcdsaSigningShareResponse =
  | {
      readonly kind: 'email_otp_ecdsa_signing_share_result_v1';
      readonly requestId: string;
      readonly ok: true;
      readonly additiveShare32: ArrayBuffer;
      readonly remainingUses: number;
      readonly expiresAtMs: number;
      readonly error?: never;
    }
  | {
      readonly kind: 'email_otp_ecdsa_signing_share_result_v1';
      readonly requestId: string;
      readonly ok: false;
      readonly additiveShare32?: never;
      readonly remainingUses?: never;
      readonly expiresAtMs?: never;
      readonly error: string;
    };

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

export function isAttachEmailOtpToPresignPort(
  value: unknown,
): value is AttachEmailOtpToPresignPort {
  const parsed = parseWorkerChannelControl(value);
  return (
    parsed?.kind === EcdsaClientWorkerControlKind.AttachEmailOtpToPresign &&
    parsed.port instanceof MessagePort
  );
}

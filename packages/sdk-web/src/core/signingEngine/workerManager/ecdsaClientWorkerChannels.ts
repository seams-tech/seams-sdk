import { isObject } from '@shared/utils/validation';
import type {
  RouterAbEcdsaClientProofFinalizationV1,
  RouterAbEcdsaDerivationActivationRefreshRequestV1,
  RouterAbEcdsaDerivationExplicitExportRequestV1,
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaDerivationRecoveryRequestV1,
  RouterAbEcdsaRegistrationActivationReceiptV1,
  RouterAbEcdsaRegistrationRecipientKeysV1,
  RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type {
  EcdsaRoleLocalBindingDigest,
  EcdsaRoleLocalDurableMaterialRef,
  EcdsaRoleLocalMaterialHandle,
} from '@/core/signingEngine/session/keyMaterialBrands';
import type {
  WasmFinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapResult,
  WasmPrepareThresholdEcdsaDerivationRoleLocalClientBootstrapResult,
} from '@/core/types/signer-worker';
import type { EcdsaRoleLocalPublicFacts } from '@/core/platform';
import type { EcdsaClientPresignPoolIdentity } from './ecdsaPresignPoolIdentity';

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
  readonly durableMaterialRef: string;
  readonly poolIdentity: EcdsaClientPresignPoolIdentity;
  readonly expectedBindingDigest: string;
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

export type EmailOtpEcdsaSigningShareRequest = {
  readonly kind: 'email_otp_ecdsa_signing_share_request_v1';
  readonly requestId: string;
  readonly sessionId: string;
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

export type RouterAbEcdsaExplicitExportRequestFactsV1 = Omit<
  RouterAbEcdsaDerivationExplicitExportRequestV1,
  | 'client_ephemeral_public_key'
  | 'deriver_a_export_envelope'
  | 'deriver_b_export_envelope'
> & {
  readonly deriver_recipient_keys: RouterAbEcdsaRegistrationRecipientKeysV1;
};

export type RouterAbEcdsaRecoveryRequestFactsV1 = Omit<
  RouterAbEcdsaDerivationRecoveryRequestV1,
  | 'client_ephemeral_public_key'
  | 'deriver_a_recovery_envelope'
  | 'deriver_b_recovery_envelope'
> & {
  readonly deriver_recipient_keys: RouterAbEcdsaRegistrationRecipientKeysV1;
};

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
      readonly kind: 'create_router_ab_ecdsa_recovery_ceremony_v1';
      readonly ceremonyId: string;
      readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
      readonly request: RouterAbEcdsaRecoveryRequestFactsV1;
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
    }
  | {
      readonly kind: 'router_ab_ecdsa_recovery_ceremony_created_v1';
      readonly ceremonyId: string;
      readonly request: RouterAbEcdsaDerivationRecoveryRequestV1;
    }
  | {
      readonly kind: 'router_ab_ecdsa_activation_refresh_ceremony_created_v1';
      readonly ceremonyId: string;
      readonly request: RouterAbEcdsaDerivationActivationRefreshRequestV1;
    };

export type FinalizeRouterAbEcdsaExplicitExportRequestV1 = {
  readonly kind: 'finalize_router_ab_ecdsa_explicit_export_v1';
  readonly ceremonyId: string;
  readonly clientProofFinalization: RouterAbEcdsaClientProofFinalizationV1;
  readonly roleLocalMaterial: {
    readonly materialHandle: EcdsaRoleLocalMaterialHandle;
    readonly bindingDigest: EcdsaRoleLocalBindingDigest;
    readonly durableMaterialRef: EcdsaRoleLocalDurableMaterialRef;
  };
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

export type VerifyRouterAbEcdsaRecoveryClientProofsRequestV1 = {
  readonly kind: 'verify_router_ab_ecdsa_recovery_client_proofs_v1';
  readonly ceremonyId: string;
  readonly clientProofFinalization: RouterAbEcdsaClientProofFinalizationV1;
};

export type VerifyRouterAbEcdsaRecoveryClientProofsResultV1 = {
  readonly kind: 'router_ab_ecdsa_recovery_client_proofs_verified_v1';
  readonly ceremonyId: string;
  readonly clientBootstrap:
    WasmPrepareThresholdEcdsaDerivationRoleLocalClientBootstrapResult['clientBootstrap'];
  readonly publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
};

export type VerifyRouterAbEcdsaRefreshClientProofsRequestV1 = {
  readonly kind: 'verify_router_ab_ecdsa_refresh_client_proofs_v1';
  readonly ceremonyId: string;
  readonly clientProofFinalization: RouterAbEcdsaClientProofFinalizationV1;
};

export type VerifyRouterAbEcdsaRefreshClientProofsResultV1 = {
  readonly kind: 'router_ab_ecdsa_refresh_client_proofs_verified_v1';
  readonly ceremonyId: string;
};

export type FinalizeRouterAbEcdsaRecoveryActivationRequestV1 = {
  readonly kind: 'finalize_router_ab_ecdsa_recovery_activation_v1';
  readonly ceremonyId: string;
  readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  readonly expectedLifecycleId: string;
  readonly expectedTranscriptDigestB64u: string;
  readonly expectedActivationEpoch: string;
  readonly expiresAtMs: number;
};

export type FinalizeRouterAbEcdsaRecoveryActivationResultV1 = {
  readonly kind: 'router_ab_ecdsa_recovery_activation_finalized_v1';
  readonly ceremonyId: string;
  readonly roleLocalMaterial: {
    readonly kind: 'ecdsa_role_local_worker_handle_v1';
    readonly materialHandle: EcdsaRoleLocalMaterialHandle;
    readonly bindingDigest: EcdsaRoleLocalBindingDigest;
    readonly durableMaterialRef: EcdsaRoleLocalDurableMaterialRef;
  };
  readonly publicFacts:
    WasmFinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapResult['publicFacts'];
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
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

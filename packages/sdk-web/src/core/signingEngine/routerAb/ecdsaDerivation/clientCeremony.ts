import type {
  WasmFinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapResult,
  WasmPrepareThresholdEcdsaDerivationRoleLocalClientBootstrapResult,
} from '@/core/types/signer-worker';
import type {
  RouterAbEcdsaClientProofFinalizationV1,
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaRegistrationActivationReceiptV1,
  RouterAbEcdsaRegistrationRequestFactsV1,
  RouterAbEcdsaRegistrationRequestV1,
  RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type {
  EcdsaRoleLocalBindingDigest,
  EcdsaRoleLocalDurableMaterialRef,
  EcdsaRoleLocalMaterialHandle,
} from '@/core/signingEngine/session/keyMaterialBrands';

export type CreateRouterAbEcdsaRegistrationCeremonyRequestV1 = {
  readonly kind: 'create_router_ab_ecdsa_registration_ceremony_v1';
  readonly ceremonyId: string;
  readonly registration: RouterAbEcdsaRegistrationRequestFactsV1;
};

export type CreateRouterAbEcdsaRegistrationCeremonyResultV1 = {
  readonly kind: 'router_ab_ecdsa_registration_ceremony_created_v1';
  readonly ceremonyId: string;
  readonly registrationRequest: RouterAbEcdsaRegistrationRequestV1;
};

export type VerifyRouterAbEcdsaRegistrationClientProofsRequestV1 = {
  readonly kind: 'verify_router_ab_ecdsa_registration_client_proofs_v1';
  readonly ceremonyId: string;
  readonly clientProofFinalization: RouterAbEcdsaClientProofFinalizationV1;
};

export type VerifyRouterAbEcdsaRegistrationClientProofsResultV1 = {
  readonly kind: 'router_ab_ecdsa_registration_client_proofs_verified_v1';
  readonly ceremonyId: string;
  readonly clientBootstrap:
    WasmPrepareThresholdEcdsaDerivationRoleLocalClientBootstrapResult['clientBootstrap'];
  readonly publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
};

export type FinalizeRouterAbEcdsaRegistrationActivationRequestV1 = {
  readonly kind: 'finalize_router_ab_ecdsa_registration_activation_v1';
  readonly ceremonyId: string;
  readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
};

export type FinalizeRouterAbEcdsaRegistrationActivationResultV1 = {
  readonly kind: 'router_ab_ecdsa_registration_activation_finalized_v1';
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

export type CloseRouterAbEcdsaRegistrationCeremonyRequestV1 = {
  readonly kind: 'close_router_ab_ecdsa_registration_ceremony_v1';
  readonly ceremonyId: string;
};

export type CloseRouterAbEcdsaRegistrationCeremonyResultV1 = {
  readonly kind: 'router_ab_ecdsa_registration_ceremony_closed_v1';
  readonly ceremonyId: string;
};

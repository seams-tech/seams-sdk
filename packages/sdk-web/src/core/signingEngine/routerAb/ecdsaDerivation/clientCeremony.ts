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
import type { EcdsaRoleLocalWorkerHandle } from '@/core/signingEngine/session/keyMaterialBrands';
import type { InitialEcdsaCapabilityActivationPlanInput } from '@/core/signingEngine/session/material/initialEcdsaCapabilityActivation';
import type { CorrelationId } from '@shared/utils/canonicalPrimitives';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';

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
  readonly clientBootstrap: WasmPrepareThresholdEcdsaDerivationRoleLocalClientBootstrapResult['clientBootstrap'];
  readonly publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
};

export type PersistInitialCanonicalEcdsaActivationRequestV1 = {
  readonly kind: 'persist_initial_canonical_ecdsa_activation_v1';
  readonly ceremonyId: string;
  readonly planInput: InitialEcdsaCapabilityActivationPlanInput;
};

export type PersistInitialCanonicalEcdsaActivationFailureCode =
  | 'invalid_ceremony_state'
  | 'ceremony_plan_mismatch'
  | 'invalid_activation_plan'
  | 'exact_record_conflict'
  | 'corrupt'
  | 'persistence_unavailable';

export type PersistInitialCanonicalEcdsaActivationResultV1 =
  | {
      readonly ok: true;
      readonly kind: 'initial_canonical_ecdsa_activation_persisted_v1';
      readonly ceremonyId: string;
      readonly journalId: InitialEcdsaCapabilityActivationPlanInput['journalId'];
      readonly code?: never;
      readonly message?: never;
    }
  | {
      readonly ok: false;
      readonly kind: 'initial_canonical_ecdsa_activation_persistence_failed_v1';
      readonly ceremonyId: string;
      readonly code: PersistInitialCanonicalEcdsaActivationFailureCode;
      readonly message: string;
      readonly journalId?: never;
    };

export type FinalizeRouterAbEcdsaRegistrationActivationRequestV1 = {
  readonly kind: 'finalize_router_ab_ecdsa_registration_activation_v1';
  readonly journalId: CorrelationId;
  readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
};

export type FinalizeRouterAbEcdsaRegistrationActivationResultV1 = {
  readonly kind: 'router_ab_ecdsa_registration_activation_finalized_v1';
  readonly journalId: CorrelationId;
  readonly roleLocalMaterial: EcdsaRoleLocalWorkerHandle;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly publicFacts: WasmFinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapResult['publicFacts'];
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

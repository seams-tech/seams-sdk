import type {
  WasmFinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapResult,
  WasmPrepareThresholdEcdsaDerivationRoleLocalClientBootstrapResult,
} from '@/core/types/signer-worker';
import type {
  RouterAbEcdsaClientProofFinalizationV1,
  RouterAbEcdsaDerivationNormalSigningStateV1,
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaRegistrationActivationReceiptV1,
  RouterAbEcdsaRegistrationRequestFactsV1,
  RouterAbEcdsaRegistrationRequestV1,
  RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { EcdsaRoleLocalWorkerHandle } from '@/core/signingEngine/session/keyMaterialBrands';
import type { InitialEcdsaCapabilityActivationPlanInput } from '@/core/signingEngine/session/material/initialEcdsaCapabilityActivation';
import type { CorrelationId } from '@shared/utils/canonicalPrimitives';
import type { CapabilityInstanceRef, MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { EcdsaServerActivationCommand } from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import type { WalletCustodyEvmFamilyPublicFacts } from '@shared/passkey-custody';

export type CreateRouterAbEcdsaRegistrationCeremonyRequestV1 = {
  readonly kind: 'create_router_ab_ecdsa_registration_ceremony_v1';
  readonly ceremonyId: string;
  readonly registration: RouterAbEcdsaRegistrationRequestFactsV1;
};

export type CreateRouterAbEcdsaRegistrationCeremonyResultV1 = {
  readonly kind: 'router_ab_ecdsa_registration_ceremony_created_v1';
  readonly ceremonyId: string;
  readonly registrationRequest: RouterAbEcdsaRegistrationRequestV1;
  /** Canonical full-envelope digest verified again by Router policy. */
  readonly registrationRequestDigestB64u: string;
};

export type VerifyRouterAbEcdsaRegistrationClientProofsRequestV1 =
  {
    readonly kind: 'verify_router_ab_ecdsa_registration_client_proofs_v1';
    readonly bootstrapOwner: 'wallet_custody';
    readonly ceremonyId: string;
    readonly clientProofFinalization: RouterAbEcdsaClientProofFinalizationV1;
  };

export type VerifyRouterAbEcdsaRegistrationClientProofsResultV1 = {
  readonly kind: 'router_ab_ecdsa_registration_wallet_custody_proofs_verified_v1';
  readonly bootstrapOwner: 'wallet_custody';
  readonly ceremonyId: string;
  readonly applicationBindingDigestB64u: string;
  readonly registrationRequestDigestB64u: string;
  readonly proofTranscriptDigestB64u: string;
};

type PersistInitialCanonicalEcdsaActivationRequestBaseV1 = {
  readonly kind: 'persist_initial_canonical_ecdsa_activation_v1';
  readonly ceremonyId: string;
  readonly planInput: InitialEcdsaCapabilityActivationPlanInput;
};

export type PersistInitialCanonicalEcdsaActivationRequestV1 =
  PersistInitialCanonicalEcdsaActivationRequestBaseV1 & {
    readonly bootstrapOwner: 'wallet_custody';
    readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
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

type FinalizeRouterAbEcdsaRegistrationActivationRequestBaseV1 = {
  readonly kind: 'finalize_router_ab_ecdsa_registration_activation_v1';
  readonly journalId: CorrelationId;
  readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  readonly routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
};

export type FinalizeRouterAbEcdsaRegistrationActivationRequestV1 =
  FinalizeRouterAbEcdsaRegistrationActivationRequestBaseV1 & {
    readonly bootstrapOwner: 'wallet_custody';
    readonly readyStateBlobB64u: string;
    readonly walletCustodyPublicFacts: WalletCustodyEvmFamilyPublicFacts;
  };

export type FinalizeRouterAbEcdsaRegistrationActivationResultV1 = {
  readonly kind: 'router_ab_ecdsa_registration_activation_finalized_v1';
  readonly journalId: CorrelationId;
  readonly authority: WalletAuthAuthorityRef;
  readonly roleLocalMaterial: EcdsaRoleLocalWorkerHandle;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly publicFacts: WasmFinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapResult['publicFacts'];
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
};

export type ReconcileCanonicalEcdsaActivationRequestV1 = {
  readonly kind: 'reconcile_canonical_ecdsa_activation_v1';
  readonly capability: CapabilityInstanceRef;
  readonly authority: WalletAuthAuthorityRef;
};

export type ReconcileCanonicalEcdsaActivationResultV1 =
  | {
      readonly kind: 'canonical_ecdsa_activation_reconciliation_pending_v1';
      readonly journalId: CorrelationId;
      readonly reason:
        | 'parent_confirmation_and_server_query_required'
        | 'wallet_custody_rejoin_required';
      readonly activationCommand: EcdsaServerActivationCommand | null;
      readonly activation?: never;
      readonly code?: never;
    }
  | {
      readonly kind: 'canonical_ecdsa_activation_reconciliation_finalized_v1';
      readonly activation: FinalizeRouterAbEcdsaRegistrationActivationResultV1;
      readonly journalId?: never;
      readonly reason?: never;
      readonly activationCommand?: never;
      readonly code?: never;
    }
  | {
      readonly kind: 'canonical_ecdsa_activation_reconciliation_absent_v1';
      readonly journalId?: never;
      readonly reason?: never;
      readonly activationCommand?: never;
      readonly activation?: never;
      readonly code?: never;
    }
  | {
      readonly kind: 'canonical_ecdsa_activation_reconciliation_failed_v1';
      readonly code: 'corrupt' | 'persistence_unavailable';
      readonly journalId?: never;
      readonly reason?: never;
      readonly activationCommand?: never;
      readonly activation?: never;
    };

export type ReconcileCanonicalEcdsaActivationWorkerResultV1 =
  | ReconcileCanonicalEcdsaActivationResultV1
  | {
      readonly kind: 'canonical_ecdsa_activation_committed_finalization_required_v1';
      readonly journalId: CorrelationId;
      readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
      readonly routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
      readonly reason?: never;
      readonly activationCommand?: never;
      readonly activation?: never;
      readonly code?: never;
    };

export type CloseRouterAbEcdsaRegistrationCeremonyRequestV1 = {
  readonly kind: 'close_router_ab_ecdsa_registration_ceremony_v1';
  readonly ceremonyId: string;
};

export type CloseRouterAbEcdsaRegistrationCeremonyResultV1 = {
  readonly kind: 'router_ab_ecdsa_registration_ceremony_closed_v1';
  readonly ceremonyId: string;
};

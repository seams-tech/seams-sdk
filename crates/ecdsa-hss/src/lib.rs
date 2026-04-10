pub mod client;
pub mod fixtures;
pub mod integration;
pub mod server;
pub mod shared;
pub mod wire;

pub use client::{ClientOutputV1, ExplicitExportClientOutputV1, NonExportClientOutputV1};
pub use integration::{
    bootstrap_evm_threshold_v1, bootstrap_registration_evm_threshold_v1,
    bootstrap_session_evm_threshold_v1, complete_presign_roundtrip_v1,
    compute_client_signature_share_v1, export_evm_threshold_v1, export_from_respond_response_v1,
    export_from_session_v1, finalize_signature_v1, init_client_presign_session_v1,
    init_relayer_presign_session_v1, parse_presignature97_v1, prepare_explicit_export_session_v1,
    prepare_signing_session_v1, sign_with_session_v1, EvmThresholdBootstrapAdapterV1,
    EvmThresholdBootstrapRequestV1, EvmThresholdBootstrapResultV1,
    EvmThresholdExplicitExportSessionV1, EvmThresholdExplicitExportV1, EvmThresholdExportRequestV1,
    EvmThresholdExportResultV1, EvmThresholdIdentityV1, EvmThresholdPartyBootstrapMaterialV1,
    EvmThresholdPresignatureV1, EvmThresholdSigningOperationV1, EvmThresholdSigningSessionV1,
    ECDSA_HSS_EVM_THRESHOLD_V1_PARTICIPANT_IDS,
};
pub use server::{
    reference_boundary::{
        hidden_eval_boundary_from_staged_request_and_response_v1,
        hidden_eval_input_boundary_from_staged_request_v1,
        hidden_eval_persisted_state_boundary_from_finalized_session_v1,
        hidden_eval_transport_boundary_from_respond_response_v1,
        operation_boundary_from_operation_v1, visible_boundary_from_respond_response_v1,
        visible_client_boundary_from_output_v1, visible_finalize_boundary_from_envelope_v1,
        visible_retained_state_boundary_from_finalized_session_v1, VisibleClientBoundaryV1,
        HiddenEvalBoundaryV1, HiddenEvalInputBoundaryV1, HiddenEvalPersistedStateBoundaryV1,
        HiddenEvalTransportBoundaryV1, VisibleExplicitExportBoundaryV1,
        VisibleFinalizeBoundaryV1, VisibleNonExportBoundaryV1, VisibleOperationBoundaryV1,
        VisibleRespondBoundaryV1, VisibleRetainedServerStateBoundaryV1,
    },
    FinalizedServerSessionV1, RespondResponseV1, RetainedServerStateV1, ServerPrepareInputsV1,
    StagedServerSessionV1,
};
pub use shared::context::{
    encode_context_v1, EcdsaHssContextV1, ECDSA_HSS_V1_CURVE, ECDSA_HSS_V1_PARTICIPANT_IDS,
    ECDSA_HSS_V1_SCHEME_ID,
};
pub use shared::derive::{
    derive_additive_shares_v1, derive_canonical_secret_v1, verify_single_key_invariant_v1,
    AdditiveShareMaterialV1, CanonicalSecretMaterialV1,
};
pub use signer_core::error::{
    CoreResult as EcdsaHssResult, SignerCoreError as EcdsaHssError,
    SignerCoreErrorCode as EcdsaHssErrorCode,
};
pub use wire::{
    AllowedOutputKindV1, FinalizeEnvelopeV1, PrepareEnvelopeV1, RespondRequestV1,
    RootShareInputsV1, ServerEvalOperationV1,
};

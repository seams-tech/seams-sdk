pub mod error;
pub mod shared;
pub mod wire;

pub use error::{
    RouterAbEcdsaDerivationError, RouterAbEcdsaDerivationErrorCode, RouterAbEcdsaDerivationResult,
};
pub use shared::context::{
    encode_context, RouterAbEcdsaDerivationStableKeyContext,
    ROUTER_AB_ECDSA_DERIVATION_CONTEXT_VERSION, ROUTER_AB_ECDSA_DERIVATION_CURVE,
    ROUTER_AB_ECDSA_DERIVATION_PARTICIPANT_IDS, ROUTER_AB_ECDSA_DERIVATION_SCHEME_ID,
};
pub use shared::derive::{
    compose_public_identity, compose_public_identity_from_public_keys, context_binding,
    derive_client_share, derive_ecdsa_lane_delta_from_source_share32_v1,
    derive_ecdsa_lane_delta_v1, derive_relayer_share, derive_relayer_share_for_client_public,
    ecdsa_lane_client_public_key_from_share32_v1, public_transcript_digest,
    rebind_ecdsa_lane_relayer_share_bytes_v1, rebind_ecdsa_lane_relayer_share_v1,
    reconstruct_ecdsa_additive_export_key_v1, reconstruct_export_key,
    sample_ecdsa_lane_client_share_v1, ClientRoleShare, EcdsaLaneClientShare, EcdsaLaneDelta,
    EcdsaLanePublicIdentityBindingV1, EcdsaLaneRelayerRebindV1, PublicIdentity, RelayerRoleShare,
};
pub use wire::{AllowedOutputKind, ServerEvalOperation};

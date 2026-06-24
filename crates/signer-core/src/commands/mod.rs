pub mod ecdsa_bootstrap;
pub mod ecdsa_export;
pub mod ed25519_worker_material;

pub use ecdsa_bootstrap::{
    Base64UrlEncodingV1, EcdsaBootstrapSecretSourceV1, EcdsaClientBootstrapAlgorithmV1,
    EcdsaClientBootstrapContextV1, EcdsaClientBootstrapFactsV1, EcdsaClientBootstrapParticipantsV1,
    EcdsaPreparePublicFactsV1, EcdsaReadyPublicFactsV1, EcdsaRoleLocalPendingStateBlobV1,
    EcdsaRoleLocalReadyStateBlobV1, FinalizeEcdsaClientBootstrapCommandKindV1,
    FinalizeEcdsaClientBootstrapCommandV1, FinalizeEcdsaClientBootstrapErrorCodeV1,
    FinalizeEcdsaClientBootstrapOutputV1, PendingStateBlobKindV1,
    PrepareEcdsaClientBootstrapCommandKindV1, PrepareEcdsaClientBootstrapCommandV1,
    PrepareEcdsaClientBootstrapErrorCodeV1, PrepareEcdsaClientBootstrapOutputV1,
    ReadyStateBlobKindV1, RelayerPublicIdentityV1, Secp256k1CurveNameV1, SignerCommandVersion,
    SignerCoreProducerV1,
};

pub use ecdsa_export::{
    BuildEcdsaRoleLocalExportArtifactCommandKindV1, BuildEcdsaRoleLocalExportArtifactCommandV1,
    BuildEcdsaRoleLocalExportArtifactErrorCodeV1, BuildEcdsaRoleLocalExportArtifactOutputV1,
    EcdsaRoleLocalExportPublicFactsV1,
};

pub use ed25519_worker_material::{
    Ed25519CreateClientPresignFromWorkerMaterialRequestKindV1,
    Ed25519CreateClientPresignFromWorkerMaterialRequestV1,
    Ed25519CreateClientPresignFromWorkerMaterialSuccessV1,
    Ed25519DeleteSealedWorkerMaterialRequestKindV1, Ed25519DeleteSealedWorkerMaterialRequestV1,
    Ed25519DeleteSealedWorkerMaterialSuccessV1, Ed25519HssClientOutputMaskTransportV1,
    Ed25519PutSealedWorkerMaterialRequestKindV1, Ed25519PutSealedWorkerMaterialRequestV1,
    Ed25519PutSealedWorkerMaterialSuccessV1, Ed25519ReadSealedWorkerMaterialRequestKindV1,
    Ed25519ReadSealedWorkerMaterialRequestV1, Ed25519ReadSealedWorkerMaterialSuccessV1,
    Ed25519RestoreWorkerMaterialRequestKindV1, Ed25519RestoreWorkerMaterialRequestV1,
    Ed25519SealedWorkerMaterialAadKindV1, Ed25519SealedWorkerMaterialAadV1,
    Ed25519SealedWorkerMaterialKindV1, Ed25519SealedWorkerMaterialTransportV1,
    Ed25519SealedWorkerMaterialV1, Ed25519ServerCommitmentsV1,
    Ed25519SignClientPresignFromWorkerMaterialRequestKindV1,
    Ed25519SignClientPresignFromWorkerMaterialRequestV1,
    Ed25519SignClientPresignFromWorkerMaterialSuccessV1,
    Ed25519StoreWorkerMaterialFromHssOutputRequestKindV1,
    Ed25519StoreWorkerMaterialFromHssOutputRequestV1, Ed25519ValidateWorkerMaterialRequestKindV1,
    Ed25519ValidateWorkerMaterialRequestV1, Ed25519ValidateWorkerMaterialSuccessV1,
    Ed25519WorkerMaterialAeadAlgorithmV1, Ed25519WorkerMaterialAeadV1,
    Ed25519WorkerMaterialBindingKindV1, Ed25519WorkerMaterialBindingV1,
    Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
    Ed25519WorkerMaterialCredentialAuthorizationV1, Ed25519WorkerMaterialCurveV1,
    Ed25519WorkerMaterialErrorCodeV1, Ed25519WorkerMaterialFailureV1,
    Ed25519WorkerMaterialFormatVersionV1, Ed25519WorkerMaterialKdfAlgorithmV1,
    Ed25519WorkerMaterialKdfV1, Ed25519WorkerMaterialKeyIdentityKindV1,
    Ed25519WorkerMaterialKeyIdentityV1, Ed25519WorkerMaterialProtocolV1,
    Ed25519WorkerMaterialSessionBindingKindV1, Ed25519WorkerMaterialSessionBindingV1,
    Ed25519WorkerMaterialStoredV1, ThresholdRuntimePolicyScopeV1,
};

#[cfg(feature = "near-crypto")]
pub use ed25519_worker_material::{
    chacha20poly1305_open_ed25519_worker_material, chacha20poly1305_seal_ed25519_worker_material,
    decode_ed25519_worker_material_plaintext, derive_ed25519_worker_material_seal_key,
    ed25519_worker_material_aad_bytes, ed25519_worker_material_aad_for_binding,
    ed25519_worker_material_binding_digest, ed25519_worker_material_canonical_json,
    ed25519_worker_material_digest_b64u, ed25519_worker_material_key_id,
    ed25519_worker_material_key_identity_from_binding,
    ed25519_worker_material_session_binding_digest, ed25519_worker_material_storage_ref,
    encode_ed25519_worker_material_plaintext, open_ed25519_worker_material_artifact,
    seal_ed25519_worker_material_artifact, validate_ed25519_worker_material_binding,
    ED25519_WORKER_MATERIAL_CHACHA20_KEY_SIZE, ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE,
    ED25519_WORKER_MATERIAL_KDF_INFO, ED25519_WORKER_MATERIAL_STORAGE_REF_PREFIX,
};

#[cfg(feature = "threshold-ecdsa-hss")]
pub use ecdsa_bootstrap::{
    finalize_ecdsa_client_bootstrap_command_v1, prepare_ecdsa_client_bootstrap_command_v1,
};

#[cfg(feature = "threshold-ecdsa-hss")]
pub use ecdsa_export::build_ecdsa_role_local_export_artifact_command_v1;

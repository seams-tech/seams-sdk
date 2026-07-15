#![forbid(unsafe_code)]
//! Local development adapters for Router/A/B signing.
//!
//! This crate may use local database drivers and filesystem-facing binaries.
//! The protocol crate remains transport-neutral and wasm-safe by default.

use base64::Engine;
use ecdsa_hss::ECDSA_HSS_PARTICIPANT_IDS;
use rand_core::OsRng;
use router_ab_core::{
    decode_ab_peer_message_payload_v1,
    decode_and_validate_ecdsa_threshold_prf_proof_batch_peer_payload_v1,
    execute_local_persistence_sql_seed_plan_v1, local_persistence_seed_sql_plan_v1,
    router_ab_ecdsa_hss_active_state_session_id_v1, router_transcript_digest_v1,
    ActiveSigningWorkerStateV1, EcdsaThresholdPrfRequestV1, EncryptedPayloadV1,
    ExpensiveWorkKindV1, LifecycleScopeV1, LocalDeriverAEndpointV1,
    LocalDeriverBEndpointV1,
    LocalEnvSnapshotV1, LocalHttpCeremonyResultV1, LocalHttpMethodV1, LocalHttpPathV1,
    LocalHttpRequestV1, LocalPersistenceSeedV1, LocalPersistenceSqlExecutionReceiptV1,
    LocalPersistenceSqlSeedExecutorV1, LocalPersistenceSqlStatementV1, LocalPersistenceSqlValueV1,
    LocalRouterEndpointV1, LocalSealedRootShareRecordV1, LocalServiceRoleV1, LocalServiceStackV1,
    LocalServiceStartupV1, LocalSigningRootMetadataV1, LocalSigningWorkerEndpointV1,
    LocalTransportEnvelopeV1, LocalTransportRouteV1, RoleEncryptedEnvelopeV1,
    RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1, RouterAbEcdsaHssEvmDigestSigningRequestV1,
    RouterAbEcdsaHssEvmDigestSigningResponseV1, RouterAbEcdsaHssNormalSigningScopeV1,
    RouterAbEcdsaHssSignatureSchemeV1, RouterAbProtocolError, RouterAbProtocolErrorCode,
    RouterAbProtocolResult, RouterTranscriptMetadataV1, ServerIdentityV1, SignerIdentityV1,
    SignerSetV1, SigningRootShareStore, WireMessageKindV1, WireMessageV1,
};
use router_ab_core::{PublicDigest32, Role, RootShareEpoch};
use rusqlite::{params, params_from_iter, types::Value, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signer_core::threshold_ecdsa::threshold_ecdsa_finalize_signature;
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

mod local_dev_http;
mod local_ecdsa_hss_pool_store;
mod local_ed25519_yao_api;
mod local_ed25519_yao_delivery;
mod local_ed25519_yao_input;
mod local_ed25519_yao_profiles;
mod local_ed25519_yao_refresh;
mod local_ed25519_yao_router;
mod local_ed25519_yao_signing_worker;
mod local_ed25519_yao_stream;
mod local_ed25519_yao_worker;
mod local_service_http;
mod local_worker_topology;

pub use local_dev_http::{
    local_dev_http_error_body_v1, local_dev_http_handle_request_v1, local_dev_http_route_error_v1,
    read_local_dev_http_request_v1, require_local_dev_internal_service_auth_v1,
    require_local_dev_normal_signing_wallet_session_v2, write_local_dev_http_response_v1,
    LocalDevHttpErrorBodyV1, LocalDevHttpRequestPartsV1, LocalDevHttpTopologyV1,
};
use local_ecdsa_hss_pool_store::{
    local_signing_worker_ecdsa_hss_presignature_pool_store_put_v1,
    local_signing_worker_ecdsa_hss_presignature_pool_store_take_v1,
};
pub use local_ed25519_yao_api::{
    build_local_activation_deriver_a_v1, build_local_activation_deriver_a_with_server_v1,
    build_local_activation_deriver_b_v1, build_local_activation_deriver_b_with_server_v1,
    build_local_export_deriver_a_v1, build_local_export_deriver_a_with_server_v1,
    build_local_export_deriver_b_v1, build_local_export_deriver_b_with_server_v1,
    build_local_refresh_deriver_a_v1, build_local_refresh_deriver_b_v1,
    derive_local_ed25519_yao_deriver_a_initial_contribution_v1,
    derive_local_ed25519_yao_deriver_b_initial_contribution_v1,
    LocalEd25519YaoActivationDeriverARequestV1, LocalEd25519YaoActivationDeriverBRequestV1,
    LocalEd25519YaoActivationRecipientsV1, LocalEd25519YaoClientContributionV1,
    LocalEd25519YaoExportDeriverARequestV1, LocalEd25519YaoExportDeriverBRequestV1,
    LocalEd25519YaoExportRecipientV1, LocalEd25519YaoRefreshDeriverARequestV1,
    LocalEd25519YaoRefreshDeriverBRequestV1,
};
pub use local_ed25519_yao_delivery::{
    derive_local_ed25519_yao_recipient_key_pair_v1,
    generate_local_ed25519_yao_recipient_key_pair_v1, open_local_ed25519_yao_client_package_v1,
    open_local_ed25519_yao_signing_worker_package_v1, seal_local_ed25519_yao_package_v1,
    LocalEd25519YaoRecipientKeyPairV1, LocalEd25519YaoRecipientPrivateKeyV1,
};
pub use local_ed25519_yao_input::{
    local_ed25519_yao_refresh_binding_digest_v1,
    open_local_ed25519_yao_activation_deriver_a_input_v1,
    open_local_ed25519_yao_activation_deriver_b_input_v1,
    open_local_ed25519_yao_export_deriver_a_input_v1,
    open_local_ed25519_yao_export_deriver_b_input_v1,
    open_local_ed25519_yao_refresh_deriver_a_input_v1,
    open_local_ed25519_yao_refresh_deriver_b_input_v1,
    seal_local_ed25519_yao_activation_deriver_a_input_v1,
    seal_local_ed25519_yao_activation_deriver_b_input_v1,
    seal_local_ed25519_yao_export_deriver_a_input_v1,
    seal_local_ed25519_yao_export_deriver_b_input_v1,
    seal_local_ed25519_yao_refresh_deriver_a_input_v1,
    seal_local_ed25519_yao_refresh_deriver_b_input_v1, LocalEd25519YaoEncryptedRefreshInputV1,
};
pub use local_ed25519_yao_profiles::{
    build_local_ed25519_yao_one_account_plan_v1, build_local_ed25519_yao_two_administrator_plan_v1,
    local_ed25519_yao_worker_artifact_digest_v1, LocalEd25519YaoArtifactIdentityV1,
    LocalEd25519YaoLocalEvidenceClaimV1, LocalEd25519YaoOneAccountDevV1,
    LocalEd25519YaoOneAccountPlanV1, LocalEd25519YaoRoleRootV1,
    LocalEd25519YaoTwoAdministratorDevV1, LocalEd25519YaoTwoAdministratorPlanV1,
    LOCAL_ED25519_YAO_ACTIVATION_CIRCUIT_ID_V1, LOCAL_ED25519_YAO_EXPORT_CIRCUIT_ID_V1,
    LOCAL_ED25519_YAO_PROTOCOL_ID_V1,
};
pub use local_ed25519_yao_refresh::{
    derive_local_ed25519_yao_joint_refresh_delta_v1,
    generate_local_ed25519_yao_deriver_a_refresh_delta_v1,
    generate_local_ed25519_yao_deriver_b_refresh_delta_v1, LocalEd25519YaoDeriverAEffectiveStateV1,
    LocalEd25519YaoDeriverAPreparedRefreshV1, LocalEd25519YaoDeriverARefreshDeltaWireV1,
    LocalEd25519YaoDeriverBEffectiveStateV1, LocalEd25519YaoDeriverBPreparedRefreshV1,
    LocalEd25519YaoDeriverBRefreshDeltaWireV1,
};
pub use local_ed25519_yao_router::{
    admit_local_ed25519_yao_export_v1, admit_local_ed25519_yao_registration_v1,
    LocalEd25519YaoRecoveryCredentialBindingV1, LocalEd25519YaoRefreshActiveEpochsV1,
    LocalEd25519YaoRouterExportAdmissionRequestV1, LocalEd25519YaoRouterExportAdmissionV1,
    LocalEd25519YaoRouterRecoveryAdmissionRequestV1, LocalEd25519YaoRouterRecoveryAdmissionV1,
    LocalEd25519YaoRouterRecoveryPromotionReceiptV1, LocalEd25519YaoRouterRecoveryStateV1,
    LocalEd25519YaoRouterRefreshAdmissionRequestV1, LocalEd25519YaoRouterRefreshStateV1,
    LocalEd25519YaoRouterRegistrationAdmissionV1,
};
pub use local_ed25519_yao_signing_worker::{
    LocalEd25519YaoSigningWorkerActivationReceiptV1, LocalEd25519YaoSigningWorkerPackageDeliveryV1,
    LocalEd25519YaoSigningWorkerRecoveryPromotionRequestV1,
    LocalEd25519YaoSigningWorkerRefreshPackageDeliveryV1,
    LocalEd25519YaoSigningWorkerRefreshReceiptV1, LocalEd25519YaoSigningWorkerStateV1,
};
pub use local_ed25519_yao_stream::{
    authenticate_local_ed25519_yao_deriver_b_peer_http_v1, run_local_activation_deriver_a_http_v1,
    run_local_activation_deriver_b_authenticated_http_v1, run_local_activation_deriver_b_http_v1,
    run_local_export_deriver_a_http_v1, run_local_export_deriver_b_authenticated_http_v1,
    run_local_export_deriver_b_http_v1, LocalEd25519YaoAuthenticatedDeriverBPeerV1,
    LocalEd25519YaoStreamErrorV1,
};
pub use local_ed25519_yao_worker::{
    dispatch_local_ed25519_yao_connection_v1, LocalEd25519YaoConnectionDispatchV1,
    LocalEd25519YaoRefreshPromotionReceiptV1, LocalEd25519YaoRefreshPromotionRequestV1,
    LocalEd25519YaoRoleCompletionV1, LocalEd25519YaoWorkerStateV1,
};
pub use local_service_http::{
    local_http_service_binding_endpoint_v1, local_http_service_binding_owner_v1,
    local_http_service_binding_path_v1, local_http_service_binding_url_v1,
    LocalHttpServiceBindingClientV1, LocalHttpServiceBindingEndpointV1,
};
pub use local_worker_topology::{
    local_worker_bind_addr_v1, local_worker_health_response_json_v1,
    local_worker_health_response_v1, local_worker_owned_paths_v1, local_worker_owns_path_v1,
    LocalWorkerHealthResponseV1,
};
pub use router_ab_core::{
    Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedInputV1, Ed25519YaoEncryptedPackageV1,
    Ed25519YaoInputKindV1, Ed25519YaoPackageKindV1, RouterAbEd25519YaoActivationAdmissionReceiptV1,
    RouterAbEd25519YaoActivationExecuteRequestV1, RouterAbEd25519YaoActivationKeysetV1,
    RouterAbEd25519YaoActivationPublicReceiptV1, RouterAbEd25519YaoActivationResultV1,
    RouterAbEd25519YaoApplicationBindingFactsV1, RouterAbEd25519YaoLifecycleScopeV1,
    RouterAbEd25519YaoRegistrationAdmissionRequestV1,
    ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
    ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
};

const LOCAL_NORMAL_SIGNING_ACTIVATION_MS_V1: u64 = 1_700_000_000_000;
const LOCAL_DEV_ACCOUNT_ID_V1: &str = "alice.testnet";
const LOCAL_DEV_ACCOUNT_PUBLIC_KEY_V1: &str = "ed25519:11111111111111111111111111111111";

/// Local worker role env key used by the private-worker development harness.
pub const LOCAL_WORKER_ROLE_ENV_V1: &str = "ROUTER_AB_LOCAL_WORKER_ROLE";
/// Router public URL env key.
pub const LOCAL_ROUTER_PUBLIC_URL_ENV_V1: &str = "ROUTER_PUBLIC_URL";
/// Deriver A private URL env key.
pub const LOCAL_DERIVER_A_URL_ENV_V1: &str = "DERIVER_A_URL";
/// Deriver B private URL env key.
pub const LOCAL_DERIVER_B_URL_ENV_V1: &str = "DERIVER_B_URL";
/// SigningWorker private URL env key.
pub const LOCAL_SIGNING_WORKER_URL_ENV_V1: &str = "SIGNING_WORKER_URL";
/// Router replay storage path env key.
pub const LOCAL_ROUTER_REPLAY_STORAGE_PATH_ENV_V1: &str = "ROUTER_REPLAY_STORAGE_PATH";
/// Router lifecycle storage path env key.
pub const LOCAL_ROUTER_LIFECYCLE_STORAGE_PATH_ENV_V1: &str = "ROUTER_LIFECYCLE_STORAGE_PATH";
/// Router project-policy storage path env key.
pub const LOCAL_ROUTER_PROJECT_POLICY_STORAGE_PATH_ENV_V1: &str =
    "ROUTER_PROJECT_POLICY_STORAGE_PATH";
/// Router quota storage path env key.
pub const LOCAL_ROUTER_QUOTA_STORAGE_PATH_ENV_V1: &str = "ROUTER_QUOTA_STORAGE_PATH";
/// Router abuse storage path env key.
pub const LOCAL_ROUTER_ABUSE_STORAGE_PATH_ENV_V1: &str = "ROUTER_ABUSE_STORAGE_PATH";
/// Deriver A envelope HPKE private-key env key.
pub const LOCAL_DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1: &str =
    "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY";
/// Deriver B envelope HPKE private-key env key.
pub const LOCAL_DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1: &str =
    "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY";
/// Deriver A root-share wire secret env key.
pub const LOCAL_DERIVER_A_ROOT_SHARE_WIRE_SECRET_ENV_V1: &str = "DERIVER_A_ROOT_SHARE_WIRE_SECRET";
/// Deriver B root-share wire secret env key.
pub const LOCAL_DERIVER_B_ROOT_SHARE_WIRE_SECRET_ENV_V1: &str = "DERIVER_B_ROOT_SHARE_WIRE_SECRET";
/// Deriver A Ed25519 Yao server-contribution root env key.
pub const LOCAL_DERIVER_A_ED25519_YAO_DERIVATION_ROOT_ENV_V1: &str =
    "DERIVER_A_ED25519_YAO_DERIVATION_ROOT";
/// Deriver B Ed25519 Yao server-contribution root env key.
pub const LOCAL_DERIVER_B_ED25519_YAO_DERIVATION_ROOT_ENV_V1: &str =
    "DERIVER_B_ED25519_YAO_DERIVATION_ROOT";
/// Deriver A Ed25519 Yao Client-input HPKE public-key env key.
pub const LOCAL_DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY_ENV_V1: &str =
    "DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY";
/// Deriver B Ed25519 Yao Client-input HPKE public-key env key.
pub const LOCAL_DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY_ENV_V1: &str =
    "DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY";
/// Deriver A peer signing key env key.
pub const LOCAL_DERIVER_A_PEER_SIGNING_KEY_ENV_V1: &str = "DERIVER_A_PEER_SIGNING_KEY";
/// Deriver B peer signing key env key.
pub const LOCAL_DERIVER_B_PEER_SIGNING_KEY_ENV_V1: &str = "DERIVER_B_PEER_SIGNING_KEY";
/// Deriver A peer verifying key env key.
pub const LOCAL_DERIVER_A_PEER_VERIFYING_KEY_ENV_V1: &str = "DERIVER_A_PEER_VERIFYING_KEY";
/// Deriver B peer verifying key env key.
pub const LOCAL_DERIVER_B_PEER_VERIFYING_KEY_ENV_V1: &str = "DERIVER_B_PEER_VERIFYING_KEY";
/// Deriver A root-share metadata storage path env key.
pub const LOCAL_DERIVER_A_ROOT_SHARE_STORAGE_PATH_ENV_V1: &str =
    "DERIVER_A_ROOT_SHARE_STORAGE_PATH";
/// Deriver B root-share metadata storage path env key.
pub const LOCAL_DERIVER_B_ROOT_SHARE_STORAGE_PATH_ENV_V1: &str =
    "DERIVER_B_ROOT_SHARE_STORAGE_PATH";
/// Deriver A sealed root-share storage path env key.
pub const LOCAL_DERIVER_A_SEALED_ROOT_SHARES_PATH_ENV_V1: &str =
    "DERIVER_A_SEALED_ROOT_SHARES_PATH";
/// Deriver B sealed root-share storage path env key.
pub const LOCAL_DERIVER_B_SEALED_ROOT_SHARES_PATH_ENV_V1: &str =
    "DERIVER_B_SEALED_ROOT_SHARES_PATH";
/// SigningWorker server-output HPKE private-key env key.
pub const LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1: &str =
    "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY";
/// SigningWorker server-output storage path env key.
pub const LOCAL_SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH_ENV_V1: &str =
    "SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH";
/// SigningWorker public identity env key.
pub const LOCAL_SIGNING_WORKER_ID_ENV_V1: &str = "SIGNING_WORKER_ID";
/// SigningWorker key epoch env key.
pub const LOCAL_SIGNING_WORKER_KEY_EPOCH_ENV_V1: &str = "SIGNING_WORKER_KEY_EPOCH";
/// SigningWorker server-output HPKE public key env key.
pub const LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY_ENV_V1: &str =
    "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY";
/// Generated Router env file path for local development.
pub const LOCAL_ROUTER_ENV_FILE_V1: &str = ".env.router-ab.router.local";
/// Generated Deriver A env file path for local development.
pub const LOCAL_DERIVER_A_ENV_FILE_V1: &str = ".env.router-ab.deriver-a.local";
/// Generated Deriver B env file path for local development.
pub const LOCAL_DERIVER_B_ENV_FILE_V1: &str = ".env.router-ab.deriver-b.local";
/// Generated SigningWorker env file path for local development.
pub const LOCAL_SIGNING_WORKER_ENV_FILE_V1: &str = ".env.router-ab.signing-worker.local";
/// Local Router state directory.
pub const LOCAL_ROUTER_STATE_DIR_V1: &str = ".router-ab-local/router";
/// Local Deriver A state directory.
pub const LOCAL_DERIVER_A_STATE_DIR_V1: &str = ".router-ab-local/deriver-a";
/// Local Deriver B state directory.
pub const LOCAL_DERIVER_B_STATE_DIR_V1: &str = ".router-ab-local/deriver-b";
/// Local SigningWorker state directory.
pub const LOCAL_SIGNING_WORKER_STATE_DIR_V1: &str = ".router-ab-local/signing-worker";
/// Local worker startup epoch for redacted diagnostics.
pub const LOCAL_WORKER_STARTUP_EPOCH_V1: &str = "local-dev-v1";
/// Local health endpoint path.
pub const LOCAL_WORKER_HEALTH_PATH: &str = "/healthz";
/// Local readiness endpoint path.
pub const LOCAL_WORKER_READY_PATH: &str = "/readyz";
/// Deriver B full-duplex Ed25519 Yao peer-stream path.
pub const LOCAL_DERIVER_B_ED25519_YAO_PEER_PATH: &str = "/router-ab/deriver-b/ed25519-yao/peer";
/// Deriver A local Ed25519 Yao activation start path.
pub const LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_START_PATH: &str =
    "/router-ab/deriver-a/ed25519-yao/activation/start";
/// Deriver B local Ed25519 Yao activation staging path.
pub const LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_STAGE_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/activation/stage";
/// Deriver A local Ed25519 Yao refresh start path.
pub const LOCAL_DERIVER_A_ED25519_YAO_REFRESH_START_PATH: &str =
    "/router-ab/deriver-a/ed25519-yao/refresh/start";
/// Deriver B local Ed25519 Yao refresh staging path.
pub const LOCAL_DERIVER_B_ED25519_YAO_REFRESH_STAGE_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/refresh/stage";
/// Deriver B private refresh-delta exchange path owned by Deriver A.
pub const LOCAL_DERIVER_B_ED25519_YAO_REFRESH_DELTA_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/refresh/delta";
/// Deriver A prepared refresh promotion path.
pub const LOCAL_DERIVER_A_ED25519_YAO_REFRESH_PROMOTE_PATH: &str =
    "/router-ab/deriver-a/ed25519-yao/refresh/promote";
/// Deriver B prepared refresh promotion path.
pub const LOCAL_DERIVER_B_ED25519_YAO_REFRESH_PROMOTE_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/refresh/promote";
/// Deriver A local Ed25519 Yao export start path.
pub const LOCAL_DERIVER_A_ED25519_YAO_EXPORT_START_PATH: &str =
    "/router-ab/deriver-a/ed25519-yao/export/start";
/// Deriver A local Ed25519 Yao public completion path.
pub const LOCAL_DERIVER_A_ED25519_YAO_RESULT_PATH: &str = "/router-ab/deriver-a/ed25519-yao/result";
/// Deriver A encrypted activation package for the Client.
pub const LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_CLIENT_PACKAGE_PATH: &str =
    "/router-ab/deriver-a/ed25519-yao/activation/client-package";
/// Deriver A encrypted activation package for the SigningWorker.
pub const LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_SIGNING_WORKER_PACKAGE_PATH: &str =
    "/router-ab/deriver-a/ed25519-yao/activation/signing-worker-package";
/// Deriver A encrypted refresh package for the Client.
pub const LOCAL_DERIVER_A_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH: &str =
    "/router-ab/deriver-a/ed25519-yao/refresh/client-package";
/// Deriver A encrypted refresh package for the SigningWorker.
pub const LOCAL_DERIVER_A_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH: &str =
    "/router-ab/deriver-a/ed25519-yao/refresh/signing-worker-package";
/// Deriver A encrypted export package for the Client.
pub const LOCAL_DERIVER_A_ED25519_YAO_EXPORT_CLIENT_PACKAGE_PATH: &str =
    "/router-ab/deriver-a/ed25519-yao/export/client-package";
/// Deriver B local Ed25519 Yao export staging path.
pub const LOCAL_DERIVER_B_ED25519_YAO_EXPORT_STAGE_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/export/stage";
/// Deriver B local Ed25519 Yao public completion path.
pub const LOCAL_DERIVER_B_ED25519_YAO_RESULT_PATH: &str = "/router-ab/deriver-b/ed25519-yao/result";
/// Deriver B encrypted activation package for the Client.
pub const LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_CLIENT_PACKAGE_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/activation/client-package";
/// Deriver B encrypted activation package for the SigningWorker.
pub const LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_SIGNING_WORKER_PACKAGE_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/activation/signing-worker-package";
/// Deriver B encrypted refresh package for the Client.
pub const LOCAL_DERIVER_B_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/refresh/client-package";
/// Deriver B encrypted refresh package for the SigningWorker.
pub const LOCAL_DERIVER_B_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/refresh/signing-worker-package";
/// Deriver B encrypted export package for the Client.
pub const LOCAL_DERIVER_B_ED25519_YAO_EXPORT_CLIENT_PACKAGE_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/export/client-package";
/// Router public normal-signing path mirrored from production.
pub const LOCAL_ROUTER_NORMAL_SIGNING_PATH: &str = "/router-ab/ed25519/sign";
/// Router public normal-signing round-1 prepare path mirrored from production.
pub const LOCAL_ROUTER_NORMAL_SIGNING_PREPARE_PATH: &str = "/router-ab/ed25519/sign/prepare";
/// Router public ECDSA-HSS digest-signing prepare path mirrored from production.
pub const LOCAL_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PATH: &str = "/router-ab/ecdsa-hss/sign/prepare";
/// Router public ECDSA-HSS digest-signing finalize path mirrored from production.
pub const LOCAL_ROUTER_ECDSA_HSS_SIGNING_PATH: &str = "/router-ab/ecdsa-hss/sign";
/// Local private service-auth secret env key shared with the TypeScript relay.
pub const LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_ENV_V1: &str =
    "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET";
/// Local default private service-auth secret used when the env key is unset.
pub const LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1: &str =
    "dev-router-ab-internal-service-auth";
/// Local private service-auth header mirrored from strict Cloudflare.
pub const LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1: &str =
    "x-router-ab-internal-service-auth";
/// Deriver A private Router-dispatch path mirrored from production.
pub const LOCAL_DERIVER_A_PRIVATE_PATH: &str = "/router-ab/deriver-a";
/// Deriver B private Router-dispatch path mirrored from production.
pub const LOCAL_DERIVER_B_PRIVATE_PATH: &str = "/router-ab/deriver-b";
/// Deriver A private peer path mirrored from production.
pub const LOCAL_DERIVER_A_PEER_PATH: &str = "/router-ab/deriver-a/peer";
/// Deriver B private peer path mirrored from production.
pub const LOCAL_DERIVER_B_PEER_PATH: &str = "/router-ab/deriver-b/peer";
/// SigningWorker activation package delivery path owned by Deriver A.
pub const LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_DERIVER_A_PATH: &str =
    "/router-ab/signing-worker/ed25519-yao/activation/deriver-a";
/// SigningWorker activation package delivery path owned by Deriver B.
pub const LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_DERIVER_B_PATH: &str =
    "/router-ab/signing-worker/ed25519-yao/activation/deriver-b";
/// SigningWorker recovery-candidate promotion path owned by the Router.
pub const LOCAL_SIGNING_WORKER_ED25519_YAO_RECOVERY_PROMOTE_PATH: &str =
    "/router-ab/signing-worker/ed25519-yao/recovery/promote";
/// SigningWorker refresh package delivery path owned by Deriver A.
pub const LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_A_PATH: &str =
    "/router-ab/signing-worker/ed25519-yao/refresh/deriver-a";
/// SigningWorker refresh package delivery path owned by Deriver B.
pub const LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_B_PATH: &str =
    "/router-ab/signing-worker/ed25519-yao/refresh/deriver-b";
/// SigningWorker normal-signing path mirrored from production.
pub const LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH: &str = "/router-ab/signing-worker/sign";
/// SigningWorker normal-signing round-1 prepare path mirrored from production.
pub const LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PREPARE_PATH: &str =
    "/router-ab/signing-worker/sign/prepare";
/// SigningWorker ECDSA-HSS presignature pool-fill path mirrored from production.
pub const LOCAL_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH: &str =
    "/router-ab/signing-worker/ecdsa-hss/presignature-pool/put";
/// SigningWorker ECDSA-HSS digest-signing prepare path mirrored from production.
pub const LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH: &str =
    "/router-ab/signing-worker/ecdsa-hss/sign/prepare";
/// SigningWorker ECDSA-HSS digest-signing finalize path mirrored from production.
pub const LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH: &str =
    "/router-ab/signing-worker/ecdsa-hss/sign";
/// Local HTTP service-binding content type for canonical protocol bytes.
pub const LOCAL_HTTP_CANONICAL_WIRE_CONTENT_TYPE_V1: &str = "application/octet-stream";
/// Local HTTP service-binding content type for Worker-shaped JSON protocol calls.
pub const LOCAL_HTTP_JSON_CONTENT_TYPE_V1: &str = "application/json";
/// Default local HTTP service-binding timeout.
pub const LOCAL_HTTP_SERVICE_BINDING_TIMEOUT_MS_V1: u64 = 10_000;

pub fn validate_local_router_wallet_session_authorization_header_v2(
    authorization: Option<&str>,
) -> Result<(), &'static str> {
    let Some(header) = authorization else {
        return Err("local Router normal-signing Wallet Session authorization is missing");
    };
    let Some(token) = header.trim().strip_prefix("Bearer ") else {
        return Err("local Router normal-signing Wallet Session authorization must use Bearer");
    };
    if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err("local Router normal-signing Wallet Session bearer token is invalid");
    }
    let mut segments = token.split('.');
    let Some(header_segment) = segments.next() else {
        return Err("local Router normal-signing Wallet Session JWT is invalid");
    };
    let Some(claims_segment) = segments.next() else {
        return Err("local Router normal-signing Wallet Session JWT is invalid");
    };
    let Some(signature_segment) = segments.next() else {
        return Err("local Router normal-signing Wallet Session JWT is invalid");
    };
    if segments.next().is_some() {
        return Err("local Router normal-signing Wallet Session JWT is invalid");
    }
    for segment in [header_segment, claims_segment, signature_segment] {
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err("local Router normal-signing Wallet Session JWT is invalid");
        }
    }
    Ok(())
}

/// Returns the local private service-auth secret used between Router and workers.
pub fn local_router_ab_internal_service_auth_secret_v1() -> String {
    std::env::var(LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_ENV_V1)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1.to_owned())
}

pub(crate) fn local_router_ab_internal_service_auth_matches_v1(
    actual: &str,
    expected: &str,
) -> bool {
    use subtle::ConstantTimeEq;

    actual.len() == expected.len() && bool::from(actual.as_bytes().ct_eq(expected.as_bytes()))
}

const LOCAL_ROUTER_FORBIDDEN_ENV_KEYS_V1: &[&str] = &[
    LOCAL_DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_DERIVER_A_ROOT_SHARE_WIRE_SECRET_ENV_V1,
    LOCAL_DERIVER_B_ROOT_SHARE_WIRE_SECRET_ENV_V1,
    LOCAL_DERIVER_A_ED25519_YAO_DERIVATION_ROOT_ENV_V1,
    LOCAL_DERIVER_B_ED25519_YAO_DERIVATION_ROOT_ENV_V1,
    LOCAL_DERIVER_A_PEER_SIGNING_KEY_ENV_V1,
    LOCAL_DERIVER_B_PEER_SIGNING_KEY_ENV_V1,
    LOCAL_DERIVER_A_ROOT_SHARE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_B_ROOT_SHARE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_A_SEALED_ROOT_SHARES_PATH_ENV_V1,
    LOCAL_DERIVER_B_SEALED_ROOT_SHARES_PATH_ENV_V1,
    LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH_ENV_V1,
];

const LOCAL_DERIVER_A_FORBIDDEN_ENV_KEYS_V1: &[&str] = &[
    LOCAL_ROUTER_REPLAY_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_LIFECYCLE_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_PROJECT_POLICY_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_QUOTA_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_ABUSE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_DERIVER_B_ROOT_SHARE_WIRE_SECRET_ENV_V1,
    LOCAL_DERIVER_B_ED25519_YAO_DERIVATION_ROOT_ENV_V1,
    LOCAL_DERIVER_B_PEER_SIGNING_KEY_ENV_V1,
    LOCAL_DERIVER_B_ROOT_SHARE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_B_SEALED_ROOT_SHARES_PATH_ENV_V1,
    LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH_ENV_V1,
];

const LOCAL_DERIVER_B_FORBIDDEN_ENV_KEYS_V1: &[&str] = &[
    LOCAL_ROUTER_REPLAY_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_LIFECYCLE_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_PROJECT_POLICY_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_QUOTA_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_ABUSE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_DERIVER_A_ROOT_SHARE_WIRE_SECRET_ENV_V1,
    LOCAL_DERIVER_A_ED25519_YAO_DERIVATION_ROOT_ENV_V1,
    LOCAL_DERIVER_A_PEER_SIGNING_KEY_ENV_V1,
    LOCAL_DERIVER_A_ROOT_SHARE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_A_SEALED_ROOT_SHARES_PATH_ENV_V1,
    LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH_ENV_V1,
];

const LOCAL_SIGNING_WORKER_FORBIDDEN_ENV_KEYS_V1: &[&str] = &[
    LOCAL_ROUTER_REPLAY_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_LIFECYCLE_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_PROJECT_POLICY_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_QUOTA_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_ABUSE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_DERIVER_A_ROOT_SHARE_WIRE_SECRET_ENV_V1,
    LOCAL_DERIVER_B_ROOT_SHARE_WIRE_SECRET_ENV_V1,
    LOCAL_DERIVER_A_ED25519_YAO_DERIVATION_ROOT_ENV_V1,
    LOCAL_DERIVER_B_ED25519_YAO_DERIVATION_ROOT_ENV_V1,
    LOCAL_DERIVER_A_PEER_SIGNING_KEY_ENV_V1,
    LOCAL_DERIVER_B_PEER_SIGNING_KEY_ENV_V1,
    LOCAL_DERIVER_A_ROOT_SHARE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_B_ROOT_SHARE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_A_SEALED_ROOT_SHARES_PATH_ENV_V1,
    LOCAL_DERIVER_B_SEALED_ROOT_SHARES_PATH_ENV_V1,
];

/// Router local worker config after raw env parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalRouterWorkerConfigV1 {
    /// Router public URL.
    pub public_url: String,
    /// Deriver A private URL.
    pub deriver_a_url: String,
    /// Deriver B private URL.
    pub deriver_b_url: String,
    /// SigningWorker private URL.
    pub signing_worker_url: String,
    /// Deriver A Client-input HPKE public key.
    pub deriver_a_ed25519_yao_input_public_key: String,
    /// Deriver B Client-input HPKE public key.
    pub deriver_b_ed25519_yao_input_public_key: String,
    /// SigningWorker recipient HPKE public key.
    pub signing_worker_ed25519_yao_recipient_public_key: String,
    /// SigningWorker selected for local Ed25519 Yao registration.
    pub signing_worker_id: String,
    /// Local private service authentication value.
    pub internal_service_auth: String,
    /// Router replay storage path.
    pub replay_storage_path: String,
    /// Router lifecycle storage path.
    pub lifecycle_storage_path: String,
    /// Router project-policy storage path.
    pub project_policy_storage_path: String,
    /// Router quota storage path.
    pub quota_storage_path: String,
    /// Router abuse storage path.
    pub abuse_storage_path: String,
}

/// Deriver A local worker config after raw env parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalDeriverAWorkerConfigV1 {
    /// Deriver A private URL.
    pub deriver_a_url: String,
    /// Deriver B private URL.
    pub deriver_b_url: String,
    /// Deriver A envelope HPKE private key.
    pub envelope_hpke_private_key: String,
    /// Deriver A root-share wire secret.
    pub root_share_wire_secret: String,
    /// Deriver A Ed25519 Yao server-contribution root.
    pub ed25519_yao_derivation_root_hex: String,
    /// Deriver A peer signing key.
    pub peer_signing_key: String,
    /// Deriver A peer verifying key.
    pub deriver_a_peer_verifying_key: String,
    /// Deriver B peer verifying key.
    pub deriver_b_peer_verifying_key: String,
    /// Deriver A root-share metadata storage path.
    pub root_share_storage_path: String,
    /// Deriver A sealed root-share storage path.
    pub sealed_root_shares_path: String,
}

/// Deriver B local worker config after raw env parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalDeriverBWorkerConfigV1 {
    /// Deriver B private URL.
    pub deriver_b_url: String,
    /// Deriver A private URL.
    pub deriver_a_url: String,
    /// Deriver B envelope HPKE private key.
    pub envelope_hpke_private_key: String,
    /// Deriver B root-share wire secret.
    pub root_share_wire_secret: String,
    /// Deriver B Ed25519 Yao server-contribution root.
    pub ed25519_yao_derivation_root_hex: String,
    /// Deriver B peer signing key.
    pub peer_signing_key: String,
    /// Deriver A peer verifying key.
    pub deriver_a_peer_verifying_key: String,
    /// Deriver B peer verifying key.
    pub deriver_b_peer_verifying_key: String,
    /// Deriver B root-share metadata storage path.
    pub root_share_storage_path: String,
    /// Deriver B sealed root-share storage path.
    pub sealed_root_shares_path: String,
}

/// SigningWorker local worker config after raw env parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalSigningWorkerConfigV1 {
    /// SigningWorker private URL.
    pub signing_worker_url: String,
    /// SigningWorker public identity.
    pub signing_worker_id: String,
    /// SigningWorker key epoch.
    pub signing_worker_key_epoch: String,
    /// SigningWorker server-output HPKE public key.
    pub server_output_hpke_public_key: String,
    /// SigningWorker server-output HPKE private key.
    pub server_output_hpke_private_key: String,
    /// SigningWorker server-output storage path.
    pub server_output_storage_path: String,
}

/// Role-specific local worker config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum LocalWorkerRoleConfigV1 {
    /// Router config branch.
    Router(LocalRouterWorkerConfigV1),
    /// Deriver A config branch.
    DeriverA(LocalDeriverAWorkerConfigV1),
    /// Deriver B config branch.
    DeriverB(LocalDeriverBWorkerConfigV1),
    /// SigningWorker config branch.
    SigningWorker(LocalSigningWorkerConfigV1),
}

impl LocalWorkerRoleConfigV1 {
    /// Returns this config's local service role.
    pub fn role(&self) -> LocalServiceRoleV1 {
        match self {
            Self::Router(_) => LocalServiceRoleV1::Router,
            Self::DeriverA(_) => LocalServiceRoleV1::DeriverA,
            Self::DeriverB(_) => LocalServiceRoleV1::DeriverB,
            Self::SigningWorker(_) => LocalServiceRoleV1::SigningWorker,
        }
    }

    /// Returns the configured local URL for this worker.
    pub fn bind_url(&self) -> &str {
        match self {
            Self::Router(config) => &config.public_url,
            Self::DeriverA(config) => &config.deriver_a_url,
            Self::DeriverB(config) => &config.deriver_b_url,
            Self::SigningWorker(config) => &config.signing_worker_url,
        }
    }
}

/// Local Durable Object storage scope for the private-worker harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalDurableObjectScopeV1 {
    /// Router replay and idempotency state.
    RouterReplay,
    /// Router public lifecycle state.
    RouterLifecycle,
    /// Router project-policy state.
    RouterProjectPolicy,
    /// Router quota and request-budget state.
    RouterQuota,
    /// Router abuse-control state.
    RouterAbuse,
    /// Deriver A root-share metadata and sealed-share state.
    DeriverARootShare,
    /// Deriver B root-share metadata and sealed-share state.
    DeriverBRootShare,
    /// SigningWorker activation and active server-output state.
    SigningWorkerServerOutput,
}

impl LocalDurableObjectScopeV1 {
    /// Returns the stable local storage scope label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RouterReplay => "router_replay",
            Self::RouterLifecycle => "router_lifecycle",
            Self::RouterProjectPolicy => "router_project_policy",
            Self::RouterQuota => "router_quota",
            Self::RouterAbuse => "router_abuse",
            Self::DeriverARootShare => "deriver_a_root_share",
            Self::DeriverBRootShare => "deriver_b_root_share",
            Self::SigningWorkerServerOutput => "signing_worker_server_output",
        }
    }

    /// Returns the worker role that owns this local storage scope.
    pub fn owner(self) -> LocalServiceRoleV1 {
        match self {
            Self::RouterReplay
            | Self::RouterLifecycle
            | Self::RouterProjectPolicy
            | Self::RouterQuota
            | Self::RouterAbuse => LocalServiceRoleV1::Router,
            Self::DeriverARootShare => LocalServiceRoleV1::DeriverA,
            Self::DeriverBRootShare => LocalServiceRoleV1::DeriverB,
            Self::SigningWorkerServerOutput => LocalServiceRoleV1::SigningWorker,
        }
    }
}

/// SQLite-backed local Durable Object key/value storage.
#[derive(Debug)]
pub struct LocalDurableObjectSqliteStorageV1<'connection> {
    connection: &'connection Connection,
    scope: LocalDurableObjectScopeV1,
}

impl<'connection> LocalDurableObjectSqliteStorageV1<'connection> {
    /// Creates a role-scoped local Durable Object store.
    pub fn new(
        connection: &'connection Connection,
        scope: LocalDurableObjectScopeV1,
    ) -> RouterAbProtocolResult<Self> {
        ensure_local_durable_object_sqlite_schema_v1(connection)?;
        Ok(Self { connection, scope })
    }

    /// Returns this store's local Durable Object scope.
    pub fn scope(&self) -> LocalDurableObjectScopeV1 {
        self.scope
    }

    /// Returns the worker role that owns this store.
    pub fn owner(&self) -> LocalServiceRoleV1 {
        self.scope.owner()
    }

    /// Stores non-empty bytes under a role-local key.
    pub fn put_bytes(&self, key: &str, value: &[u8]) -> RouterAbProtocolResult<()> {
        require_non_empty("local durable object key", key)?;
        if value.is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::EmptyField,
                "local durable object value must not be empty",
            ));
        }
        self.connection
            .execute(
                "
                INSERT INTO local_durable_object_kv (scope, key, value)
                VALUES (?1, ?2, ?3)
                ON CONFLICT(scope, key) DO UPDATE SET value = excluded.value
                ",
                params![self.scope.as_str(), key, value],
            )
            .map_err(map_sqlite_error)?;
        Ok(())
    }

    /// Reads bytes from a role-local key.
    pub fn get_bytes(&self, key: &str) -> RouterAbProtocolResult<Option<Vec<u8>>> {
        require_non_empty("local durable object key", key)?;
        self.connection
            .query_row(
                "SELECT value FROM local_durable_object_kv WHERE scope = ?1 AND key = ?2",
                params![self.scope.as_str(), key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(map_sqlite_error)
    }

    /// Deletes one role-local key and returns whether a row was removed.
    pub fn delete_key(&self, key: &str) -> RouterAbProtocolResult<bool> {
        require_non_empty("local durable object key", key)?;
        let rows = self
            .connection
            .execute(
                "DELETE FROM local_durable_object_kv WHERE scope = ?1 AND key = ?2",
                params![self.scope.as_str(), key],
            )
            .map_err(map_sqlite_error)?;
        Ok(rows > 0)
    }

    /// Lists keys in this role-local store.
    pub fn list_keys(&self) -> RouterAbProtocolResult<Vec<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT key FROM local_durable_object_kv WHERE scope = ?1 ORDER BY key")
            .map_err(map_sqlite_error)?;
        let rows = statement
            .query_map(params![self.scope.as_str()], |row| row.get::<_, String>(0))
            .map_err(map_sqlite_error)?;
        let mut keys = Vec::new();
        for row in rows {
            keys.push(row.map_err(map_sqlite_error)?);
        }
        Ok(keys)
    }
}

/// One deterministic local Durable Object seed entry.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalDurableObjectSeedEntryV1 {
    /// Scope that owns the seed entry.
    pub scope: LocalDurableObjectScopeV1,
    /// Role-local key.
    pub key: String,
    value: Vec<u8>,
}

impl LocalDurableObjectSeedEntryV1 {
    /// Creates a validated local Durable Object seed entry.
    pub fn new(
        scope: LocalDurableObjectScopeV1,
        key: impl Into<String>,
        value: impl Into<Vec<u8>>,
    ) -> RouterAbProtocolResult<Self> {
        let entry = Self {
            scope,
            key: key.into(),
            value: value.into(),
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Returns the seed value bytes.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Validates required seed fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("local durable object seed key", &self.key)?;
        if self.value.is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::EmptyField,
                "local durable object seed value must not be empty",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for LocalDurableObjectSeedEntryV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalDurableObjectSeedEntryV1")
            .field("scope", &self.scope)
            .field("key", &self.key)
            .field("value_len", &self.value.len())
            .field("value", &"[redacted]")
            .finish()
    }
}

/// Deterministic local Durable Object seed plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDurableObjectSeedPlanV1 {
    /// Entries to write.
    pub entries: Vec<LocalDurableObjectSeedEntryV1>,
}

impl LocalDurableObjectSeedPlanV1 {
    /// Creates a validated local Durable Object seed plan.
    pub fn new(entries: Vec<LocalDurableObjectSeedEntryV1>) -> RouterAbProtocolResult<Self> {
        if entries.is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::EmptyField,
                "local durable object seed plan requires at least one entry",
            ));
        }
        for entry in &entries {
            entry.validate()?;
        }
        Ok(Self { entries })
    }
}

/// Redacted receipt from a local Durable Object seed operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalDurableObjectSeedReceiptV1 {
    /// Number of entries written.
    pub written_entry_count: u32,
    /// Scope labels touched by the seed operation.
    pub scope_labels: Vec<String>,
}

/// Redacted receipt from seeding all local storage parity state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalStorageParitySeedReceiptV1 {
    /// SQL seed receipt for signing-root metadata.
    pub signing_root_metadata: LocalPersistenceSqlExecutionReceiptV1,
    /// Durable Object seed receipt.
    pub durable_objects: LocalDurableObjectSeedReceiptV1,
}

/// Returns the deterministic local Durable Object seed plan used by smoke tests.
pub fn example_local_durable_object_seed_plan_v1(
) -> RouterAbProtocolResult<LocalDurableObjectSeedPlanV1> {
    LocalDurableObjectSeedPlanV1::new(vec![
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::RouterReplay,
            "replay/request/dev",
            br#"{"state":"available"}"#.to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::RouterLifecycle,
            "lifecycle/dev",
            br#"{"state":"initialized"}"#.to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::RouterProjectPolicy,
            "project/default",
            br#"{"admission":"allow"}"#.to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::RouterQuota,
            "quota/default",
            br#"{"remaining":1}"#.to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::RouterAbuse,
            "abuse/default",
            br#"{"decision":"allow"}"#.to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::DeriverARootShare,
            "sealed/share/a",
            b"local-dev-sealed-root-share-a".to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::DeriverBRootShare,
            "sealed/share/b",
            b"local-dev-sealed-root-share-b".to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::SigningWorkerServerOutput,
            "activation/dev",
            br#"{"state":"activated"}"#.to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::SigningWorkerServerOutput,
            "active-state/dev",
            br#"{"state":"active"}"#.to_vec(),
        )?,
    ])
}

/// Seeds local Durable Object SQLite storage with deterministic smoke state.
pub fn seed_example_local_durable_object_sqlite_v1(
    connection: &Connection,
) -> RouterAbProtocolResult<LocalDurableObjectSeedReceiptV1> {
    let plan = example_local_durable_object_seed_plan_v1()?;
    seed_local_durable_object_sqlite_v1(connection, &plan)
}

/// Seeds local Durable Object SQLite storage from a validated plan.
pub fn seed_local_durable_object_sqlite_v1(
    connection: &Connection,
    plan: &LocalDurableObjectSeedPlanV1,
) -> RouterAbProtocolResult<LocalDurableObjectSeedReceiptV1> {
    if plan.entries.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            "local durable object seed plan requires at least one entry",
        ));
    }
    let mut scope_labels = Vec::<String>::new();
    for entry in &plan.entries {
        entry.validate()?;
        let store = LocalDurableObjectSqliteStorageV1::new(connection, entry.scope)?;
        store.put_bytes(&entry.key, entry.value())?;
        let scope_label = entry.scope.as_str().to_owned();
        if !scope_labels.contains(&scope_label) {
            scope_labels.push(scope_label);
        }
    }
    let written_entry_count = u32::try_from(plan.entries.len()).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local durable object seed entry count did not fit u32",
        )
    })?;
    Ok(LocalDurableObjectSeedReceiptV1 {
        written_entry_count,
        scope_labels,
    })
}

/// Seeds deterministic signing-root metadata and local Durable Object state.
pub fn seed_example_local_storage_parity_v1(
    connection: &Connection,
) -> RouterAbProtocolResult<LocalStorageParitySeedReceiptV1> {
    Ok(LocalStorageParitySeedReceiptV1 {
        signing_root_metadata: seed_example_local_sqlite_v1(connection)?,
        durable_objects: seed_example_local_durable_object_sqlite_v1(connection)?,
    })
}

/// One generated local env file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalEnvMaterializedFileV1 {
    /// Role that owns this env file.
    pub role: LocalServiceRoleV1,
    /// Relative path to write.
    pub path: String,
    /// File contents.
    pub contents: String,
}

/// Files and directories needed by the local Router/A/B dev harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalEnvMaterializationPlanV1 {
    /// Directories to create before writing env files.
    pub directories: Vec<String>,
    /// Env files to write.
    pub files: Vec<LocalEnvMaterializedFileV1>,
}

impl LocalEnvMaterializationPlanV1 {
    /// Validates every generated env file parses into the matching role branch.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_exact_len_v1(
            "local env materialization directories",
            self.directories.len(),
            4,
        )?;
        require_exact_len_v1("local env materialization files", self.files.len(), 4)?;
        for directory in &self.directories {
            require_non_empty("local state directory", directory)?;
        }
        for file in &self.files {
            require_non_empty("local env file path", &file.path)?;
            require_non_empty("local env file contents", &file.contents)?;
            let config = parse_local_worker_role_config_for_role_v1(
                file.role,
                parse_local_env_file_contents_v1(&file.contents)?,
            )?;
            if config.role() != file.role {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "local env materialization produced wrong role branch",
                ));
            }
        }
        Ok(())
    }
}

/// Builds generated local env files and state directories from a caller-provided seed.
pub fn local_env_materialization_plan_v1(
    seed: &[u8],
) -> RouterAbProtocolResult<LocalEnvMaterializationPlanV1> {
    require_non_empty("local env materialization seed", &hex::encode(seed))?;
    let plan = LocalEnvMaterializationPlanV1 {
        directories: vec![
            LOCAL_ROUTER_STATE_DIR_V1.to_owned(),
            LOCAL_DERIVER_A_STATE_DIR_V1.to_owned(),
            LOCAL_DERIVER_B_STATE_DIR_V1.to_owned(),
            LOCAL_SIGNING_WORKER_STATE_DIR_V1.to_owned(),
        ],
        files: vec![
            LocalEnvMaterializedFileV1 {
                role: LocalServiceRoleV1::Router,
                path: LOCAL_ROUTER_ENV_FILE_V1.to_owned(),
                contents: materialize_template_v1(
                    include_str!("../env/router.local.example"),
                    seed,
                )?,
            },
            LocalEnvMaterializedFileV1 {
                role: LocalServiceRoleV1::DeriverA,
                path: LOCAL_DERIVER_A_ENV_FILE_V1.to_owned(),
                contents: materialize_template_v1(
                    include_str!("../env/deriver-a.local.example"),
                    seed,
                )?,
            },
            LocalEnvMaterializedFileV1 {
                role: LocalServiceRoleV1::DeriverB,
                path: LOCAL_DERIVER_B_ENV_FILE_V1.to_owned(),
                contents: materialize_template_v1(
                    include_str!("../env/deriver-b.local.example"),
                    seed,
                )?,
            },
            LocalEnvMaterializedFileV1 {
                role: LocalServiceRoleV1::SigningWorker,
                path: LOCAL_SIGNING_WORKER_ENV_FILE_V1.to_owned(),
                contents: materialize_template_v1(
                    include_str!("../env/signing-worker.local.example"),
                    seed,
                )?,
            },
        ],
    };
    plan.validate()?;
    Ok(plan)
}

/// Parses simple `KEY=value` local env file contents.
pub fn parse_local_env_file_contents_v1(
    contents: &str,
) -> RouterAbProtocolResult<Vec<(String, String)>> {
    let mut entries = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("local env line {} must use KEY=value", index + 1),
            ));
        };
        entries.push((key.to_owned(), value.to_owned()));
    }
    Ok(entries)
}

/// Parses one local worker role label.
pub fn parse_local_service_role_label_v1(
    label: &str,
) -> RouterAbProtocolResult<LocalServiceRoleV1> {
    match label {
        "router" => Ok(LocalServiceRoleV1::Router),
        "deriver-a" | "deriver_a" => Ok(LocalServiceRoleV1::DeriverA),
        "deriver-b" | "deriver_b" => Ok(LocalServiceRoleV1::DeriverB),
        "signing-worker" | "signing_worker" => Ok(LocalServiceRoleV1::SigningWorker),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("unknown local worker role '{label}'"),
        )),
    }
}

/// Parses raw local worker env entries into one role-specific config branch.
pub fn parse_local_worker_role_config_v1(
    entries: impl IntoIterator<Item = (String, String)>,
) -> RouterAbProtocolResult<LocalWorkerRoleConfigV1> {
    let env = local_env_map_v1(entries)?;
    let role =
        parse_local_service_role_label_v1(&required_env_v1(&env, LOCAL_WORKER_ROLE_ENV_V1)?)?;
    parse_local_worker_role_config_for_role_v1(role, entries_from_env_map_v1(&env))
}

/// Parses raw local worker env entries for a CLI-selected role and checks env role agreement.
pub fn parse_local_worker_role_config_for_role_v1(
    expected_role: LocalServiceRoleV1,
    entries: impl IntoIterator<Item = (String, String)>,
) -> RouterAbProtocolResult<LocalWorkerRoleConfigV1> {
    let env = local_env_map_v1(entries)?;
    let actual_role =
        parse_local_service_role_label_v1(&required_env_v1(&env, LOCAL_WORKER_ROLE_ENV_V1)?)?;
    if actual_role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            format!(
                "local worker env role {} does not match selected role {}",
                actual_role.as_str(),
                expected_role.as_str()
            ),
        ));
    }
    match expected_role {
        LocalServiceRoleV1::Router => {
            reject_forbidden_env_keys_v1(&env, LOCAL_ROUTER_FORBIDDEN_ENV_KEYS_V1)?;
            Ok(LocalWorkerRoleConfigV1::Router(LocalRouterWorkerConfigV1 {
                public_url: required_env_v1(&env, LOCAL_ROUTER_PUBLIC_URL_ENV_V1)?,
                deriver_a_url: required_env_v1(&env, LOCAL_DERIVER_A_URL_ENV_V1)?,
                deriver_b_url: required_env_v1(&env, LOCAL_DERIVER_B_URL_ENV_V1)?,
                signing_worker_url: required_env_v1(&env, LOCAL_SIGNING_WORKER_URL_ENV_V1)?,
                deriver_a_ed25519_yao_input_public_key: required_x25519_public_key_env_v1(
                    &env,
                    LOCAL_DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY_ENV_V1,
                )?,
                deriver_b_ed25519_yao_input_public_key: required_x25519_public_key_env_v1(
                    &env,
                    LOCAL_DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY_ENV_V1,
                )?,
                signing_worker_ed25519_yao_recipient_public_key: required_x25519_public_key_env_v1(
                    &env,
                    LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY_ENV_V1,
                )?,
                signing_worker_id: required_env_v1(&env, LOCAL_SIGNING_WORKER_ID_ENV_V1)?,
                internal_service_auth: required_env_v1(
                    &env,
                    LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_ENV_V1,
                )?,
                replay_storage_path: required_env_v1(
                    &env,
                    LOCAL_ROUTER_REPLAY_STORAGE_PATH_ENV_V1,
                )?,
                lifecycle_storage_path: required_env_v1(
                    &env,
                    LOCAL_ROUTER_LIFECYCLE_STORAGE_PATH_ENV_V1,
                )?,
                project_policy_storage_path: required_env_v1(
                    &env,
                    LOCAL_ROUTER_PROJECT_POLICY_STORAGE_PATH_ENV_V1,
                )?,
                quota_storage_path: required_env_v1(&env, LOCAL_ROUTER_QUOTA_STORAGE_PATH_ENV_V1)?,
                abuse_storage_path: required_env_v1(&env, LOCAL_ROUTER_ABUSE_STORAGE_PATH_ENV_V1)?,
            }))
        }
        LocalServiceRoleV1::DeriverA => {
            reject_forbidden_env_keys_v1(&env, LOCAL_DERIVER_A_FORBIDDEN_ENV_KEYS_V1)?;
            Ok(LocalWorkerRoleConfigV1::DeriverA(
                LocalDeriverAWorkerConfigV1 {
                    deriver_a_url: required_env_v1(&env, LOCAL_DERIVER_A_URL_ENV_V1)?,
                    deriver_b_url: required_env_v1(&env, LOCAL_DERIVER_B_URL_ENV_V1)?,
                    envelope_hpke_private_key: required_hex_32_env_v1(
                        &env,
                        LOCAL_DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1,
                    )?,
                    root_share_wire_secret: required_env_v1(
                        &env,
                        LOCAL_DERIVER_A_ROOT_SHARE_WIRE_SECRET_ENV_V1,
                    )?,
                    ed25519_yao_derivation_root_hex: required_hex_32_env_v1(
                        &env,
                        LOCAL_DERIVER_A_ED25519_YAO_DERIVATION_ROOT_ENV_V1,
                    )?,
                    peer_signing_key: required_env_v1(
                        &env,
                        LOCAL_DERIVER_A_PEER_SIGNING_KEY_ENV_V1,
                    )?,
                    deriver_a_peer_verifying_key: required_env_v1(
                        &env,
                        LOCAL_DERIVER_A_PEER_VERIFYING_KEY_ENV_V1,
                    )?,
                    deriver_b_peer_verifying_key: required_env_v1(
                        &env,
                        LOCAL_DERIVER_B_PEER_VERIFYING_KEY_ENV_V1,
                    )?,
                    root_share_storage_path: required_env_v1(
                        &env,
                        LOCAL_DERIVER_A_ROOT_SHARE_STORAGE_PATH_ENV_V1,
                    )?,
                    sealed_root_shares_path: required_env_v1(
                        &env,
                        LOCAL_DERIVER_A_SEALED_ROOT_SHARES_PATH_ENV_V1,
                    )?,
                },
            ))
        }
        LocalServiceRoleV1::DeriverB => {
            reject_forbidden_env_keys_v1(&env, LOCAL_DERIVER_B_FORBIDDEN_ENV_KEYS_V1)?;
            Ok(LocalWorkerRoleConfigV1::DeriverB(
                LocalDeriverBWorkerConfigV1 {
                    deriver_b_url: required_env_v1(&env, LOCAL_DERIVER_B_URL_ENV_V1)?,
                    deriver_a_url: required_env_v1(&env, LOCAL_DERIVER_A_URL_ENV_V1)?,
                    envelope_hpke_private_key: required_hex_32_env_v1(
                        &env,
                        LOCAL_DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1,
                    )?,
                    root_share_wire_secret: required_env_v1(
                        &env,
                        LOCAL_DERIVER_B_ROOT_SHARE_WIRE_SECRET_ENV_V1,
                    )?,
                    ed25519_yao_derivation_root_hex: required_hex_32_env_v1(
                        &env,
                        LOCAL_DERIVER_B_ED25519_YAO_DERIVATION_ROOT_ENV_V1,
                    )?,
                    peer_signing_key: required_env_v1(
                        &env,
                        LOCAL_DERIVER_B_PEER_SIGNING_KEY_ENV_V1,
                    )?,
                    deriver_a_peer_verifying_key: required_env_v1(
                        &env,
                        LOCAL_DERIVER_A_PEER_VERIFYING_KEY_ENV_V1,
                    )?,
                    deriver_b_peer_verifying_key: required_env_v1(
                        &env,
                        LOCAL_DERIVER_B_PEER_VERIFYING_KEY_ENV_V1,
                    )?,
                    root_share_storage_path: required_env_v1(
                        &env,
                        LOCAL_DERIVER_B_ROOT_SHARE_STORAGE_PATH_ENV_V1,
                    )?,
                    sealed_root_shares_path: required_env_v1(
                        &env,
                        LOCAL_DERIVER_B_SEALED_ROOT_SHARES_PATH_ENV_V1,
                    )?,
                },
            ))
        }
        LocalServiceRoleV1::SigningWorker => {
            reject_forbidden_env_keys_v1(&env, LOCAL_SIGNING_WORKER_FORBIDDEN_ENV_KEYS_V1)?;
            Ok(LocalWorkerRoleConfigV1::SigningWorker(
                LocalSigningWorkerConfigV1 {
                    signing_worker_url: required_env_v1(&env, LOCAL_SIGNING_WORKER_URL_ENV_V1)?,
                    signing_worker_id: required_env_v1(&env, LOCAL_SIGNING_WORKER_ID_ENV_V1)?,
                    signing_worker_key_epoch: required_env_v1(
                        &env,
                        LOCAL_SIGNING_WORKER_KEY_EPOCH_ENV_V1,
                    )?,
                    server_output_hpke_public_key: required_x25519_public_key_env_v1(
                        &env,
                        LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY_ENV_V1,
                    )?,
                    server_output_hpke_private_key: required_hex_32_env_v1(
                        &env,
                        LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1,
                    )?,
                    server_output_storage_path: required_env_v1(
                        &env,
                        LOCAL_SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH_ENV_V1,
                    )?,
                },
            ))
        }
    }
}

/// Summary read back from local SQLite after seeding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalSqliteSeedSummaryV1 {
    /// Number of signing-root metadata rows.
    pub signing_root_count: u32,
    /// Number of sealed root-share rows.
    pub sealed_share_count: u32,
    /// Signer roles present in sealed-share storage.
    pub signer_roles: Vec<String>,
}

/// Successful signer startup check against local SQLite share storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalSqliteSignerStartupCheckV1 {
    /// Signer set that owns the checked root share.
    pub signer_set_id: String,
    /// Signer role checked at startup.
    pub role: Role,
    /// Root-share epoch checked at startup.
    pub root_share_epoch: RootShareEpoch,
    /// Signer id stored with the sealed share.
    pub signer_id: String,
    /// Signer key epoch stored with the sealed share.
    pub signer_key_epoch: String,
    /// Storage key for the sealed share blob.
    pub sealed_share_storage_key: String,
}

/// Combined dev harness output for the typed local HTTP Router/A/B ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRouterAbDevHttpCeremonyResultV1 {
    /// Fixed ECDSA threshold-PRF request used for the core local ceremony.
    pub router_request: EcdsaThresholdPrfRequestV1,
    /// Initial Router-to-Deriver A request over the checked local HTTP boundary.
    pub deriver_a_request: LocalHttpRequestV1,
    /// Initial Router-to-Deriver B request over the checked local HTTP boundary.
    pub deriver_b_request: LocalHttpRequestV1,
    /// Result of the typed local HTTP Router/Deriver/SigningWorker ceremony.
    pub core_http_ceremony: LocalHttpCeremonyResultV1,
}

/// Redacted receipt from a local Deriver peer-message route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDeriverPeerMessageReceiptV1 {
    /// Deriver worker role that accepted the peer message.
    pub receiver_role: LocalServiceRoleV1,
    /// Producing signer role bound inside the peer message.
    pub accepted_from_role: Role,
    /// Stable peer wire-message kind.
    pub peer_message_kind: WireMessageKindV1,
    /// Transcript digest for routing and smoke assertions.
    pub transcript_digest_hex: String,
    /// Number of proof bundles in the peer payload.
    pub proof_bundle_count: usize,
    /// Redacted receipt status.
    pub status: String,
}

/// Parses and validates a Deriver peer-message JSON body for local worker routes.
pub fn handle_local_deriver_peer_message_json_v1(
    receiver_role: LocalServiceRoleV1,
    path: &str,
    body: &[u8],
) -> RouterAbProtocolResult<String> {
    let receipt = handle_local_deriver_peer_message_v1(
        receiver_role,
        path,
        serde_json::from_slice::<WireMessageV1>(body).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("local Deriver peer message JSON parse failed: {error}"),
            )
        })?,
    )?;
    serde_json::to_string(&receipt).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("local Deriver peer receipt JSON serialization failed: {error}"),
        )
    })
}

/// Validates a Deriver peer message and returns a redacted local receipt.
pub fn handle_local_deriver_peer_message_v1(
    receiver_role: LocalServiceRoleV1,
    path: &str,
    message: WireMessageV1,
) -> RouterAbProtocolResult<LocalDeriverPeerMessageReceiptV1> {
    let (expected_path, expected_kind, expected_from, expected_to) = match receiver_role {
        LocalServiceRoleV1::DeriverA => (
            LOCAL_DERIVER_A_PEER_PATH,
            WireMessageKindV1::SignerBToSignerA,
            Role::SignerB,
            Role::SignerA,
        ),
        LocalServiceRoleV1::DeriverB => (
            LOCAL_DERIVER_B_PEER_PATH,
            WireMessageKindV1::SignerAToSignerB,
            Role::SignerA,
            Role::SignerB,
        ),
        LocalServiceRoleV1::Router | LocalServiceRoleV1::SigningWorker => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "local Deriver peer route requires Deriver A or Deriver B receiver",
            ));
        }
    };
    if path != expected_path {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "{} peer route must be served at {}",
                receiver_role.as_str(),
                expected_path
            ),
        ));
    }
    if message.kind != expected_kind {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalRoute,
            format!(
                "{} peer route expected {} message, received {}",
                receiver_role.as_str(),
                expected_kind.as_str(),
                message.kind.as_str()
            ),
        ));
    }
    let peer_payload = decode_ab_peer_message_payload_v1(message.payload.as_bytes())?;
    let proof_batch = decode_and_validate_ecdsa_threshold_prf_proof_batch_peer_payload_v1(&peer_payload)?;
    if peer_payload.transcript_digest != message.transcript_digest
        || proof_batch.transcript_digest != message.transcript_digest
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "local Deriver peer payload transcript does not match wire message",
        ));
    }
    if peer_payload.from.role != expected_from || peer_payload.to.role != expected_to {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "local Deriver peer message signer direction does not match route",
        ));
    }
    Ok(LocalDeriverPeerMessageReceiptV1 {
        receiver_role,
        accepted_from_role: peer_payload.from.role,
        peer_message_kind: message.kind,
        transcript_digest_hex: hex::encode(message.transcript_digest.as_bytes()),
        proof_bundle_count: proof_batch.proof_bundles.len(),
        status: "accepted".to_owned(),
    })
}

/// Private SigningWorker request to fill the local ECDSA-HSS presignature pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSigningWorkerEcdsaHssPresignaturePoolPutRequestV1 {
    /// Normal-signing identity and active SigningWorker scope.
    pub scope: RouterAbEcdsaHssNormalSigningScopeV1,
    /// Client-selected presignature id shared by the client and SigningWorker.
    pub server_presignature_id: String,
    /// Compressed secp256k1 presignature R point encoded as unpadded base64url.
    pub server_big_r33_b64u: String,
    /// SigningWorker-local ECDSA presignature k share encoded as unpadded base64url.
    pub server_k_share32_b64u: String,
    /// SigningWorker-local ECDSA presignature sigma share encoded as unpadded base64url.
    pub server_sigma_share32_b64u: String,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl LocalSigningWorkerEcdsaHssPresignaturePoolPutRequestV1 {
    /// Validates request fields without applying wall-clock expiry.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_non_empty("server_presignature_id", &self.server_presignature_id)?;
        decode_base64url_fixed_33_v1("server_big_r33_b64u", &self.server_big_r33_b64u)?;
        decode_base64url_fixed_32_v1("server_k_share32_b64u", &self.server_k_share32_b64u)?;
        decode_base64url_fixed_32_v1("server_sigma_share32_b64u", &self.server_sigma_share32_b64u)?;
        require_positive_unix_ms_v1(
            "ECDSA-HSS presignature pool fill expires_at_ms",
            self.expires_at_ms,
        )
    }

    /// Validates this pool-fill request can be accepted at the supplied timestamp.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        require_positive_unix_ms_v1("ECDSA-HSS presignature pool fill now_unix_ms", now_unix_ms)?;
        if self.expires_at_ms <= now_unix_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "ECDSA-HSS presignature pool fill request expired",
            ));
        }
        Ok(())
    }

    fn to_pool_record(
        &self,
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<LocalSigningWorkerEcdsaHssPresignaturePoolRecordV1> {
        self.validate_at(now_unix_ms)?;
        LocalSigningWorkerEcdsaHssPresignaturePoolRecordV1::new(
            active_signing_worker_state,
            self.server_presignature_id.clone(),
            self.server_big_r33_b64u.clone(),
            self.server_k_share32_b64u.clone(),
            self.server_sigma_share32_b64u.clone(),
            now_unix_ms,
            self.expires_at_ms,
        )
    }
}

/// Redacted receipt returned by the local ECDSA-HSS presignature pool-fill route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1 {
    /// Active SigningWorker state selected for this pool entry.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local presignature id accepted by the route.
    pub server_presignature_id: String,
    /// Compressed secp256k1 presignature R point encoded as unpadded base64url.
    pub server_big_r33_b64u: String,
    /// Whether the entry was inserted into the one-use pool.
    pub stored: bool,
}

impl LocalSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1 {
    fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        server_presignature_id: impl Into<String>,
        server_big_r33_b64u: impl Into<String>,
        stored: bool,
    ) -> RouterAbProtocolResult<Self> {
        let receipt = Self {
            active_signing_worker_state,
            server_presignature_id: server_presignature_id.into(),
            server_big_r33_b64u: server_big_r33_b64u.into(),
            stored,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty(
            "receipt.server_presignature_id",
            &self.server_presignature_id,
        )?;
        decode_base64url_fixed_33_v1("receipt.server_big_r33_b64u", &self.server_big_r33_b64u)?;
        Ok(())
    }
}

/// Local Router admission attached to a private ECDSA-HSS SigningWorker request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRouterEcdsaHssTrustedAdmissionV1 {
    /// Wallet/account id admitted by Router.
    pub account_id: String,
    /// Active ECDSA-HSS signing session id admitted by Router.
    pub session_id: String,
    /// Canonical request digest admitted by Router.
    pub request_digest: PublicDigest32,
    /// Exact EVM digest admitted for SigningWorker signing.
    pub signing_digest: PublicDigest32,
    /// Admission timestamp in Unix milliseconds.
    pub admitted_at_ms: u64,
    /// Expiry timestamp copied from the admitted request.
    pub expires_at_ms: u64,
}

impl LocalRouterEcdsaHssTrustedAdmissionV1 {
    fn validate_common(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("local ECDSA-HSS admission account_id", &self.account_id)?;
        require_non_empty("local ECDSA-HSS admission session_id", &self.session_id)?;
        require_positive_unix_ms_v1(
            "local ECDSA-HSS admission admitted_at_ms",
            self.admitted_at_ms,
        )?;
        require_positive_unix_ms_v1(
            "local ECDSA-HSS admission expires_at_ms",
            self.expires_at_ms,
        )?;
        if self.expires_at_ms <= self.admitted_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "local ECDSA-HSS admission expiry must be after admission",
            ));
        }
        Ok(())
    }

    fn validate_for_prepare(
        &self,
        request: &RouterAbEcdsaHssEvmDigestSigningRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate_common()?;
        request.validate()?;
        if self.account_id != request.scope.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "local ECDSA-HSS prepare admission account_id does not match request scope",
            ));
        }
        if self.session_id
            != router_ab_ecdsa_hss_active_state_session_id_v1(
                &request.scope.ecdsa_threshold_key_id,
                &request.scope.signing_root_id,
                &request.scope.signing_root_version,
                &request.scope.activation_epoch,
            )?
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "local ECDSA-HSS prepare admission session_id does not match request scope",
            ));
        }
        if self.request_digest != request.request_digest()?
            || self.signing_digest != request.signing_digest()?
            || self.expires_at_ms != request.expires_at_ms
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "local ECDSA-HSS prepare admission does not match request",
            ));
        }
        Ok(())
    }

    fn validate_for_finalize(
        &self,
        request: &RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate_common()?;
        request.validate()?;
        if self.account_id != request.scope.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "local ECDSA-HSS finalize admission account_id does not match request scope",
            ));
        }
        if self.session_id
            != router_ab_ecdsa_hss_active_state_session_id_v1(
                &request.scope.ecdsa_threshold_key_id,
                &request.scope.signing_root_id,
                &request.scope.signing_root_version,
                &request.scope.activation_epoch,
            )?
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "local ECDSA-HSS finalize admission session_id does not match request scope",
            ));
        }
        if self.request_digest != request.request_digest()?
            || self.signing_digest != request.signing_digest()?
            || self.expires_at_ms != request.expires_at_ms
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "local ECDSA-HSS finalize admission does not match request",
            ));
        }
        Ok(())
    }
}

/// Local Router-admitted ECDSA-HSS prepare request sent to SigningWorker.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSigningWorkerAdmittedEcdsaHssPrepareRequestV1 {
    /// Typed public ECDSA-HSS prepare request accepted by Router.
    pub request: RouterAbEcdsaHssEvmDigestSigningRequestV1,
    /// Trusted local Router admission for this exact request.
    pub trusted_admission: LocalRouterEcdsaHssTrustedAdmissionV1,
}

impl LocalSigningWorkerAdmittedEcdsaHssPrepareRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.trusted_admission.validate_for_prepare(&self.request)
    }
}

/// Local Router-admitted ECDSA-HSS finalize request sent to SigningWorker.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSigningWorkerAdmittedEcdsaHssFinalizeRequestV1 {
    /// Typed public ECDSA-HSS finalize request accepted by Router.
    pub request: RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    /// Trusted local Router admission for this exact finalize request.
    pub trusted_admission: LocalRouterEcdsaHssTrustedAdmissionV1,
}

impl LocalSigningWorkerAdmittedEcdsaHssFinalizeRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.trusted_admission.validate_for_finalize(&self.request)
    }
}

/// One-use local ECDSA-HSS presignature pool record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSigningWorkerEcdsaHssPresignaturePoolRecordV1 {
    /// Active SigningWorker state selected for this pool entry.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local presignature id.
    pub server_presignature_id: String,
    /// Compressed secp256k1 presignature R point encoded as unpadded base64url.
    pub server_big_r33_b64u: String,
    /// SigningWorker-local ECDSA presignature k share encoded as unpadded base64url.
    pub server_k_share32_b64u: String,
    /// SigningWorker-local ECDSA presignature sigma share encoded as unpadded base64url.
    pub server_sigma_share32_b64u: String,
    /// Insertion timestamp in Unix milliseconds.
    pub created_at_ms: u64,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl LocalSigningWorkerEcdsaHssPresignaturePoolRecordV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        server_presignature_id: impl Into<String>,
        server_big_r33_b64u: impl Into<String>,
        server_k_share32_b64u: impl Into<String>,
        server_sigma_share32_b64u: impl Into<String>,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            active_signing_worker_state,
            server_presignature_id: server_presignature_id.into(),
            server_big_r33_b64u: server_big_r33_b64u.into(),
            server_k_share32_b64u: server_k_share32_b64u.into(),
            server_sigma_share32_b64u: server_sigma_share32_b64u.into(),
            created_at_ms,
            expires_at_ms,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty(
            "ECDSA-HSS pool record server_presignature_id",
            &self.server_presignature_id,
        )?;
        decode_base64url_fixed_33_v1(
            "ECDSA-HSS pool record server_big_r33_b64u",
            &self.server_big_r33_b64u,
        )?;
        decode_base64url_fixed_32_v1(
            "ECDSA-HSS pool record server_k_share32_b64u",
            &self.server_k_share32_b64u,
        )?;
        decode_base64url_fixed_32_v1(
            "ECDSA-HSS pool record server_sigma_share32_b64u",
            &self.server_sigma_share32_b64u,
        )?;
        require_positive_unix_ms_v1("ECDSA-HSS pool record created_at_ms", self.created_at_ms)?;
        require_positive_unix_ms_v1("ECDSA-HSS pool record expires_at_ms", self.expires_at_ms)?;
        if self.expires_at_ms <= self.created_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "ECDSA-HSS pool record expiry must be after creation",
            ));
        }
        Ok(())
    }

    fn same_pool_identity_and_material(&self, other: &Self) -> bool {
        self.active_signing_worker_state == other.active_signing_worker_state
            && self.server_presignature_id == other.server_presignature_id
            && self.server_big_r33_b64u == other.server_big_r33_b64u
            && self.server_k_share32_b64u == other.server_k_share32_b64u
            && self.server_sigma_share32_b64u == other.server_sigma_share32_b64u
            && self.expires_at_ms == other.expires_at_ms
    }
}

/// One-use local ECDSA-HSS presignature record bound to an exact signing request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSigningWorkerEcdsaHssPresignatureRecordV1 {
    /// Active SigningWorker state selected for this signing request.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local presignature id consumed by finalize.
    pub server_presignature_id: String,
    /// Canonical prepare request digest.
    pub request_digest: PublicDigest32,
    /// Exact 32-byte EVM digest this presignature may sign.
    pub admitted_signing_digest: PublicDigest32,
    /// Compressed secp256k1 presignature R point encoded as unpadded base64url.
    pub server_big_r33_b64u: String,
    /// Public 32-byte rerandomization entropy both ECDSA parties must use.
    pub rerandomization_entropy32_b64u: String,
    /// SigningWorker-local ECDSA presignature k share encoded as unpadded base64url.
    pub server_k_share32_b64u: String,
    /// SigningWorker-local ECDSA presignature sigma share encoded as unpadded base64url.
    pub server_sigma_share32_b64u: String,
    /// Insertion timestamp in Unix milliseconds.
    pub created_at_ms: u64,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl LocalSigningWorkerEcdsaHssPresignatureRecordV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        server_presignature_id: impl Into<String>,
        request_digest: PublicDigest32,
        admitted_signing_digest: PublicDigest32,
        server_big_r33_b64u: impl Into<String>,
        rerandomization_entropy32_b64u: impl Into<String>,
        server_k_share32_b64u: impl Into<String>,
        server_sigma_share32_b64u: impl Into<String>,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            active_signing_worker_state,
            server_presignature_id: server_presignature_id.into(),
            request_digest,
            admitted_signing_digest,
            server_big_r33_b64u: server_big_r33_b64u.into(),
            rerandomization_entropy32_b64u: rerandomization_entropy32_b64u.into(),
            server_k_share32_b64u: server_k_share32_b64u.into(),
            server_sigma_share32_b64u: server_sigma_share32_b64u.into(),
            created_at_ms,
            expires_at_ms,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty(
            "ECDSA-HSS prepared record server_presignature_id",
            &self.server_presignature_id,
        )?;
        decode_base64url_fixed_33_v1(
            "ECDSA-HSS prepared record server_big_r33_b64u",
            &self.server_big_r33_b64u,
        )?;
        decode_base64url_fixed_32_v1(
            "ECDSA-HSS prepared record rerandomization_entropy32_b64u",
            &self.rerandomization_entropy32_b64u,
        )?;
        decode_base64url_fixed_32_v1(
            "ECDSA-HSS prepared record server_k_share32_b64u",
            &self.server_k_share32_b64u,
        )?;
        decode_base64url_fixed_32_v1(
            "ECDSA-HSS prepared record server_sigma_share32_b64u",
            &self.server_sigma_share32_b64u,
        )?;
        require_positive_unix_ms_v1(
            "ECDSA-HSS prepared record created_at_ms",
            self.created_at_ms,
        )?;
        require_positive_unix_ms_v1(
            "ECDSA-HSS prepared record expires_at_ms",
            self.expires_at_ms,
        )?;
        if self.expires_at_ms <= self.created_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "ECDSA-HSS prepared record expiry must be after creation",
            ));
        }
        Ok(())
    }

    fn validate_for_finalize(
        &self,
        active_signing_worker_state: &ActiveSigningWorkerStateV1,
        request: &RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate_at(now_unix_ms)?;
        if self.active_signing_worker_state != *active_signing_worker_state {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "local ECDSA-HSS prepared record active SigningWorker mismatch",
            ));
        }
        if self.server_presignature_id != request.server_presignature_id
            || self.request_digest != request.prepare_request_digest()?
            || self.admitted_signing_digest != request.signing_digest()?
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "local ECDSA-HSS finalize request does not match prepared presignature",
            ));
        }
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "local ECDSA-HSS prepared presignature expired",
            ));
        }
        Ok(())
    }
}

/// Handles the local SigningWorker ECDSA-HSS presignature pool-fill route.
pub fn handle_local_signing_worker_ecdsa_hss_presignature_pool_put_json_v1(
    config: &LocalSigningWorkerConfigV1,
    receiver_role: LocalServiceRoleV1,
    path: &str,
    body: &[u8],
) -> RouterAbProtocolResult<String> {
    if receiver_role != LocalServiceRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local ECDSA-HSS presignature pool-fill route requires SigningWorker receiver",
        ));
    }
    if path != LOCAL_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "SigningWorker ECDSA-HSS presignature pool-fill route must be served at {}",
                LOCAL_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH
            ),
        ));
    }
    let now_unix_ms = local_now_unix_ms_v1()?;
    let request = parse_local_json_body_v1::<LocalSigningWorkerEcdsaHssPresignaturePoolPutRequestV1>(
        "local ECDSA-HSS presignature pool-fill request",
        body,
    )?;
    request.validate_at(now_unix_ms)?;
    let active_signing_worker_state =
        local_active_ecdsa_hss_signing_worker_state_v1(config, &request.scope)?;
    let record = request.to_pool_record(active_signing_worker_state.clone(), now_unix_ms)?;
    let stored = local_signing_worker_ecdsa_hss_presignature_pool_store_put_v1(record)?;
    let receipt = LocalSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1::new(
        active_signing_worker_state,
        request.server_presignature_id,
        request.server_big_r33_b64u,
        stored,
    )?;
    serde_json::to_string(&receipt).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "local SigningWorker ECDSA-HSS presignature pool-fill receipt JSON serialization failed: {error}"
            ),
        )
    })
}

/// Handles the local SigningWorker ECDSA-HSS digest-signing prepare route.
pub fn handle_local_signing_worker_ecdsa_hss_prepare_json_v1(
    config: &LocalSigningWorkerConfigV1,
    receiver_role: LocalServiceRoleV1,
    path: &str,
    body: &[u8],
) -> RouterAbProtocolResult<String> {
    if receiver_role != LocalServiceRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local ECDSA-HSS prepare route requires SigningWorker receiver",
        ));
    }
    if path != LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "SigningWorker ECDSA-HSS prepare route must be served at {}",
                LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH
            ),
        ));
    }
    let now_unix_ms = local_now_unix_ms_v1()?;
    let admitted = parse_local_json_body_v1::<LocalSigningWorkerAdmittedEcdsaHssPrepareRequestV1>(
        "local admitted ECDSA-HSS prepare request",
        body,
    )?;
    admitted.validate()?;
    let request = admitted.request;
    request.validate_at(now_unix_ms)?;
    let active_signing_worker_state =
        local_active_ecdsa_hss_signing_worker_state_v1(config, &request.scope)?;
    let pool_record = local_signing_worker_ecdsa_hss_presignature_pool_store_take_v1(
        &active_signing_worker_state,
        &request.client_presignature_id,
        now_unix_ms,
    )?;
    let mut rerandomization_entropy32 = [0u8; 32];
    let mut rng = OsRng;
    rand_core::RngCore::fill_bytes(&mut rng, &mut rerandomization_entropy32);
    let rerandomization_entropy32_b64u = encode_base64url_bytes_v1(&rerandomization_entropy32);
    let response = RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1::new_for_request(
        &request,
        pool_record.server_presignature_id.clone(),
        pool_record.server_big_r33_b64u.clone(),
        rerandomization_entropy32_b64u.clone(),
        now_unix_ms,
    )?;
    let prepared_record = LocalSigningWorkerEcdsaHssPresignatureRecordV1::new(
        active_signing_worker_state,
        pool_record.server_presignature_id,
        request.request_digest()?,
        request.signing_digest()?,
        pool_record.server_big_r33_b64u,
        rerandomization_entropy32_b64u,
        pool_record.server_k_share32_b64u,
        pool_record.server_sigma_share32_b64u,
        now_unix_ms,
        request.expires_at_ms,
    )?;
    local_signing_worker_ecdsa_hss_presignature_store_put_v1(prepared_record)?;
    serde_json::to_string(&response).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "local SigningWorker ECDSA-HSS prepare response JSON serialization failed: {error}"
            ),
        )
    })
}

/// Handles the local SigningWorker ECDSA-HSS digest-signing finalize route.
pub fn handle_local_signing_worker_ecdsa_hss_finalize_json_v1(
    config: &LocalSigningWorkerConfigV1,
    receiver_role: LocalServiceRoleV1,
    path: &str,
    body: &[u8],
) -> RouterAbProtocolResult<String> {
    if receiver_role != LocalServiceRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local ECDSA-HSS finalize route requires SigningWorker receiver",
        ));
    }
    if path != LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "SigningWorker ECDSA-HSS finalize route must be served at {}",
                LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH
            ),
        ));
    }
    let now_unix_ms = local_now_unix_ms_v1()?;
    let admitted = parse_local_json_body_v1::<LocalSigningWorkerAdmittedEcdsaHssFinalizeRequestV1>(
        "local admitted ECDSA-HSS finalize request",
        body,
    )?;
    admitted.validate()?;
    let request = admitted.request;
    request.validate_at(now_unix_ms)?;
    let active_signing_worker_state =
        local_active_ecdsa_hss_signing_worker_state_v1(config, &request.scope)?;
    let prepare_request_digest = request.prepare_request_digest()?;
    let record = local_signing_worker_ecdsa_hss_presignature_store_take_v1(
        &request.server_presignature_id,
        prepare_request_digest,
    )?;
    record.validate_for_finalize(&active_signing_worker_state, &request, now_unix_ms)?;
    let participant_ids = ECDSA_HSS_PARTICIPANT_IDS.map(u32::from);
    let signature65 = threshold_ecdsa_finalize_signature(
        &participant_ids,
        2,
        &decode_base64url_fixed_33_v1(
            "local ECDSA-HSS threshold_public_key33_b64u",
            &request.scope.public_identity.threshold_public_key33_b64u,
        )?,
        &decode_base64url_fixed_33_v1(
            "local ECDSA-HSS server_big_r33_b64u",
            &record.server_big_r33_b64u,
        )?,
        &decode_base64url_fixed_32_v1(
            "local ECDSA-HSS server_k_share32_b64u",
            &record.server_k_share32_b64u,
        )?,
        &decode_base64url_fixed_32_v1(
            "local ECDSA-HSS server_sigma_share32_b64u",
            &record.server_sigma_share32_b64u,
        )?,
        record.admitted_signing_digest.as_bytes(),
        &decode_base64url_fixed_32_v1(
            "local ECDSA-HSS rerandomization_entropy32_b64u",
            &record.rerandomization_entropy32_b64u,
        )?,
        &request.client_signature_share32()?,
    )
    .map_err(map_signer_core_ecdsa_error_v1)?;
    let response = RouterAbEcdsaHssEvmDigestSigningResponseV1 {
        scope: request.scope.clone(),
        request_id: request.request_id.clone(),
        request_digest: request.request_digest()?,
        signing_digest: request.signing_digest()?,
        signature_scheme: RouterAbEcdsaHssSignatureSchemeV1::EcdsaSecp256k1RecoverableV1,
        signature65_b64u: encode_base64url_bytes_v1(&signature65),
    };
    response.validate()?;
    serde_json::to_string(&response).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "local SigningWorker ECDSA-HSS finalize response JSON serialization failed: {error}"
            ),
        )
    })
}

fn parse_local_json_body_v1<T>(label: &str, body: &[u8]) -> RouterAbProtocolResult<T>
where
    T: DeserializeOwned,
{
    serde_json::from_slice::<T>(body).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{label} JSON parse failed: {error}"),
        )
    })
}

fn local_active_ecdsa_hss_signing_worker_state_v1(
    config: &LocalSigningWorkerConfigV1,
    scope: &RouterAbEcdsaHssNormalSigningScopeV1,
) -> RouterAbProtocolResult<ActiveSigningWorkerStateV1> {
    scope.validate()?;
    let signing_worker = ServerIdentityV1::new(
        config.signing_worker_id.clone(),
        config.signing_worker_key_epoch.clone(),
        config.server_output_hpke_public_key.clone(),
    )?;
    if scope.signing_worker != signing_worker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local ECDSA-HSS scope SigningWorker does not match local worker config",
        ));
    }
    let session_id = router_ab_ecdsa_hss_active_state_session_id_v1(
        &scope.ecdsa_threshold_key_id,
        &scope.signing_root_id,
        &scope.signing_root_version,
        &scope.activation_epoch,
    )?;
    let state = ActiveSigningWorkerStateV1::new(
        scope.wallet_id.clone(),
        session_id,
        scope.public_identity.threshold_public_key33_b64u.clone(),
        signing_worker,
        local_ecdsa_hss_digest_v1(b"activation-transcript"),
        local_ecdsa_hss_digest_v1(b"activation"),
        format!(
            "local-ecdsa-hss/{}/{}/{}",
            scope.ecdsa_threshold_key_id, scope.signing_root_version, scope.activation_epoch
        ),
        LOCAL_NORMAL_SIGNING_ACTIVATION_MS_V1,
    )?;
    if state.signing_worker != scope.signing_worker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local ECDSA-HSS active state SigningWorker mismatch",
        ));
    }
    Ok(state)
}

fn local_ecdsa_hss_digest_v1(label: &[u8]) -> PublicDigest32 {
    let mut hasher = Sha256::new();
    push_hash_field_v1(&mut hasher, b"router-ab-dev/ecdsa-hss/v1");
    push_hash_field_v1(&mut hasher, label);
    PublicDigest32::new(hasher.finalize().into())
}

fn local_now_unix_ms_v1() -> RouterAbProtocolResult<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("local system clock is before Unix epoch: {error}"),
            )
        })?;
    u64::try_from(elapsed.as_millis()).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local Unix timestamp exceeds u64 milliseconds",
        )
    })
}

fn local_signing_worker_ecdsa_hss_presignature_store_v1(
) -> &'static Mutex<BTreeMap<String, LocalSigningWorkerEcdsaHssPresignatureRecordV1>> {
    static STORE: OnceLock<
        Mutex<BTreeMap<String, LocalSigningWorkerEcdsaHssPresignatureRecordV1>>,
    > = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn local_signing_worker_ecdsa_hss_presignature_store_key_v1(
    server_presignature_id: &str,
    request_digest: PublicDigest32,
) -> RouterAbProtocolResult<String> {
    require_non_empty(
        "ECDSA-HSS prepared lookup server_presignature_id",
        server_presignature_id,
    )?;
    Ok(format!(
        "{}:{}",
        server_presignature_id,
        encode_base64url_bytes_v1(request_digest.as_bytes())
    ))
}

fn local_signing_worker_ecdsa_hss_presignature_store_put_v1(
    record: LocalSigningWorkerEcdsaHssPresignatureRecordV1,
) -> RouterAbProtocolResult<()> {
    record.validate()?;
    let key = local_signing_worker_ecdsa_hss_presignature_store_key_v1(
        &record.server_presignature_id,
        record.request_digest,
    )?;
    let mut store = local_signing_worker_ecdsa_hss_presignature_store_v1()
        .lock()
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local ECDSA-HSS prepared presignature store lock poisoned",
            )
        })?;
    if store.insert(key, record).is_some() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local ECDSA-HSS prepared presignature collision",
        ));
    }
    Ok(())
}

fn local_signing_worker_ecdsa_hss_presignature_store_take_v1(
    server_presignature_id: &str,
    request_digest: PublicDigest32,
) -> RouterAbProtocolResult<LocalSigningWorkerEcdsaHssPresignatureRecordV1> {
    let key = local_signing_worker_ecdsa_hss_presignature_store_key_v1(
        server_presignature_id,
        request_digest,
    )?;
    let mut store = local_signing_worker_ecdsa_hss_presignature_store_v1()
        .lock()
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local ECDSA-HSS prepared presignature store lock poisoned",
            )
        })?;
    store.remove(&key).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local ECDSA-HSS prepared presignature is not available",
        )
    })
}

fn encode_base64url_bytes_v1(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_base64url_fixed_32_v1(field: &str, encoded: &str) -> RouterAbProtocolResult<[u8; 32]> {
    let bytes = decode_base64url_bytes_v1(field, encoded)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must decode to 32 bytes, received {}", bytes.len()),
        )
    })
}

fn decode_base64url_fixed_33_v1(field: &str, encoded: &str) -> RouterAbProtocolResult<[u8; 33]> {
    let bytes = decode_base64url_bytes_v1(field, encoded)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must decode to 33 bytes, received {}", bytes.len()),
        )
    })
}

fn decode_base64url_bytes_v1(field: &str, encoded: &str) -> RouterAbProtocolResult<Vec<u8>> {
    require_non_empty(field, encoded)?;
    require_no_ascii_whitespace_v1(field, encoded)?;
    if encoded.contains('=') {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must be unpadded base64url"),
        ));
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} base64url decode failed: {error}"),
            )
        })
}

fn require_no_ascii_whitespace_v1(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must not contain ASCII whitespace"),
        ));
    }
    Ok(())
}

fn require_positive_unix_ms_v1(field: &str, value: u64) -> RouterAbProtocolResult<()> {
    if value == 0 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            format!("{field} must be positive"),
        ));
    }
    Ok(())
}

/// SQLite executor for protocol-generated local seed statements.
pub struct LocalSqliteSeedExecutorV1<'conn> {
    connection: &'conn Connection,
}

impl<'conn> LocalSqliteSeedExecutorV1<'conn> {
    /// Creates a SQLite seed executor for an existing connection.
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }
}

impl LocalPersistenceSqlSeedExecutorV1 for LocalSqliteSeedExecutorV1<'_> {
    fn execute_local_persistence_sql_statement_v1(
        &mut self,
        _statement_index: u32,
        statement: &LocalPersistenceSqlStatementV1,
    ) -> RouterAbProtocolResult<()> {
        statement.validate()?;
        let values = statement
            .values
            .iter()
            .map(sqlite_value)
            .collect::<Vec<_>>();
        self.connection
            .execute(&statement.sql, params_from_iter(values.iter()))
            .map_err(map_sqlite_error)?;
        Ok(())
    }
}

/// SQLite-backed local signing-root share store.
pub struct LocalSqliteSigningRootShareStoreV1<'conn> {
    connection: &'conn Connection,
    signer_set_id: String,
}

impl<'conn> LocalSqliteSigningRootShareStoreV1<'conn> {
    /// Creates a local SQLite root-share store for one signer set.
    pub fn new(
        connection: &'conn Connection,
        signer_set_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let store = Self {
            connection,
            signer_set_id: signer_set_id.into(),
        };
        require_non_empty("signer_set_id", &store.signer_set_id)?;
        Ok(store)
    }

    /// Reads the startup metadata required for a role-specific local signer.
    pub fn require_startup_share(
        &self,
        role: Role,
        root_share_epoch: &RootShareEpoch,
    ) -> RouterAbProtocolResult<LocalSqliteSignerStartupCheckV1> {
        require_sqlite_signer_role(role)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT signer_id, signer_key_epoch, sealed_share_storage_key \
                 FROM local_sealed_root_shares \
                 WHERE signer_set_id = ?1 AND signer_role = ?2 AND root_share_epoch = ?3",
            )
            .map_err(map_sqlite_error)?;
        let row = statement
            .query_row(
                params![
                    self.signer_set_id.as_str(),
                    role.as_str(),
                    root_share_epoch.as_str()
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .map_err(|error| map_sqlite_missing_share(error, role, root_share_epoch))?;
        Ok(LocalSqliteSignerStartupCheckV1 {
            signer_set_id: self.signer_set_id.clone(),
            role,
            root_share_epoch: root_share_epoch.clone(),
            signer_id: row.0,
            signer_key_epoch: row.1,
            sealed_share_storage_key: row.2,
        })
    }
}

impl SigningRootShareStore for LocalSqliteSigningRootShareStoreV1<'_> {
    fn has_root_share(&self, role: Role, epoch: &RootShareEpoch) -> RouterAbProtocolResult<bool> {
        require_sqlite_signer_role(role)?;
        let count = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM local_sealed_root_shares \
                 WHERE signer_set_id = ?1 AND signer_role = ?2 AND root_share_epoch = ?3",
                params![self.signer_set_id.as_str(), role.as_str(), epoch.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(map_sqlite_error)?;
        Ok(count > 0)
    }
}

/// Runs the local Router/Deriver/SigningWorker ceremony through checked local HTTP requests.
pub fn run_example_local_router_ab_dev_http_ceremony_v1(
) -> RouterAbProtocolResult<LocalRouterAbDevHttpCeremonyResultV1> {
    let router_request = local_ecdsa_threshold_prf_request_v1()?;
    let (signer_a_request, signer_b_request) = router_request.to_signer_wire_messages()?;
    let deriver_a_request = LocalHttpRequestV1::new(
        LocalHttpMethodV1::Post,
        LocalHttpPathV1::RouterToSignerA,
        LocalTransportEnvelopeV1::new(LocalTransportRouteV1::RouterToSignerA, signer_a_request)?,
    )?;
    let deriver_b_request = LocalHttpRequestV1::new(
        LocalHttpMethodV1::Post,
        LocalHttpPathV1::RouterToSignerB,
        LocalTransportEnvelopeV1::new(LocalTransportRouteV1::RouterToSignerB, signer_b_request)?,
    )?;
    let core_http_ceremony = local_service_stack_v1()?.run_deterministic_http_ceremony(
        router_request.lifecycle.lifecycle_id.clone(),
        deriver_a_request.clone(),
        deriver_b_request.clone(),
    )?;
    Ok(LocalRouterAbDevHttpCeremonyResultV1 {
        router_request,
        deriver_a_request,
        deriver_b_request,
        core_http_ceremony,
    })
}

/// Ensures local SQLite tables used by file-backed Durable Object storage exist.
pub fn ensure_local_durable_object_sqlite_schema_v1(
    connection: &Connection,
) -> RouterAbProtocolResult<()> {
    connection
        .execute_batch(
            "
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS local_durable_object_kv (
                scope TEXT NOT NULL,
                key TEXT NOT NULL,
                value BLOB NOT NULL CHECK (length(value) > 0),
                PRIMARY KEY (scope, key)
            );
            ",
        )
        .map_err(map_sqlite_error)
}

/// Ensures local SQLite tables used by Router/A/B seed tests exist.
pub fn ensure_local_sqlite_schema_v1(connection: &Connection) -> RouterAbProtocolResult<()> {
    connection
        .execute_batch(
            "
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS local_signing_roots (
                signer_set_id TEXT NOT NULL,
                signing_root_version TEXT NOT NULL,
                root_share_epoch TEXT NOT NULL,
                account_id TEXT NOT NULL,
                PRIMARY KEY (signer_set_id, root_share_epoch)
            );

            CREATE TABLE IF NOT EXISTS local_sealed_root_shares (
                signer_set_id TEXT NOT NULL,
                signer_role TEXT NOT NULL CHECK (signer_role IN ('signer_a', 'signer_b')),
                signer_id TEXT NOT NULL,
                signer_key_epoch TEXT NOT NULL,
                root_share_epoch TEXT NOT NULL,
                sealed_share_storage_key TEXT NOT NULL,
                sealed_share_commitment_hex TEXT NOT NULL CHECK (length(sealed_share_commitment_hex) = 64),
                sealed_share_len INTEGER NOT NULL CHECK (sealed_share_len > 0),
                PRIMARY KEY (signer_set_id, signer_role, root_share_epoch),
                FOREIGN KEY (signer_set_id, root_share_epoch)
                    REFERENCES local_signing_roots (signer_set_id, root_share_epoch)
            );
            ",
        )
        .map_err(map_sqlite_error)
}

/// Seeds local SQLite with a validated Router/A/B persistence seed.
pub fn seed_local_sqlite_v1(
    connection: &Connection,
    seed: &LocalPersistenceSeedV1,
) -> RouterAbProtocolResult<LocalPersistenceSqlExecutionReceiptV1> {
    ensure_local_sqlite_schema_v1(connection)?;
    let plan = local_persistence_seed_sql_plan_v1(seed)?;
    let mut executor = LocalSqliteSeedExecutorV1::new(connection);
    execute_local_persistence_sql_seed_plan_v1(&plan, &mut executor)
}

/// Reads a small verification summary from local SQLite.
pub fn read_local_sqlite_seed_summary_v1(
    connection: &Connection,
) -> RouterAbProtocolResult<LocalSqliteSeedSummaryV1> {
    let signing_root_count =
        query_u32_count(connection, "SELECT COUNT(*) FROM local_signing_roots")?;
    let sealed_share_count =
        query_u32_count(connection, "SELECT COUNT(*) FROM local_sealed_root_shares")?;
    let signer_roles = query_signer_roles(connection)?;
    Ok(LocalSqliteSeedSummaryV1 {
        signing_root_count,
        sealed_share_count,
        signer_roles,
    })
}

/// Creates the deterministic local dev persistence seed used by smoke tests.
pub fn example_local_persistence_seed_v1() -> RouterAbProtocolResult<LocalPersistenceSeedV1> {
    LocalPersistenceSeedV1::new(
        LocalSigningRootMetadataV1::new(
            "signer-set-v1",
            "signing-root-v1",
            root_epoch()?,
            LOCAL_DEV_ACCOUNT_ID_V1,
        )?,
        sealed_share_record(Role::SignerA)?,
        sealed_share_record(Role::SignerB)?,
    )
}

/// Seeds local SQLite with the deterministic dev seed.
pub fn seed_example_local_sqlite_v1(
    connection: &Connection,
) -> RouterAbProtocolResult<LocalPersistenceSqlExecutionReceiptV1> {
    seed_local_sqlite_v1(connection, &example_local_persistence_seed_v1()?)
}

/// Checks that a local signer can see its role-specific sealed root share.
pub fn require_example_local_sqlite_signer_startup_v1(
    connection: &Connection,
    role: Role,
) -> RouterAbProtocolResult<LocalSqliteSignerStartupCheckV1> {
    let seed = example_local_persistence_seed_v1()?;
    let store = LocalSqliteSigningRootShareStoreV1::new(
        connection,
        seed.root_metadata.signer_set_id.clone(),
    )?;
    store.require_startup_share(role, &seed.root_metadata.root_share_epoch)
}

fn query_u32_count(connection: &Connection, sql: &str) -> RouterAbProtocolResult<u32> {
    let count = connection
        .query_row(sql, [], |row| row.get::<_, i64>(0))
        .map_err(map_sqlite_error)?;
    u32::try_from(count).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local SQLite count did not fit u32",
        )
    })
}

fn query_signer_roles(connection: &Connection) -> RouterAbProtocolResult<Vec<String>> {
    let mut statement = connection
        .prepare("SELECT signer_role FROM local_sealed_root_shares ORDER BY signer_role")
        .map_err(map_sqlite_error)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(map_sqlite_error)?;
    let mut roles = Vec::new();
    for row in rows {
        roles.push(row.map_err(map_sqlite_error)?);
    }
    Ok(roles)
}

fn sealed_share_record(role: Role) -> RouterAbProtocolResult<LocalSealedRootShareRecordV1> {
    let (signer, storage_key, commitment_seed) = match role {
        Role::SignerA => (signer_identity(Role::SignerA)?, "sealed/share/a", 0xa1),
        Role::SignerB => (signer_identity(Role::SignerB)?, "sealed/share/b", 0xb1),
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "local dev seed requires signer role",
            ));
        }
    };
    LocalSealedRootShareRecordV1::new(
        "signer-set-v1",
        signer,
        root_epoch()?,
        storage_key,
        digest(commitment_seed),
        33,
    )
}

fn local_ecdsa_threshold_prf_request_v1() -> RouterAbProtocolResult<EcdsaThresholdPrfRequestV1> {
    let account_public_key = LOCAL_DEV_ACCOUNT_PUBLIC_KEY_V1.to_owned();
    let lifecycle = local_lifecycle_scope_v1(LOCAL_DEV_ACCOUNT_ID_V1)?;
    let signer_set = signer_set_v1()?;
    let metadata = RouterTranscriptMetadataV1::new(
        "near-testnet",
        account_public_key.clone(),
        "local-router",
        "client",
        "x25519:local-dev-client-ephemeral-public-key",
    )?;
    let transcript_digest = router_transcript_digest_v1(
        &lifecycle,
        &signer_set,
        &metadata,
        root_epoch()?,
    )?;
    EcdsaThresholdPrfRequestV1::new(
        "request-nonce-1",
        2_000,
        lifecycle,
        signer_set,
        metadata.network_id,
        account_public_key,
        metadata.router_id,
        metadata.client_id,
        metadata.client_ephemeral_public_key,
        transcript_digest,
        role_envelope_v1(Role::SignerA, 0xa0)?,
        role_envelope_v1(Role::SignerB, 0xb0)?,
    )
}

fn local_lifecycle_scope_v1(account_id: &str) -> RouterAbProtocolResult<LifecycleScopeV1> {
    LifecycleScopeV1::new(
        "lifecycle-1",
        ExpensiveWorkKindV1::RegistrationPrepare,
        root_epoch()?,
        account_id,
        "session-1",
        "signer-set-v1",
        "server-a",
    )
}

fn signer_set_v1() -> RouterAbProtocolResult<SignerSetV1> {
    SignerSetV1::v1_all2(
        "signer-set-v1",
        signer_identity(Role::SignerA)?,
        signer_identity(Role::SignerB)?,
        server_identity_v1()?,
    )
}

fn server_identity_v1() -> RouterAbProtocolResult<ServerIdentityV1> {
    ServerIdentityV1::new(
        "server-a",
        "server-epoch",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
    )
}

fn role_envelope_v1(role: Role, seed: u8) -> RouterAbProtocolResult<RoleEncryptedEnvelopeV1> {
    RoleEncryptedEnvelopeV1::new(
        role,
        digest(seed),
        digest(seed.wrapping_add(1)),
        EncryptedPayloadV1::new(vec![seed, seed.wrapping_add(2)])?,
    )
}

fn local_service_stack_v1() -> RouterAbProtocolResult<LocalServiceStackV1> {
    LocalServiceStackV1::new(
        LocalServiceStartupV1::router(router_endpoint_v1()?, router_env_snapshot_v1()?)?,
        LocalServiceStartupV1::deriver_a(
            deriver_a_endpoint_v1()?,
            signer_identity(Role::SignerA)?,
            deriver_a_env_snapshot_v1()?,
        )?,
        LocalServiceStartupV1::deriver_b(
            deriver_b_endpoint_v1()?,
            signer_identity(Role::SignerB)?,
            deriver_b_env_snapshot_v1()?,
        )?,
        LocalServiceStartupV1::signing_worker(
            signing_worker_endpoint_v1()?,
            server_identity_v1()?,
            signing_worker_env_snapshot_v1()?,
        )?,
    )
}

fn router_endpoint_v1() -> RouterAbProtocolResult<LocalRouterEndpointV1> {
    LocalRouterEndpointV1::new(
        "http://127.0.0.1:9090",
        "http://127.0.0.1:9091",
        "http://127.0.0.1:9092",
        "http://127.0.0.1:9093",
    )
}

fn deriver_a_endpoint_v1() -> RouterAbProtocolResult<LocalDeriverAEndpointV1> {
    LocalDeriverAEndpointV1::new("http://127.0.0.1:9091", "http://127.0.0.1:9092")
}

fn deriver_b_endpoint_v1() -> RouterAbProtocolResult<LocalDeriverBEndpointV1> {
    LocalDeriverBEndpointV1::new("http://127.0.0.1:9092", "http://127.0.0.1:9091")
}

fn signing_worker_endpoint_v1() -> RouterAbProtocolResult<LocalSigningWorkerEndpointV1> {
    LocalSigningWorkerEndpointV1::new("http://127.0.0.1:9093", "local-server-output")
}

fn router_env_snapshot_v1() -> RouterAbProtocolResult<LocalEnvSnapshotV1> {
    LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::Router,
        vec![
            "ROUTER_PUBLIC_URL".to_owned(),
            "DERIVER_A_URL".to_owned(),
            "DERIVER_B_URL".to_owned(),
            "SIGNING_WORKER_URL".to_owned(),
        ],
    )
}

fn deriver_a_env_snapshot_v1() -> RouterAbProtocolResult<LocalEnvSnapshotV1> {
    LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::DeriverA,
        vec![
            "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY".to_owned(),
            "SIGNING_ROOT_SHARE_A_KEK".to_owned(),
            "DERIVER_B_URL".to_owned(),
        ],
    )
}

fn deriver_b_env_snapshot_v1() -> RouterAbProtocolResult<LocalEnvSnapshotV1> {
    LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::DeriverB,
        vec![
            "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY".to_owned(),
            "SIGNING_ROOT_SHARE_B_KEK".to_owned(),
            "DERIVER_A_URL".to_owned(),
        ],
    )
}

fn signing_worker_env_snapshot_v1() -> RouterAbProtocolResult<LocalEnvSnapshotV1> {
    LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::SigningWorker,
        vec!["SERVER_OUTPUT_STORAGE".to_owned()],
    )
}

fn signer_identity(role: Role) -> RouterAbProtocolResult<SignerIdentityV1> {
    match role {
        Role::SignerA => SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a"),
        Role::SignerB => SignerIdentityV1::new(Role::SignerB, "signer-b", "epoch-b"),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local dev seed requires signer identity",
        )),
    }
}

fn root_epoch() -> RouterAbProtocolResult<RootShareEpoch> {
    RootShareEpoch::new("epoch-1").map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            error.to_string(),
        )
    })
}

fn require_non_empty(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("{field} must not be empty"),
        ));
    }
    Ok(())
}

fn local_env_map_v1(
    entries: impl IntoIterator<Item = (String, String)>,
) -> RouterAbProtocolResult<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    for (key, value) in entries {
        require_non_empty("local env key", &key)?;
        if env.insert(key.clone(), value).is_some() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("duplicate local env key {key}"),
            ));
        }
    }
    Ok(env)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalHttpUrlPartsV1 {
    authority: String,
    path: String,
}

fn parse_http_bind_addr_v1(url: &str) -> RouterAbProtocolResult<String> {
    Ok(parse_http_url_parts_v1(url)?.authority)
}

fn parse_http_url_parts_v1(url: &str) -> RouterAbProtocolResult<LocalHttpUrlPartsV1> {
    require_non_empty("local worker bind URL", url)?;
    let Some(rest) = url.strip_prefix("http://") else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local worker bind URL must start with http://",
        ));
    };
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_owned()),
    };
    require_non_empty("local worker bind authority", authority)?;
    let Some((host, port)) = authority.rsplit_once(':') else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local worker bind URL must include host:port",
        ));
    };
    require_non_empty("local worker bind host", host)?;
    require_non_empty("local worker bind port", port)?;
    let parsed_port = port.parse::<u16>().map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("local worker bind port is invalid: {error}"),
        )
    })?;
    Ok(LocalHttpUrlPartsV1 {
        authority: format!("{host}:{parsed_port}"),
        path,
    })
}

fn split_local_http_response_v1(response: &[u8]) -> RouterAbProtocolResult<(u16, Vec<u8>)> {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            "local HTTP service-binding response missing header terminator",
        ));
    };
    let headers = std::str::from_utf8(&response[..header_end]).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!("local HTTP service-binding response headers are not UTF-8: {error}"),
        )
    })?;
    let status_line = headers.lines().next().unwrap_or_default();
    let mut status_parts = status_line.split_whitespace();
    let protocol = status_parts.next().unwrap_or_default();
    if protocol != "HTTP/1.1" && protocol != "HTTP/1.0" {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            "local HTTP service-binding response has invalid HTTP version",
        ));
    }
    let status = status_parts
        .next()
        .unwrap_or_default()
        .parse::<u16>()
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                format!("local HTTP service-binding response status is invalid: {error}"),
            )
        })?;
    Ok((status, response[header_end + 4..].to_vec()))
}

fn map_local_http_io_error_v1(error: std::io::Error) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
        format!("local HTTP service-binding I/O failed: {error}"),
    )
}

fn materialize_template_v1(template: &str, seed: &[u8]) -> RouterAbProtocolResult<String> {
    require_non_empty("local env materialization template", template)?;
    let replacements = [
        (
            "dev-only-deriver-a-root-share-wire-secret",
            "deriver-a-root-share-wire-secret",
        ),
        (
            "dev-only-deriver-b-root-share-wire-secret",
            "deriver-b-root-share-wire-secret",
        ),
        (
            "dev-only-deriver-a-peer-signing-key",
            "deriver-a-peer-signing-key",
        ),
        (
            "dev-only-deriver-b-peer-signing-key",
            "deriver-b-peer-signing-key",
        ),
        (
            "dev-only-deriver-a-peer-verifying-key",
            "deriver-a-peer-verifying-key",
        ),
        (
            "dev-only-deriver-b-peer-verifying-key",
            "deriver-b-peer-verifying-key",
        ),
    ];
    let mut contents = template.to_owned();
    for (placeholder, label) in replacements {
        let material = local_generated_secret_v1(label, seed)?;
        contents = contents.replace(placeholder, &material);
    }
    for (placeholder, label) in [
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "deriver-a-ed25519-yao-derivation-root",
        ),
        (
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "deriver-b-ed25519-yao-derivation-root",
        ),
    ] {
        let material = local_generated_secret_bytes_v1(label, seed)?;
        contents = contents.replace(placeholder, &hex::encode(material));
    }
    for (private_placeholder, public_placeholder, label) in [
        (
            "1111111111111111111111111111111111111111111111111111111111111111",
            "x25519:1111111111111111111111111111111111111111111111111111111111111111",
            "deriver-a-ed25519-yao-input-hpke-key-pair",
        ),
        (
            "2222222222222222222222222222222222222222222222222222222222222222",
            "x25519:2222222222222222222222222222222222222222222222222222222222222222",
            "deriver-b-ed25519-yao-input-hpke-key-pair",
        ),
    ] {
        let ikm = local_generated_secret_bytes_v1(label, seed)?;
        let key_pair = derive_local_ed25519_yao_recipient_key_pair_v1(&ikm)?;
        contents = contents.replace(
            public_placeholder,
            &format!("x25519:{}", hex::encode(key_pair.public_key)),
        );
        contents = contents.replace(
            private_placeholder,
            &hex::encode(key_pair.private_key.as_bytes()),
        );
    }
    let signing_worker_hpke_ikm =
        local_generated_secret_bytes_v1("signing-worker-server-output-hpke-key-pair", seed)?;
    let signing_worker_hpke =
        derive_local_ed25519_yao_recipient_key_pair_v1(&signing_worker_hpke_ikm)?;
    contents = contents.replace(
        "4444444444444444444444444444444444444444444444444444444444444444",
        &hex::encode(signing_worker_hpke.private_key.as_bytes()),
    );
    contents = contents.replace(
        "x25519:3333333333333333333333333333333333333333333333333333333333333333",
        &format!("x25519:{}", hex::encode(signing_worker_hpke.public_key)),
    );
    Ok(contents)
}

fn local_generated_secret_bytes_v1(label: &str, seed: &[u8]) -> RouterAbProtocolResult<[u8; 32]> {
    require_non_empty("local generated secret label", label)?;
    if seed.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            "local env materialization seed must not be empty",
        ));
    }
    let mut hasher = Sha256::new();
    push_hash_field_v1(&mut hasher, b"router-ab-dev/local-env-materialization/v1");
    push_hash_field_v1(&mut hasher, label.as_bytes());
    push_hash_field_v1(&mut hasher, seed);
    Ok(hasher.finalize().into())
}

fn local_generated_secret_v1(label: &str, seed: &[u8]) -> RouterAbProtocolResult<String> {
    require_non_empty("local generated secret label", label)?;
    if seed.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            "local env materialization seed must not be empty",
        ));
    }
    let mut hasher = Sha256::new();
    push_hash_field_v1(&mut hasher, b"router-ab-dev/local-env-materialization/v1");
    push_hash_field_v1(&mut hasher, label.as_bytes());
    push_hash_field_v1(&mut hasher, seed);
    Ok(format!(
        "dev-only-generated-{label}-{}",
        hex::encode(hasher.finalize())
    ))
}

fn entries_from_env_map_v1(env: &BTreeMap<String, String>) -> Vec<(String, String)> {
    env.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn required_env_v1(
    env: &BTreeMap<String, String>,
    key: &'static str,
) -> RouterAbProtocolResult<String> {
    let value = env.get(key).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            format!("missing local worker env key {key}"),
        )
    })?;
    require_non_empty(key, value)?;
    Ok(value.clone())
}

fn required_hex_32_env_v1(
    env: &BTreeMap<String, String>,
    key: &'static str,
) -> RouterAbProtocolResult<String> {
    let value = required_env_v1(env, key)?;
    let bytes = hex::decode(&value).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("local worker env key {key} must be hex: {error}"),
        )
    })?;
    if bytes.len() != 32 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("local worker env key {key} must contain exactly 32 bytes"),
        ));
    }
    Ok(hex::encode(bytes))
}

fn required_x25519_public_key_env_v1(
    env: &BTreeMap<String, String>,
    key: &'static str,
) -> RouterAbProtocolResult<String> {
    let value = required_env_v1(env, key)?;
    let Some(encoded) = value.strip_prefix("x25519:") else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("local worker env key {key} must use x25519:<hex>"),
        ));
    };
    let bytes = hex::decode(encoded).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("local worker env key {key} must be hex: {error}"),
        )
    })?;
    if bytes.len() != 32 || bytes.iter().all(|byte| *byte == 0) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("local worker env key {key} must contain 32 nonzero bytes"),
        ));
    }
    Ok(format!("x25519:{}", hex::encode(bytes)))
}

fn reject_forbidden_env_keys_v1(
    env: &BTreeMap<String, String>,
    forbidden_keys: &[&'static str],
) -> RouterAbProtocolResult<()> {
    for key in forbidden_keys {
        if env.contains_key(*key) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                format!("local worker role cannot receive env key {key}"),
            ));
        }
    }
    Ok(())
}

fn require_exact_len_v1(field: &str, actual: usize, expected: usize) -> RouterAbProtocolResult<()> {
    if actual != expected {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} expected {expected} entries, received {actual}"),
        ));
    }
    Ok(())
}

fn require_sqlite_signer_role(role: Role) -> RouterAbProtocolResult<()> {
    match role {
        Role::SignerA | Role::SignerB => Ok(()),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            format!(
                "local SQLite root-share store requires signer role, received {}",
                role.as_str()
            ),
        )),
    }
}

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

fn push_hash_field_v1(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

fn sqlite_value(value: &LocalPersistenceSqlValueV1) -> Value {
    match value {
        LocalPersistenceSqlValueV1::Text(value) => Value::Text(value.clone()),
        LocalPersistenceSqlValueV1::U32(value) => Value::Integer(i64::from(*value)),
    }
}

fn map_sqlite_error(error: rusqlite::Error) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("local SQLite seed failed: {error}"),
    )
}

fn map_signer_core_ecdsa_error_v1(
    error: signer_core::error::SignerCoreError,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("local ECDSA-HSS signature finalization failed: {error}"),
    )
}

fn map_sqlite_missing_share(
    error: rusqlite::Error,
    role: Role,
    epoch: &RootShareEpoch,
) -> RouterAbProtocolError {
    match error {
        rusqlite::Error::QueryReturnedNoRows => RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!(
                "local SQLite signer startup missing {} root share for epoch {}",
                role.as_str(),
                epoch.as_str()
            ),
        ),
        other => map_sqlite_error(other),
    }
}

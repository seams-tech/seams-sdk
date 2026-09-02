use crate::{CloudflareEnvReaderV1, CloudflareWorkerRoleV1};
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hpke_ng::{DhKemX25519HkdfSha256, Kem};
use router_ab_core::{
    ExecutedTenantRootCommandV1, PendingTenantRootInitialRoleAttemptV1, RouterAbDerivationError,
    RouterAbDerivationErrorCode, RouterAbDerivationResult, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult, TenantRootCanaryCurveFamilyV1,
    TenantRootCeremonyContextV1, TenantRootCommandTerminalReceiptV1,
    TenantRootManagedBackupSealRequestV1, TenantRootManagedRestoreRoleV1,
    TenantRootProviderCanaryReceiptBindingV1, TenantRootSignedManagedBackupV1,
    TenantRootSignedProviderCanaryReceiptV1, TwoPartyDeriverRole,
    VerifiedTenantRootCommandSuccessReceiptV1, VerifiedTenantRootCreationCommitmentPairV1,
    VerifiedTenantRootInitialRoleAttemptV1, VerifiedTenantRootRoleCreationCommandV1,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "workers-rs")]
use crate::tenant_root_operational_provider::CloudflareTenantRootOperationalRotationProviderInputsV1;
#[cfg(feature = "workers-rs")]
use crate::tenant_root_operational_provider::CloudflareTenantRootOperationalRotationProviderV1;

#[cfg(feature = "workers-rs")]
use crate::CloudflareWorkerEnvReaderV1;

/// SigningWorker presign-session Durable Object binding env key.
pub const SIGNING_WORKER_PRESIGN_SESSION_DO_BINDING_ENV: &str =
    "SIGNING_WORKER_PRESIGN_SESSION_DO_BINDING";
/// SigningWorker presign-session Durable Object object-name env key.
pub const SIGNING_WORKER_PRESIGN_SESSION_DO_OBJECT_ENV: &str =
    "SIGNING_WORKER_PRESIGN_SESSION_DO_OBJECT";
/// SigningWorker presign-session Durable Object key-prefix env key.
pub const SIGNING_WORKER_PRESIGN_SESSION_DO_KEY_PREFIX_ENV: &str =
    "SIGNING_WORKER_PRESIGN_SESSION_DO_KEY_PREFIX";
/// SigningWorker server-output HPKE private-key binding-name env key.
pub const SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING_ENV: &str =
    "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING";
/// SigningWorker server-output HPKE key epoch env key.
pub const SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH_ENV: &str =
    "SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH";
/// SigningWorker server-output HPKE public key env key.
pub const SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY_ENV: &str =
    "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY";
/// Deriver A signing-root-share wire Secret binding-name env key.
pub const DERIVER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV: &str =
    "DERIVER_A_ROOT_SHARE_WIRE_SECRET_BINDING";
/// Deriver B signing-root-share wire Secret binding-name env key.
pub const DERIVER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV: &str =
    "DERIVER_B_ROOT_SHARE_WIRE_SECRET_BINDING";
/// Deriver A peer binding env key.
pub const DERIVER_A_PEER_BINDING_ENV: &str = "DERIVER_A_PEER_BINDING";
/// Deriver B peer binding env key.
pub const DERIVER_B_PEER_BINDING_ENV: &str = "DERIVER_B_PEER_BINDING";
/// SigningWorker peer binding env key.
pub const SIGNING_WORKER_PEER_BINDING_ENV: &str = "SIGNING_WORKER_PEER_BINDING";
/// Internal service-auth secret binding-name env key shared by strict private Workers.
pub const ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING_ENV: &str =
    "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING";
/// Internal service-auth header required by strict private Workers.
pub const ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1: &str = "x-router-ab-internal-service-auth";
/// Deriver A signer-envelope HPKE private-key binding-name env key.
pub const DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV: &str =
    "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING";
/// Deriver A signer-envelope HPKE key epoch env key.
pub const DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH_ENV: &str = "DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH";
/// Deriver A signer-envelope HPKE public key env key.
pub const DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY_ENV: &str = "DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY";
/// Previous Deriver A signer-envelope HPKE key epoch env key.
pub const DERIVER_A_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV: &str =
    "DERIVER_A_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH";
/// Previous Deriver A signer-envelope HPKE public key env key.
pub const DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV: &str =
    "DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY";
/// Previous Deriver A signer-envelope HPKE private-key binding-name env key.
pub const DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV: &str =
    "DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING";
/// Deriver B signer-envelope HPKE private-key binding-name env key.
pub const DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV: &str =
    "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING";
/// Deriver B signer-envelope HPKE key epoch env key.
pub const DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH_ENV: &str = "DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH";
/// Deriver B signer-envelope HPKE public key env key.
pub const DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY_ENV: &str = "DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY";
/// Previous Deriver B signer-envelope HPKE key epoch env key.
pub const DERIVER_B_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV: &str =
    "DERIVER_B_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH";
/// Previous Deriver B signer-envelope HPKE public key env key.
pub const DERIVER_B_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV: &str =
    "DERIVER_B_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY";
/// Previous Deriver B signer-envelope HPKE private-key binding-name env key.
pub const DERIVER_B_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV: &str =
    "DERIVER_B_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING";
/// Previous signer-envelope HPKE public-key retirement timestamp.
pub const ROUTER_AB_PREVIOUS_ENVELOPE_HPKE_RETIRE_AT_MS_ENV: &str =
    "ROUTER_AB_PREVIOUS_ENVELOPE_HPKE_RETIRE_AT_MS";
/// Deriver A A/B peer-message Ed25519 signing secret binding-name env key.
pub const DERIVER_A_PEER_SIGNING_KEY_BINDING_ENV: &str = "DERIVER_A_PEER_SIGNING_KEY_BINDING";
/// Deriver A A/B peer-message Ed25519 signing key epoch env key.
pub const DERIVER_A_PEER_SIGNING_KEY_EPOCH_ENV: &str = "DERIVER_A_PEER_SIGNING_KEY_EPOCH";
/// Deriver B A/B peer-message Ed25519 signing secret binding-name env key.
pub const DERIVER_B_PEER_SIGNING_KEY_BINDING_ENV: &str = "DERIVER_B_PEER_SIGNING_KEY_BINDING";
/// Deriver B A/B peer-message Ed25519 signing key epoch env key.
pub const DERIVER_B_PEER_SIGNING_KEY_EPOCH_ENV: &str = "DERIVER_B_PEER_SIGNING_KEY_EPOCH";
/// Deriver A A/B peer-message Ed25519 verifying key env key.
pub const DERIVER_A_PEER_VERIFYING_KEY_HEX_ENV: &str = "DERIVER_A_PEER_VERIFYING_KEY_HEX";
/// Deriver B A/B peer-message Ed25519 verifying key env key.
pub const DERIVER_B_PEER_VERIFYING_KEY_HEX_ENV: &str = "DERIVER_B_PEER_VERIFYING_KEY_HEX";
/// Router JWT issuer env key.
pub const ROUTER_JWT_ISSUER_ENV: &str = "ROUTER_JWT_ISSUER";
/// Router JWT audience env key.
pub const ROUTER_JWT_AUDIENCE_ENV: &str = "ROUTER_JWT_AUDIENCE";
/// Router JWKS JSON env key.
pub const ROUTER_JWT_JWKS_JSON_ENV: &str = "ROUTER_JWT_JWKS_JSON";
/// Router project-policy bootstrap JSON env key.
pub const ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON_ENV: &str = "ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON";
/// Retained Ed25519 issuer-key set trusted for initial tenant-root creation capabilities.
///
/// This is a public trust anchor owned by the tenant-root control plane, not
/// Router configuration. The Router, Deriver A and Deriver B all require it:
/// each verifies a signed creation command at its own boundary, because a
/// `VerifiedTenantRootRoleCreationCommandV1` is a process-local proof token and
/// cannot be serialized by one Worker and trusted by another. It stays
/// forbidden in the Signing Worker, which has no tenant-root lifecycle role.
pub const TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV: &str =
    "TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON";
/// Authorities trusted to sign a tenant-root creation grant.
///
/// Genesis is the one operation with no authoritative state to derive from, so
/// its authorization arrives signed by an external authority. This anchor names
/// which authorities the issuer accepts. It is deliberately a separate binding
/// and a separate type from the issuer keyset: the issuer signs commands, the
/// grant authority authorizes creating a tenant at all, and confusing the two
/// would let the issuer authorize its own work.
pub const TENANT_ROOT_CONTROL_PLANE_GRANT_AUTHORITY_VERIFYING_KEYS_JSON_ENV: &str =
    "TENANT_ROOT_CONTROL_PLANE_GRANT_AUTHORITY_VERIFYING_KEYS_JSON";
/// Tenant-root control-plane issuer private signing-key Secret binding name.
///
/// Only the dedicated `tenant-root-control-plane` Worker may hold this. It is
/// a deployment authority, versioned per environment, never a per-tenant
/// custody secret, and is forbidden in every other Worker.
pub const TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING_ENV: &str =
    "TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING";
/// Tenant-root control-plane issuer signing key ID env key.
///
/// Names which entry of the versioned public keyset the issuer currently signs
/// with. Retired key IDs stay in the public set for durable verification while
/// the issuer stops signing with them.
pub const TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_ID_ENV: &str =
    "TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_ID";
/// Retained role signing-key set used to verify tenant-root installation evidence.
pub const ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON_ENV: &str =
    "ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON";
/// Deriver A tenant-root creation role-signing secret binding-name env key.
pub const DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV: &str =
    "DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING";
/// Deriver A tenant-root creation role-signing key ID env key.
pub const DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV: &str =
    "DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID";
/// Deriver B tenant-root creation role-signing secret binding-name env key.
pub const DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV: &str =
    "DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING";
/// Deriver B tenant-root creation role-signing key ID env key.
pub const DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV: &str =
    "DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_ID";
/// Deriver A tenant-root online epoch wrapping-key reference env key.
pub const DERIVER_A_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF_ENV: &str =
    "DERIVER_A_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF";
/// Deriver A tenant-root online HPKE public-key env key.
pub const DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY_ENV: &str =
    "DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY";
/// Deriver A tenant-root online HPKE private-key Secret binding-name env key.
pub const DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING_ENV: &str =
    "DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING";
/// Deriver A tenant-root managed-backup provider identifier env key.
pub const DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID_ENV: &str =
    "DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID";
/// Deriver A tenant-root managed-backup key-version env key.
pub const DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION_ENV: &str =
    "DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION";
/// Deriver A tenant-root managed-backup HPKE public-key env key.
pub const DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY_ENV: &str =
    "DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY";
/// Deriver A tenant-root managed-backup HPKE private-key Secret binding-name env key.
pub const DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING_ENV: &str =
    "DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING";
/// Deriver B tenant-root online epoch wrapping-key reference env key.
pub const DERIVER_B_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF_ENV: &str =
    "DERIVER_B_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF";
/// Deriver B tenant-root online HPKE public-key env key.
pub const DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY_ENV: &str =
    "DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY";
/// Deriver B tenant-root online HPKE private-key Secret binding-name env key.
pub const DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING_ENV: &str =
    "DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING";
/// Deriver B tenant-root managed-backup provider identifier env key.
pub const DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID_ENV: &str =
    "DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID";
/// Deriver B tenant-root managed-backup key-version env key.
pub const DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION_ENV: &str =
    "DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION";
/// Deriver B tenant-root managed-backup HPKE public-key env key.
pub const DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY_ENV: &str =
    "DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY";
/// Deriver B tenant-root managed-backup HPKE private-key Secret binding-name env key.
pub const DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING_ENV: &str =
    "DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING";
/// Maximum random bytes a single Deriver-host preload may request.
pub const CLOUDFLARE_DERIVER_HOST_RANDOM_PRELOAD_MAX_BYTES_V1: usize = 65_536;
/// Versioned text prefix for a role-local MPC PRF signing-root-share wire secret.
pub const CLOUDFLARE_ROOT_SHARE_WIRE_SECRET_PREFIX_V1: &str = "mpc-prf-root-share-wire-v1:";
/// Versioned text prefix for a role-local signer-envelope HPKE private key.
pub const CLOUDFLARE_SIGNER_ENVELOPE_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1: &str =
    "hpke-x25519-private-v1:";
/// Versioned text prefix for SigningWorker's server-output HPKE private key.
pub const CLOUDFLARE_SERVER_OUTPUT_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1: &str =
    "hpke-x25519-server-output-private-v1:";

/// Everything the tenant-root control-plane Worker must never receive.
///
/// It is the sole holder of the issuer private signing key, so that binding is
/// the one thing absent from this list. It is Router-shaped in every scalar
/// and Secret it cannot see, and additionally cannot see Router authorization
/// configuration: the issuer validates tenant authorization from authenticated
/// capabilities and authoritative Durable Object state, never from raw
/// credentials.
pub(crate) const TENANT_ROOT_CONTROL_PLANE_FORBIDDEN_ENV_KEYS: &[&str] = &[
    ROUTER_JWT_ISSUER_ENV,
    ROUTER_JWT_AUDIENCE_ENV,
    ROUTER_JWT_JWKS_JSON_ENV,
    ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON_ENV,
    SIGNING_WORKER_PRESIGN_SESSION_DO_BINDING_ENV,
    SIGNING_WORKER_PRESIGN_SESSION_DO_OBJECT_ENV,
    SIGNING_WORKER_PRESIGN_SESSION_DO_KEY_PREFIX_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    DERIVER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_B_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_PEER_SIGNING_KEY_BINDING_ENV,
    DERIVER_A_PEER_SIGNING_KEY_EPOCH_ENV,
    DERIVER_B_PEER_SIGNING_KEY_BINDING_ENV,
    DERIVER_B_PEER_SIGNING_KEY_EPOCH_ENV,
    // The role signing key IDs are public ceremony metadata: the issuer names
    // both roles' expected signers in the creation context it constructs, so it
    // requires them. Their Secret bindings stay forbidden.
    DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
    DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
    DERIVER_A_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF_ENV,
    DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY_ENV,
    DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID_ENV,
    DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION_ENV,
    DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY_ENV,
    DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_B_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF_ENV,
    DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY_ENV,
    DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID_ENV,
    DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION_ENV,
    DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY_ENV,
    DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING_ENV,
];
pub(crate) const ROUTER_FORBIDDEN_ENV_KEYS: &[&str] = &[
    TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING_ENV,
    SIGNING_WORKER_PRESIGN_SESSION_DO_BINDING_ENV,
    SIGNING_WORKER_PRESIGN_SESSION_DO_OBJECT_ENV,
    SIGNING_WORKER_PRESIGN_SESSION_DO_KEY_PREFIX_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    DERIVER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_B_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_PEER_SIGNING_KEY_BINDING_ENV,
    DERIVER_A_PEER_SIGNING_KEY_EPOCH_ENV,
    DERIVER_B_PEER_SIGNING_KEY_BINDING_ENV,
    DERIVER_B_PEER_SIGNING_KEY_EPOCH_ENV,
    DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
    DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
    DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
    DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
    DERIVER_A_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF_ENV,
    DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY_ENV,
    DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID_ENV,
    DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION_ENV,
    DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY_ENV,
    DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_B_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF_ENV,
    DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY_ENV,
    DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID_ENV,
    DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION_ENV,
    DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY_ENV,
    DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING_ENV,
];
pub(crate) const DERIVER_A_FORBIDDEN_ENV_KEYS: &[&str] = &[
    ROUTER_JWT_ISSUER_ENV,
    ROUTER_JWT_AUDIENCE_ENV,
    ROUTER_JWT_JWKS_JSON_ENV,
    ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON_ENV,
    TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING_ENV,
    DERIVER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_B_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_B_PEER_SIGNING_KEY_BINDING_ENV,
    DERIVER_B_PEER_SIGNING_KEY_EPOCH_ENV,
    DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
    DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
    DERIVER_B_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF_ENV,
    DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY_ENV,
    DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID_ENV,
    DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION_ENV,
    DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY_ENV,
    DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNING_WORKER_PRESIGN_SESSION_DO_BINDING_ENV,
    SIGNING_WORKER_PRESIGN_SESSION_DO_OBJECT_ENV,
    SIGNING_WORKER_PRESIGN_SESSION_DO_KEY_PREFIX_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNING_WORKER_PEER_BINDING_ENV,
];
pub(crate) const DERIVER_B_FORBIDDEN_ENV_KEYS: &[&str] = &[
    ROUTER_JWT_ISSUER_ENV,
    ROUTER_JWT_AUDIENCE_ENV,
    ROUTER_JWT_JWKS_JSON_ENV,
    ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON_ENV,
    TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING_ENV,
    DERIVER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    SIGNING_WORKER_PRESIGN_SESSION_DO_BINDING_ENV,
    SIGNING_WORKER_PRESIGN_SESSION_DO_OBJECT_ENV,
    SIGNING_WORKER_PRESIGN_SESSION_DO_KEY_PREFIX_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_PEER_SIGNING_KEY_BINDING_ENV,
    DERIVER_A_PEER_SIGNING_KEY_EPOCH_ENV,
    DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
    DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
    DERIVER_A_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF_ENV,
    DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY_ENV,
    DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID_ENV,
    DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION_ENV,
    DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY_ENV,
    DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING_ENV,
];
pub(crate) const SIGNING_WORKER_FORBIDDEN_ENV_KEYS: &[&str] = &[
    ROUTER_JWT_ISSUER_ENV,
    ROUTER_JWT_AUDIENCE_ENV,
    ROUTER_JWT_JWKS_JSON_ENV,
    ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON_ENV,
    TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
    TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING_ENV,
    DERIVER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_PEER_SIGNING_KEY_BINDING_ENV,
    DERIVER_A_PEER_SIGNING_KEY_EPOCH_ENV,
    DERIVER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_B_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_B_PEER_SIGNING_KEY_BINDING_ENV,
    DERIVER_B_PEER_SIGNING_KEY_EPOCH_ENV,
    DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
    DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
    DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
    DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
    DERIVER_A_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF_ENV,
    DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY_ENV,
    DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID_ENV,
    DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION_ENV,
    DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY_ENV,
    DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_B_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF_ENV,
    DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY_ENV,
    DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID_ENV,
    DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION_ENV,
    DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY_ENV,
    DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING_ENV,
];

const CLOUDFLARE_X25519_PUBLIC_KEY_PREFIX_V1: &str = "x25519:";

/// Non-secret role-local operational provider configuration read from Cloudflare Env.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CloudflareTenantRootOperationalRotationProviderConfigV1 {
    role: TwoPartyDeriverRole,
    online_epoch_wrapping_key_ref: String,
    online_public_key: String,
    online_public_key_bytes: [u8; 32],
    online_secret_binding_name: String,
    backup_provider_id: String,
    backup_key_version: String,
    backup_public_key: String,
    backup_public_key_bytes: [u8; 32],
    backup_secret_binding_name: String,
}

impl CloudflareTenantRootOperationalRotationProviderConfigV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        role: TwoPartyDeriverRole,
        online_epoch_wrapping_key_ref: String,
        online_public_key: String,
        online_secret_binding_name: String,
        backup_provider_id: String,
        backup_key_version: String,
        backup_public_key: String,
        backup_secret_binding_name: String,
    ) -> RouterAbProtocolResult<Self> {
        let online_public_key_bytes =
            decode_cloudflare_tenant_root_operational_hpke_public_key_v1(&online_public_key)?;
        let backup_public_key_bytes =
            decode_cloudflare_tenant_root_operational_hpke_public_key_v1(&backup_public_key)?;
        let config = Self {
            role,
            online_epoch_wrapping_key_ref,
            online_public_key,
            online_public_key_bytes,
            online_secret_binding_name,
            backup_provider_id,
            backup_key_version,
            backup_public_key,
            backup_public_key_bytes,
            backup_secret_binding_name,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        for (field, value) in [
            (
                "tenant-root online epoch wrapping-key reference",
                self.online_epoch_wrapping_key_ref(),
            ),
            (
                "tenant-root managed-backup provider id",
                self.backup_provider_id(),
            ),
            (
                "tenant-root managed-backup key version",
                self.backup_key_version(),
            ),
        ] {
            validate_operational_descriptor(field, value)?;
        }
        validate_operational_secret_binding_name(self.role(), self.online_secret_binding_name())?;
        validate_operational_secret_binding_name(self.role(), self.backup_secret_binding_name())?;
        if self.online_secret_binding_name == self.backup_secret_binding_name {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root online and managed-backup Secret bindings must be distinct",
            ));
        }
        if self.online_epoch_wrapping_key_ref() == self.backup_provider_id()
            || self.online_epoch_wrapping_key_ref() == self.backup_key_version()
            || self.backup_provider_id() == self.backup_key_version()
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root operational provider descriptors must be distinct",
            ));
        }
        if self.online_public_key_bytes == self.backup_public_key_bytes {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root online and managed-backup public keys must be distinct",
            ));
        }
        if decode_cloudflare_tenant_root_operational_hpke_public_key_v1(self.online_public_key())?
            != self.online_public_key_bytes
            || decode_cloudflare_tenant_root_operational_hpke_public_key_v1(
                self.backup_public_key(),
            )? != self.backup_public_key_bytes
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root operational public-key descriptor is inconsistent",
            ));
        }
        Ok(())
    }

    /// Returns the role this operational provider configuration is local to.
    pub(crate) fn role(&self) -> TwoPartyDeriverRole {
        self.role
    }

    /// Returns the online epoch wrapping-key reference descriptor.
    pub(crate) fn online_epoch_wrapping_key_ref(&self) -> &str {
        &self.online_epoch_wrapping_key_ref
    }

    /// Returns the online HPKE public-key descriptor.
    pub(crate) fn online_public_key(&self) -> &str {
        &self.online_public_key
    }

    /// Returns the managed-backup provider id descriptor.
    pub(crate) fn backup_provider_id(&self) -> &str {
        &self.backup_provider_id
    }

    /// Returns the managed-backup key version descriptor.
    pub(crate) fn backup_key_version(&self) -> &str {
        &self.backup_key_version
    }

    /// Returns the managed-backup HPKE public-key descriptor.
    pub(crate) fn backup_public_key(&self) -> &str {
        &self.backup_public_key
    }

    /// Returns the online Secret binding name.
    pub(crate) fn online_secret_binding_name(&self) -> &str {
        &self.online_secret_binding_name
    }

    /// Returns the managed-backup Secret binding name.
    pub(crate) fn backup_secret_binding_name(&self) -> &str {
        &self.backup_secret_binding_name
    }

    #[cfg(feature = "workers-rs")]
    fn into_provider_inputs(
        self,
        online_secret_bytes: Zeroizing<Vec<u8>>,
        backup_secret_bytes: Zeroizing<Vec<u8>>,
    ) -> CloudflareTenantRootOperationalRotationProviderInputsV1 {
        CloudflareTenantRootOperationalRotationProviderInputsV1::new(
            self.role,
            self.online_epoch_wrapping_key_ref,
            self.online_public_key_bytes,
            online_secret_bytes,
            self.backup_provider_id,
            self.backup_key_version,
            self.backup_public_key_bytes,
            backup_secret_bytes,
        )
    }
}

/// Parses the role-local operational provider's non-secret Cloudflare Env.
pub(crate) fn parse_cloudflare_tenant_root_operational_rotation_provider_config_v1(
    worker_role: CloudflareWorkerRoleV1,
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareTenantRootOperationalRotationProviderConfigV1> {
    let (
        role,
        online_ref_key,
        online_public_key_key,
        online_secret_binding_key,
        backup_provider_key,
        backup_version_key,
        backup_public_key_key,
        backup_secret_binding_key,
        forbidden_keys,
    ) = match worker_role {
        CloudflareWorkerRoleV1::DeriverA => (
            TwoPartyDeriverRole::DeriverA,
            DERIVER_A_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF_ENV,
            DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY_ENV,
            DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING_ENV,
            DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID_ENV,
            DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION_ENV,
            DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY_ENV,
            DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING_ENV,
            DERIVER_A_FORBIDDEN_ENV_KEYS,
        ),
        CloudflareWorkerRoleV1::DeriverB => (
            TwoPartyDeriverRole::DeriverB,
            DERIVER_B_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF_ENV,
            DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY_ENV,
            DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING_ENV,
            DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID_ENV,
            DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION_ENV,
            DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY_ENV,
            DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING_ENV,
            DERIVER_B_FORBIDDEN_ENV_KEYS,
        ),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SigningWorker
        | CloudflareWorkerRoleV1::TenantRootControlPlane => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "this Worker cannot access tenant-root operational provider Secrets",
            ));
        }
    };
    crate::reject_forbidden_env_keys(worker_role, env, forbidden_keys)?;
    let config = CloudflareTenantRootOperationalRotationProviderConfigV1::new(
        role,
        read_required_raw_env_text(env, online_ref_key)?,
        read_required_raw_env_text(env, online_public_key_key)?,
        read_required_tenant_root_identifier(env, online_secret_binding_key)?,
        read_required_raw_env_text(env, backup_provider_key)?,
        read_required_raw_env_text(env, backup_version_key)?,
        read_required_raw_env_text(env, backup_public_key_key)?,
        read_required_tenant_root_identifier(env, backup_secret_binding_key)?,
    )?;
    reject_reused_operational_secret_bindings(env, &config)?;
    Ok(config)
}

fn reject_reused_operational_secret_bindings(
    env: &impl CloudflareEnvReaderV1,
    config: &CloudflareTenantRootOperationalRotationProviderConfigV1,
) -> RouterAbProtocolResult<()> {
    let configured_bindings = [
        config.online_secret_binding_name(),
        config.backup_secret_binding_name(),
    ];
    let reserved_binding_keys = [
        DERIVER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
        DERIVER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
        DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
        DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
        DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
        DERIVER_B_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
        DERIVER_A_PEER_SIGNING_KEY_BINDING_ENV,
        DERIVER_B_PEER_SIGNING_KEY_BINDING_ENV,
        DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
        DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
    ];
    for key in reserved_binding_keys {
        let Some(binding_name) = env.get_text(key)? else {
            continue;
        };
        if configured_bindings
            .iter()
            .any(|configured| *configured == binding_name)
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root operational provider Secret cannot reuse another role-local Secret",
            ));
        }
    }
    Ok(())
}

fn validate_operational_secret_binding_name(
    role: TwoPartyDeriverRole,
    binding_name: &str,
) -> RouterAbProtocolResult<()> {
    validate_role_specific_binding_name(role, binding_name)?;
    if binding_name.chars().any(char::is_whitespace) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root operational provider Secret binding contains whitespace",
        ));
    }
    let tenant_root_prefix = match role {
        TwoPartyDeriverRole::DeriverA => "DERIVER_A_TENANT_ROOT_",
        TwoPartyDeriverRole::DeriverB => "DERIVER_B_TENANT_ROOT_",
    };
    if !binding_name.starts_with(tenant_root_prefix)
        || binding_name.contains("ROOT_SHARE")
        || binding_name.contains("ENVELOPE_HPKE")
        || binding_name.contains("PEER_SIGNING_KEY")
        || binding_name.contains("CREATION_SIGNING")
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root operational provider Secret binding is not dedicated to its key slot",
        ));
    }
    Ok(())
}

fn validate_operational_descriptor(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    validate_tenant_root_identifier(field, value)?;
    if value.chars().any(char::is_whitespace) {
        return Err(invalid_operational_config(format!(
            "{field} must not contain whitespace"
        )));
    }
    Ok(())
}

/// Decodes one strict Cloudflare X25519 public-key descriptor.
pub(crate) fn decode_cloudflare_tenant_root_operational_hpke_public_key_v1(
    value: &str,
) -> RouterAbProtocolResult<[u8; 32]> {
    if value.trim() != value {
        return Err(invalid_operational_config(
            "tenant-root operational public key must not contain whitespace",
        ));
    }
    let hex_value = value
        .strip_prefix(CLOUDFLARE_X25519_PUBLIC_KEY_PREFIX_V1)
        .ok_or_else(|| {
            invalid_operational_config(
                "tenant-root operational public key must use x25519:<64 lowercase hex chars>",
            )
        })?;
    let bytes = decode_operational_lower_hex_32(hex_value, "tenant-root operational public key")?;
    let public_key = DhKemX25519HkdfSha256::pk_from_bytes(&bytes)
        .map_err(|_| invalid_operational_config("tenant-root operational public key is invalid"))?;
    if DhKemX25519HkdfSha256::pk_to_bytes(&public_key) != bytes {
        return Err(invalid_operational_config(
            "tenant-root operational public key is not canonical",
        ));
    }
    Ok(bytes)
}

/// Decodes one strict Cloudflare X25519 private-key Secret into owned bytes.
fn decode_cloudflare_tenant_root_operational_hpke_private_key_secret_v1(
    value: &str,
) -> RouterAbProtocolResult<Zeroizing<Vec<u8>>> {
    if value.trim() != value {
        return Err(invalid_operational_config(
            "tenant-root operational private-key Secret must not contain whitespace",
        ));
    }
    let hex_value = value
        .strip_prefix(CLOUDFLARE_SIGNER_ENVELOPE_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1)
        .ok_or_else(|| {
            invalid_operational_config(
                "tenant-root operational private-key Secret has an unsupported prefix",
            )
        })?;
    let mut bytes =
        decode_operational_lower_hex_32(hex_value, "tenant-root operational private-key Secret")?;
    DhKemX25519HkdfSha256::sk_from_bytes(&bytes).map_err(|_| {
        invalid_operational_config("tenant-root operational private-key Secret is invalid")
    })?;
    let output = Zeroizing::new(bytes.to_vec());
    bytes.zeroize();
    Ok(output)
}

fn decode_operational_lower_hex_32(
    value: &str,
    field: &'static str,
) -> RouterAbProtocolResult<[u8; 32]> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(invalid_operational_config(format!(
            "{field} must be exactly 64 lowercase hexadecimal characters"
        )));
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(chunk[0]) << 4) | hex_nibble(chunk[1]);
    }
    Ok(output)
}

fn invalid_operational_config(message: impl Into<String>) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        message,
    )
}

#[cfg(feature = "workers-rs")]
/// Loads the role-local operational provider from Cloudflare Env and Secret bindings.
pub(crate) fn load_cloudflare_tenant_root_operational_rotation_provider_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<CloudflareTenantRootOperationalRotationProviderV1> {
    let reader = CloudflareWorkerEnvReaderV1::new(env);
    let config =
        parse_cloudflare_tenant_root_operational_rotation_provider_config_v1(worker_role, &reader)?;
    let online_secret = load_cloudflare_tenant_root_operational_private_key_secret_v1(
        env,
        config.online_secret_binding_name(),
    )?;
    let backup_secret = load_cloudflare_tenant_root_operational_private_key_secret_v1(
        env,
        config.backup_secret_binding_name(),
    )?;
    CloudflareTenantRootOperationalRotationProviderV1::from_inputs(
        config.into_provider_inputs(online_secret, backup_secret),
    )
    .map_err(map_operational_provider_error)
}

#[cfg(feature = "workers-rs")]
fn load_cloudflare_tenant_root_operational_private_key_secret_v1(
    env: &worker::Env,
    binding_name: &str,
) -> RouterAbProtocolResult<Zeroizing<Vec<u8>>> {
    let secret = env.secret(binding_name).map_err(|err| {
        crate::worker_binding_error(
            crate::worker_binding_error_code(&err, binding_name),
            binding_name,
            "secret",
            err,
        )
    })?;
    let secret_value = Zeroizing::new(secret.to_string());
    decode_cloudflare_tenant_root_operational_hpke_private_key_secret_v1(&secret_value)
}

#[cfg(feature = "workers-rs")]
fn map_operational_provider_error(error: RouterAbDerivationError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!(
            "tenant-root operational provider construction failed: {}",
            error.message()
        ),
    )
}

/// One Deriver's dormant tenant-root creation role-signing Secret binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CloudflareTenantRootCreationRoleSigningKeyBindingV1 {
    /// Fixed Deriver A or Deriver B role that owns the Secret.
    role: TwoPartyDeriverRole,
    /// Exact retained role-signing key identifier.
    signing_key_id: String,
    /// Cloudflare Secret binding name containing the Ed25519 seed.
    binding_name: String,
}

impl CloudflareTenantRootCreationRoleSigningKeyBindingV1 {
    /// Creates a validated role- and key-ID-bound Secret binding.
    pub(crate) fn new(
        role: TwoPartyDeriverRole,
        signing_key_id: impl Into<String>,
        binding_name: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            role,
            signing_key_id: signing_key_id.into(),
            binding_name: binding_name.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates the fixed role, key ID, and binding name.
    pub(crate) fn validate(&self) -> RouterAbProtocolResult<()> {
        validate_tenant_root_identifier("tenant-root role signing key ID", &self.signing_key_id)?;
        validate_tenant_root_identifier(
            "tenant-root role signing Secret binding name",
            &self.binding_name,
        )?;
        validate_role_specific_binding_name(self.role, &self.binding_name)
    }

    /// Returns the role that owns this Secret.
    pub(crate) const fn role(&self) -> TwoPartyDeriverRole {
        self.role
    }

    /// Returns the retained role-signing key identifier.
    pub(crate) fn signing_key_id(&self) -> &str {
        &self.signing_key_id
    }

    /// Returns the Cloudflare Secret binding name.
    pub(crate) fn binding_name(&self) -> &str {
        &self.binding_name
    }

    /// Validates that only the owning Deriver Worker can see this Secret.
    pub(crate) fn validate_visible_to(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        let visible = matches!(
            (worker_role, self.role),
            (
                CloudflareWorkerRoleV1::DeriverA,
                TwoPartyDeriverRole::DeriverA
            ) | (
                CloudflareWorkerRoleV1::DeriverB,
                TwoPartyDeriverRole::DeriverB
            )
        );
        if visible {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            format!(
                "{} Worker cannot access {:?} tenant-root role-signing Secret",
                worker_role.as_str(),
                self.role
            ),
        ))
    }
}

fn validate_role_specific_binding_name(
    role: TwoPartyDeriverRole,
    binding_name: &str,
) -> RouterAbProtocolResult<()> {
    let (role_prefix, peer_prefix) = match role {
        TwoPartyDeriverRole::DeriverA => ("DERIVER_A_", "DERIVER_B_"),
        TwoPartyDeriverRole::DeriverB => ("DERIVER_B_", "DERIVER_A_"),
    };
    if !binding_name.starts_with(role_prefix)
        || binding_name.starts_with(peer_prefix)
        || binding_name.contains("PEER_SIGNING_KEY")
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root role-signing Secret binding is not role-specific",
        ));
    }
    Ok(())
}

/// Zeroizing 32-byte Ed25519 role-signing Secret material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct CloudflareTenantRootCreationRoleSigningSecretV1 {
    bytes: [u8; 32],
}

impl CloudflareTenantRootCreationRoleSigningSecretV1 {
    fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl core::fmt::Debug for CloudflareTenantRootCreationRoleSigningSecretV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareTenantRootCreationRoleSigningSecretV1")
            .field("bytes", &"[redacted]")
            .finish()
    }
}

/// A trusted role/key selection returned by the authoritative retained key set.
///
/// The private fields make verifier provenance part of the value's construction path: callers
/// can only obtain a selection through `parse_cloudflare_tenant_root_creation_role_signing_key_selection_v1`.
#[derive(Debug)]
pub(crate) struct CloudflareTenantRootCreationRoleSigningKeySelectionV1 {
    binding: CloudflareTenantRootCreationRoleSigningKeyBindingV1,
    verifying_key: [u8; 32],
}

#[allow(dead_code)]
impl CloudflareTenantRootCreationRoleSigningKeySelectionV1 {
    fn new(
        binding: CloudflareTenantRootCreationRoleSigningKeyBindingV1,
        verifying_key: [u8; 32],
    ) -> RouterAbProtocolResult<Self> {
        binding.validate()?;
        VerifyingKey::from_bytes(&verifying_key).map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "configured tenant-root role verifying key is invalid",
            )
        })?;
        Ok(Self {
            binding,
            verifying_key,
        })
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.binding.validate()?;
        VerifyingKey::from_bytes(&self.verifying_key).map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "configured tenant-root role verifying key is invalid",
            )
        })?;
        Ok(())
    }

    /// Returns the selected Deriver role.
    pub(crate) const fn role(&self) -> TwoPartyDeriverRole {
        self.binding.role()
    }

    /// Returns the selected retained role-signing key identifier.
    pub(crate) fn signing_key_id(&self) -> &str {
        self.binding.signing_key_id()
    }

    /// Returns the binding selected with the trusted role key.
    #[allow(dead_code)]
    pub(crate) fn binding(&self) -> &CloudflareTenantRootCreationRoleSigningKeyBindingV1 {
        &self.binding
    }

    /// Returns the selected public verifier bytes.
    pub(crate) fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key
    }

    fn into_parts(
        self,
    ) -> (
        CloudflareTenantRootCreationRoleSigningKeyBindingV1,
        [u8; 32],
    ) {
        (self.binding, self.verifying_key)
    }
}

/// Non-cloneable role-constrained signer produced from a trusted key selection.
/// Builds a role signer directly for the workerd-gated creation probe.
///
/// Debug builds only, and only reachable behind the integration env flag.
#[cfg(all(debug_assertions, feature = "workers-rs"))]
pub(crate) fn cloudflare_tenant_root_creation_role_signer_for_probe_v1(
    role: TwoPartyDeriverRole,
    signing_key_id: &str,
    signing_key: SigningKey,
) -> CloudflareTenantRootCreationRoleSignerV1 {
    CloudflareTenantRootCreationRoleSignerV1 {
        role,
        signing_key_id: signing_key_id.to_owned(),
        signing_key,
    }
}

/// Builds a role signer directly, for tests that exercise the admission
/// boundary without a full Env. Never compiled into a Worker.
#[cfg(test)]
pub(crate) fn test_support_tenant_root_creation_role_signer_v1(
    role: TwoPartyDeriverRole,
    signing_key_id: &str,
    signing_key: SigningKey,
) -> CloudflareTenantRootCreationRoleSignerV1 {
    CloudflareTenantRootCreationRoleSignerV1 {
        role,
        signing_key_id: signing_key_id.to_owned(),
        signing_key,
    }
}

pub(crate) struct CloudflareTenantRootCreationRoleSignerV1 {
    role: TwoPartyDeriverRole,
    signing_key_id: String,
    signing_key: SigningKey,
}

impl core::fmt::Debug for CloudflareTenantRootCreationRoleSignerV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareTenantRootCreationRoleSignerV1")
            .field("role", &self.role)
            .field("signing_key_id", &self.signing_key_id)
            .field("signing_key", &"[redacted]")
            .finish()
    }
}

#[allow(dead_code)]
impl CloudflareTenantRootCreationRoleSignerV1 {
    /// Returns the role bound to this signer.
    pub(crate) const fn role(&self) -> TwoPartyDeriverRole {
        self.role
    }

    /// Returns the retained role-signing key identifier.
    pub(crate) fn signing_key_id(&self) -> &str {
        &self.signing_key_id
    }

    /// Returns this signer's public verifier bytes.
    pub(crate) fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Starts one role-local creation attempt without exposing the signing seed.
    pub(crate) fn begin_initial_role_attempt<R>(
        &self,
        command: VerifiedTenantRootRoleCreationCommandV1,
        context: TenantRootCeremonyContextV1,
        now_ms: u64,
        rng: &mut R,
    ) -> RouterAbDerivationResult<PendingTenantRootInitialRoleAttemptV1>
    where
        R: rand_core_06::RngCore + rand_core_06::CryptoRng,
    {
        let seed = Zeroizing::new(self.signing_key.to_bytes());
        PendingTenantRootInitialRoleAttemptV1::new(
            command,
            context,
            &seed,
            &self.verifying_key_bytes(),
            now_ms,
            rng,
        )
    }

    /// Finalizes one live role-local attempt without exposing the signing seed.
    pub(crate) fn finalize_initial_role_attempt<R>(
        &self,
        pending: PendingTenantRootInitialRoleAttemptV1,
        pair: VerifiedTenantRootCreationCommitmentPairV1,
        rng: &mut R,
    ) -> RouterAbDerivationResult<VerifiedTenantRootInitialRoleAttemptV1>
    where
        R: rand_core_06::RngCore + rand_core_06::CryptoRng,
    {
        let seed = Zeroizing::new(self.signing_key.to_bytes());
        pending.finalize(pair, &seed, rng)
    }

    /// Signs and locally verifies one successful terminal receipt for an
    /// executed command.
    pub(crate) fn sign_verified_success_terminal_receipt(
        &self,
        executed: &ExecutedTenantRootCommandV1,
        payload: &[u8],
        terminal_at_ms: u64,
    ) -> RouterAbDerivationResult<VerifiedTenantRootCommandSuccessReceiptV1> {
        if executed.key().role() != self.role {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::SignerIdentityMismatch,
                "tenant-root terminal receipt signer identity does not match command role",
            ));
        }
        let receipt = TenantRootCommandTerminalReceiptV1::sign_success(
            *executed.key(),
            executed.command_digest(),
            payload.to_vec(),
            terminal_at_ms,
            self.signing_key_id.clone(),
            self.signing_key.as_bytes(),
        )?;
        let receipt_bytes = receipt.canonical_bytes()?;
        let decoded = TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&receipt_bytes)?;
        let verifying_key = self.verifying_key_bytes();
        decoded.verify_success(executed, &self.signing_key_id, &verifying_key)
    }

    /// Signs one validated managed-backup request with this role-constrained key.
    pub(crate) fn sign_managed_backup(
        &self,
        request: TenantRootManagedBackupSealRequestV1,
        ciphertext: Vec<u8>,
    ) -> RouterAbDerivationResult<TenantRootSignedManagedBackupV1> {
        let expected_role = match self.role {
            TwoPartyDeriverRole::DeriverA => TenantRootManagedRestoreRoleV1::DeriverA,
            TwoPartyDeriverRole::DeriverB => TenantRootManagedRestoreRoleV1::DeriverB,
        };
        if request.binding().role() != expected_role
            || request.binding().role_signing_key_id() != self.signing_key_id
        {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::SignerIdentityMismatch,
                "tenant-root managed-backup request signer identity does not match role signer",
            ));
        }
        let role_seed = Zeroizing::new(self.signing_key.to_bytes());
        TenantRootSignedManagedBackupV1::sign(request, ciphertext, &role_seed)
    }

    /// Signs one role-constrained provider canary without exposing the role seed.
    pub(crate) fn sign_provider_canary(
        &self,
        binding: TenantRootProviderCanaryReceiptBindingV1,
    ) -> RouterAbDerivationResult<TenantRootSignedProviderCanaryReceiptV1> {
        let expected_family = match self.role {
            TwoPartyDeriverRole::DeriverA => TenantRootCanaryCurveFamilyV1::Ecdsa,
            TwoPartyDeriverRole::DeriverB => TenantRootCanaryCurveFamilyV1::Ed25519,
        };
        if binding.curve_family() != expected_family
            || binding.signing_key_id() != self.signing_key_id
        {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::SignerIdentityMismatch,
                "tenant-root provider canary binding does not match role signer",
            ));
        }
        let role_seed = Zeroizing::new(self.signing_key.to_bytes());
        TenantRootSignedProviderCanaryReceiptV1::sign(binding, &role_seed)
    }
}

/// Derives role-signing material from a verifier selection parsed from the retained key set.
pub(crate) fn derive_cloudflare_tenant_root_creation_role_signing_key_v1(
    selection: CloudflareTenantRootCreationRoleSigningKeySelectionV1,
    secret: CloudflareTenantRootCreationRoleSigningSecretV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationRoleSignerV1> {
    selection.validate()?;
    let (binding, verifying_key) = selection.into_parts();
    binding.validate()?;
    VerifyingKey::from_bytes(&verifying_key).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "configured tenant-root role verifying key is invalid",
        )
    })?;
    let signing_key = SigningKey::from_bytes(secret.as_bytes());
    if signing_key.verifying_key().to_bytes() != verifying_key {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root role-signing Secret does not match its configured verifying key",
        ));
    }
    Ok(CloudflareTenantRootCreationRoleSignerV1 {
        role: binding.role,
        signing_key_id: binding.signing_key_id,
        signing_key,
    })
}

/// Decodes one unpadded base64url 32-byte role-signing Secret.
pub(crate) fn decode_cloudflare_tenant_root_creation_role_signing_secret_v1(
    secret_value: &str,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationRoleSigningSecretV1> {
    if secret_value.trim() != secret_value {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root role-signing Secret must not contain surrounding whitespace",
        ));
    }
    let mut bytes =
        match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(secret_value.as_bytes()) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "tenant-root role-signing Secret must be unpadded base64url",
                ));
            }
        };
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root role-signing Secret must decode to 32 bytes",
        ));
    }
    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(CloudflareTenantRootCreationRoleSigningSecretV1::new(secret))
}

/// Non-secret descriptor of the control-plane issuer's Ed25519 signing Secret.
///
/// Holds the Secret *binding name* and the retained key ID, never the seed.
/// Only the tenant-root control-plane Worker may construct one from Env.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareTenantRootControlPlaneIssuerSigningKeyBindingV1 {
    signing_key_id: String,
    binding_name: String,
}

impl CloudflareTenantRootControlPlaneIssuerSigningKeyBindingV1 {
    /// Creates a validated issuer key-ID-bound Secret binding descriptor.
    pub fn new(
        signing_key_id: impl Into<String>,
        binding_name: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            signing_key_id: signing_key_id.into(),
            binding_name: binding_name.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates the key ID and binding name.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        validate_tenant_root_identifier(
            "tenant-root control-plane issuer signing key ID",
            &self.signing_key_id,
        )?;
        validate_tenant_root_identifier(
            "tenant-root control-plane issuer signing Secret binding name",
            &self.binding_name,
        )?;
        if !self
            .binding_name
            .starts_with(TENANT_ROOT_CONTROL_PLANE_SECRET_BINDING_PREFIX_V1)
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root control-plane issuer signing Secret binding must be control-plane scoped",
            ));
        }
        Ok(())
    }

    /// Returns the retained issuer signing key identifier.
    pub fn signing_key_id(&self) -> &str {
        &self.signing_key_id
    }

    /// Returns the Cloudflare Secret binding name.
    pub fn binding_name(&self) -> &str {
        &self.binding_name
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRootCreationIssuerKeySetWireV1 {
    keys: Vec<TenantRootCreationIssuerKeyWireV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRootCreationIssuerKeyWireV1 {
    issuer_key_id: String,
    verifying_key_hex: String,
}

/// Decodes the bounded control-plane issuer verifying key set.
///
/// Config parsing, so it lives with the other Env decoders rather than in the
/// Durable Object: the Router, both Derivers, and the control plane all read
/// this same published anchor.
pub(crate) fn decode_issuer_verifying_keys(
    json: &str,
) -> RouterAbProtocolResult<BTreeMap<String, [u8; 32]>> {
    let wire: TenantRootCreationIssuerKeySetWireV1 =
        serde_json::from_str(json).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("tenant-root creation issuer key set JSON is invalid: {error}"),
            )
        })?;
    if wire.keys.is_empty() || wire.keys.len() > 32 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root creation issuer key set must contain between one and 32 keys",
        ));
    }
    let mut keys = BTreeMap::new();
    for entry in wire.keys {
        if !valid_config_key_id(&entry.issuer_key_id) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root creation issuer key id is invalid",
            ));
        }
        let verifying_key = decode_lower_hex_32(&entry.verifying_key_hex)?;
        ed25519_dalek::VerifyingKey::from_bytes(&verifying_key).map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root creation issuer verifying key is not a valid Ed25519 point",
            )
        })?;
        if keys.insert(entry.issuer_key_id, verifying_key).is_some() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root creation issuer key id is duplicated",
            ));
        }
    }
    Ok(keys)
}

fn valid_config_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

const TENANT_ROOT_CONTROL_PLANE_SECRET_BINDING_PREFIX_V1: &str = "TENANT_ROOT_CONTROL_PLANE_";

/// Bounded, validated control-plane issuer verifying key set.
///
/// The published trust anchor, held by the Router, Deriver A, Deriver B, and
/// the control plane. Parsed once at startup so a malformed set fails the
/// Worker at boot rather than at first verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1 {
    keys: BTreeMap<String, [u8; 32]>,
}

impl CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1 {
    /// Decodes and validates the published key set.
    pub fn decode(json: &str) -> RouterAbProtocolResult<Self> {
        Ok(Self {
            keys: decode_issuer_verifying_keys(json)?,
        })
    }

    /// Revalidates the retained key set.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.keys.is_empty() || self.keys.len() > 32 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root creation issuer key set must contain between one and 32 keys",
            ));
        }
        for (issuer_key_id, verifying_key) in &self.keys {
            if !valid_config_key_id(issuer_key_id) {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "tenant-root creation issuer key id is invalid",
                ));
            }
            VerifyingKey::from_bytes(verifying_key).map_err(|_| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "tenant-root creation issuer verifying key is not a valid Ed25519 point",
                )
            })?;
        }
        Ok(())
    }

    /// Returns the verifying key retained for one issuer key id.
    ///
    /// Retired ids stay present so previously issued durable artifacts keep
    /// verifying.
    pub fn for_issuer_key_id(&self, issuer_key_id: &str) -> Option<&[u8; 32]> {
        self.keys.get(issuer_key_id)
    }

    /// Returns the retained key set.
    pub const fn keys(&self) -> &BTreeMap<String, [u8; 32]> {
        &self.keys
    }
}

/// Bounded, validated set of authorities trusted to sign creation grants.
///
/// Structurally identical to the issuer keyset but a distinct type on purpose:
/// the compiler refuses to verify a grant with the issuer's keys, or a command
/// with a grant authority's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareTenantRootCreationGrantAuthorityVerifyingKeysV1 {
    keys: BTreeMap<String, [u8; 32]>,
}

impl CloudflareTenantRootCreationGrantAuthorityVerifyingKeysV1 {
    /// Decodes and validates the published grant-authority set.
    pub fn decode(json: &str) -> RouterAbProtocolResult<Self> {
        Ok(Self {
            keys: decode_issuer_verifying_keys(json)?,
        })
    }

    /// Revalidates the retained set.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.keys.is_empty() || self.keys.len() > 32 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root creation grant authority set must contain between one and 32 keys",
            ));
        }
        for (key_id, verifying_key) in &self.keys {
            if !valid_config_key_id(key_id) {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "tenant-root creation grant authority key id is invalid",
                ));
            }
            VerifyingKey::from_bytes(verifying_key).map_err(|_| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "tenant-root creation grant authority key is not a valid Ed25519 point",
                )
            })?;
        }
        Ok(())
    }

    /// Returns the verifying key trusted for one grant authority id.
    pub fn for_grant_key_id(&self, grant_key_id: &str) -> Option<&[u8; 32]> {
        self.keys.get(grant_key_id)
    }

    /// Returns the retained grant-authority set.
    pub const fn keys(&self) -> &BTreeMap<String, [u8; 32]> {
        &self.keys
    }
}

/// Parses the trusted grant-authority set from Env.
pub(crate) fn parse_cloudflare_tenant_root_creation_grant_authority_verifying_keys_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationGrantAuthorityVerifyingKeysV1> {
    CloudflareTenantRootCreationGrantAuthorityVerifyingKeysV1::decode(&read_required_raw_env_text(
        env,
        TENANT_ROOT_CONTROL_PLANE_GRANT_AUTHORITY_VERIFYING_KEYS_JSON_ENV,
    )?)
}

/// Parses the published role verifying keyset.
///
/// The control plane holds this to prove the role signing IDs it names in a
/// ceremony actually exist under their roles.
pub(crate) fn parse_cloudflare_tenant_root_creation_role_verifying_keys_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<TenantRootCreationRoleVerifyingKeysV1> {
    let key_set = decode_role_verifying_keys(&read_required_raw_env_text(
        env,
        ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON_ENV,
    )?)?;
    validate_tenant_root_creation_role_verifying_keys_against_peer_v1(env, &key_set)?;
    Ok(key_set)
}

/// Reads the public role signing key id the issuer names for one role.
pub(crate) fn read_cloudflare_tenant_root_creation_role_signing_key_id_v1(
    env: &impl CloudflareEnvReaderV1,
    role: TwoPartyDeriverRole,
) -> RouterAbProtocolResult<String> {
    let key = match role {
        TwoPartyDeriverRole::DeriverA => DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
        TwoPartyDeriverRole::DeriverB => DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
    };
    let value = read_required_raw_env_text(env, key)?;
    validate_tenant_root_identifier("tenant-root creation role signing key ID", &value)?;
    Ok(value)
}

/// Parses the published control-plane issuer verifying key set from Env.
pub(crate) fn parse_cloudflare_tenant_root_control_plane_issuer_verifying_keys_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1> {
    CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1::decode(&read_required_raw_env_text(
        env,
        TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
    )?)
}

/// Decodes the control-plane issuer signing Secret into a zeroizing seed.
///
/// Same encoding as the Deriver role-signing Secrets: unpadded base64url over
/// exactly 32 bytes.
pub(crate) fn decode_cloudflare_tenant_root_control_plane_issuer_signing_secret_v1(
    secret_value: &str,
) -> RouterAbProtocolResult<Zeroizing<[u8; 32]>> {
    let mut bytes =
        match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(secret_value.as_bytes()) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "tenant-root control-plane issuer Secret must be unpadded base64url",
                ));
            }
        };
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root control-plane issuer Secret must decode to 32 bytes",
        ));
    }
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(Zeroizing::new(seed))
}

/// Proves the issuer Secret derives the public key published under its active key ID.
///
/// The active key ID is local configuration; a caller can never select it. A
/// retired key ID stays in the published set so previously issued durable
/// artifacts keep verifying, but it can no longer be the active one, so this
/// check is what stops a retired private key from continuing to sign.
pub fn validate_cloudflare_tenant_root_control_plane_issuer_key_provenance_v1(
    binding: &CloudflareTenantRootControlPlaneIssuerSigningKeyBindingV1,
    published: &CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    secret_value: &str,
) -> RouterAbProtocolResult<()> {
    binding.validate()?;
    published.validate()?;
    let Some(expected) = published.for_issuer_key_id(binding.signing_key_id()) else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root control-plane active issuer key ID is not in the published verifying key set",
        ));
    };
    let seed = decode_cloudflare_tenant_root_control_plane_issuer_signing_secret_v1(secret_value)?;
    let derived = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    if derived != *expected {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root control-plane issuer Secret does not match its published verifying key",
        ));
    }
    Ok(())
}

/// Parses the tenant-root control-plane Worker's issuer signing Secret binding.
///
/// Fails closed for every other Worker role before touching Env: the issuer
/// private key has exactly one owner.
pub fn parse_cloudflare_tenant_root_control_plane_issuer_signing_key_binding_v1(
    worker_role: CloudflareWorkerRoleV1,
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneIssuerSigningKeyBindingV1> {
    if worker_role != CloudflareWorkerRoleV1::TenantRootControlPlane {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "only the tenant-root control-plane Worker may hold the issuer signing Secret",
        ));
    }
    crate::reject_forbidden_env_keys(
        worker_role,
        env,
        TENANT_ROOT_CONTROL_PLANE_FORBIDDEN_ENV_KEYS,
    )?;
    CloudflareTenantRootControlPlaneIssuerSigningKeyBindingV1::new(
        read_required_raw_env_text(env, TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_ID_ENV)?,
        read_required_raw_env_text(
            env,
            TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING_ENV,
        )?,
    )
}

/// Parses the current Deriver's dormant tenant-root role-signing Secret binding.
pub(crate) fn parse_cloudflare_tenant_root_creation_role_signing_key_binding_v1(
    worker_role: CloudflareWorkerRoleV1,
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationRoleSigningKeyBindingV1> {
    let (role, binding_key, signing_key_id_key, forbidden_keys) = match worker_role {
        CloudflareWorkerRoleV1::DeriverA => (
            TwoPartyDeriverRole::DeriverA,
            DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
            DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
            DERIVER_A_FORBIDDEN_ENV_KEYS,
        ),
        CloudflareWorkerRoleV1::DeriverB => (
            TwoPartyDeriverRole::DeriverB,
            DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
            DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
            DERIVER_B_FORBIDDEN_ENV_KEYS,
        ),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SigningWorker
        | CloudflareWorkerRoleV1::TenantRootControlPlane => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "this Worker cannot access tenant-root role-signing Secrets",
            ));
        }
    };
    crate::reject_forbidden_env_keys(worker_role, env, forbidden_keys)?;
    let binding = CloudflareTenantRootCreationRoleSigningKeyBindingV1::new(
        role,
        read_required_tenant_root_identifier(env, signing_key_id_key)?,
        read_required_tenant_root_identifier(env, binding_key)?,
    )?;
    reject_reused_peer_signing_binding(env, &binding)?;
    binding.validate_visible_to(worker_role)?;
    Ok(binding)
}

/// Parses the authoritative role/key/verifier selection for one Deriver.
pub(crate) fn parse_cloudflare_tenant_root_creation_role_signing_key_selection_v1(
    worker_role: CloudflareWorkerRoleV1,
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationRoleSigningKeySelectionV1> {
    let binding =
        parse_cloudflare_tenant_root_creation_role_signing_key_binding_v1(worker_role, env)?;
    let key_set_json = read_required_raw_env_text(
        env,
        ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON_ENV,
    )?;
    let key_set = decode_role_verifying_keys(&key_set_json)?;
    validate_tenant_root_creation_role_verifying_keys_against_peer_v1(env, &key_set)?;
    key_set.reject_ambiguous_role_selection(binding.role(), binding.signing_key_id())?;
    let verifying_key = key_set.for_role_and_key_id(binding.role(), binding.signing_key_id())?;
    CloudflareTenantRootCreationRoleSigningKeySelectionV1::new(binding, *verifying_key)
}

#[derive(Debug)]
pub(crate) struct TenantRootCreationRoleVerifyingKeysV1 {
    deriver_a: BTreeMap<String, [u8; 32]>,
    deriver_b: BTreeMap<String, [u8; 32]>,
}

impl TenantRootCreationRoleVerifyingKeysV1 {
    pub(crate) fn for_role_and_key_id(
        &self,
        role: TwoPartyDeriverRole,
        signing_key_id: &str,
    ) -> RouterAbProtocolResult<&[u8; 32]> {
        let keys = match role {
            TwoPartyDeriverRole::DeriverA => &self.deriver_a,
            TwoPartyDeriverRole::DeriverB => &self.deriver_b,
        };
        keys.get(signing_key_id).ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root creation role signing key is not trusted",
            )
        })
    }

    fn contains_verifying_key(&self, verifying_key: &[u8; 32]) -> bool {
        self.deriver_a.values().any(|key| key == verifying_key)
            || self.deriver_b.values().any(|key| key == verifying_key)
    }

    fn reject_ambiguous_role_selection(
        &self,
        role: TwoPartyDeriverRole,
        signing_key_id: &str,
    ) -> RouterAbProtocolResult<()> {
        let peer_keys = match role {
            TwoPartyDeriverRole::DeriverA => &self.deriver_b,
            TwoPartyDeriverRole::DeriverB => &self.deriver_a,
        };
        if peer_keys.contains_key(signing_key_id) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root role signing key ID is assigned to the opposite role",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRootCreationRoleVerifyingKeySetWireV1 {
    keys: Vec<TenantRootCreationRoleVerifyingKeyWireV1>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum TenantRootCreationRoleVerifyingKeyRoleWireV1 {
    DeriverA,
    DeriverB,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRootCreationRoleVerifyingKeyWireV1 {
    role: TenantRootCreationRoleVerifyingKeyRoleWireV1,
    signing_key_id: String,
    verifying_key_hex: String,
}

/// Parses the retained role verifier set once at the configuration boundary.
pub(crate) fn decode_role_verifying_keys(
    json: &str,
) -> RouterAbProtocolResult<TenantRootCreationRoleVerifyingKeysV1> {
    let wire: TenantRootCreationRoleVerifyingKeySetWireV1 =
        serde_json::from_str(json).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("tenant-root creation role key set JSON is invalid: {error}"),
            )
        })?;
    if wire.keys.len() < 2 || wire.keys.len() > 64 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root creation role key set must contain between two and 64 keys",
        ));
    }
    let mut deriver_a = BTreeMap::new();
    let mut deriver_b = BTreeMap::new();
    let mut verifying_keys = BTreeSet::new();
    for entry in wire.keys {
        validate_tenant_root_identifier(
            "tenant-root creation role signing key ID",
            &entry.signing_key_id,
        )?;
        let verifying_key = decode_lower_hex_32(&entry.verifying_key_hex)?;
        VerifyingKey::from_bytes(&verifying_key).map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root creation role verifying key is not a valid Ed25519 point",
            )
        })?;
        if !verifying_keys.insert(verifying_key) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root creation role verifying key is duplicated",
            ));
        }
        let role_keys = match entry.role {
            TenantRootCreationRoleVerifyingKeyRoleWireV1::DeriverA => &mut deriver_a,
            TenantRootCreationRoleVerifyingKeyRoleWireV1::DeriverB => &mut deriver_b,
        };
        if role_keys
            .insert(entry.signing_key_id, verifying_key)
            .is_some()
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root creation role signing key ID is duplicated",
            ));
        }
    }
    if deriver_a.is_empty() || deriver_b.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root creation role key set must retain at least one key for each role",
        ));
    }
    Ok(TenantRootCreationRoleVerifyingKeysV1 {
        deriver_a,
        deriver_b,
    })
}

#[cfg(feature = "workers-rs")]
/// Loads and verifies the current Deriver's dormant tenant-root role-signing Secret.
pub(crate) fn load_cloudflare_tenant_root_creation_role_signing_key_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<(
    CloudflareTenantRootCreationRoleSigningKeyBindingV1,
    CloudflareTenantRootCreationRoleSignerV1,
)> {
    let reader = CloudflareWorkerEnvReaderV1::new(env);
    let selection =
        parse_cloudflare_tenant_root_creation_role_signing_key_selection_v1(worker_role, &reader)?;
    let binding = selection.binding().clone();
    let secret = env.secret(binding.binding_name()).map_err(|err| {
        crate::worker_binding_error(
            crate::worker_binding_error_code(&err, binding.binding_name()),
            binding.binding_name(),
            "secret",
            err,
        )
    })?;
    let mut secret_value = secret.to_string();
    let decoded = decode_cloudflare_tenant_root_creation_role_signing_secret_v1(&secret_value);
    secret_value.zeroize();
    let signer = derive_cloudflare_tenant_root_creation_role_signing_key_v1(selection, decoded?)?;
    Ok((binding, signer))
}

fn read_required_raw_env_text(
    env: &impl CloudflareEnvReaderV1,
    key: &str,
) -> RouterAbProtocolResult<String> {
    match env.get_text(key)? {
        Some(value) if !value.is_empty() => Ok(value),
        Some(_) => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Cloudflare Env key {key} is empty"),
        )),
        None => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            format!("Cloudflare Env is missing required key {key}"),
        )),
    }
}

fn read_required_tenant_root_identifier(
    env: &impl CloudflareEnvReaderV1,
    key: &str,
) -> RouterAbProtocolResult<String> {
    let value = read_required_raw_env_text(env, key)?;
    validate_tenant_root_identifier(key, &value)?;
    Ok(value)
}

fn reject_reused_peer_signing_binding(
    env: &impl CloudflareEnvReaderV1,
    binding: &CloudflareTenantRootCreationRoleSigningKeyBindingV1,
) -> RouterAbProtocolResult<()> {
    for key in [
        DERIVER_A_PEER_SIGNING_KEY_BINDING_ENV,
        DERIVER_B_PEER_SIGNING_KEY_BINDING_ENV,
    ] {
        if let Some(peer_binding) = env.get_text(key)? {
            validate_tenant_root_identifier("A/B peer-signing Secret binding name", &peer_binding)?;
            if peer_binding == binding.binding_name() {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                    "tenant-root role-signing Secret cannot reuse an A/B peer-signing Secret",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_tenant_root_creation_role_verifying_keys_against_peer_v1(
    env: &impl CloudflareEnvReaderV1,
    key_set: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<()> {
    for (role, key) in [
        (
            TwoPartyDeriverRole::DeriverA,
            DERIVER_A_PEER_VERIFYING_KEY_HEX_ENV,
        ),
        (
            TwoPartyDeriverRole::DeriverB,
            DERIVER_B_PEER_VERIFYING_KEY_HEX_ENV,
        ),
    ] {
        let Some(value) = env.get_text(key)? else {
            continue;
        };
        let verifying_key = decode_lower_hex_32(&value)?;
        VerifyingKey::from_bytes(&verifying_key).map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("{key} is not a valid Ed25519 point"),
            )
        })?;
        if key_set.contains_verifying_key(&verifying_key) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                format!(
                    "tenant-root role verifying key cannot reuse the {role:?} A/B peer verifier"
                ),
            ));
        }
    }
    Ok(())
}

fn decode_lower_hex_32(value: &str) -> RouterAbProtocolResult<[u8; 32]> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root role verifying key must be exactly 64 lowercase hexadecimal characters",
        ));
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(chunk[0]) << 4) | hex_nibble(chunk[1]);
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("validated lowercase hexadecimal input"),
    }
}

fn validate_tenant_root_identifier(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() || value.len() > 256 || value.trim() != value {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} is invalid"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} is invalid"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CloudflareEnvMapV1, CloudflareWorkerRoleV1};

    fn lower_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }

    fn operational_keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let (private_key, public_key) =
            DhKemX25519HkdfSha256::derive_key_pair(&[seed; 32]).expect("operational key pair");
        let private_key_bytes = DhKemX25519HkdfSha256::sk_to_bytes(&private_key);
        let public_key_bytes = DhKemX25519HkdfSha256::pk_to_bytes(&public_key);
        let mut private_key_out = [0_u8; 32];
        let mut public_key_out = [0_u8; 32];
        private_key_out.copy_from_slice(&private_key_bytes);
        public_key_out.copy_from_slice(&public_key_bytes);
        (private_key_out, public_key_out)
    }

    fn operational_public_descriptor(seed: u8) -> String {
        let (_, public_key) = operational_keypair(seed);
        format!("x25519:{}", lower_hex(&public_key))
    }

    fn operational_private_secret(seed: u8) -> String {
        let (private_key, _) = operational_keypair(seed);
        format!(
            "{}{}",
            CLOUDFLARE_SIGNER_ENVELOPE_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1,
            lower_hex(&private_key)
        )
    }

    /// The R120 tenant-root control-plane key ownership matrix.
    ///
    /// | Material | Owner |
    /// |---|---|
    /// | issuer private signing key | dedicated control-plane Worker only |
    /// | issuer public verifying keyset | Router, Deriver A, Deriver B |
    ///
    /// The forbidden-env lists are the enforcement point, so they are pinned
    /// here: before this test the four lists had no coverage at all, and a
    /// change to any of them was silent.
    #[test]
    fn tenant_root_control_plane_key_ownership_matrix_is_exact() {
        for (worker_role, forbidden) in [
            (
                CloudflareWorkerRoleV1::Router,
                crate::env::ROUTER_FORBIDDEN_ENV_KEYS,
            ),
            (
                CloudflareWorkerRoleV1::DeriverA,
                crate::env::DERIVER_A_FORBIDDEN_ENV_KEYS,
            ),
            (
                CloudflareWorkerRoleV1::DeriverB,
                crate::env::DERIVER_B_FORBIDDEN_ENV_KEYS,
            ),
            (
                CloudflareWorkerRoleV1::SigningWorker,
                crate::env::SIGNING_WORKER_FORBIDDEN_ENV_KEYS,
            ),
        ] {
            // The private issuer key is forbidden in every Worker in this
            // deployment. Only the dedicated control-plane Worker holds it.
            assert!(
                forbidden.contains(&TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING_ENV),
                "{} must never receive the issuer private signing binding",
                worker_role.as_str()
            );

            // The public verifying anchor is required wherever a signed
            // creation command is verified, and forbidden where it is not.
            let anchor_forbidden =
                forbidden.contains(&TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV);
            match worker_role {
                CloudflareWorkerRoleV1::SigningWorker => assert!(
                    anchor_forbidden,
                    "the Signing Worker has no tenant-root lifecycle role"
                ),
                CloudflareWorkerRoleV1::Router
                | CloudflareWorkerRoleV1::DeriverA
                | CloudflareWorkerRoleV1::DeriverB => assert!(
                    !anchor_forbidden,
                    "{} verifies signed creation commands at its own boundary and requires the public anchor",
                    worker_role.as_str()
                ),
                CloudflareWorkerRoleV1::TenantRootControlPlane => assert!(
                    !anchor_forbidden,
                    "the issuer holds its own public set to preflight that its signing key id is trusted"
                ),
            }
        }
    }

    /// A public trust anchor is not Router configuration.
    ///
    /// Router *configuration and authorization state* stays forbidden in both
    /// Derivers; the control-plane public keyset does not, because a
    /// `VerifiedTenantRootRoleCreationCommandV1` is a process-local proof token
    /// that one Worker cannot serialize for another to trust.
    #[test]
    fn router_configuration_stays_forbidden_in_derivers_but_the_public_anchor_does_not() {
        for forbidden in [
            crate::env::DERIVER_A_FORBIDDEN_ENV_KEYS,
            crate::env::DERIVER_B_FORBIDDEN_ENV_KEYS,
        ] {
            for router_config in [
                ROUTER_JWT_ISSUER_ENV,
                ROUTER_JWT_AUDIENCE_ENV,
                ROUTER_JWT_JWKS_JSON_ENV,
                ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON_ENV,
            ] {
                assert!(
                    forbidden.contains(&router_config),
                    "Router configuration {router_config} must not leak into a Deriver"
                );
            }
            assert!(!forbidden.contains(&TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV));
            // The role verifying keyset is the existing precedent for a shared
            // public anchor that a Deriver legitimately reads.
            assert!(!forbidden.contains(&ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON_ENV));
        }
    }

    /// Boot-time enforcement, not just list membership.
    #[test]
    fn each_worker_rejects_the_issuer_private_binding_and_accepts_the_public_anchor() {
        for (worker_role, forbidden) in [
            (
                CloudflareWorkerRoleV1::Router,
                crate::env::ROUTER_FORBIDDEN_ENV_KEYS,
            ),
            (
                CloudflareWorkerRoleV1::DeriverA,
                crate::env::DERIVER_A_FORBIDDEN_ENV_KEYS,
            ),
            (
                CloudflareWorkerRoleV1::DeriverB,
                crate::env::DERIVER_B_FORBIDDEN_ENV_KEYS,
            ),
        ] {
            let with_private_key = CloudflareEnvMapV1::new(vec![(
                TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING_ENV,
                "TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY",
            )]);
            let error = crate::reject_forbidden_env_keys(worker_role, &with_private_key, forbidden)
                .expect_err("issuer private binding must be rejected");
            assert_eq!(
                error.code(),
                RouterAbProtocolErrorCode::ForbiddenLocalBinding
            );

            let with_public_anchor = CloudflareEnvMapV1::new(vec![(
                TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
                "{}",
            )]);
            crate::reject_forbidden_env_keys(worker_role, &with_public_anchor, forbidden)
                .expect("public verifying anchor must be accepted");
        }

        // The Signing Worker rejects both.
        for key in [
            TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING_ENV,
            TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        ] {
            let env = CloudflareEnvMapV1::new(vec![(key, "x")]);
            assert_eq!(
                crate::reject_forbidden_env_keys(
                    CloudflareWorkerRoleV1::SigningWorker,
                    &env,
                    crate::env::SIGNING_WORKER_FORBIDDEN_ENV_KEYS,
                )
                .expect_err("signing worker must reject tenant-root control-plane keys")
                .code(),
                RouterAbProtocolErrorCode::ForbiddenLocalBinding
            );
        }
    }

    fn issuer_key_set(
        entries: &[(&str, [u8; 32])],
    ) -> CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1 {
        CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1::decode(&issuer_key_set_json(entries))
            .expect("issuer key set")
    }

    fn issuer_key_set_json(entries: &[(&str, [u8; 32])]) -> String {
        let keys: Vec<String> = entries
            .iter()
            .map(|(id, key)| {
                format!(
                    "{{\"issuer_key_id\":\"{id}\",\"verifying_key_hex\":\"{}\"}}",
                    lower_hex(key)
                )
            })
            .collect();
        format!("{{\"keys\":[{}]}}", keys.join(","))
    }

    fn issuer_binding(key_id: &str) -> CloudflareTenantRootControlPlaneIssuerSigningKeyBindingV1 {
        CloudflareTenantRootControlPlaneIssuerSigningKeyBindingV1::new(
            key_id,
            "TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY",
        )
        .expect("issuer binding")
    }

    fn seed_b64u(seed: &[u8; 32]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed)
    }

    /// The issuer Secret must derive the key published under its active key ID.
    #[test]
    fn issuer_key_provenance_requires_the_secret_to_match_its_published_active_key() {
        let seed = [0x51_u8; 32];
        let verifying = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let key_id = "control-plane-issuer-v1";

        validate_cloudflare_tenant_root_control_plane_issuer_key_provenance_v1(
            &issuer_binding(key_id),
            &issuer_key_set(&[(key_id, verifying)]),
            &seed_b64u(&seed),
        )
        .expect("matching issuer Secret");

        // A different Secret under the same published key id fails closed.
        let other = [0x52_u8; 32];
        assert_eq!(
            validate_cloudflare_tenant_root_control_plane_issuer_key_provenance_v1(
                &issuer_binding(key_id),
                &issuer_key_set(&[(key_id, verifying)]),
                &seed_b64u(&other),
            )
            .expect_err("substituted Secret")
            .code(),
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig
        );

        // A substituted published key under the same id fails closed.
        let foreign = SigningKey::from_bytes(&other).verifying_key().to_bytes();
        assert!(
            validate_cloudflare_tenant_root_control_plane_issuer_key_provenance_v1(
                &issuer_binding(key_id),
                &issuer_key_set(&[(key_id, foreign)]),
                &seed_b64u(&seed),
            )
            .is_err()
        );

        // An active key id absent from the published set fails closed.
        assert!(
            validate_cloudflare_tenant_root_control_plane_issuer_key_provenance_v1(
                &issuer_binding("control-plane-issuer-unknown"),
                &issuer_key_set(&[(key_id, verifying)]),
                &seed_b64u(&seed),
            )
            .is_err()
        );

        // Malformed Secret encodings fail closed.
        for bad in ["", "not-base64url!", &seed_b64u(&seed)[..40]] {
            assert!(
                validate_cloudflare_tenant_root_control_plane_issuer_key_provenance_v1(
                    &issuer_binding(key_id),
                    &issuer_key_set(&[(key_id, verifying)]),
                    bad,
                )
                .is_err()
            );
        }
    }

    /// A retained non-active key still verifies; only the active one signs.
    ///
    /// This proves a configuration property, not an operational guarantee: the
    /// configured active key ID, its Secret, and the published key must agree,
    /// and a non-active published key is still available for verification.
    ///
    /// It does NOT prevent an operator from restoring an old seed and selecting
    /// its retained ID again. Retirement is an operational invariant enforced by
    /// deployment, not by this check: change the active ID, replace or delete
    /// the old Secret, and retain only its public key so previously issued
    /// durable artifacts keep verifying.
    #[test]
    fn a_retained_non_active_issuer_key_still_verifies_while_only_the_active_key_signs() {
        let retained_seed = [0x61_u8; 32];
        let active_seed = [0x62_u8; 32];
        let retained = SigningKey::from_bytes(&retained_seed)
            .verifying_key()
            .to_bytes();
        let active = SigningKey::from_bytes(&active_seed)
            .verifying_key()
            .to_bytes();
        let published = issuer_key_set(&[
            ("control-plane-issuer-retained", retained),
            ("control-plane-issuer-active", active),
        ]);

        // Both keys stay available for verification of durable artifacts.
        assert_eq!(
            published.for_issuer_key_id("control-plane-issuer-retained"),
            Some(&retained)
        );
        assert_eq!(
            published.for_issuer_key_id("control-plane-issuer-active"),
            Some(&active)
        );

        // The active configuration must carry the matching active Secret.
        validate_cloudflare_tenant_root_control_plane_issuer_key_provenance_v1(
            &issuer_binding("control-plane-issuer-active"),
            &published,
            &seed_b64u(&active_seed),
        )
        .expect("active issuer key");

        // With the active Secret installed, the retained ID cannot be selected:
        // the Secret does not derive it. Deleting the retained Secret is what
        // makes that permanent; this check only enforces the agreement.
        assert!(
            validate_cloudflare_tenant_root_control_plane_issuer_key_provenance_v1(
                &issuer_binding("control-plane-issuer-retained"),
                &published,
                &seed_b64u(&active_seed),
            )
            .is_err()
        );

        // Stated plainly: restoring the retained seed alongside its retained ID
        // is again a consistent configuration. Nothing here forbids it, which is
        // exactly why retirement requires removing the Secret.
        validate_cloudflare_tenant_root_control_plane_issuer_key_provenance_v1(
            &issuer_binding("control-plane-issuer-retained"),
            &published,
            &seed_b64u(&retained_seed),
        )
        .expect("a restored retained Secret is still a consistent configuration");
    }

    fn operational_env(
        worker_role: CloudflareWorkerRoleV1,
        online_seed: u8,
        backup_seed: u8,
    ) -> CloudflareEnvMapV1 {
        let (
            online_ref_key,
            online_public_key,
            online_binding_key,
            provider_key,
            version_key,
            backup_public_key,
            backup_binding_key,
        ) = match worker_role {
            CloudflareWorkerRoleV1::DeriverA => (
                DERIVER_A_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF_ENV,
                DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY_ENV,
                DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING_ENV,
                DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID_ENV,
                DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION_ENV,
                DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY_ENV,
                DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING_ENV,
            ),
            CloudflareWorkerRoleV1::DeriverB => (
                DERIVER_B_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF_ENV,
                DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY_ENV,
                DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING_ENV,
                DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID_ENV,
                DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION_ENV,
                DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY_ENV,
                DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING_ENV,
            ),
            CloudflareWorkerRoleV1::Router
            | CloudflareWorkerRoleV1::SigningWorker
            | CloudflareWorkerRoleV1::TenantRootControlPlane => {
                panic!("operational provider requires a Deriver role")
            }
        };
        let role_prefix = match worker_role {
            CloudflareWorkerRoleV1::DeriverA => "DERIVER_A",
            CloudflareWorkerRoleV1::DeriverB => "DERIVER_B",
            CloudflareWorkerRoleV1::Router
            | CloudflareWorkerRoleV1::SigningWorker
            | CloudflareWorkerRoleV1::TenantRootControlPlane => {
                unreachable!()
            }
        };
        CloudflareEnvMapV1::new(vec![
            (online_ref_key, "online-epoch-1".to_owned()),
            (
                online_public_key,
                operational_public_descriptor(online_seed),
            ),
            (
                online_binding_key,
                format!("{role_prefix}_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY"),
            ),
            (provider_key, "cloudflare-operational".to_owned()),
            (version_key, "backup-epoch-1".to_owned()),
            (
                backup_public_key,
                operational_public_descriptor(backup_seed),
            ),
            (
                backup_binding_key,
                format!("{role_prefix}_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY"),
            ),
        ])
    }

    fn role_key_set_json(
        deriver_a_key_id: &str,
        deriver_a_key: &SigningKey,
        deriver_b_key_id: &str,
        deriver_b_key: &SigningKey,
    ) -> String {
        serde_json::json!({
            "keys": [
                {
                    "role": "deriver_a",
                    "signing_key_id": deriver_a_key_id,
                    "verifying_key_hex": lower_hex(&deriver_a_key.verifying_key().to_bytes()),
                },
                {
                    "role": "deriver_b",
                    "signing_key_id": deriver_b_key_id,
                    "verifying_key_hex": lower_hex(&deriver_b_key.verifying_key().to_bytes()),
                },
            ],
        })
        .to_string()
    }

    fn role_signing_env(
        binding_name: &str,
        signing_key_id: &str,
        key_set: String,
    ) -> CloudflareEnvMapV1 {
        CloudflareEnvMapV1::new(vec![
            (
                DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
                binding_name.to_owned(),
            ),
            (
                DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
                signing_key_id.to_owned(),
            ),
            (
                ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON_ENV,
                key_set,
            ),
        ])
    }

    #[test]
    fn role_signing_binding_is_private_and_deriver_local() {
        let env = CloudflareEnvMapV1::new(vec![
            (
                DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
                "DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY",
            ),
            (
                DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
                "tenant-root-a",
            ),
        ]);
        let binding = parse_cloudflare_tenant_root_creation_role_signing_key_binding_v1(
            CloudflareWorkerRoleV1::DeriverA,
            &env,
        )
        .expect("Deriver A role-signing binding");
        assert_eq!(binding.role(), TwoPartyDeriverRole::DeriverA);
        assert_eq!(binding.signing_key_id(), "tenant-root-a");
        assert_eq!(
            binding.binding_name(),
            "DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY"
        );
        assert!(binding
            .validate_visible_to(CloudflareWorkerRoleV1::DeriverA)
            .is_ok());
        assert_eq!(
            binding
                .validate_visible_to(CloudflareWorkerRoleV1::DeriverB)
                .expect_err("Deriver B must not see Deriver A role key")
                .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );
        for worker_role in [
            CloudflareWorkerRoleV1::Router,
            CloudflareWorkerRoleV1::SigningWorker,
        ] {
            assert_eq!(
                parse_cloudflare_tenant_root_creation_role_signing_key_binding_v1(
                    worker_role,
                    &env,
                )
                .expect_err("public workers must not see role-signing Secrets")
                .code(),
                RouterAbProtocolErrorCode::ForbiddenLocalBinding
            );
        }
        let malformed = CloudflareTenantRootCreationRoleSigningKeyBindingV1 {
            role: TwoPartyDeriverRole::DeriverA,
            signing_key_id: " tenant-root-a".to_owned(),
            binding_name: "DERIVER_A_TENANT_ROOT_SIGNING_KEY".to_owned(),
        };
        assert!(malformed
            .validate_visible_to(CloudflareWorkerRoleV1::DeriverA)
            .is_err());
    }

    #[test]
    fn role_signing_selection_proves_verifier_provenance() {
        let signing_key_a = SigningKey::from_bytes(&[0xa1; 32]);
        let signing_key_b = SigningKey::from_bytes(&[0xb1; 32]);
        let env = role_signing_env(
            "DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY",
            "tenant-root-a",
            role_key_set_json(
                "tenant-root-a",
                &signing_key_a,
                "tenant-root-b",
                &signing_key_b,
            ),
        );
        let selection = parse_cloudflare_tenant_root_creation_role_signing_key_selection_v1(
            CloudflareWorkerRoleV1::DeriverA,
            &env,
        )
        .expect("trusted role-signing selection");
        assert_eq!(selection.role(), TwoPartyDeriverRole::DeriverA);
        assert_eq!(selection.signing_key_id(), "tenant-root-a");
        assert_eq!(
            selection.verifying_key_bytes(),
            signing_key_a.verifying_key().to_bytes()
        );
        let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xa1; 32]);
        let signer = derive_cloudflare_tenant_root_creation_role_signing_key_v1(
            selection,
            decode_cloudflare_tenant_root_creation_role_signing_secret_v1(&secret)
                .expect("role-signing Secret"),
        )
        .expect("role signer");
        assert_eq!(signer.role(), TwoPartyDeriverRole::DeriverA);
        assert_eq!(signer.signing_key_id(), "tenant-root-a");
        assert_eq!(
            signer.verifying_key_bytes(),
            signing_key_a.verifying_key().to_bytes()
        );

        let wrong_secret_selection =
            parse_cloudflare_tenant_root_creation_role_signing_key_selection_v1(
                CloudflareWorkerRoleV1::DeriverA,
                &env,
            )
            .expect("trusted role-signing selection");
        let wrong_secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xb1; 32]);
        assert!(derive_cloudflare_tenant_root_creation_role_signing_key_v1(
            wrong_secret_selection,
            decode_cloudflare_tenant_root_creation_role_signing_secret_v1(&wrong_secret)
                .expect("role-signing Secret"),
        )
        .is_err());
        assert!(
            decode_cloudflare_tenant_root_creation_role_signing_secret_v1(&format!(" {secret}"))
                .is_err()
        );
    }

    #[test]
    fn role_signing_rejects_peer_aliases_and_opposite_role_key() {
        let signing_key_a = SigningKey::from_bytes(&[0xa1; 32]);
        let signing_key_b = SigningKey::from_bytes(&[0xb1; 32]);
        let key_set = role_key_set_json(
            "tenant-root-a",
            &signing_key_a,
            "tenant-root-b",
            &signing_key_b,
        );
        let reused_peer_env = CloudflareEnvMapV1::new(vec![
            (
                DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
                "DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY".to_owned(),
            ),
            (
                DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
                "tenant-root-a".to_owned(),
            ),
            (
                DERIVER_A_PEER_SIGNING_KEY_BINDING_ENV,
                "DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY".to_owned(),
            ),
        ]);
        assert!(
            parse_cloudflare_tenant_root_creation_role_signing_key_binding_v1(
                CloudflareWorkerRoleV1::DeriverA,
                &reused_peer_env,
            )
            .is_err()
        );
        let whitespace_peer_env = CloudflareEnvMapV1::new(vec![
            (
                DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
                "DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY".to_owned(),
            ),
            (
                DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
                "tenant-root-a".to_owned(),
            ),
            (
                DERIVER_A_PEER_SIGNING_KEY_BINDING_ENV,
                " DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY".to_owned(),
            ),
        ]);
        assert!(
            parse_cloudflare_tenant_root_creation_role_signing_key_binding_v1(
                CloudflareWorkerRoleV1::DeriverA,
                &whitespace_peer_env,
            )
            .is_err()
        );
        let static_peer_alias_env = CloudflareEnvMapV1::new(vec![
            (
                DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
                "DERIVER_A_PEER_SIGNING_KEY",
            ),
            (
                DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
                "tenant-root-a",
            ),
        ]);
        assert!(
            parse_cloudflare_tenant_root_creation_role_signing_key_binding_v1(
                CloudflareWorkerRoleV1::DeriverA,
                &static_peer_alias_env,
            )
            .is_err()
        );

        let reused_peer_verifier_env = CloudflareEnvMapV1::new(vec![
            (
                DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
                "DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY".to_owned(),
            ),
            (
                DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
                "tenant-root-a".to_owned(),
            ),
            (
                ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON_ENV,
                key_set,
            ),
            (
                DERIVER_A_PEER_VERIFYING_KEY_HEX_ENV,
                lower_hex(&signing_key_a.verifying_key().to_bytes()),
            ),
        ]);
        assert!(
            parse_cloudflare_tenant_root_creation_role_signing_key_selection_v1(
                CloudflareWorkerRoleV1::DeriverA,
                &reused_peer_verifier_env,
            )
            .is_err()
        );

        let opposite_role_key_env = role_signing_env(
            "DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY",
            "tenant-root-b",
            role_key_set_json(
                "tenant-root-a",
                &signing_key_a,
                "tenant-root-b",
                &signing_key_b,
            ),
        );
        assert_eq!(
            parse_cloudflare_tenant_root_creation_role_signing_key_selection_v1(
                CloudflareWorkerRoleV1::DeriverA,
                &opposite_role_key_env,
            )
            .expect_err("Deriver A must not select Deriver B key")
            .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );
    }

    #[test]
    fn role_verifying_key_validator_rejects_peer_verifier_for_router_loader() {
        let signing_key_a = SigningKey::from_bytes(&[0xa1; 32]);
        let signing_key_b = SigningKey::from_bytes(&[0xb1; 32]);
        let key_set = decode_role_verifying_keys(&role_key_set_json(
            "tenant-root-a",
            &signing_key_a,
            "tenant-root-b",
            &signing_key_b,
        ))
        .expect("trusted role key set");
        let env = CloudflareEnvMapV1::new(vec![(
            DERIVER_A_PEER_VERIFYING_KEY_HEX_ENV,
            lower_hex(&signing_key_a.verifying_key().to_bytes()),
        )]);
        assert_eq!(
            validate_tenant_root_creation_role_verifying_keys_against_peer_v1(&env, &key_set)
                .expect_err("Router loader must reject peer verifier reuse")
                .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );
    }

    #[test]
    fn router_role_key_set_rejects_cross_role_verifier_aliases() {
        let signing_key = SigningKey::from_bytes(&[0xa1; 32]);
        let key_set = serde_json::json!({
            "keys": [
                {
                    "role": "deriver_a",
                    "signing_key_id": "router-a-key",
                    "verifying_key_hex": lower_hex(&signing_key.verifying_key().to_bytes()),
                },
                {
                    "role": "deriver_b",
                    "signing_key_id": "router-b-key",
                    "verifying_key_hex": lower_hex(&signing_key.verifying_key().to_bytes()),
                },
            ],
        })
        .to_string();
        assert_eq!(
            decode_role_verifying_keys(&key_set)
                .expect_err("Router role key set must reject verifier aliases")
                .code(),
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig
        );
    }

    #[test]
    fn role_signing_key_set_rejects_duplicate_ids_and_verifiers() {
        let signing_key_a = SigningKey::from_bytes(&[0xa1; 32]);
        let signing_key_b = SigningKey::from_bytes(&[0xb1; 32]);
        let duplicate_id = serde_json::json!({
            "keys": [
                {
                    "role": "deriver_a",
                    "signing_key_id": "same-id",
                    "verifying_key_hex": lower_hex(&signing_key_a.verifying_key().to_bytes()),
                },
                {
                    "role": "deriver_b",
                    "signing_key_id": "same-id",
                    "verifying_key_hex": lower_hex(&signing_key_b.verifying_key().to_bytes()),
                },
            ],
        })
        .to_string();
        let duplicate_verifier = serde_json::json!({
            "keys": [
                {
                    "role": "deriver_a",
                    "signing_key_id": "a-id",
                    "verifying_key_hex": lower_hex(&signing_key_a.verifying_key().to_bytes()),
                },
                {
                    "role": "deriver_b",
                    "signing_key_id": "b-id",
                    "verifying_key_hex": lower_hex(&signing_key_a.verifying_key().to_bytes()),
                },
            ],
        })
        .to_string();
        for key_set in [duplicate_id, duplicate_verifier] {
            let env = role_signing_env("DERIVER_A_TENANT_ROOT_SIGNING_KEY", "same-id", key_set);
            assert!(
                parse_cloudflare_tenant_root_creation_role_signing_key_selection_v1(
                    CloudflareWorkerRoleV1::DeriverA,
                    &env,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn operational_provider_config_is_role_local_and_preserves_exact_descriptors() {
        for worker_role in [
            CloudflareWorkerRoleV1::DeriverA,
            CloudflareWorkerRoleV1::DeriverB,
        ] {
            let env = operational_env(worker_role, 0x21, 0x31);
            let config = parse_cloudflare_tenant_root_operational_rotation_provider_config_v1(
                worker_role,
                &env,
            )
            .expect("operational provider config");
            let expected_role = match worker_role {
                CloudflareWorkerRoleV1::DeriverA => TwoPartyDeriverRole::DeriverA,
                CloudflareWorkerRoleV1::DeriverB => TwoPartyDeriverRole::DeriverB,
                CloudflareWorkerRoleV1::Router
                | CloudflareWorkerRoleV1::SigningWorker
                | CloudflareWorkerRoleV1::TenantRootControlPlane => {
                    unreachable!()
                }
            };
            assert_eq!(config.role(), expected_role);
            assert_eq!(config.online_epoch_wrapping_key_ref(), "online-epoch-1");
            assert_eq!(config.backup_provider_id(), "cloudflare-operational");
            assert_eq!(config.backup_key_version(), "backup-epoch-1");
            assert_eq!(
                config.online_public_key(),
                operational_public_descriptor(0x21)
            );
            assert_eq!(
                config.backup_public_key(),
                operational_public_descriptor(0x31)
            );
            assert!(config
                .online_secret_binding_name()
                .starts_with(worker_role.as_str().to_ascii_uppercase().as_str()));
            assert!(config
                .backup_secret_binding_name()
                .starts_with(worker_role.as_str().to_ascii_uppercase().as_str()));
        }
    }

    #[test]
    fn operational_provider_config_rejects_wrong_role_and_reused_bindings() {
        let env = operational_env(CloudflareWorkerRoleV1::DeriverA, 0x41, 0x51);
        for worker_role in [
            CloudflareWorkerRoleV1::Router,
            CloudflareWorkerRoleV1::SigningWorker,
        ] {
            assert_eq!(
                parse_cloudflare_tenant_root_operational_rotation_provider_config_v1(
                    worker_role,
                    &env,
                )
                .expect_err("public workers cannot parse operational provider secrets")
                .code(),
                RouterAbProtocolErrorCode::ForbiddenLocalBinding
            );
        }

        let wrong_role_env = env.clone().with_overrides(vec![(
            DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING_ENV,
            "DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY",
        )]);
        assert!(
            parse_cloudflare_tenant_root_operational_rotation_provider_config_v1(
                CloudflareWorkerRoleV1::DeriverA,
                &wrong_role_env,
            )
            .is_err()
        );

        let reused_binding_env = env.clone().with_overrides(vec![(
            DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING_ENV,
            "DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY",
        )]);
        assert_eq!(
            parse_cloudflare_tenant_root_operational_rotation_provider_config_v1(
                CloudflareWorkerRoleV1::DeriverA,
                &reused_binding_env,
            )
            .expect_err("online and backup Secret bindings must be distinct")
            .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );

        let peer_alias_env = env.with_overrides(vec![(
            DERIVER_A_PEER_SIGNING_KEY_BINDING_ENV,
            "DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY",
        )]);
        assert_eq!(
            parse_cloudflare_tenant_root_operational_rotation_provider_config_v1(
                CloudflareWorkerRoleV1::DeriverA,
                &peer_alias_env,
            )
            .expect_err("operational Secret must not reuse peer Secret")
            .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );
    }

    #[test]
    fn operational_provider_config_rejects_raw_whitespace_and_descriptor_aliases() {
        let env = operational_env(CloudflareWorkerRoleV1::DeriverA, 0x61, 0x71);
        for (key, value) in [
            (
                DERIVER_A_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF_ENV,
                " online-epoch-1",
            ),
            (
                DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID_ENV,
                "cloudflare-operational ",
            ),
            (
                DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION_ENV,
                "backup-epoch-1\n",
            ),
            (
                DERIVER_A_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF_ENV,
                "online epoch-1",
            ),
            (
                DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY_ENV,
                " x25519:00",
            ),
        ] {
            assert!(
                parse_cloudflare_tenant_root_operational_rotation_provider_config_v1(
                    CloudflareWorkerRoleV1::DeriverA,
                    &env.clone().with_overrides(vec![(key, value)]),
                )
                .is_err()
            );
        }

        let same_public_key_env = env.with_overrides(vec![(
            DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY_ENV,
            operational_public_descriptor(0x61),
        )]);
        assert_eq!(
            parse_cloudflare_tenant_root_operational_rotation_provider_config_v1(
                CloudflareWorkerRoleV1::DeriverA,
                &same_public_key_env,
            )
            .expect_err("online and backup public keys must be distinct")
            .code(),
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig
        );
    }

    #[test]
    fn operational_private_key_secret_decoder_is_strict_and_owned() {
        let expected = operational_private_secret(0x81);
        let decoded =
            decode_cloudflare_tenant_root_operational_hpke_private_key_secret_v1(&expected)
                .expect("operational private Secret");
        let (private_key, _) = operational_keypair(0x81);
        assert_eq!(decoded.as_slice(), private_key);

        for malformed in [
            format!(" {expected}"),
            format!("{expected} "),
            expected.to_ascii_uppercase(),
            expected
                .trim_start_matches("hpke-x25519-private-v1:")
                .to_owned(),
            format!("{expected}="),
        ] {
            assert!(
                decode_cloudflare_tenant_root_operational_hpke_private_key_secret_v1(&malformed,)
                    .is_err()
            );
        }
    }
}

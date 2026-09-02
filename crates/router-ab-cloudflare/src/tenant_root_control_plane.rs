//! Tenant-root control-plane issuer operations.
//!
//! The control plane is the sole holder of the R120 issuer private signing
//! key. Every operation here constructs a canonical artifact from
//! authoritative Durable Object state and local key configuration, then
//! signs it. There is deliberately no raw-payload signing entry point: the
//! request types name *what* to issue, never the bytes to sign.

use router_ab_core::{
    TenantRootCeremonyContextV1, TenantRootControlPlaneAuthorityIdV1, TenantRootCreationJournalV1,
    TenantRootRoleCreationCommandPackageV1, TenantRootRoleCreationCommandV1,
    TENANT_ROOT_MAX_LIFETIME_MS_V1,
};
use serde::{Deserialize, Serialize};
use threshold_prf::TwoPartyDeriverRole;
use zeroize::Zeroizing;

use crate::durable_object::tenant_root_creation::{
    CloudflareTenantRootCreationInstallationRoleV1,
    CloudflareTenantRootCreationJournalReadResponseV1, ValidatedTenantRootCreationJournalV1,
};
use crate::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};

/// Maximum accepted request size for the role creation command operation.
pub const TENANT_ROOT_CONTROL_PLANE_ROLE_CREATION_COMMAND_REQUEST_MAX_BYTES_V1: usize = 2 * 1024;

/// Role label on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareTenantRootControlPlaneRoleV1 {
    DeriverA,
    DeriverB,
}

impl CloudflareTenantRootControlPlaneRoleV1 {
    pub(crate) const fn to_protocol(self) -> TwoPartyDeriverRole {
        match self {
            Self::DeriverA => TwoPartyDeriverRole::DeriverA,
            Self::DeriverB => TwoPartyDeriverRole::DeriverB,
        }
    }
}

/// Router -> control plane: mint the creation command for one role.
///
/// This is the entire caller-supplied surface. Authority, revision, session,
/// nonce, journal, context, time window, and issuer key are all derived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootControlPlaneRoleCreationCommandRequestV1 {
    pub identity_digest_b64u: String,
    pub custody_lineage_b64u: String,
    pub role: CloudflareTenantRootControlPlaneRoleV1,
}

/// Control plane -> Router: the signed command and its self-contained package.
///
/// Public bytes only. The package carries the Started journal preimage so a
/// Deriver can verify the command at its own boundary with no Router state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootControlPlaneRoleCreationCommandResponseV1 {
    pub role: CloudflareTenantRootControlPlaneRoleV1,
    pub issuer_key_id: String,
    pub role_creation_command_b64u: String,
    pub role_creation_command_package_b64u: String,
}

/// Public creation progress the issuer must respect before minting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TenantRootCreationProgressV1 {
    pub(crate) committed_roles: Vec<TwoPartyDeriverRole>,
    pub(crate) installation_checkpointed: bool,
}

impl TenantRootCreationProgressV1 {
    pub(crate) fn from_read_response(
        response: &CloudflareTenantRootCreationJournalReadResponseV1,
    ) -> Self {
        Self {
            committed_roles: response
                .committed_roles
                .iter()
                .map(|role: &CloudflareTenantRootCreationInstallationRoleV1| role.to_protocol())
                .collect(),
            installation_checkpointed: response.installation_checkpointed,
        }
    }
}

/// Everything the issuer derives before it signs; nothing here is caller-chosen.
pub(crate) struct TenantRootRoleCreationCommandIssuanceV1<'a> {
    /// Validated against the issuer's own published keys and the locally
    /// derived authority id.
    pub(crate) journal: &'a ValidatedTenantRootCreationJournalV1,
    pub(crate) progress: &'a TenantRootCreationProgressV1,
    pub(crate) role: TwoPartyDeriverRole,
    /// Derived from the Durable Object binding, never read from a request.
    pub(crate) authority_id: TenantRootControlPlaneAuthorityIdV1,
    pub(crate) now_ms: u64,
}

/// A signed command and the package a Deriver consumes. Both are public artifacts.
#[derive(Debug)]
pub(crate) struct IssuedTenantRootRoleCreationCommandV1 {
    pub(crate) command: TenantRootRoleCreationCommandV1,
    pub(crate) package: TenantRootRoleCreationCommandPackageV1,
}

fn refused(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::ForbiddenLocalBinding, message)
}

fn derivation(error: router_ab_core::RouterAbDerivationError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("tenant-root control-plane issuance failed: {error}"),
    )
}

/// Mints one role creation command from authoritative state.
///
/// Fail-closed conditions, in order: creation already checkpointed; the role
/// already committed; `now` outside the ceremony window; a command window
/// that would be empty. The command is then signed with the active issuer key
/// and packaged with the Started journal preimage.
pub(crate) fn issue_tenant_root_role_creation_command_v1(
    issuance: TenantRootRoleCreationCommandIssuanceV1<'_>,
    active_issuer_key_id: &str,
    issuer_seed: &Zeroizing<[u8; 32]>,
) -> RouterAbProtocolResult<IssuedTenantRootRoleCreationCommandV1> {
    if issuance.progress.installation_checkpointed {
        return Err(refused(
            "tenant-root creation is already checkpointed; no further role command may be issued",
        ));
    }
    if issuance.progress.committed_roles.contains(&issuance.role) {
        return Err(refused(
            "tenant-root creation role has already committed; its command may not be reissued",
        ));
    }
    let context: &TenantRootCeremonyContextV1 = &issuance.journal.ceremony_context;
    if issuance.now_ms < context.issued_at_ms() || issuance.now_ms >= context.expires_at_ms() {
        return Err(refused(
            "tenant-root creation ceremony window does not contain the issuance time",
        ));
    }
    let issued_at_ms = issuance.now_ms;
    let expires_at_ms = issued_at_ms
        .saturating_add(TENANT_ROOT_MAX_LIFETIME_MS_V1)
        .min(context.expires_at_ms());
    if expires_at_ms <= issued_at_ms {
        return Err(refused(
            "tenant-root creation ceremony window leaves no room for a role command",
        ));
    }
    let journal: &TenantRootCreationJournalV1 = &issuance.journal.journal;
    let command = TenantRootRoleCreationCommandV1::sign(
        journal,
        context,
        issuance.role,
        issuance.authority_id,
        issued_at_ms,
        expires_at_ms,
        active_issuer_key_id,
        issuer_seed,
    )
    .map_err(derivation)?;
    let package = TenantRootRoleCreationCommandPackageV1::new(journal.clone(), command.clone())
        .map_err(derivation)?;
    Ok(IssuedTenantRootRoleCreationCommandV1 { command, package })
}

#[cfg(feature = "workers-rs")]
pub use live::handle_cloudflare_tenant_root_control_plane_role_creation_command_v1;

#[cfg(feature = "workers-rs")]
mod live {
    use super::*;
    use crate::durable_object::tenant_root_creation::{
        decode_canonical_base64url, tenant_root_creation_object_name_v1, validate_creation_record,
        CloudflareTenantRootCreationJournalReadRequestV1,
        CloudflareTenantRootCreationJournalRecordV1,
        CLOUDFLARE_TENANT_ROOT_CREATION_JOURNAL_READ_PATH,
    };
    use crate::env::decode_cloudflare_tenant_root_control_plane_issuer_signing_secret_v1;
    use crate::{encode_base64url_bytes_v1, CloudflareTenantRootControlPlaneRuntimeV1};
    use router_ab_core::{TenantRootCustodyLineageId, TenantRootIdentityDigestV1};
    use zeroize::Zeroize;

    const ROUTER_TENANT_ROOT_CREATION_DO_BINDING_V1: &str = "ROUTER_TENANT_ROOT_CREATION_DO";

    fn local(message: String) -> RouterAbProtocolError {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            message,
        )
    }

    /// Reads authoritative creation state from the Router-owned Durable Object
    /// through this Worker's own external binding.
    async fn read_creation_state(
        env: &worker::Env,
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
    ) -> RouterAbProtocolResult<(
        TenantRootControlPlaneAuthorityIdV1,
        CloudflareTenantRootCreationJournalReadResponseV1,
    )> {
        let namespace = env
            .durable_object(ROUTER_TENANT_ROOT_CREATION_DO_BINDING_V1)
            .map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    format!("tenant-root creation Durable Object binding is unavailable: {error}"),
                )
            })?;
        let object_name = tenant_root_creation_object_name_v1(identity_digest, custody_lineage);
        let object_id = namespace
            .id_from_name(&object_name)
            .map_err(|error| {
                local(format!(
                    "tenant-root creation Durable Object id derivation failed: {error}"
                ))
            })?
            .to_string();
        // The authority id IS the object id: derived here, never read from a request.
        let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(
            crate::durable_object::tenant_root_creation::decode_lower_hex_32(
                "tenant-root creation Durable Object id",
                &object_id,
            )?,
        );
        let stub = namespace.get_by_name(&object_name).map_err(|error| {
            local(format!(
                "tenant-root creation Durable Object stub lookup failed: {error}"
            ))
        })?;
        let body = serde_json::to_string(&CloudflareTenantRootCreationJournalReadRequestV1 {
            identity_digest_b64u: encode_base64url_bytes_v1(identity_digest.as_bytes()),
            custody_lineage_b64u: encode_base64url_bytes_v1(custody_lineage.as_bytes()),
        })
        .map_err(|error| {
            local(format!(
                "tenant-root creation read request encoding failed: {error}"
            ))
        })?;
        let headers = worker::Headers::new();
        headers
            .set("content-type", "application/json")
            .map_err(|error| local(format!("tenant-root creation read headers failed: {error}")))?;
        crate::set_cloudflare_internal_service_auth_header_v1(
            env,
            &headers,
            "tenant-root creation read",
        )?;
        let mut init = worker::RequestInit::new();
        init.with_method(worker::Method::Post)
            .with_headers(headers)
            .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body)));
        let request = worker::Request::new_with_init(
            &format!(
                "https://router-ab-do.internal{CLOUDFLARE_TENANT_ROOT_CREATION_JOURNAL_READ_PATH}"
            ),
            &init,
        )
        .map_err(|error| {
            local(format!(
                "tenant-root creation read request construction failed: {error}"
            ))
        })?;
        let mut response = stub
            .fetch_with_request(request)
            .await
            .map_err(|error| local(format!("tenant-root creation read request failed: {error}")))?;
        if response.status_code() != 200 {
            return Err(refused(
                "tenant-root creation Durable Object refused the read",
            ));
        }
        let parsed: CloudflareTenantRootCreationJournalReadResponseV1 =
            response.json().await.map_err(|error| {
                local(format!(
                    "tenant-root creation read response decoding failed: {error}"
                ))
            })?;
        Ok((authority_id, parsed))
    }

    /// The typed issuer operation: mint one role creation command.
    pub async fn handle_cloudflare_tenant_root_control_plane_role_creation_command_v1(
        request: CloudflareTenantRootControlPlaneRoleCreationCommandRequestV1,
        env: &worker::Env,
        runtime: &CloudflareTenantRootControlPlaneRuntimeV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneRoleCreationCommandResponseV1> {
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(
            decode_canonical_base64url(
                "tenant-root control-plane identity digest",
                &request.identity_digest_b64u,
                32,
                48,
            )?
            .as_slice()
            .try_into()
            .map_err(|_| refused("tenant-root control-plane identity digest length is invalid"))?,
        );
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(
            decode_canonical_base64url(
                "tenant-root control-plane custody lineage",
                &request.custody_lineage_b64u,
                16,
                24,
            )?
            .as_slice()
            .try_into()
            .map_err(|_| refused("tenant-root control-plane custody lineage length is invalid"))?,
        )
        .map_err(|error| {
            refused_owned(format!(
                "tenant-root control-plane custody lineage is invalid: {error}"
            ))
        })?;

        let (authority_id, read) =
            read_creation_state(env, identity_digest, custody_lineage).await?;
        // Re-validate the returned bytes against OUR published keys and OUR derived
        // authority id: the object is authoritative, but the issuer trusts nothing
        // it did not verify itself.
        let record = CloudflareTenantRootCreationJournalRecordV1 {
            journal_b64u: read.journal_b64u.clone(),
            creation_capability_b64u: read.creation_capability_b64u.clone(),
        };
        let journal = validate_creation_record(
            record,
            authority_id,
            runtime.bindings().issuer_verifying_keys.keys(),
        )?;
        if journal.identity_digest != identity_digest || journal.custody_lineage != custody_lineage
        {
            return Err(refused(
                "tenant-root creation state does not name the requested identity and lineage",
            ));
        }
        let progress = TenantRootCreationProgressV1::from_read_response(&read);
        let now_ms = crate::cloudflare_now_unix_ms_v1()?;

        let binding = &runtime.bindings().issuer_signing_key;
        let secret = env.secret(binding.binding_name()).map_err(|error| {
            crate::worker_binding_error(
                crate::worker_binding_error_code(&error, binding.binding_name()),
                binding.binding_name(),
                "secret",
                error,
            )
        })?;
        let mut secret_value = secret.to_string();
        let seed =
            decode_cloudflare_tenant_root_control_plane_issuer_signing_secret_v1(&secret_value);
        secret_value.zeroize();
        let seed = seed?;

        let issued = issue_tenant_root_role_creation_command_v1(
            TenantRootRoleCreationCommandIssuanceV1 {
                journal: &journal,
                progress: &progress,
                role: request.role.to_protocol(),
                authority_id,
                now_ms,
            },
            binding.signing_key_id(),
            &seed,
        )?;
        Ok(
            CloudflareTenantRootControlPlaneRoleCreationCommandResponseV1 {
                role: request.role,
                issuer_key_id: binding.signing_key_id().to_owned(),
                role_creation_command_b64u: encode_base64url_bytes_v1(
                    &issued.command.canonical_bytes().map_err(derivation)?,
                ),
                role_creation_command_package_b64u: encode_base64url_bytes_v1(
                    &issued.package.canonical_bytes().map_err(derivation)?,
                ),
            },
        )
    }

    fn refused_owned(message: String) -> RouterAbProtocolError {
        RouterAbProtocolError::new(RouterAbProtocolErrorCode::ForbiddenLocalBinding, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable_object::tenant_root_creation::{
        validate_creation_record, CloudflareTenantRootCreationJournalRecordV1,
    };
    use crate::encode_base64url_bytes_v1;
    use ed25519_dalek::SigningKey;
    use router_ab_core::{
        TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1,
        TenantRootCreationCapabilityNonceV1, TenantRootCreationCapabilityV1,
        TenantRootCustodyLineageId, TenantRootIdentityV1,
    };
    use std::collections::BTreeMap;

    const ISSUER_KEY_ID: &str = "control-plane-issuer-active";
    const ISSUER_SEED: [u8; 32] = [0x51; 32];
    const OTHER_SEED: [u8; 32] = [0x52; 32];
    const AUTHORITY: [u8; 32] = [0x44; 32];
    // A 30-second ceremony window, inside the frozen 300-second maximum lifetime
    // that the capability, context, and command all enforce.
    const CEREMONY_ISSUED_AT_MS: u64 = 1_000_000;
    const CEREMONY_EXPIRES_AT_MS: u64 = 1_030_000;

    fn seed() -> Zeroizing<[u8; 32]> {
        Zeroizing::new(ISSUER_SEED)
    }

    fn published() -> BTreeMap<String, [u8; 32]> {
        BTreeMap::from([(
            ISSUER_KEY_ID.to_owned(),
            SigningKey::from_bytes(&ISSUER_SEED)
                .verifying_key()
                .to_bytes(),
        )])
    }

    fn authority() -> TenantRootControlPlaneAuthorityIdV1 {
        TenantRootControlPlaneAuthorityIdV1::from_bytes(AUTHORITY)
    }

    /// A persisted, issuer-authorized Started journal exactly as the Durable
    /// Object would hand it back and the issuer would re-validate it.
    fn validated_journal() -> ValidatedTenantRootCreationJournalV1 {
        let identity =
            TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
                .expect("identity");
        let lineage = TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage");
        let context = TenantRootCeremonyContextV1::new(
            identity.digest().expect("identity digest"),
            lineage,
            TenantRootCeremonyEpochsV1::create(),
            TenantRootCeremonySessionIdV1::from_bytes([0x11; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x33; 32]).expect("nonce"),
            CEREMONY_ISSUED_AT_MS,
            CEREMONY_EXPIRES_AT_MS,
            "deriver-a-signing-key-7",
            "deriver-b-signing-key-9",
        )
        .expect("context");
        let journal =
            TenantRootCreationJournalV1::started(identity, lineage, context).expect("journal");
        let capability = TenantRootCreationCapabilityV1::sign(
            journal.identity_digest(),
            journal.custody_lineage(),
            journal.digest().expect("journal digest"),
            authority(),
            TenantRootCreationCapabilityNonceV1::from_bytes([0x55; 32]).expect("capability nonce"),
            CEREMONY_ISSUED_AT_MS,
            CEREMONY_EXPIRES_AT_MS,
            ISSUER_KEY_ID,
            &ISSUER_SEED,
        )
        .expect("capability");
        validate_creation_record(
            CloudflareTenantRootCreationJournalRecordV1 {
                journal_b64u: encode_base64url_bytes_v1(
                    &journal.canonical_bytes().expect("journal bytes"),
                ),
                creation_capability_b64u: encode_base64url_bytes_v1(
                    &capability.canonical_bytes().expect("capability bytes"),
                ),
            },
            authority(),
            &published(),
        )
        .expect("validated journal")
    }

    fn fresh() -> TenantRootCreationProgressV1 {
        TenantRootCreationProgressV1 {
            committed_roles: Vec::new(),
            installation_checkpointed: false,
        }
    }

    fn issue(
        journal: &ValidatedTenantRootCreationJournalV1,
        progress: &TenantRootCreationProgressV1,
        role: TwoPartyDeriverRole,
        now_ms: u64,
        issuer_seed: &Zeroizing<[u8; 32]>,
    ) -> RouterAbProtocolResult<IssuedTenantRootRoleCreationCommandV1> {
        issue_tenant_root_role_creation_command_v1(
            TenantRootRoleCreationCommandIssuanceV1 {
                journal,
                progress: &progress.clone(),
                role,
                authority_id: authority(),
                now_ms,
            },
            ISSUER_KEY_ID,
            issuer_seed,
        )
    }

    #[test]
    fn issued_command_verifies_at_a_deriver_with_only_the_package_and_the_public_anchor() {
        let journal = validated_journal();
        let now = CEREMONY_ISSUED_AT_MS + 10_000;
        for role in [TwoPartyDeriverRole::DeriverA, TwoPartyDeriverRole::DeriverB] {
            let issued = issue(&journal, &fresh(), role, now, &seed()).expect("issued");

            // Exactly what a Deriver holds: the package bytes, its own expected
            // role and authority, and the published issuer key. No Router state.
            let package = TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(
                &issued.package.canonical_bytes().expect("package bytes"),
            )
            .expect("package decodes");
            let verified = package
                .verify(
                    role,
                    authority(),
                    ISSUER_KEY_ID,
                    &published()[ISSUER_KEY_ID],
                )
                .expect("verifies");
            assert_eq!(verified.command().role(), role);
            assert_eq!(verified.command().issuer_key_id(), ISSUER_KEY_ID);
            assert_eq!(issued.command.role(), role);

            // The window is derived: starts now, capped by the ceremony window
            // and the frozen maximum lifetime.
            assert_eq!(issued.command.issued_at_ms(), now);
            assert_eq!(
                issued.command.expires_at_ms(),
                (now + TENANT_ROOT_MAX_LIFETIME_MS_V1).min(CEREMONY_EXPIRES_AT_MS)
            );
            assert!(verified.command().require_fresh(now + 1).is_ok());

            // A Deriver expecting the other role must reject it.
            let other = match role {
                TwoPartyDeriverRole::DeriverA => TwoPartyDeriverRole::DeriverB,
                TwoPartyDeriverRole::DeriverB => TwoPartyDeriverRole::DeriverA,
            };
            assert!(package
                .verify(
                    other,
                    authority(),
                    ISSUER_KEY_ID,
                    &published()[ISSUER_KEY_ID]
                )
                .is_err());
        }
    }

    #[test]
    fn issuance_fails_closed_once_creation_is_checkpointed_or_the_role_committed() {
        let journal = validated_journal();
        let now = CEREMONY_ISSUED_AT_MS + 10_000;

        let checkpointed = TenantRootCreationProgressV1 {
            committed_roles: Vec::new(),
            installation_checkpointed: true,
        };
        assert_eq!(
            issue(
                &journal,
                &checkpointed,
                TwoPartyDeriverRole::DeriverA,
                now,
                &seed()
            )
            .expect_err("checkpointed")
            .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );

        let a_committed = TenantRootCreationProgressV1 {
            committed_roles: vec![TwoPartyDeriverRole::DeriverA],
            installation_checkpointed: false,
        };
        assert!(issue(
            &journal,
            &a_committed,
            TwoPartyDeriverRole::DeriverA,
            now,
            &seed()
        )
        .is_err());
        // The peer that has not committed may still be issued its command.
        assert!(issue(
            &journal,
            &a_committed,
            TwoPartyDeriverRole::DeriverB,
            now,
            &seed()
        )
        .is_ok());
    }

    #[test]
    fn issuance_fails_closed_outside_the_ceremony_window() {
        let journal = validated_journal();
        for now in [
            0,
            CEREMONY_ISSUED_AT_MS - 1,
            CEREMONY_EXPIRES_AT_MS,
            CEREMONY_EXPIRES_AT_MS + 1,
        ] {
            assert!(
                issue(
                    &journal,
                    &fresh(),
                    TwoPartyDeriverRole::DeriverA,
                    now,
                    &seed()
                )
                .is_err(),
                "now={now} must be refused"
            );
        }
        // The last instant inside the window still yields a non-empty command window.
        let issued = issue(
            &journal,
            &fresh(),
            TwoPartyDeriverRole::DeriverA,
            CEREMONY_EXPIRES_AT_MS - 1,
            &seed(),
        )
        .expect("edge of window");
        assert_eq!(issued.command.expires_at_ms(), CEREMONY_EXPIRES_AT_MS);
    }

    #[test]
    fn a_command_signed_with_the_wrong_seed_never_verifies_under_the_published_key() {
        // The issuer cannot mint a verifiable command without the seed that
        // derives the published active key; boot-time provenance proves the
        // seed, this proves the consequence if it were ever bypassed.
        let journal = validated_journal();
        let issued = issue(
            &journal,
            &fresh(),
            TwoPartyDeriverRole::DeriverA,
            CEREMONY_ISSUED_AT_MS + 10_000,
            &Zeroizing::new(OTHER_SEED),
        )
        .expect("signing itself succeeds");
        assert!(issued
            .package
            .verify(
                TwoPartyDeriverRole::DeriverA,
                authority(),
                ISSUER_KEY_ID,
                &published()[ISSUER_KEY_ID],
            )
            .is_err());
    }

    #[test]
    fn the_request_surface_names_only_identity_lineage_and_role() {
        // Structural: every other command field is derived by the issuer.
        let request = CloudflareTenantRootControlPlaneRoleCreationCommandRequestV1 {
            identity_digest_b64u: "a".repeat(43),
            custody_lineage_b64u: "b".repeat(22),
            role: CloudflareTenantRootControlPlaneRoleV1::DeriverB,
        };
        let json = serde_json::to_value(&request).expect("json");
        let mut keys: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["custody_lineage_b64u", "identity_digest_b64u", "role"]
        );
        // Unknown fields such as an authority id or a time window are rejected.
        let smuggled = r#"{"identity_digest_b64u":"a","custody_lineage_b64u":"b","role":"deriver_a","authority_id_b64u":"x"}"#;
        assert!(
            serde_json::from_str::<CloudflareTenantRootControlPlaneRoleCreationCommandRequestV1>(
                smuggled
            )
            .is_err()
        );
    }
}

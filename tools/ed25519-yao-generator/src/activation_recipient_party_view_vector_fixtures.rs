//! Strict synthetic corpus for post-release activation recipient party views.

use core::fmt;

use serde::Serialize;

use crate::activation_recipient_party_view_fixtures::{
    canonical_activated_recipient_fixture_v1, canonical_activation_recipients_released_v1,
};
use crate::activation_recipient_party_views::{
    activation_client_delivery_evidence_v1,
    build_host_only_activation_recipients_released_party_view_set_v1,
    build_host_only_signing_worker_activated_party_view_set_v1,
    HostOnlyActivationRecipientAuthorizationStateV1,
};
use crate::lifecycle_domain::{ActivationPackageOriginV1, ZeroReevaluationWitnessV1};

/// Schema identifier for the strict activation recipient-party-view corpus.
pub const ACTIVATION_RECIPIENT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:activation-recipient-party-views:v1";

/// Scope separating synthetic custody evidence from deployed delivery claims.
pub const ACTIVATION_RECIPIENT_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1: &str =
    "host_only_synthetic_activation_recipient_party_views_v1";

/// Strict registration/recovery/refresh post-release recipient-view corpus.
#[derive(Serialize)]
pub struct ActivationRecipientPartyViewVectorCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    cases: Vec<ActivationRecipientPartyViewVectorCaseV1>,
}

impl ActivationRecipientPartyViewVectorCorpusV1 {
    /// Returns the fixed corpus schema.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Returns the fixed protocol identifier.
    pub fn protocol_id(&self) -> &str {
        &self.protocol_id
    }

    /// Returns the narrow host-only evidence scope.
    pub fn evidence_scope(&self) -> &str {
        &self.evidence_scope
    }

    /// Returns the exact case count.
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }
}

#[derive(Serialize)]
struct ActivationRecipientPartyViewVectorCaseV1 {
    case_id: String,
    origin_request_kind: ActivationRecipientOriginRequestKindVectorV1,
    activation_delivery_case_id: String,
    output_party_view_case_id: String,
    recipients_released: ActivationRecipientsReleasedPartyViewsVectorV1,
    signing_worker_activated: SigningWorkerActivatedPartyViewsVectorV1,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ActivationRecipientOriginRequestKindVectorV1 {
    Registration,
    Recovery,
    Refresh,
}

#[derive(Serialize)]
struct ActivationRecipientsReleasedPartyViewsVectorV1 {
    common_public: ActivationRecipientsReleasedCommonVectorV1,
    role_extensions: ActivationRecipientsReleasedRoleExtensionsVectorV1,
}

#[derive(Serialize)]
struct ActivationRecipientsReleasedCommonVectorV1 {
    stage: ActivationRecipientsReleasedStageVectorV1,
    origin_request_kind: ActivationRecipientOriginRequestKindVectorV1,
    package_set_digest_hex: String,
    output_committed_receipt_digest_hex: String,
    activation_transcript_digest_hex: String,
    activation_authorization_state: ActivationRecipientAuthorizationStateVectorV1,
    zero_private_evaluation_work: ActivationRecipientZeroWorkVectorV1,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ActivationRecipientsReleasedStageVectorV1 {
    RecipientsReleased,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ActivationRecipientAuthorizationStateVectorV1 {
    Consumed,
}

#[derive(Serialize)]
struct ActivationRecipientsReleasedRoleExtensionsVectorV1 {
    deriver_a: EmptyActivationRecipientExtensionV1,
    deriver_b: EmptyActivationRecipientExtensionV1,
    client: ActivationRecipientClientCapabilityVectorV1,
    signing_worker: ActivationSigningWorkerReleaseAuthorityVectorV1,
    router: EmptyActivationRecipientExtensionV1,
    observer: EmptyActivationRecipientExtensionV1,
    diagnostics: EmptyActivationRecipientExtensionV1,
}

#[derive(Serialize)]
struct ActivationRecipientClientCapabilityVectorV1 {
    extension_kind: ActivationClientExtensionKindVectorV1,
    package_set_digest_hex: String,
    delivery_evidence_digest_hex: String,
    x_client_base_hex: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ActivationClientExtensionKindVectorV1 {
    ActivationClientScalarRelease,
}

#[derive(Serialize)]
struct ActivationSigningWorkerReleaseAuthorityVectorV1 {
    extension_kind: ActivationSigningWorkerReleaseExtensionKindVectorV1,
    package_set_digest_hex: String,
    delivery_evidence_digest_hex: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ActivationSigningWorkerReleaseExtensionKindVectorV1 {
    SigningWorkerActivationReleaseAuthority,
}

#[derive(Serialize)]
struct SigningWorkerActivatedPartyViewsVectorV1 {
    common_public: SigningWorkerActivatedCommonVectorV1,
    role_extensions: SigningWorkerActivatedRoleExtensionsVectorV1,
}

#[derive(Serialize)]
struct SigningWorkerActivatedCommonVectorV1 {
    stage: SigningWorkerActivatedStageVectorV1,
    origin_request_kind: ActivationRecipientOriginRequestKindVectorV1,
    package_set_digest_hex: String,
    output_committed_receipt_digest_hex: String,
    activation_epoch: u64,
    signing_worker_id: String,
    signing_worker_recipient_key_epoch: u64,
    registered_public_key_hex: String,
    x_server_hex: String,
    output_storage_evidence_digest_hex: String,
    activation_receipt_encoding_hex: String,
    activation_receipt_digest_hex: String,
    activation_receipt_signature_hex: String,
    receipt_key_epoch: u64,
    receipt_key_digest_hex: String,
    receipt_verifying_key_hex: String,
    activation_authorization_state: ActivationRecipientAuthorizationStateVectorV1,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum SigningWorkerActivatedStageVectorV1 {
    SigningWorkerActivated,
}

#[derive(Serialize)]
struct SigningWorkerActivatedRoleExtensionsVectorV1 {
    deriver_a: EmptyActivationRecipientExtensionV1,
    deriver_b: EmptyActivationRecipientExtensionV1,
    client: ActivationRecipientClientCapabilityVectorV1,
    signing_worker: ActivatedSigningWorkerExtensionVectorV1,
    router: EmptyActivationRecipientExtensionV1,
    observer: EmptyActivationRecipientExtensionV1,
    diagnostics: EmptyActivationRecipientExtensionV1,
}

#[derive(Serialize)]
struct ActivatedSigningWorkerExtensionVectorV1 {
    extension_kind: ActivatedSigningWorkerExtensionKindVectorV1,
    x_server_base_hex: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ActivatedSigningWorkerExtensionKindVectorV1 {
    SealedSigningWorkerActivatedState,
}

#[derive(Serialize)]
struct EmptyActivationRecipientExtensionV1 {}

#[derive(Serialize)]
struct ActivationRecipientZeroWorkVectorV1 {
    yao_evaluations: u8,
    deriver_a_invocations: u8,
    deriver_b_invocations: u8,
    contribution_derivations: u8,
    output_share_samples: u8,
}

/// Failure returned for noncanonical activation recipient-party-view bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationRecipientPartyViewVectorCorpusParseErrorV1;

impl fmt::Display for ActivationRecipientPartyViewVectorCorpusParseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "activation recipient-party-view corpus must equal the exact canonical LF-terminated JSON bytes",
        )
    }
}

impl std::error::Error for ActivationRecipientPartyViewVectorCorpusParseErrorV1 {}

/// Builds the canonical three-origin activation recipient-party-view corpus.
pub fn canonical_activation_recipient_party_view_vector_corpus_v1(
) -> ActivationRecipientPartyViewVectorCorpusV1 {
    ActivationRecipientPartyViewVectorCorpusV1 {
        schema: ACTIVATION_RECIPIENT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: ACTIVATION_RECIPIENT_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1.to_owned(),
        cases: [
            ActivationPackageOriginV1::Registration,
            ActivationPackageOriginV1::Recovery,
            ActivationPackageOriginV1::Refresh,
        ]
        .into_iter()
        .map(activation_recipient_party_view_case)
        .collect(),
    }
}

/// Encodes the exact canonical corpus with one trailing LF.
pub fn canonical_activation_recipient_party_view_vector_corpus_json_bytes_v1() -> Vec<u8> {
    let mut encoded =
        serde_json::to_vec_pretty(&canonical_activation_recipient_party_view_vector_corpus_v1())
            .expect("fixed activation recipient-party-view corpus serializes");
    encoded.push(b'\n');
    encoded
}

/// Parses only the exact canonical LF-terminated corpus bytes.
pub fn parse_canonical_activation_recipient_party_view_vector_corpus_json_v1(
    encoded: &[u8],
) -> Result<
    ActivationRecipientPartyViewVectorCorpusV1,
    ActivationRecipientPartyViewVectorCorpusParseErrorV1,
> {
    if encoded != canonical_activation_recipient_party_view_vector_corpus_json_bytes_v1() {
        return Err(ActivationRecipientPartyViewVectorCorpusParseErrorV1);
    }
    Ok(canonical_activation_recipient_party_view_vector_corpus_v1())
}

fn activation_recipient_party_view_case(
    origin: ActivationPackageOriginV1,
) -> ActivationRecipientPartyViewVectorCaseV1 {
    ActivationRecipientPartyViewVectorCaseV1 {
        case_id: case_id(origin).to_owned(),
        origin_request_kind: origin_kind(origin),
        activation_delivery_case_id: activation_delivery_case_id(origin).to_owned(),
        output_party_view_case_id: output_party_view_case_id(origin).to_owned(),
        recipients_released: recipients_released_views(origin),
        signing_worker_activated: signing_worker_activated_views(origin),
    }
}

fn recipients_released_views(
    origin: ActivationPackageOriginV1,
) -> ActivationRecipientsReleasedPartyViewsVectorV1 {
    let common_view = build_host_only_activation_recipients_released_party_view_set_v1(
        canonical_activation_recipients_released_v1(origin),
    )
    .expect("canonical release views")
    .observe_observer_v1();
    let common = common_view.common();

    let client_view = build_host_only_activation_recipients_released_party_view_set_v1(
        canonical_activation_recipients_released_v1(origin),
    )
    .expect("canonical release views")
    .observe_client_v1();
    let client = client_view.capability();

    let worker_view = build_host_only_activation_recipients_released_party_view_set_v1(
        canonical_activation_recipients_released_v1(origin),
    )
    .expect("canonical release views")
    .observe_signing_worker_v1();
    let worker_package = *worker_view.common().package_set_digest();
    let worker_evidence = worker_view.delivery_evidence();

    assert_eq!(
        common.authorization_state(),
        HostOnlyActivationRecipientAuthorizationStateV1::Consumed
    );
    ActivationRecipientsReleasedPartyViewsVectorV1 {
        common_public: ActivationRecipientsReleasedCommonVectorV1 {
            stage: ActivationRecipientsReleasedStageVectorV1::RecipientsReleased,
            origin_request_kind: origin_kind(origin),
            package_set_digest_hex: encode_hex(common.package_set_digest()),
            output_committed_receipt_digest_hex: encode_hex(
                common.output_committed_receipt_digest(),
            ),
            activation_transcript_digest_hex: encode_hex(common.activation_transcript_digest()),
            activation_authorization_state: ActivationRecipientAuthorizationStateVectorV1::Consumed,
            zero_private_evaluation_work: zero_work(common.zero_private_work()),
        },
        role_extensions: ActivationRecipientsReleasedRoleExtensionsVectorV1 {
            deriver_a: EmptyActivationRecipientExtensionV1 {},
            deriver_b: EmptyActivationRecipientExtensionV1 {},
            client: client_extension(client),
            signing_worker: ActivationSigningWorkerReleaseAuthorityVectorV1 {
                extension_kind: ActivationSigningWorkerReleaseExtensionKindVectorV1::SigningWorkerActivationReleaseAuthority,
                package_set_digest_hex: encode_hex(&worker_package),
                delivery_evidence_digest_hex: encode_hex(worker_evidence.as_bytes()),
            },
            router: EmptyActivationRecipientExtensionV1 {},
            observer: EmptyActivationRecipientExtensionV1 {},
            diagnostics: EmptyActivationRecipientExtensionV1 {},
        },
    }
}

fn signing_worker_activated_views(
    origin: ActivationPackageOriginV1,
) -> SigningWorkerActivatedPartyViewsVectorV1 {
    let fixture = canonical_activated_recipient_fixture_v1(origin);
    let x_server_base = fixture.x_server_base().expose_bytes();
    let (client, signing_worker) = fixture.into_recipient_states();
    let common_view =
        build_host_only_signing_worker_activated_party_view_set_v1(client, signing_worker)
            .expect("canonical activated views")
            .observe_observer_v1();
    let common = common_view.common();

    let fixture = canonical_activated_recipient_fixture_v1(origin);
    let (client, signing_worker) = fixture.into_recipient_states();
    let client_view =
        build_host_only_signing_worker_activated_party_view_set_v1(client, signing_worker)
            .expect("canonical activated views")
            .observe_client_v1();

    let fixture = canonical_activated_recipient_fixture_v1(origin);
    let (client, signing_worker) = fixture.into_recipient_states();
    let worker_view =
        build_host_only_signing_worker_activated_party_view_set_v1(client, signing_worker)
            .expect("canonical activated views")
            .observe_signing_worker_v1();
    assert_eq!(worker_view.common().origin(), origin);

    SigningWorkerActivatedPartyViewsVectorV1 {
        common_public: SigningWorkerActivatedCommonVectorV1 {
            stage: SigningWorkerActivatedStageVectorV1::SigningWorkerActivated,
            origin_request_kind: origin_kind(origin),
            package_set_digest_hex: encode_hex(common.package_set_digest()),
            output_committed_receipt_digest_hex: encode_hex(
                common.output_committed_receipt_digest(),
            ),
            activation_epoch: common.activation_epoch().value(),
            signing_worker_id: common.worker().id().as_str().to_owned(),
            signing_worker_recipient_key_epoch: common.worker().key_epoch().value(),
            registered_public_key_hex: encode_hex(common.registered_public_key().as_bytes()),
            x_server_hex: encode_hex(common.x_server()),
            output_storage_evidence_digest_hex: encode_hex(
                common.storage_receipt_digest().as_bytes(),
            ),
            activation_receipt_encoding_hex: encode_hex(common.activation_receipt_encoding()),
            activation_receipt_digest_hex: encode_hex(
                common.activation_receipt_digest().as_bytes(),
            ),
            activation_receipt_signature_hex: encode_hex(
                common.activation_receipt_signature().as_bytes(),
            ),
            receipt_key_epoch: common.receipt_key_epoch().value(),
            receipt_key_digest_hex: encode_hex(common.receipt_key_digest()),
            receipt_verifying_key_hex: encode_hex(common.receipt_verifying_key()),
            activation_authorization_state: match common.authorization_state() {
                HostOnlyActivationRecipientAuthorizationStateV1::Consumed => {
                    ActivationRecipientAuthorizationStateVectorV1::Consumed
                }
            },
        },
        role_extensions: SigningWorkerActivatedRoleExtensionsVectorV1 {
            deriver_a: EmptyActivationRecipientExtensionV1 {},
            deriver_b: EmptyActivationRecipientExtensionV1 {},
            client: client_extension(client_view.capability()),
            signing_worker: ActivatedSigningWorkerExtensionVectorV1 {
                extension_kind:
                    ActivatedSigningWorkerExtensionKindVectorV1::SealedSigningWorkerActivatedState,
                x_server_base_hex: encode_hex(&x_server_base),
            },
            router: EmptyActivationRecipientExtensionV1 {},
            observer: EmptyActivationRecipientExtensionV1 {},
            diagnostics: EmptyActivationRecipientExtensionV1 {},
        },
    }
}

fn client_extension(
    client: &crate::activation_delivery::HostOnlyActivationClientReleasedV1,
) -> ActivationRecipientClientCapabilityVectorV1 {
    ActivationRecipientClientCapabilityVectorV1 {
        extension_kind: ActivationClientExtensionKindVectorV1::ActivationClientScalarRelease,
        package_set_digest_hex: encode_hex(client.package_set_digest().as_bytes()),
        delivery_evidence_digest_hex: encode_hex(
            activation_client_delivery_evidence_v1(client).as_bytes(),
        ),
        x_client_base_hex: encode_hex(&client.x_client_base().expose_bytes()),
    }
}

fn zero_work(witness: ZeroReevaluationWitnessV1) -> ActivationRecipientZeroWorkVectorV1 {
    ActivationRecipientZeroWorkVectorV1 {
        yao_evaluations: witness.yao_evaluations(),
        deriver_a_invocations: witness.deriver_a_invocations(),
        deriver_b_invocations: witness.deriver_b_invocations(),
        contribution_derivations: witness.contribution_derivations(),
        output_share_samples: witness.output_share_samples(),
    }
}

const fn origin_kind(
    origin: ActivationPackageOriginV1,
) -> ActivationRecipientOriginRequestKindVectorV1 {
    match origin {
        ActivationPackageOriginV1::Registration => {
            ActivationRecipientOriginRequestKindVectorV1::Registration
        }
        ActivationPackageOriginV1::Recovery => {
            ActivationRecipientOriginRequestKindVectorV1::Recovery
        }
        ActivationPackageOriginV1::Refresh => ActivationRecipientOriginRequestKindVectorV1::Refresh,
    }
}

const fn case_id(origin: ActivationPackageOriginV1) -> &'static str {
    match origin {
        ActivationPackageOriginV1::Registration => {
            "registration_activation_recipient_party_views_v1"
        }
        ActivationPackageOriginV1::Recovery => "recovery_activation_recipient_party_views_v1",
        ActivationPackageOriginV1::Refresh => "refresh_activation_recipient_party_views_v1",
    }
}

const fn activation_delivery_case_id(origin: ActivationPackageOriginV1) -> &'static str {
    match origin {
        ActivationPackageOriginV1::Registration => "registration_activation_delivery_v1",
        ActivationPackageOriginV1::Recovery => "recovery_activation_delivery_v1",
        ActivationPackageOriginV1::Refresh => "refresh_activation_delivery_v1",
    }
}

const fn output_party_view_case_id(origin: ActivationPackageOriginV1) -> &'static str {
    match origin {
        ActivationPackageOriginV1::Registration => {
            "registration_output_party_views_package_prepared_v1"
        }
        ActivationPackageOriginV1::Recovery => "recovery_output_party_views_package_prepared_v1",
        ActivationPackageOriginV1::Refresh => "refresh_output_party_views_package_prepared_v1",
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

//! Deterministic prose goldens for the fixed reference specification.

use core::fmt;
use core::fmt::Write as _;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};

use crate::kdf::contribution_expand_info_v1;
use crate::kdf_fixtures::canonical_synthetic_kdf_material_v1;
use crate::{
    canonical_activation_delivery_vector_corpus_json_bytes_v1,
    canonical_activation_delivery_vector_corpus_v1,
    canonical_activation_recipient_party_view_vector_corpus_json_bytes_v1,
    canonical_activation_recipient_party_view_vector_corpus_v1,
    canonical_ceremony_context_vector_corpus_v1,
    canonical_evaluation_input_party_view_vector_corpus_json_bytes_v1,
    canonical_evaluation_input_party_view_vector_corpus_v1,
    canonical_evaluator_abort_view_vector_corpus_json_bytes_v1,
    canonical_evaluator_abort_view_vector_corpus_v1,
    canonical_export_delivery_vector_corpus_json_bytes_v1,
    canonical_export_delivery_vector_corpus_v1,
    canonical_export_evaluator_authorization_vector_corpus_json_bytes_v1,
    canonical_export_evaluator_authorization_vector_corpus_v1, canonical_kdf_vector_corpus_v1,
    canonical_lifecycle_continuity_corpus_v1,
    canonical_output_party_view_vector_corpus_json_bytes_v1,
    canonical_output_party_view_vector_corpus_v1,
    canonical_output_sharing_vector_corpus_json_bytes_v1,
    canonical_output_sharing_vector_corpus_v1, canonical_provenance_vector_corpus_v1,
    canonical_recovery_credential_transition_vector_corpus_json_bytes_v1,
    canonical_recovery_credential_transition_vector_corpus_v1,
    canonical_recovery_evaluator_admission_vector_corpus_json_bytes_v1,
    canonical_recovery_evaluator_admission_vector_corpus_v1,
    canonical_registration_evaluator_admission_vector_corpus_json_bytes_v1,
    canonical_registration_evaluator_admission_vector_corpus_v1,
    canonical_semantic_lifecycle_vector_corpus_json_bytes_v1,
    canonical_semantic_lifecycle_vector_corpus_v1,
    canonical_uniform_abort_vector_corpus_json_bytes_v1, canonical_uniform_abort_vector_corpus_v1,
    canonical_vector_corpus_v1, clamp_rfc8032, StableKeyDerivationContext,
    CONTRIBUTION_KDF_CLIENT_SOURCE_TAG_V1, CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1,
    CONTRIBUTION_KDF_EXPAND_INFO_LEN_V1, CONTRIBUTION_KDF_EXTRACT_SALT_V1,
    CONTRIBUTION_KDF_ROLE_A_TAG_V1, CONTRIBUTION_KDF_ROLE_B_TAG_V1,
    CONTRIBUTION_KDF_SERVER_SOURCE_TAG_V1, CONTRIBUTION_KDF_TAU_OUTPUT_TAG_V1,
    CONTRIBUTION_KDF_Y_OUTPUT_TAG_V1, ED25519_YAO_APPLICATION_BINDING_DOMAIN_V1,
    ED25519_YAO_APPLICATION_BINDING_KEY_CREATION_SIGNER_SLOT_LABEL_V1,
    ED25519_YAO_APPLICATION_BINDING_SIGNING_KEY_ID_LABEL_V1,
    ED25519_YAO_APPLICATION_BINDING_SIGNING_ROOT_ID_LABEL_V1,
    ED25519_YAO_APPLICATION_BINDING_WALLET_ID_LABEL_V1,
    STABLE_KEY_DERIVATION_CONTEXT_BINDING_DOMAIN_V1, STABLE_KEY_DERIVATION_CONTEXT_DOMAIN_V1,
};

const OUTPUT_SHARING_SPECIFICATION_V1: &[u8] = include_bytes!("../docs/output-sharing-v1.md");
const CIRCUIT_IR_SPECIFICATION_V1: &[u8] = include_bytes!("../docs/circuit-ir-v1.md");
const CEREMONY_CONTEXT_SPECIFICATION_V1: &[u8] = include_bytes!("../docs/ceremony-context-v1.md");
const INPUT_PROVENANCE_SPECIFICATION_V1: &[u8] = include_bytes!("../docs/input-provenance-v1.md");
const SEMANTIC_ARTIFACT_LIFECYCLE_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/semantic-artifact-lifecycle-v1.md");
const OUTPUT_PARTY_VIEWS_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/output-party-views-v1.md");
const EVALUATION_INPUT_PARTY_VIEWS_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/evaluation-input-party-views-v1.md");
const UNIFORM_ABORT_ENVELOPE_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/uniform-abort-envelope-v1.md");
const EVALUATOR_ABORT_STATE_PARTY_VIEWS_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/evaluator-abort-state-party-views-v1.md");
const AUTHENTICATED_STORE_RESOLUTION_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/authenticated-store-resolution-v1.md");
const SIGNING_WORKER_ACTIVATION_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/signing-worker-activation-v1.md");
const REFRESH_PROMOTION_SPECIFICATION_V1: &[u8] = include_bytes!("../docs/refresh-promotion-v1.md");
const BENCHMARK_MANIFEST_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/benchmark-manifest-v1.md");
const ARTIFACT_FILESYSTEM_POLICY_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/artifact-filesystem-policy-v1.md");
const JOINT_REFRESH_DELTA_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/joint-refresh-delta-v1.md");
const EXPORT_DELIVERY_LIFECYCLE_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/export-delivery-lifecycle-v1.md");
const ACTIVATION_DELIVERY_LIFECYCLE_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/activation-delivery-lifecycle-v1.md");
const ACTIVATION_RECIPIENT_PARTY_VIEWS_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/activation-recipient-party-views-v1.md");
const RECOVERY_CREDENTIAL_TRANSITION_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/recovery-credential-transition-v1.md");
const EXPORT_EVALUATOR_AUTHORIZATION_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/export-evaluator-authorization-v1.md");
const REGISTRATION_EVALUATOR_ADMISSION_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/registration-evaluator-admission-v1.md");
const RECOVERY_EVALUATOR_ADMISSION_SPECIFICATION_V1: &[u8] =
    include_bytes!("../docs/recovery-evaluator-admission-v1.md");

/// Opening marker for the only generated region in `fixed-reference-v1.md`.
pub const FIXED_REFERENCE_GENERATED_BEGIN_V1: &str =
    "<!-- BEGIN GENERATED: ED25519_YAO_FIXED_REFERENCE_V1 -->";

/// Closing marker for the only generated region in `fixed-reference-v1.md`.
pub const FIXED_REFERENCE_GENERATED_END_V1: &str =
    "<!-- END GENERATED: ED25519_YAO_FIXED_REFERENCE_V1 -->";

/// Schema identifier for the generated fixed-reference prose block.
pub const FIXED_REFERENCE_GENERATED_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:fixed-reference-goldens:v1";

/// Failure while locating or rendering the fixed-reference generated region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixedReferenceSpecificationErrorV1 {
    /// The opening marker is absent.
    MissingBeginMarker,
    /// More than one opening marker is present.
    DuplicateBeginMarker,
    /// The closing marker is absent.
    MissingEndMarker,
    /// More than one closing marker is present.
    DuplicateEndMarker,
    /// A marker is not on its own LF-delimited line.
    NonCanonicalMarkerLine,
    /// The closing marker appears before the opening marker.
    InvalidMarkerOrder,
    /// The specification does not end in exactly one LF.
    NonCanonicalDocumentEnding,
    /// A canonical corpus could not be serialized.
    CorpusSerialization {
        /// Stable corpus label.
        corpus: &'static str,
        /// Serialization failure text.
        message: String,
    },
}

impl fmt::Display for FixedReferenceSpecificationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBeginMarker => {
                formatter.write_str("fixed-reference begin marker is missing")
            }
            Self::DuplicateBeginMarker => {
                formatter.write_str("fixed-reference begin marker appears more than once")
            }
            Self::MissingEndMarker => formatter.write_str("fixed-reference end marker is missing"),
            Self::DuplicateEndMarker => {
                formatter.write_str("fixed-reference end marker appears more than once")
            }
            Self::NonCanonicalMarkerLine => {
                formatter.write_str("fixed-reference markers must occupy standalone LF lines")
            }
            Self::InvalidMarkerOrder => {
                formatter.write_str("fixed-reference end marker precedes its begin marker")
            }
            Self::NonCanonicalDocumentEnding => {
                formatter.write_str("fixed-reference specification must end in exactly one LF")
            }
            Self::CorpusSerialization { corpus, message } => {
                write!(formatter, "failed to serialize {corpus} corpus: {message}")
            }
        }
    }
}

impl std::error::Error for FixedReferenceSpecificationErrorV1 {}

struct CorpusCommitment {
    path: &'static str,
    schema: String,
    case_count: usize,
    byte_length: usize,
    sha256_hex: String,
}

struct KdfGoldenRow<'a> {
    role: &'static str,
    role_tag: u8,
    source: &'static str,
    source_tag: u8,
    output: &'static str,
    output_tag: u8,
    output_hex: &'a str,
}

/// Replaces the single generated region with canonical version-one prose.
pub fn render_fixed_reference_specification_v1(
    template: &str,
) -> Result<String, FixedReferenceSpecificationErrorV1> {
    if !template.ends_with('\n') || template.ends_with("\n\n") || template.ends_with("\r\n") {
        return Err(FixedReferenceSpecificationErrorV1::NonCanonicalDocumentEnding);
    }
    let begin = unique_marker(
        template,
        FIXED_REFERENCE_GENERATED_BEGIN_V1,
        FixedReferenceSpecificationErrorV1::MissingBeginMarker,
        FixedReferenceSpecificationErrorV1::DuplicateBeginMarker,
    )?;
    let end = unique_marker(
        template,
        FIXED_REFERENCE_GENERATED_END_V1,
        FixedReferenceSpecificationErrorV1::MissingEndMarker,
        FixedReferenceSpecificationErrorV1::DuplicateEndMarker,
    )?;

    if end <= begin {
        return Err(FixedReferenceSpecificationErrorV1::InvalidMarkerOrder);
    }
    if !is_standalone_lf_line(template, begin, FIXED_REFERENCE_GENERATED_BEGIN_V1)
        || !is_standalone_lf_line(template, end, FIXED_REFERENCE_GENERATED_END_V1)
    {
        return Err(FixedReferenceSpecificationErrorV1::NonCanonicalMarkerLine);
    }

    let prefix_end = begin + FIXED_REFERENCE_GENERATED_BEGIN_V1.len();
    let suffix_start = end;
    let generated = canonical_fixed_reference_generated_block_v1()?;
    Ok(format!(
        "{}\n{}{}",
        &template[..prefix_end],
        generated,
        &template[suffix_start..]
    ))
}

/// Builds the canonical Markdown inside the fixed-reference generated markers.
pub fn canonical_fixed_reference_generated_block_v1(
) -> Result<String, FixedReferenceSpecificationErrorV1> {
    let kdf_corpus = canonical_kdf_vector_corpus_v1();
    let kdf_material = canonical_synthetic_kdf_material_v1();
    let context_binding = kdf_material.context.binding_digest();
    let kdf_case = kdf_corpus
        .cases
        .first()
        .expect("the canonical KDF corpus has one fixed case");
    let unit_context =
        StableKeyDerivationContext::new([0x42; 32], 2, 1).expect("the fixed unit context is valid");
    let scalar_order = scalar_order_le();
    let clamp_zero = clamp_rfc8032([0; 32]);
    let clamp_ones = clamp_rfc8032([0xff; 32]);
    let basepoint = ED25519_BASEPOINT_POINT.compress().to_bytes();

    let arithmetic_corpus = canonical_vector_corpus_v1();
    let ceremony_context_corpus = canonical_ceremony_context_vector_corpus_v1();
    let lifecycle_corpus = canonical_lifecycle_continuity_corpus_v1();
    let provenance_corpus = canonical_provenance_vector_corpus_v1();
    let output_sharing_corpus = canonical_output_sharing_vector_corpus_v1();
    let semantic_lifecycle_corpus = canonical_semantic_lifecycle_vector_corpus_v1();
    let output_party_view_corpus = canonical_output_party_view_vector_corpus_v1();
    let evaluation_input_party_view_corpus =
        canonical_evaluation_input_party_view_vector_corpus_v1();
    let uniform_abort_corpus = canonical_uniform_abort_vector_corpus_v1();
    let evaluator_abort_view_corpus = canonical_evaluator_abort_view_vector_corpus_v1();
    let export_delivery_corpus = canonical_export_delivery_vector_corpus_v1();
    let activation_delivery_corpus = canonical_activation_delivery_vector_corpus_v1();
    let activation_recipient_party_view_corpus =
        canonical_activation_recipient_party_view_vector_corpus_v1();
    let recovery_credential_transition_corpus =
        canonical_recovery_credential_transition_vector_corpus_v1();
    let export_evaluator_authorization_corpus =
        canonical_export_evaluator_authorization_vector_corpus_v1();
    let registration_evaluator_admission_corpus =
        canonical_registration_evaluator_admission_vector_corpus_v1();
    let recovery_evaluator_admission_corpus =
        canonical_recovery_evaluator_admission_vector_corpus_v1();
    let commitments = [
        corpus_commitment(
            "vectors/ed25519-yao-v1.json",
            arithmetic_corpus.schema.clone(),
            arithmetic_corpus.cases.len(),
            &arithmetic_corpus,
            "clear arithmetic",
        )?,
        corpus_commitment(
            "vectors/ed25519-yao-kdf-v1.json",
            kdf_corpus.schema.clone(),
            kdf_corpus.cases.len(),
            &kdf_corpus,
            "contribution KDF",
        )?,
        corpus_commitment(
            "vectors/ed25519-yao-ceremony-context-v1.json",
            ceremony_context_corpus.schema.clone(),
            ceremony_context_corpus.cases.len(),
            &ceremony_context_corpus,
            "ceremony context",
        )?,
        corpus_commitment(
            "vectors/ed25519-yao-lifecycle-continuity-v1.json",
            lifecycle_corpus.schema.clone(),
            lifecycle_corpus.cases.len(),
            &lifecycle_corpus,
            "lifecycle continuity",
        )?,
        corpus_commitment(
            "vectors/ed25519-yao-provenance-v1.json",
            provenance_corpus.schema.clone(),
            provenance_corpus.cases.len(),
            &provenance_corpus,
            "provenance outer contract",
        )?,
        corpus_commitment_from_bytes(
            "vectors/ed25519-yao-output-sharing-v1.json",
            output_sharing_corpus.schema().to_owned(),
            output_sharing_corpus.case_count(),
            &canonical_output_sharing_vector_corpus_json_bytes_v1(),
        ),
        corpus_commitment_from_bytes(
            "vectors/ed25519-yao-semantic-lifecycle-v1.json",
            semantic_lifecycle_corpus.schema().to_owned(),
            semantic_lifecycle_corpus.case_count(),
            &canonical_semantic_lifecycle_vector_corpus_json_bytes_v1(),
        ),
        corpus_commitment_from_bytes(
            "vectors/ed25519-yao-output-party-views-v1.json",
            output_party_view_corpus.schema().to_owned(),
            output_party_view_corpus.case_count(),
            &canonical_output_party_view_vector_corpus_json_bytes_v1(),
        ),
        corpus_commitment_from_bytes(
            "vectors/ed25519-yao-evaluation-input-party-views-v1.json",
            evaluation_input_party_view_corpus.schema().to_owned(),
            evaluation_input_party_view_corpus.case_count(),
            &canonical_evaluation_input_party_view_vector_corpus_json_bytes_v1(),
        ),
        corpus_commitment_from_bytes(
            "vectors/ed25519-yao-uniform-abort-envelope-v1.json",
            uniform_abort_corpus.schema().to_owned(),
            uniform_abort_corpus.case_count(),
            &canonical_uniform_abort_vector_corpus_json_bytes_v1(),
        ),
        corpus_commitment_from_bytes(
            "vectors/ed25519-yao-evaluator-abort-state-party-views-v1.json",
            evaluator_abort_view_corpus.schema().to_owned(),
            evaluator_abort_view_corpus.case_count(),
            &canonical_evaluator_abort_view_vector_corpus_json_bytes_v1(),
        ),
        corpus_commitment_from_bytes(
            "vectors/ed25519-yao-export-delivery-v1.json",
            export_delivery_corpus.schema().to_owned(),
            export_delivery_corpus.case_count(),
            &canonical_export_delivery_vector_corpus_json_bytes_v1(),
        ),
        corpus_commitment_from_bytes(
            "vectors/ed25519-yao-activation-delivery-v1.json",
            activation_delivery_corpus.schema().to_owned(),
            activation_delivery_corpus.case_count(),
            &canonical_activation_delivery_vector_corpus_json_bytes_v1(),
        ),
        corpus_commitment_from_bytes(
            "vectors/ed25519-yao-activation-recipient-party-views-v1.json",
            activation_recipient_party_view_corpus.schema().to_owned(),
            activation_recipient_party_view_corpus.case_count(),
            &canonical_activation_recipient_party_view_vector_corpus_json_bytes_v1(),
        ),
        corpus_commitment_from_bytes(
            "vectors/ed25519-yao-recovery-credential-transition-v1.json",
            recovery_credential_transition_corpus.schema().to_owned(),
            recovery_credential_transition_corpus.case_count(),
            &canonical_recovery_credential_transition_vector_corpus_json_bytes_v1(),
        ),
        corpus_commitment_from_bytes(
            "vectors/ed25519-yao-export-evaluator-authorization-v1.json",
            export_evaluator_authorization_corpus.schema().to_owned(),
            export_evaluator_authorization_corpus.case_count(),
            &canonical_export_evaluator_authorization_vector_corpus_json_bytes_v1(),
        ),
        corpus_commitment_from_bytes(
            "vectors/ed25519-yao-registration-evaluator-admission-v1.json",
            registration_evaluator_admission_corpus.schema().to_owned(),
            registration_evaluator_admission_corpus.case_count(),
            &canonical_registration_evaluator_admission_vector_corpus_json_bytes_v1(),
        ),
        corpus_commitment_from_bytes(
            "vectors/ed25519-yao-recovery-evaluator-admission-v1.json",
            recovery_evaluator_admission_corpus.schema().to_owned(),
            recovery_evaluator_admission_corpus.case_count(),
            &canonical_recovery_evaluator_admission_vector_corpus_json_bytes_v1(),
        ),
    ];

    let contributions = &kdf_case.contributions;
    let rows = [
        KdfGoldenRow {
            role: "A",
            role_tag: CONTRIBUTION_KDF_ROLE_A_TAG_V1,
            source: "client",
            source_tag: CONTRIBUTION_KDF_CLIENT_SOURCE_TAG_V1,
            output: "y",
            output_tag: CONTRIBUTION_KDF_Y_OUTPUT_TAG_V1,
            output_hex: &contributions.y_client_a_hex,
        },
        KdfGoldenRow {
            role: "A",
            role_tag: CONTRIBUTION_KDF_ROLE_A_TAG_V1,
            source: "client",
            source_tag: CONTRIBUTION_KDF_CLIENT_SOURCE_TAG_V1,
            output: "tau",
            output_tag: CONTRIBUTION_KDF_TAU_OUTPUT_TAG_V1,
            output_hex: &contributions.tau_client_a_hex,
        },
        KdfGoldenRow {
            role: "B",
            role_tag: CONTRIBUTION_KDF_ROLE_B_TAG_V1,
            source: "client",
            source_tag: CONTRIBUTION_KDF_CLIENT_SOURCE_TAG_V1,
            output: "y",
            output_tag: CONTRIBUTION_KDF_Y_OUTPUT_TAG_V1,
            output_hex: &contributions.y_client_b_hex,
        },
        KdfGoldenRow {
            role: "B",
            role_tag: CONTRIBUTION_KDF_ROLE_B_TAG_V1,
            source: "client",
            source_tag: CONTRIBUTION_KDF_CLIENT_SOURCE_TAG_V1,
            output: "tau",
            output_tag: CONTRIBUTION_KDF_TAU_OUTPUT_TAG_V1,
            output_hex: &contributions.tau_client_b_hex,
        },
        KdfGoldenRow {
            role: "A",
            role_tag: CONTRIBUTION_KDF_ROLE_A_TAG_V1,
            source: "server",
            source_tag: CONTRIBUTION_KDF_SERVER_SOURCE_TAG_V1,
            output: "y",
            output_tag: CONTRIBUTION_KDF_Y_OUTPUT_TAG_V1,
            output_hex: &contributions.y_server_a_hex,
        },
        KdfGoldenRow {
            role: "A",
            role_tag: CONTRIBUTION_KDF_ROLE_A_TAG_V1,
            source: "server",
            source_tag: CONTRIBUTION_KDF_SERVER_SOURCE_TAG_V1,
            output: "tau",
            output_tag: CONTRIBUTION_KDF_TAU_OUTPUT_TAG_V1,
            output_hex: &contributions.tau_server_a_hex,
        },
        KdfGoldenRow {
            role: "B",
            role_tag: CONTRIBUTION_KDF_ROLE_B_TAG_V1,
            source: "server",
            source_tag: CONTRIBUTION_KDF_SERVER_SOURCE_TAG_V1,
            output: "y",
            output_tag: CONTRIBUTION_KDF_Y_OUTPUT_TAG_V1,
            output_hex: &contributions.y_server_b_hex,
        },
        KdfGoldenRow {
            role: "B",
            role_tag: CONTRIBUTION_KDF_ROLE_B_TAG_V1,
            source: "server",
            source_tag: CONTRIBUTION_KDF_SERVER_SOURCE_TAG_V1,
            output: "tau",
            output_tag: CONTRIBUTION_KDF_TAU_OUTPUT_TAG_V1,
            output_hex: &contributions.tau_server_b_hex,
        },
    ];

    let mut output = String::new();
    writeln!(
        output,
        "Generated schema: `{FIXED_REFERENCE_GENERATED_SCHEMA_V1}`"
    )
    .unwrap();
    writeln!(output).unwrap();
    writeln!(output, "### Fixed identifiers").unwrap();
    writeln!(output).unwrap();
    writeln!(output, "| Identifier | UTF-8 value | Byte length | Hex |").unwrap();
    writeln!(output, "| --- | --- | ---: | --- |").unwrap();
    append_ascii_row(
        &mut output,
        "protocol",
        ed25519_yao::PROTOCOL_ID_STR.as_bytes(),
    );
    append_ascii_row(
        &mut output,
        "activation circuit family",
        ed25519_yao::ACTIVATION_CIRCUIT_ID_STR.as_bytes(),
    );
    append_ascii_row(
        &mut output,
        "export circuit family",
        ed25519_yao::EXPORT_CIRCUIT_ID_STR.as_bytes(),
    );
    append_ascii_row(
        &mut output,
        "activation output schema",
        ed25519_yao::ACTIVATION_OUTPUT_SCHEMA_ID_STR.as_bytes(),
    );
    append_ascii_row(
        &mut output,
        "export output schema",
        ed25519_yao::EXPORT_OUTPUT_SCHEMA_ID_STR.as_bytes(),
    );

    writeln!(output).unwrap();
    writeln!(output, "### Domains and labels").unwrap();
    writeln!(output).unwrap();
    writeln!(output, "| Constant | Byte length | Hex |").unwrap();
    writeln!(output, "| --- | ---: | --- |").unwrap();
    append_bytes_row(
        &mut output,
        "application binding domain",
        ED25519_YAO_APPLICATION_BINDING_DOMAIN_V1,
    );
    append_bytes_row(
        &mut output,
        "wallet ID label",
        ED25519_YAO_APPLICATION_BINDING_WALLET_ID_LABEL_V1,
    );
    append_bytes_row(
        &mut output,
        "signing-key ID label",
        ED25519_YAO_APPLICATION_BINDING_SIGNING_KEY_ID_LABEL_V1,
    );
    append_bytes_row(
        &mut output,
        "signing-root ID label",
        ED25519_YAO_APPLICATION_BINDING_SIGNING_ROOT_ID_LABEL_V1,
    );
    append_bytes_row(
        &mut output,
        "key-creation signer-slot label",
        ED25519_YAO_APPLICATION_BINDING_KEY_CREATION_SIGNER_SLOT_LABEL_V1,
    );
    append_bytes_row(
        &mut output,
        "stable context domain",
        STABLE_KEY_DERIVATION_CONTEXT_DOMAIN_V1,
    );
    append_bytes_row(
        &mut output,
        "stable context binding domain",
        STABLE_KEY_DERIVATION_CONTEXT_BINDING_DOMAIN_V1,
    );
    append_bytes_row(
        &mut output,
        "contribution KDF extract salt",
        CONTRIBUTION_KDF_EXTRACT_SALT_V1,
    );
    append_bytes_row(
        &mut output,
        "contribution KDF expand domain",
        CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1,
    );

    writeln!(output).unwrap();
    writeln!(output, "### Arithmetic constants and fixtures").unwrap();
    writeln!(output).unwrap();
    writeln!(
        output,
        "- Scalar order `l`, canonical LE32: `{}`",
        encode_hex(&scalar_order)
    )
    .unwrap();
    writeln!(
        output,
        "- Compressed Ed25519 basepoint: `{}`",
        encode_hex(&basepoint)
    )
    .unwrap();
    writeln!(
        output,
        "- `clamp_rfc8032(00 * 32)`: `{}`",
        encode_hex(&clamp_zero)
    )
    .unwrap();
    writeln!(
        output,
        "- `clamp_rfc8032(ff * 32)`: `{}`",
        encode_hex(&clamp_ones)
    )
    .unwrap();
    writeln!(
        output,
        "- Contribution expand-info byte length: `{CONTRIBUTION_KDF_EXPAND_INFO_LEN_V1}`"
    )
    .unwrap();

    let application = &kdf_case.application_binding;
    let context = &kdf_case.context;
    writeln!(output).unwrap();
    writeln!(output, "### Application-binding and stable-context golden").unwrap();
    writeln!(output).unwrap();
    writeln!(output, "- Wallet ID: `{}`", application.wallet_id).unwrap();
    writeln!(
        output,
        "- NEAR Ed25519 signing-key ID: `{}`",
        application.near_ed25519_signing_key_id
    )
    .unwrap();
    writeln!(
        output,
        "- Signing-root ID: `{}`",
        application.signing_root_id
    )
    .unwrap();
    writeln!(
        output,
        "- Key-creation signer slot: `{}`",
        application.key_creation_signer_slot
    )
    .unwrap();
    writeln!(
        output,
        "- Application-binding bytes: `{}`",
        application.encoded_hex
    )
    .unwrap();
    writeln!(
        output,
        "- Application-binding SHA-256: `{}`",
        application.digest_sha256_hex
    )
    .unwrap();
    writeln!(output, "- Participant IDs: `{:?}`", context.participant_ids).unwrap();
    writeln!(output, "- Stable-context bytes: `{}`", context.encoded_hex).unwrap();
    writeln!(
        output,
        "- Stable-context binding SHA-256: `{}`",
        context.binding_sha256_hex
    )
    .unwrap();
    writeln!(
        output,
        "- `0x42 * 32`, participants `[1, 2]`, stable-context bytes: `{}`",
        encode_hex(unit_context.encode().as_bytes())
    )
    .unwrap();
    writeln!(
        output,
        "- `0x42 * 32`, participants `[1, 2]`, binding SHA-256: `{}`",
        encode_hex(unit_context.binding_digest().as_bytes())
    )
    .unwrap();

    writeln!(output).unwrap();
    writeln!(output, "### Contribution KDF golden").unwrap();
    writeln!(output).unwrap();
    writeln!(
        output,
        "Synthetic roots: client=`{}`, Deriver A=`{}`, Deriver B=`{}`.",
        kdf_case.synthetic_roots.client_root_hex,
        kdf_case.synthetic_roots.deriver_a_root_hex,
        kdf_case.synthetic_roots.deriver_b_root_hex
    )
    .unwrap();
    writeln!(output).unwrap();
    writeln!(
        output,
        "| Role | Role tag | Source | Source tag | Output | Output tag | Expand info hex | Canonical output hex |"
    )
    .unwrap();
    writeln!(
        output,
        "| --- | ---: | --- | ---: | --- | ---: | --- | --- |"
    )
    .unwrap();
    for row in rows {
        let info = contribution_expand_info_v1(
            row.role_tag,
            row.source_tag,
            row.output_tag,
            context_binding.as_bytes(),
        );
        writeln!(
            output,
            "| {} | `0x{:02x}` | {} | `0x{:02x}` | {} | `0x{:02x}` | `{}` | `{}` |",
            row.role,
            row.role_tag,
            row.source,
            row.source_tag,
            row.output,
            row.output_tag,
            encode_hex(&info),
            row.output_hex
        )
        .unwrap();
    }
    writeln!(output).unwrap();
    writeln!(
        output,
        "Joined seed: `{}`.",
        kdf_case.synthetic_clear_reference_trace.joined_seed_hex
    )
    .unwrap();
    writeln!(
        output,
        "Ed25519 public key: `{}`.",
        kdf_case.synthetic_clear_reference_trace.public_key_hex
    )
    .unwrap();

    writeln!(output).unwrap();
    writeln!(output, "### Normative companion specification commitments").unwrap();
    writeln!(output).unwrap();
    writeln!(output, "| Repository-relative path | Bytes | SHA-256 |").unwrap();
    writeln!(output, "| --- | ---: | --- |").unwrap();
    writeln!(
        output,
        "| `docs/output-sharing-v1.md` | {} | `{}` |",
        OUTPUT_SHARING_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(OUTPUT_SHARING_SPECIFICATION_V1))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/circuit-ir-v1.md` | {} | `{}` |",
        CIRCUIT_IR_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(CIRCUIT_IR_SPECIFICATION_V1))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/ceremony-context-v1.md` | {} | `{}` |",
        CEREMONY_CONTEXT_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(CEREMONY_CONTEXT_SPECIFICATION_V1))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/input-provenance-v1.md` | {} | `{}` |",
        INPUT_PROVENANCE_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(INPUT_PROVENANCE_SPECIFICATION_V1))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/semantic-artifact-lifecycle-v1.md` | {} | `{}` |",
        SEMANTIC_ARTIFACT_LIFECYCLE_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(
            SEMANTIC_ARTIFACT_LIFECYCLE_SPECIFICATION_V1
        ))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/output-party-views-v1.md` | {} | `{}` |",
        OUTPUT_PARTY_VIEWS_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(OUTPUT_PARTY_VIEWS_SPECIFICATION_V1))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/evaluation-input-party-views-v1.md` | {} | `{}` |",
        EVALUATION_INPUT_PARTY_VIEWS_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(
            EVALUATION_INPUT_PARTY_VIEWS_SPECIFICATION_V1
        ))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/uniform-abort-envelope-v1.md` | {} | `{}` |",
        UNIFORM_ABORT_ENVELOPE_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(UNIFORM_ABORT_ENVELOPE_SPECIFICATION_V1))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/evaluator-abort-state-party-views-v1.md` | {} | `{}` |",
        EVALUATOR_ABORT_STATE_PARTY_VIEWS_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(
            EVALUATOR_ABORT_STATE_PARTY_VIEWS_SPECIFICATION_V1
        ))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/authenticated-store-resolution-v1.md` | {} | `{}` |",
        AUTHENTICATED_STORE_RESOLUTION_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(
            AUTHENTICATED_STORE_RESOLUTION_SPECIFICATION_V1
        ))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/signing-worker-activation-v1.md` | {} | `{}` |",
        SIGNING_WORKER_ACTIVATION_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(SIGNING_WORKER_ACTIVATION_SPECIFICATION_V1))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/refresh-promotion-v1.md` | {} | `{}` |",
        REFRESH_PROMOTION_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(REFRESH_PROMOTION_SPECIFICATION_V1))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/benchmark-manifest-v1.md` | {} | `{}` |",
        BENCHMARK_MANIFEST_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(BENCHMARK_MANIFEST_SPECIFICATION_V1))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/artifact-filesystem-policy-v1.md` | {} | `{}` |",
        ARTIFACT_FILESYSTEM_POLICY_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(ARTIFACT_FILESYSTEM_POLICY_SPECIFICATION_V1))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/joint-refresh-delta-v1.md` | {} | `{}` |",
        JOINT_REFRESH_DELTA_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(JOINT_REFRESH_DELTA_SPECIFICATION_V1))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/export-delivery-lifecycle-v1.md` | {} | `{}` |",
        EXPORT_DELIVERY_LIFECYCLE_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(EXPORT_DELIVERY_LIFECYCLE_SPECIFICATION_V1))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/activation-delivery-lifecycle-v1.md` | {} | `{}` |",
        ACTIVATION_DELIVERY_LIFECYCLE_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(
            ACTIVATION_DELIVERY_LIFECYCLE_SPECIFICATION_V1
        ))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/activation-recipient-party-views-v1.md` | {} | `{}` |",
        ACTIVATION_RECIPIENT_PARTY_VIEWS_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(
            ACTIVATION_RECIPIENT_PARTY_VIEWS_SPECIFICATION_V1
        ))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/recovery-credential-transition-v1.md` | {} | `{}` |",
        RECOVERY_CREDENTIAL_TRANSITION_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(
            RECOVERY_CREDENTIAL_TRANSITION_SPECIFICATION_V1
        ))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/export-evaluator-authorization-v1.md` | {} | `{}` |",
        EXPORT_EVALUATOR_AUTHORIZATION_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(
            EXPORT_EVALUATOR_AUTHORIZATION_SPECIFICATION_V1
        ))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/registration-evaluator-admission-v1.md` | {} | `{}` |",
        REGISTRATION_EVALUATOR_ADMISSION_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(
            REGISTRATION_EVALUATOR_ADMISSION_SPECIFICATION_V1
        ))
    )
    .unwrap();
    writeln!(
        output,
        "| `docs/recovery-evaluator-admission-v1.md` | {} | `{}` |",
        RECOVERY_EVALUATOR_ADMISSION_SPECIFICATION_V1.len(),
        encode_hex(&Sha256::digest(
            RECOVERY_EVALUATOR_ADMISSION_SPECIFICATION_V1
        ))
    )
    .unwrap();

    writeln!(output).unwrap();
    writeln!(output, "### Canonical corpus commitments").unwrap();
    writeln!(output).unwrap();
    writeln!(
        output,
        "| Repository-relative path | Schema | Cases | Bytes | SHA-256 |"
    )
    .unwrap();
    writeln!(output, "| --- | --- | ---: | ---: | --- |").unwrap();
    for commitment in commitments {
        writeln!(
            output,
            "| `{}` | `{}` | {} | {} | `{}` |",
            commitment.path,
            commitment.schema,
            commitment.case_count,
            commitment.byte_length,
            commitment.sha256_hex
        )
        .unwrap();
    }
    writeln!(output).unwrap();

    Ok(output)
}

fn unique_marker(
    source: &str,
    marker: &str,
    missing: FixedReferenceSpecificationErrorV1,
    duplicate: FixedReferenceSpecificationErrorV1,
) -> Result<usize, FixedReferenceSpecificationErrorV1> {
    let mut matches = source.match_indices(marker);
    let first = matches.next().ok_or(missing)?;
    if matches.next().is_some() {
        return Err(duplicate);
    }
    Ok(first.0)
}

fn is_standalone_lf_line(source: &str, offset: usize, marker: &str) -> bool {
    let starts_line = offset == 0 || source.as_bytes().get(offset - 1) == Some(&b'\n');
    let end = offset + marker.len();
    let ends_line = end == source.len() || source.as_bytes().get(end) == Some(&b'\n');
    let excludes_crlf = offset == 0 || source.as_bytes().get(offset - 1) != Some(&b'\r');
    starts_line && ends_line && excludes_crlf
}

fn corpus_commitment<T: serde::Serialize>(
    path: &'static str,
    schema: String,
    case_count: usize,
    corpus: &T,
    corpus_label: &'static str,
) -> Result<CorpusCommitment, FixedReferenceSpecificationErrorV1> {
    let mut bytes = serde_json::to_vec_pretty(corpus).map_err(|error| {
        FixedReferenceSpecificationErrorV1::CorpusSerialization {
            corpus: corpus_label,
            message: error.to_string(),
        }
    })?;
    bytes.push(b'\n');
    Ok(CorpusCommitment {
        path,
        schema,
        case_count,
        byte_length: bytes.len(),
        sha256_hex: encode_hex(&Sha256::digest(&bytes)),
    })
}

fn corpus_commitment_from_bytes(
    path: &'static str,
    schema: String,
    case_count: usize,
    bytes: &[u8],
) -> CorpusCommitment {
    CorpusCommitment {
        path,
        schema,
        case_count,
        byte_length: bytes.len(),
        sha256_hex: encode_hex(&Sha256::digest(bytes)),
    }
}

fn append_ascii_row(output: &mut String, name: &str, bytes: &[u8]) {
    let value = core::str::from_utf8(bytes).expect("fixed identifier is ASCII");
    writeln!(
        output,
        "| {name} | `{value}` | {} | `{}` |",
        bytes.len(),
        encode_hex(bytes)
    )
    .unwrap();
}

fn append_bytes_row(output: &mut String, name: &str, bytes: &[u8]) {
    writeln!(
        output,
        "| {name} | {} | `{}` |",
        bytes.len(),
        encode_hex(bytes)
    )
    .unwrap();
}

fn scalar_order_le() -> [u8; 32] {
    let mut order = (Scalar::ZERO - Scalar::ONE).to_bytes();
    for byte in &mut order {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    order
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").unwrap();
    }
    output
}

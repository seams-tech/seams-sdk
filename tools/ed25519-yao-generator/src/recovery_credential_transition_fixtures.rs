//! Strict synthetic corpus for recovery credential suspension and promotion.

use core::fmt;

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;

use crate::activation_recipient_party_view_fixtures::canonical_activated_recipient_fixture_v1;
use crate::authenticated_store::{ActiveStoreStateVersionV1, StoreAuthoritySignature64V1};
use crate::lifecycle_domain::{ActivationPackageOriginV1, RegisteredLifecyclePreStateV1};
use crate::recovery_credential_transition::{
    prepare_authenticated_recovery_promotion_v1, RecoveryPromotionTransactionReceiptDigest32V1,
};

/// Schema identifier for the strict recovery credential-transition corpus.
pub const RECOVERY_CREDENTIAL_TRANSITION_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:recovery-credential-transition-vectors:v1";
/// Scope separating host transition evidence from durable production claims.
pub const RECOVERY_CREDENTIAL_TRANSITION_VECTOR_EVIDENCE_SCOPE_V1: &str =
    "host_only_synthetic_recovery_credential_transition_v1";

#[derive(Serialize)]
/// Strict one-case recovery suspension and promotion corpus.
pub struct RecoveryCredentialTransitionVectorCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    cases: Vec<RecoveryCredentialTransitionVectorCaseV1>,
}

impl RecoveryCredentialTransitionVectorCorpusV1 {
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
struct RecoveryCredentialTransitionVectorCaseV1 {
    case_id: String,
    request_kind: RecoveryRequestKindVectorV1,
    source_references: RecoveryTransitionSourceReferencesV1,
    suspended: RecoverySuspendedCredentialVectorV1,
    worker_activated: RecoveryWorkerActivatedVectorV1,
    promoted: RecoveryPromotedCredentialVectorV1,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum RecoveryRequestKindVectorV1 {
    Recovery,
}

#[derive(Serialize)]
struct RecoveryTransitionSourceReferencesV1 {
    ceremony_context_case_id: String,
    provenance_case_id: String,
    semantic_lifecycle_case_id: String,
    activation_delivery_case_id: String,
    activation_recipient_party_view_case_id: String,
}

#[derive(Serialize)]
struct RecoverySuspendedCredentialVectorV1 {
    credential_state: RecoveryCredentialStateVectorV1,
    old_active_state_version: u64,
    old_credential_binding_digest_hex: String,
    replacement_credential_binding_digest_hex: String,
    same_root_evidence_artifact_digest_hex: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum RecoveryCredentialStateVectorV1 {
    Suspended,
    Active,
    Tombstoned,
}

#[derive(Serialize)]
struct RecoveryWorkerActivatedVectorV1 {
    activation_receipt_digest_hex: String,
    package_set_digest_hex: String,
    output_committed_receipt_digest_hex: String,
    worker_storage_receipt_digest_hex: String,
    activation_epoch: u64,
}

#[derive(Serialize)]
struct RecoveryPromotedCredentialVectorV1 {
    credential_state: RecoveryCredentialStateVectorV1,
    old_state: RecoveryRegisteredStateVectorV1,
    next_state: RecoveryRegisteredStateVectorV1,
    tombstone: RecoveryCredentialTombstoneVectorV1,
    transaction_receipt_digest_hex: String,
    promotion_receipt_encoding_hex: String,
    promotion_receipt_digest_hex: String,
    promotion_receipt_signature_hex: String,
}

#[derive(Serialize)]
struct RecoveryRegisteredStateVectorV1 {
    active_state_version: u64,
    registered_public_key_hex: String,
    active_credential_binding_digest_hex: String,
    stable_scope_encoding_hex: String,
    active_activation_epoch: u64,
    deriver_a_root_record_hex: String,
    deriver_a_root_binding_hex: String,
    deriver_a_root_epoch: u64,
    deriver_a_state_record_hex: String,
    deriver_a_input_state_epoch: u64,
    deriver_b_root_record_hex: String,
    deriver_b_root_binding_hex: String,
    deriver_b_root_epoch: u64,
    deriver_b_state_record_hex: String,
    deriver_b_input_state_epoch: u64,
}

#[derive(Serialize)]
struct RecoveryCredentialTombstoneVectorV1 {
    credential_state: RecoveryCredentialStateVectorV1,
    credential_binding_digest_hex: String,
    retired_state_version: u64,
    tombstone_digest_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Failure returned for noncanonical recovery transition corpus bytes.
pub struct RecoveryCredentialTransitionVectorCorpusParseErrorV1;

impl fmt::Display for RecoveryCredentialTransitionVectorCorpusParseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("recovery credential-transition corpus must equal the exact canonical LF-terminated JSON bytes")
    }
}

impl std::error::Error for RecoveryCredentialTransitionVectorCorpusParseErrorV1 {}

/// Builds the canonical one-case recovery credential-transition corpus.
pub fn canonical_recovery_credential_transition_vector_corpus_v1(
) -> RecoveryCredentialTransitionVectorCorpusV1 {
    RecoveryCredentialTransitionVectorCorpusV1 {
        schema: RECOVERY_CREDENTIAL_TRANSITION_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: RECOVERY_CREDENTIAL_TRANSITION_VECTOR_EVIDENCE_SCOPE_V1.to_owned(),
        cases: vec![recovery_credential_transition_case()],
    }
}

/// Encodes the exact canonical corpus with one trailing LF.
pub fn canonical_recovery_credential_transition_vector_corpus_json_bytes_v1() -> Vec<u8> {
    let mut encoded =
        serde_json::to_vec_pretty(&canonical_recovery_credential_transition_vector_corpus_v1())
            .expect("fixed recovery credential-transition corpus serializes");
    encoded.push(b'\n');
    encoded
}

/// Parses only the exact canonical LF-terminated corpus bytes.
pub fn parse_canonical_recovery_credential_transition_vector_corpus_json_v1(
    encoded: &[u8],
) -> Result<
    RecoveryCredentialTransitionVectorCorpusV1,
    RecoveryCredentialTransitionVectorCorpusParseErrorV1,
> {
    if encoded != canonical_recovery_credential_transition_vector_corpus_json_bytes_v1() {
        return Err(RecoveryCredentialTransitionVectorCorpusParseErrorV1);
    }
    Ok(canonical_recovery_credential_transition_vector_corpus_v1())
}

fn recovery_credential_transition_case() -> RecoveryCredentialTransitionVectorCaseV1 {
    let activated = canonical_activated_recipient_fixture_v1(ActivationPackageOriginV1::Recovery);
    let (_, activation) = activated.into_recipient_states();
    let suspension = activation
        .state()
        .recovery_terminal_evaluation()
        .expect("canonical recovery terminal admission")
        .suspension();
    let old_state_version = suspension.active_state_version();
    let next_state_version = ActiveStoreStateVersionV1::new(old_state_version.value() + 1)
        .expect("next recovery state version");
    let transaction_receipt_digest = RecoveryPromotionTransactionReceiptDigest32V1::new([0xec; 32])
        .expect("transaction receipt digest");
    let suspended = RecoverySuspendedCredentialVectorV1 {
        credential_state: RecoveryCredentialStateVectorV1::Suspended,
        old_active_state_version: old_state_version.value(),
        old_credential_binding_digest_hex: encode_hex(
            suspension
                .continuity()
                .active_credential_binding_digest()
                .as_bytes(),
        ),
        replacement_credential_binding_digest_hex: encode_hex(
            suspension
                .continuity()
                .replacement_credential_binding_digest()
                .as_bytes(),
        ),
        same_root_evidence_artifact_digest_hex: encode_hex(
            suspension
                .continuity()
                .same_root_evidence_artifact_digest()
                .as_bytes(),
        ),
    };
    let worker_activated = RecoveryWorkerActivatedVectorV1 {
        activation_receipt_digest_hex: encode_hex(activation.receipt().digest().as_bytes()),
        package_set_digest_hex: encode_hex(activation.state().package_set_digest().as_bytes()),
        output_committed_receipt_digest_hex: encode_hex(
            activation
                .state()
                .output_committed_receipt_digest()
                .as_bytes(),
        ),
        worker_storage_receipt_digest_hex: encode_hex(
            activation.state().storage_receipt_digest().as_bytes(),
        ),
        activation_epoch: activation.state().activation_epoch().value(),
    };
    let prepared = prepare_authenticated_recovery_promotion_v1(
        activation,
        next_state_version,
        transaction_receipt_digest,
    )
    .expect("canonical recovery promotion preparation");
    let signing_key = SigningKey::from_bytes(&[0x5a; 32]);
    let signature = StoreAuthoritySignature64V1::from_bytes(
        signing_key
            .sign(&prepared.signing_bytes().expect("promotion signing bytes"))
            .to_bytes(),
    );
    let promoted = prepared
        .verify(signature)
        .expect("canonical recovery promotion");
    let old_state = promoted
        .activation()
        .state()
        .recovery_terminal_evaluation()
        .expect("retained recovery terminal admission")
        .suspension()
        .state();
    let tombstone = promoted.tombstone();
    let promoted_vector = RecoveryPromotedCredentialVectorV1 {
        credential_state: RecoveryCredentialStateVectorV1::Active,
        old_state: registered_state_vector(old_state_version, old_state),
        next_state: registered_state_vector(next_state_version, promoted.next_state()),
        tombstone: RecoveryCredentialTombstoneVectorV1 {
            credential_state: RecoveryCredentialStateVectorV1::Tombstoned,
            credential_binding_digest_hex: encode_hex(
                tombstone.credential_binding_digest().as_bytes(),
            ),
            retired_state_version: tombstone.retired_state_version().value(),
            tombstone_digest_hex: encode_hex(tombstone.digest().as_bytes()),
        },
        transaction_receipt_digest_hex: encode_hex(transaction_receipt_digest.as_bytes()),
        promotion_receipt_encoding_hex: encode_hex(
            &promoted
                .receipt()
                .body()
                .encode()
                .expect("promotion receipt bytes"),
        ),
        promotion_receipt_digest_hex: encode_hex(promoted.receipt().digest().as_bytes()),
        promotion_receipt_signature_hex: encode_hex(promoted.receipt().signature().as_bytes()),
    };
    RecoveryCredentialTransitionVectorCaseV1 {
        case_id: "recovery_credential_suspension_promotion_v1".to_owned(),
        request_kind: RecoveryRequestKindVectorV1::Recovery,
        source_references: RecoveryTransitionSourceReferencesV1 {
            ceremony_context_case_id: "ceremony-recovery-v1".to_owned(),
            provenance_case_id: "recovery_provenance_outer_v1".to_owned(),
            semantic_lifecycle_case_id: "recovery_semantic_artifacts_output_committed_v1"
                .to_owned(),
            activation_delivery_case_id: "recovery_activation_delivery_v1".to_owned(),
            activation_recipient_party_view_case_id: "recovery_activation_recipient_party_views_v1"
                .to_owned(),
        },
        suspended,
        worker_activated,
        promoted: promoted_vector,
    }
}

fn registered_state_vector(
    active_state_version: ActiveStoreStateVersionV1,
    state: &RegisteredLifecyclePreStateV1,
) -> RecoveryRegisteredStateVectorV1 {
    RecoveryRegisteredStateVectorV1 {
        active_state_version: active_state_version.value(),
        registered_public_key_hex: encode_hex(state.registered_public_key.as_bytes()),
        active_credential_binding_digest_hex: encode_hex(
            state.active_credential_binding_digest.as_bytes(),
        ),
        stable_scope_encoding_hex: encode_hex(
            &state.stable_scope.encode().expect("canonical stable scope"),
        ),
        active_activation_epoch: state.active_activation_epoch.value(),
        deriver_a_root_record_hex: encode_hex(state.deriver_a_root_record.as_bytes()),
        deriver_a_root_binding_hex: encode_hex(state.deriver_a_root_binding.as_bytes()),
        deriver_a_root_epoch: state.deriver_a_root_epoch.value(),
        deriver_a_state_record_hex: encode_hex(state.deriver_a_state_record.as_bytes()),
        deriver_a_input_state_epoch: state.deriver_a_input_state_epoch.value(),
        deriver_b_root_record_hex: encode_hex(state.deriver_b_root_record.as_bytes()),
        deriver_b_root_binding_hex: encode_hex(state.deriver_b_root_binding.as_bytes()),
        deriver_b_root_epoch: state.deriver_b_root_epoch.value(),
        deriver_b_state_record_hex: encode_hex(state.deriver_b_state_record.as_bytes()),
        deriver_b_input_state_epoch: state.deriver_b_input_state_epoch.value(),
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
